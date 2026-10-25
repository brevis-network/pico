//! `d_malloc` waits for a neighbouring lane's free instead of failing.
//!
//! One thread fills the card until an allocation fails; a second asks for one more chunk, which
//! cannot succeed until the first frees one; the first frees one 300 ms later. The second must
//! come back with memory, and must have waited for it.
//!
//! Its own file, and the only test in it: cargo isolates per FILE, `MLE_OOM_WAIT_MS` is read once
//! per process, and the fill takes every free byte on the card -- a second test here would race
//! it, and so would anything else using the card. Run it on an idle one (under
//! `CUDA_VISIBLE_DEVICES` pinning the visible device is ordinal 0).

use std::{
    ffi::c_void,
    thread,
    time::{Duration, Instant},
};

use cuda_mle::runtime::{
    error::MemoryError,
    memory_manager::{d_free, d_malloc},
};

const CHUNK: usize = 256 << 20;

#[test]
fn a_failed_allocation_waits_for_a_neighbouring_free() {
    // Read once, before the first allocation below. Short enough that the fill's terminal
    // failure -- which waits the whole budget -- keeps the test quick.
    std::env::set_var("MLE_OOM_WAIT_MS", "2000");

    let mut held: Vec<*mut c_void> = Vec::new();
    let terminal = loop {
        match d_malloc(CHUNK) {
            Ok(ptr) => held.push(ptr),
            Err(e) => break e,
        }
    };
    assert!(
        matches!(&terminal, MemoryError::Cuda(c) if c.is_out_of_memory()),
        "the fill should end on out-of-memory, not {terminal:?}"
    );
    assert!(
        !held.is_empty(),
        "the card should hold at least one chunk of {CHUNK} bytes"
    );

    let t0 = Instant::now();
    // A device pointer is not `Send`; the waiter hands it back as an address.
    let waiter = thread::spawn(move || (d_malloc(CHUNK).map(|p| p as usize), t0.elapsed()));
    thread::sleep(Duration::from_millis(300));
    // SAFETY: the pointer came from `d_malloc` above and leaves `held` here, so it is freed once.
    unsafe { d_free(held.pop().unwrap()).unwrap() };

    let (got, waited) = waiter.join().unwrap();
    let ptr = got.expect("the waiter should have been handed the freed chunk") as *mut c_void;
    assert!(
        waited >= Duration::from_millis(250),
        "waited only {waited:?}: the first attempt should have failed and waited for the free"
    );
    assert!(
        waited < Duration::from_millis(1_000),
        "took {waited:?}: the freed chunk should have been found within a few polls of the free"
    );

    // SAFETY: every pointer came from `d_malloc` in this test and is freed exactly once.
    unsafe {
        d_free(ptr).unwrap();
        for p in held {
            d_free(p).unwrap();
        }
    }
}
