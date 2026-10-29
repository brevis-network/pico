//! External-pool allocator contract.
//!
//! Test-backfill decision: the prototype's 701-line `memory_manager/tests.rs` was deleted with the
//! self-managed virtual-memory pool it existed to test (page mapping, VA reservation,
//! defragmentation) — none of that code or behaviour survives, so restoring those tests would mean
//! writing tests for a subsystem that no longer exists. What is worth pinning is the contract the
//! external-pool design actually has, which is what this file covers:
//!
//! - the fallback path allocates and frees, and the tracker accounts for it exactly;
//! - registering / clearing an external pool is observable and routes allocations;
//! - freeing a pointer this manager never handed out is a typed error, not UB or a panic;
//! - `tracked_current_bytes` counts live Rust-side bytes only (it returns to its baseline after a
//!   free, even though the pool retains the backing memory).
//!
//! This lives in `tests/` (its own process), not in a `#[cfg(test)]` module, for the same reason
//! `from_pool.rs` does: `set_external_pool` and the byte counters are **per-device global state**,
//! so asserting on them inside the lib test binary would race the ~180 other tests running in
//! parallel.
//!
//! **Cargo isolates per FILE, not per TEST.** These four still run as parallel threads inside
//! that one binary, racing on the very globals they assert on, so every test takes
//! [`GLOBAL_STATE`] for its whole body.
//!
//! `from_pool.rs` remains the end-to-end companion (pool-routed alloc → kernel → free → verify).

use cuda_mle::{
    prelude::F,
    runtime::{
        d_buffer::DeviceBuffer,
        memory_manager::{
            d_free, device_default_mem_pool, device_mem_info, external_pool_is_set,
            set_external_pool, tracked_current_bytes,
        },
    },
};

/// Under `CUDA_VISIBLE_DEVICES` pinning the visible device is ordinal 0.
const DEV: usize = 0;

/// Clears the external-pool routing on the way out, panic or not.
///
/// Without it, a failed assert in the middle of the pool test leaves the routing registered; and
/// because [`serialised`] absorbs poisoning rather than propagating it, the next test to take the
/// lock then fails on *its* "no external pool registered" assert. That reports the wrong test for
/// the wrong reason — exactly the confusion the poison absorption exists to avoid.
struct ClearPoolOnDrop(usize);

impl Drop for ClearPoolOnDrop {
    fn drop(&mut self) {
        // SAFETY: a null pool clears the routing, and every allocation drawn from the pool in this
        // file is freed before the guard drops.
        unsafe {
            let _ = set_external_pool(self.0, std::ptr::null_mut());
        }
    }
}

/// Serialises this file's tests, which all assert on process-global per-device state.
///
/// Poisoning is absorbed rather than unwrapped: one panicking test would otherwise turn into three
/// poison failures that hide it.
static GLOBAL_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serialised() -> std::sync::MutexGuard<'static, ()> {
    GLOBAL_STATE.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn tracked_bytes_follow_alloc_and_free_on_the_fallback_path() {
    let _serial = serialised();
    // No pool registered: allocations take the `cudaMallocAsync` fallback.
    assert!(
        !external_pool_is_set(DEV),
        "no external pool should be registered here — the pool test is the only one that \
         registers, and its ClearPoolOnDrop guard clears on every exit path"
    );

    let base = tracked_current_bytes();
    let n = 1usize << 16;
    let bytes = n * std::mem::size_of::<F>();

    let buf = DeviceBuffer::<F>::with_capacity(n);
    assert_eq!(
        tracked_current_bytes(),
        base + bytes,
        "a live DeviceBuffer must be accounted for exactly"
    );

    drop(buf);
    assert_eq!(
        tracked_current_bytes(),
        base,
        "freeing must return the tracked figure to its baseline (the pool may still retain the \
         backing memory — that is deliberately not counted)"
    );
}

#[test]
fn external_pool_registration_is_observable_and_routes_allocations() {
    let _serial = serialised();
    let pool = device_default_mem_pool(DEV).expect("device default mem pool");
    assert!(!pool.is_null(), "default mem pool handle is null");

    // SAFETY: `pool` is the device's own default pool, valid for the process lifetime, and every
    // allocation drawn from it below is freed before the routing is cleared.
    unsafe { set_external_pool(DEV, pool).expect("register external pool") };
    // Declared after `_serial`, so it drops (and clears) while this test still holds the lock.
    let _routing = ClearPoolOnDrop(DEV);
    assert!(external_pool_is_set(DEV), "registration must be observable");

    // Routed through `cudaMallocFromPoolAsync` now; tracking is unchanged by the routing.
    let base = tracked_current_bytes();
    let n = 1usize << 14;
    let buf = DeviceBuffer::<F>::with_capacity(n);
    assert_eq!(
        tracked_current_bytes(),
        base + n * std::mem::size_of::<F>(),
        "pool-routed allocations are tracked like fallback ones"
    );
    drop(buf); // returns to the pool via cudaFreeAsync
    assert_eq!(tracked_current_bytes(), base);

    // SAFETY: passing a null pool clears the routing; all pool allocations above are freed.
    unsafe { set_external_pool(DEV, std::ptr::null_mut()).expect("clear external pool") };
    assert!(
        !external_pool_is_set(DEV),
        "clearing must be observable, so a later assert-on-pool cannot pass spuriously"
    );
}

#[test]
fn freeing_an_untracked_pointer_is_a_typed_error() {
    let _serial = serialised();
    // A pointer this manager never handed out: freeing it must be rejected rather than passed to
    // `cudaFreeAsync`, which is what keeps `d_free` safe to call during cross-device teardown.
    let bogus = 0xdead_beef_usize as *mut std::ffi::c_void;
    // SAFETY: `d_free` is expected to reject this before dereferencing or freeing anything.
    let err = unsafe { d_free(bogus) }.expect_err("untracked pointer must not be freed");
    assert!(
        matches!(
            err,
            cuda_mle::runtime::error::MemoryError::InvalidPointer
                | cuda_mle::runtime::error::MemoryError::NullPointer
        ),
        "expected InvalidPointer, got {err:?}"
    );
}

#[test]
fn device_mem_info_is_device_wide_and_at_least_the_tracked_working_set() {
    let _serial = serialised();
    // `device_mem_info` is the figure the driver enforces, so it must bound this crate's tracked
    // bytes. This is the invariant that makes it (not `tracked_current_bytes`) the right thing to
    // budget a device against — see the `memory_manager` module header.
    let n = 1usize << 18;
    let _buf = DeviceBuffer::<F>::with_capacity(n);

    let (free, total) = device_mem_info();
    assert!(total > 0, "device total memory must be non-zero");
    assert!(free <= total, "free must not exceed total");

    let used = total - free;
    assert!(
        used >= tracked_current_bytes(),
        "device-wide used ({used}) must bound the tracked working set ({})",
        tracked_current_bytes()
    );
}
