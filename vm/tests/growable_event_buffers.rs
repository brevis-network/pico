//! The growable event buffers the host prover switches to.
//!
//! Its own test binary: the scopes are process-wide, and the pool capacity below comes from the
//! environment, so neither may leak into the other vm tests. Needs a CUDA driver (pinned memory).

use std::{sync::mpsc, thread, time::Duration};

use pico_vm::{
    chips::chips::alu::event::AluEvent,
    emulator::riscv::{
        alu_event_pool::{
            alu_event_buffer_capacity, alu_event_buffer_pool_size, get_alu_event_buffer,
            init_alu_event_buffer_pool, return_alu_event_buffer, size_alu_event_buffer_pool,
        },
        event_pool::{growable_event_buffers, pooled_event_buffers, HostAllocFlags, Pinning},
    },
};

/// The pool's buffer capacity here, set before anything reads it.
const POOL_CAPACITY: usize = 8192;

fn event(i: usize) -> AluEvent {
    AluEvent {
        clk: i as _,
        ..AluEvent::default()
    }
}

#[test]
fn growable_buffers() {
    std::env::set_var("ALU_EVENT_BUFFER_SIZE", POOL_CAPACITY.to_string());
    // A size-0 pool, as the host prover makes: anything returned to it blocks unless dropped.
    init_alu_event_buffer_pool(0, HostAllocFlags::DEFAULT);
    let growable = growable_event_buffers();

    // Contents survive every grow, through pushes and extends alike.
    let mut buf = get_alu_event_buffer().expect("a buffer");
    let mut expected = Vec::new();
    for i in 0..3 * 4096 + 7 {
        buf.push_alu(event(i)).expect("push");
        expected.push(i);
    }
    let tail: Vec<AluEvent> = (20_000..20_100).map(event).collect();
    buf.extend_from_alu_slice(&tail).expect("extend");
    expected.extend(20_000..20_100);
    let clks: Vec<usize> = buf.as_slice().iter().map(|e| e.clk as usize).collect();
    assert_eq!(clks, expected);
    assert_eq!(buf.remaining_capacity(), usize::MAX);

    // Serde round trip above the initial capacity.
    let bytes = bincode::serialize(&buf).expect("serialize");
    let back: pico_vm::emulator::riscv::alu_event_pool::AluEventBuffer =
        bincode::deserialize(&bytes).expect("deserialize");
    let back_clks: Vec<usize> = back.as_slice().iter().map(|e| e.clk as usize).collect();
    assert_eq!(back_clks, expected);

    // A growable buffer that ends at exactly the pool's capacity is freed, not sent to the pool.
    let mut full = get_alu_event_buffer().expect("a buffer");
    for i in 0..POOL_CAPACITY {
        full.push_alu(event(i)).expect("push");
    }
    assert_eq!(full.capacity(), POOL_CAPACITY);
    let (done, wait) = mpsc::channel();
    thread::spawn(move || {
        return_alu_event_buffer(full);
        let _ = done.send(());
    });
    wait.recv_timeout(Duration::from_secs(30))
        .expect("returning a grown buffer blocked on the pool");

    // A pooled run waits for the growable scope to close.
    let (entered, pooled_entered) = mpsc::channel();
    let pooled_run = thread::spawn(move || {
        let scope = pooled_event_buffers();
        let _ = entered.send(());
        // Hold it until the main thread has seen a growable scope wait on it.
        thread::sleep(Duration::from_millis(500));
        drop(scope);
    });
    assert!(pooled_entered
        .recv_timeout(Duration::from_millis(300))
        .is_err());
    drop(growable);
    pooled_entered
        .recv_timeout(Duration::from_secs(30))
        .expect("the pooled run never started");
    // ... and a growable scope waits for the pooled run.
    let t = std::time::Instant::now();
    let regrown = growable_event_buffers();
    assert!(t.elapsed() >= Duration::from_millis(100));
    drop(regrown);
    pooled_run.join().unwrap();

    // Past the scope, a sized pool lends bounded buffers again: the emulation's growable mode does
    // not leak into a later pipeline.
    size_alu_event_buffer_pool(2, None, Pinning::UpFront, HostAllocFlags::DEFAULT);
    assert_eq!(alu_event_buffer_pool_size(), Some(2));
    let mut pooled = get_alu_event_buffer().expect("a pooled buffer");
    assert_eq!(pooled.capacity(), POOL_CAPACITY);
    for i in 0..POOL_CAPACITY {
        pooled.push_alu(event(i)).expect("push");
    }
    assert!(pooled.push_alu(event(0)).is_err(), "a pooled buffer grew");

    // A buffer lent before a resize is freed, not sent to the new pool, whose channel is full. The
    // resize states its own capacity, which wins over the environment's.
    size_alu_event_buffer_pool(
        1,
        Some(2 * POOL_CAPACITY),
        Pinning::OnDemand,
        HostAllocFlags::DEFAULT,
    );
    assert_eq!(alu_event_buffer_capacity(), 2 * POOL_CAPACITY);
    let (done, wait) = mpsc::channel();
    thread::spawn(move || {
        return_alu_event_buffer(pooled);
        return_alu_event_buffer(buf);
        drop(back);
        let _ = done.send(());
    });
    wait.recv_timeout(Duration::from_secs(30))
        .expect("returning an old buffer blocked on the new pool");
}
