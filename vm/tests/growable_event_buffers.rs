//! The growable event buffers the host prover switches to.
//!
//! Its own test binary: the switch is process-wide, and the pool capacity below comes from the
//! environment, so neither may leak into the other vm tests. Needs a CUDA driver (pinned memory).

use std::{sync::mpsc, thread, time::Duration};

use pico_vm::{
    chips::chips::alu::event::AluEvent,
    emulator::riscv::{
        alu_event_pool::{
            get_alu_event_buffer, init_alu_event_buffer_pool, return_alu_event_buffer,
        },
        event_pool::use_growable_event_buffers,
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
    init_alu_event_buffer_pool(
        0,
        pico_vm::emulator::riscv::event_pool::HostAllocFlags::DEFAULT,
    );
    use_growable_event_buffers();

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

    return_alu_event_buffer(buf);
    drop(back);
}
