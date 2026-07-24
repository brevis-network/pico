use crossbeam::channel::{Receiver, Sender};
use once_cell::sync::Lazy;

use super::contiguous::ContiguousRiscvMemory;

pub static GLOBAL_MEMORY_POOL: Lazy<(
    Sender<ContiguousRiscvMemory>,
    Receiver<ContiguousRiscvMemory>,
)> = Lazy::new(|| {
    let pool_size = std::env::var("MEMORY_POOL_SIZE")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(16);

    let (tx, rx) = crossbeam::channel::bounded(pool_size);
    for _ in 0..pool_size {
        let _ = tx.send(ContiguousRiscvMemory::new());
    }
    (tx, rx)
});

/// Eagerly initialize the memory pool and recycler threads.
/// Safe to call multiple times.
pub fn init_memory_pool() {
    let _ = GLOBAL_MEMORY_POOL.1.len();
    let _ = &*GLOBAL_MEMORY_RECYCLER;
}

pub static GLOBAL_MEMORY_RECYCLER: Lazy<Sender<(ContiguousRiscvMemory, bool)>> = Lazy::new(|| {
    let (tx, rx) = crossbeam::channel::unbounded::<(ContiguousRiscvMemory, bool)>();
    let num_recyclers = std::env::var("MEMORY_RECYCLER_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(4);

    for i in 0..num_recyclers {
        let rx_clone = rx.clone();
        std::thread::Builder::new()
            .name(format!("MemoryRecycler-{i}"))
            .spawn(move || {
                while let Ok((mut mem, needs_reset)) = rx_clone.recv() {
                    if needs_reset {
                        mem.reset();
                    }
                    let _ = GLOBAL_MEMORY_POOL.0.send(mem);
                }
            })
            .expect("Failed to spawn memory recycler thread");
    }
    tx
});
