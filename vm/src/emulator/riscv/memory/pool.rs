use crossbeam::channel::{Receiver, Sender};
use once_cell::sync::Lazy;
use std::time::Duration;

/// Re-exported so callers outside this crate can tell a timed-out wait from a closed pool without
/// taking a crossbeam dependency of their own.
pub use crossbeam::channel::RecvTimeoutError;

use super::contiguous::ContiguousRiscvMemory;

/// The cap on how many memories are in flight at once. A function rather than an inline read, so
/// the startup check that warns about a pool too small for the run cannot drift from it.
pub fn memory_pool_size() -> usize {
    std::env::var("MEMORY_POOL_SIZE")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(16)
}

/// How many memories the pool creates up front; the rest are created as it runs low.
fn memory_pool_eager() -> usize {
    std::env::var("MEMORY_POOL_EAGER")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(8)
        .min(memory_pool_size())
}

/// The pool tops itself up while it holds fewer memories than this.
fn memory_pool_low_water() -> usize {
    std::env::var("MEMORY_POOL_LOW_WATER")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(8)
}

/// How many memories the pool ever holds: [`memory_pool_size`], unless a low-water mark of 0 stops
/// it creating any past the eager ones.
pub fn memory_pool_capacity() -> usize {
    if memory_pool_low_water() == 0 {
        memory_pool_eager()
    } else {
        memory_pool_size()
    }
}

/// How long a caller waits on an empty pool before saying so. Both callers report and keep
/// waiting: a run that is merely slow must not lose its work. Long enough that a run simply
/// under back-pressure never reaches it.
pub const POOL_WAIT: Duration = Duration::from_secs(600);

pub static GLOBAL_MEMORY_POOL: Lazy<(
    Sender<ContiguousRiscvMemory>,
    Receiver<ContiguousRiscvMemory>,
)> = Lazy::new(|| {
    let pool_size = memory_pool_size();

    let (tx, rx) = crossbeam::channel::bounded(pool_size);

    // Each entry maps ~4GB of zero pages, so pre-creating all `pool_size` of them costs ~0.7s up
    // front and most are never handed out. Treat `MEMORY_POOL_SIZE` as a cap: seed a working set,
    // then top up from a background thread while the pool is below the low-water mark. In-flight
    // entries cannot exceed the cap, so the recycler sending into `tx` cannot deadlock the filler.
    let eager = memory_pool_eager();
    let low_water = memory_pool_low_water();

    for _ in 0..eager {
        let _ = tx.send(ContiguousRiscvMemory::new());
    }

    if pool_size > eager {
        let tx_bg = tx.clone();
        std::thread::Builder::new()
            .name("MemoryPoolFill".to_string())
            .spawn(move || {
                let mut created = eager;
                while created < pool_size {
                    if tx_bg.len() >= low_water {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        continue;
                    }
                    if tx_bg.send(ContiguousRiscvMemory::new()).is_err() {
                        break;
                    }
                    created += 1;
                }
            })
            .expect("Failed to spawn memory pool fill thread");
    }

    (tx, rx)
});

/// Eagerly initialize the memory pool and recycler threads.
/// Safe to call multiple times.
pub fn init_memory_pool() {
    let _ = GLOBAL_MEMORY_POOL.1.len();
    let _ = &*GLOBAL_MEMORY_RECYCLER;
}

/// How many threads put recycled memories back in the pool. A function for the reason
/// [`memory_pool_size`] is one.
pub fn memory_recycler_threads() -> usize {
    std::env::var("MEMORY_RECYCLER_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(4)
}

pub static GLOBAL_MEMORY_RECYCLER: Lazy<Sender<(ContiguousRiscvMemory, bool)>> = Lazy::new(|| {
    let (tx, rx) = crossbeam::channel::unbounded::<(ContiguousRiscvMemory, bool)>();
    let num_recyclers = memory_recycler_threads();

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
