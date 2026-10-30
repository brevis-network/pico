mod constants;
mod contiguous;
mod contiguous_ops;
mod paged;
mod pool;
mod storage;

#[cfg(test)]
mod tests_contiguous;
#[cfg(test)]
mod tests_paged;

pub use constants::{METADATA_SIZE, NUM_REGISTERS, VALUES_SIZE};
pub use contiguous::{ContiguousMemoryCheckpoint, ContiguousRiscvMemory};
pub use contiguous_ops::MemoryRecordRef;
pub use paged::{
    Addr, Memory, Memory32, Memory64, PagedMemory, PagedMemory32, PagedMemory64, Registers,
};
pub use pool::{
    init_memory_pool, memory_pool_capacity, memory_pool_free, memory_pool_size,
    memory_recycler_threads, raise_pool_size_floor, RecvTimeoutError, GLOBAL_MEMORY_POOL,
    GLOBAL_MEMORY_RECYCLER, POOL_WAIT,
};
