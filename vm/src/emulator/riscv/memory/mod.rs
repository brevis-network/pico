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
pub use contiguous::ContiguousRiscvMemory;
pub use paged::{Addr, Memory, Memory64, PagedMemory, Registers};
pub(crate) use pool::memory_pool_capacity_if_raised;
#[cfg(test)]
pub(crate) use pool::pool_size_floor;
pub use pool::{
    init_memory_pool, memories_made, memory_pool_capacity, memory_pool_free, memory_pool_size,
    memory_recycler_threads, raise_pool_size_floor, RecvTimeoutError, GLOBAL_MEMORY_POOL,
    GLOBAL_MEMORY_RECYCLER, POOL_WAIT,
};
