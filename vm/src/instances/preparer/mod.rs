pub mod device_history;
mod event_counter;
#[cfg(test)]
mod host_tracegen_tests;
mod memory;
mod prepared_gpu_events;
#[cfg(test)]
mod utils;

pub use event_counter::{
    precompute_event_size, CpuExtraEventIndices, DivremExtraEventIndices, EventCounter,
    StartIndices,
};

pub use device_history::{
    DeviceHistory, DeviceHistoryError, DeviceProgram, HistoryReader, Readiness,
};

pub use prepared_gpu_events::PreparedGpuEvents;

pub use memory::{
    add_byte_lookups_to_raw_table, additive_byte_table, gpu_add_host_byte_lookups,
    gpu_add_host_byte_lookups_additive, gpu_add_host_byte_lookups_through_host,
    gpu_allocate_and_copy_global_events, gpu_allocate_and_copy_poseidon2_events,
    gpu_allocate_byte_trace, gpu_finalize_byte_trace, GpuMemoryError, PreallocatedGpuMemory,
};

#[cfg(test)]
pub use utils::{verify_global_events, verify_poseidon2_events};
