mod event_counter;
#[cfg(test)]
mod host_tracegen_tests;
mod memory;
mod packed_events;
mod prepared_gpu_events;
mod shape;
mod utils;

pub use event_counter::{
    precompute_event_size, CpuExtraEventIndices, DivremExtraEventIndices, EventCounter,
    StartIndices,
};

pub use shape::padding_shape;

pub use packed_events::{
    init_packed_event_pools, packed_events_enabled, packed_pools_initialized, AddSubEventPacked,
    CpuEventPacked, LtEventPacked, MemRecordPacked, PackedEventStage, PACKED_EVENT_FORMAT_V1,
};

#[cfg(test)]
pub use packed_events::try_stage_forced;

pub use prepared_gpu_events::PreparedGpuEvents;

pub use memory::{
    add_byte_lookups_to_raw_table, gpu_add_host_byte_lookups, gpu_allocate_and_copy_add_sub_events,
    gpu_allocate_and_copy_alu_events, gpu_allocate_and_copy_cpu_events,
    gpu_allocate_and_copy_global_events, gpu_allocate_and_copy_lt_events,
    gpu_allocate_and_copy_mul_events, gpu_allocate_and_copy_poseidon2_events,
    gpu_allocate_byte_trace, gpu_allocate_cpu_events, gpu_finalize_byte_trace, GpuMemoryError,
    PreallocatedGpuMemory,
};

pub use utils::{
    verify_add_sub_events, verify_global_events, verify_lt_events, verify_mul_events,
    verify_poseidon2_events,
};
