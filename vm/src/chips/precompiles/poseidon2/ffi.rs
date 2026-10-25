use tracing::debug;

use crate::{
    chips::chips::events::{MemoryReadRecord, MemoryWriteRecord},
    emulator::riscv::syscalls::precompiles::Poseidon2PermuteEvent,
    primitives::consts::PERMUTATION_WIDTH,
};

// TODO: consider removing this
#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct FfiPoseidon2PermuteEvent {
    pub chunk: u32,
    pub clk: u32,
    pub state_values: [u32; PERMUTATION_WIDTH],
    pub input_memory_ptr: u32,
    pub output_memory_ptr: u32,
    pub state_read_records: [MemoryReadRecord; PERMUTATION_WIDTH],
    pub state_write_records: [MemoryWriteRecord; PERMUTATION_WIDTH],
}

impl From<Poseidon2PermuteEvent> for FfiPoseidon2PermuteEvent {
    fn from(event: Poseidon2PermuteEvent) -> Self {
        debug!("Converting Poseidon2PermuteEvent to FfiPoseidon2PermuteEvent");
        debug!(
            "Poseidon2PermuteEvent.state_read_records size: {}",
            event.state_read_records.len()
        );

        Self {
            chunk: event.chunk,
            clk: event.clk.try_into().unwrap(),
            state_values: event
                .state_values
                .try_into()
                .expect("Expected Vec<u32> to have length equal to PERMUTATION_WIDTH"),
            input_memory_ptr: event.input_memory_ptr.try_into().unwrap(),
            output_memory_ptr: event.output_memory_ptr.try_into().unwrap(),
            state_read_records: event
                .state_read_records
                .try_into()
                .expect("Expected Vec<MemoryReadRecord> to have length equal to PERMUTATION_WIDTH"),
            state_write_records: event.state_write_records.try_into().expect(
                "Expected Vec<MemoryWriteRecord> to have length equal to PERMUTATION_WIDTH",
            ),
        }
    }
}

impl From<&Poseidon2PermuteEvent> for FfiPoseidon2PermuteEvent {
    fn from(event: &Poseidon2PermuteEvent) -> Self {
        debug!("Converting Poseidon2PermuteEvent to FfiPoseidon2PermuteEvent");
        debug!(
            "Poseidon2PermuteEvent.state_read_records size: {}",
            event.state_read_records.len()
        );

        Self {
            chunk: event.chunk,
            clk: event.clk.try_into().unwrap(),
            state_values: event
                .state_values
                .clone()
                .try_into()
                .expect("Expected Vec<u32> to have length equal to PERMUTATION_WIDTH"),
            input_memory_ptr: event.input_memory_ptr.try_into().unwrap(),
            output_memory_ptr: event.output_memory_ptr.try_into().unwrap(),
            state_read_records: event
                .state_read_records
                .clone()
                .try_into()
                .expect("Expected Vec<MemoryReadRecord> to have length equal to PERMUTATION_WIDTH"),
            state_write_records: event.state_write_records.clone().try_into().expect(
                "Expected Vec<MemoryWriteRecord> to have length equal to PERMUTATION_WIDTH",
            ),
        }
    }
}
