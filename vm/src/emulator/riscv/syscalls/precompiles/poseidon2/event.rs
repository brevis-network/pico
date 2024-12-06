use serde::{Deserialize, Serialize};

use crate::chips::chips::riscv_memory::event::{MemoryReadRecord, MemoryWriteRecord};

/// Poseidon2 Permutation Event.
///
/// This event is emitted when a Poseidon2 Permutation operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Poseidon2PermuteEvent {
    /// The lookup identifier.
    pub lookup_id: u128,
    /// The chunk number.
    pub chunk: u32,
    /// The clock cycle.
    pub clk: u32,
    /// State
    pub state_values: Vec<u32>,
    /// The pointer to the memory.
    pub input_memory_ptr: u32,
    /// The pointer to the memory.
    pub output_memory_ptr: u32,
    /// The memory records for the pre-state.
    pub state_read_records: Vec<MemoryReadRecord>,
    /// The memory records for the post-state.
    pub state_write_records: Vec<MemoryWriteRecord>,
}
