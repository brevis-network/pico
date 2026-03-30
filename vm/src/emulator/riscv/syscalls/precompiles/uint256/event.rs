use crate::{
    chips::{
        chips::riscv_memory::event::{MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord},
        precompiles::uint256::UINT256_NUM_WORDS,
    },
    emulator::riscv::event_types::{RvAddr, RvChunk, RvClk, RvValue},
};
use serde::{Deserialize, Serialize};

/// Uint256 Mul Event.
///
/// This event is emitted when uint256 multiplication operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Uint256MulEvent {
    /// The chunk number
    pub chunk: RvChunk,
    /// The clock cycle
    pub clk: RvClk,
    /// The pointer to the x value
    pub x_ptr: RvAddr,
    /// The x value in native guest-memory dword form.
    pub x: [RvValue; UINT256_NUM_WORDS],
    /// The pointer to the y value
    pub y_ptr: RvAddr,
    /// The y value in native guest-memory dword form.
    pub y: [RvValue; UINT256_NUM_WORDS],
    /// The modulus in native guest-memory dword form.
    pub modulus: [RvValue; UINT256_NUM_WORDS],
    /// The memory records for the x value
    pub x_memory_records: [MemoryWriteRecord; UINT256_NUM_WORDS],
    /// The memory records for the y value
    pub y_memory_records: [MemoryReadRecord; UINT256_NUM_WORDS],
    /// The memory records for the modulus
    pub modulus_memory_records: [MemoryReadRecord; UINT256_NUM_WORDS],
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}
