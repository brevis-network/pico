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

#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct FfiMemoryReadRecord {
    pub value: u32,
    pub chunk: u32,
    pub timestamp: u32,
    pub prev_chunk: u32,
    pub prev_timestamp: u32,
}

#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct FfiMemoryWriteRecord {
    pub value: u32,
    pub chunk: u32,
    pub timestamp: u32,
    pub prev_value: u32,
    pub prev_chunk: u32,
    pub prev_timestamp: u32,
}

/// Uint256 Mul FFI Event.
#[derive(Default, Debug, Clone)]
#[repr(C)]
pub struct FfiUint256MulEvent {
    /// The chunk number
    pub chunk: u32,
    pub _pad: u32,
    /// The clock cycle
    pub clk: u64,
    /// The pointer to the x value
    pub x_ptr: u64,
    /// The x value as a list of words
    pub x: [u32; 8],
    /// The pointer to the y value
    pub y_ptr: u64,
    /// The y value as a list of words
    pub y: [u32; 8],
    /// The modulus as a list of word.
    pub modulus: [u32; 8],
    /// The memory records for the x value
    pub x_memory_records: [FfiMemoryWriteRecord; 8],
    /// The memory records for the y value
    pub y_memory_records: [FfiMemoryReadRecord; 8],
    /// The memory records for the modulus
    pub modulus_memory_records: [FfiMemoryReadRecord; 8],
}

impl From<Uint256MulEvent> for FfiUint256MulEvent {
    fn from(event: Uint256MulEvent) -> Self {
        let to_u32_arr = |arr: &[u64; 4]| -> [u32; 8] {
            let mut res = [0u32; 8];
            for i in 0..4 {
                res[2 * i] = (arr[i] & 0xFFFFFFFF) as u32;
                res[2 * i + 1] = (arr[i] >> 32) as u32;
            }
            res
        };

        let x_memory_records = {
            let mut res = [FfiMemoryWriteRecord::default(); 8];
            for i in 0..4 {
                let rec = event.x_memory_records[i];
                res[2 * i] = FfiMemoryWriteRecord {
                    value: (rec.value & 0xFFFFFFFF) as u32,
                    chunk: rec.chunk,
                    timestamp: rec.timestamp,
                    prev_value: (rec.prev_value & 0xFFFFFFFF) as u32,
                    prev_chunk: rec.prev_chunk,
                    prev_timestamp: rec.prev_timestamp,
                };
                res[2 * i + 1] = FfiMemoryWriteRecord {
                    value: (rec.value >> 32) as u32,
                    chunk: rec.chunk,
                    timestamp: rec.timestamp,
                    prev_value: (rec.prev_value >> 32) as u32,
                    prev_chunk: rec.prev_chunk,
                    prev_timestamp: rec.prev_timestamp,
                };
            }
            res
        };

        let to_read_records = |arr: &[MemoryReadRecord; 4]| -> [FfiMemoryReadRecord; 8] {
            let mut res = [FfiMemoryReadRecord::default(); 8];
            for i in 0..4 {
                let rec = arr[i];
                res[2 * i] = FfiMemoryReadRecord {
                    value: (rec.value & 0xFFFFFFFF) as u32,
                    chunk: rec.chunk,
                    timestamp: rec.timestamp,
                    prev_chunk: rec.prev_chunk,
                    prev_timestamp: rec.prev_timestamp,
                };
                res[2 * i + 1] = FfiMemoryReadRecord {
                    value: (rec.value >> 32) as u32,
                    chunk: rec.chunk,
                    timestamp: rec.timestamp,
                    prev_chunk: rec.prev_chunk,
                    prev_timestamp: rec.prev_timestamp,
                };
            }
            res
        };

        Self {
            chunk: event.chunk,
            _pad: 0,
            clk: event.clk,
            x_ptr: event.x_ptr,
            x: to_u32_arr(&event.x),
            y_ptr: event.y_ptr,
            y: to_u32_arr(&event.y),
            modulus: to_u32_arr(&event.modulus),
            x_memory_records,
            y_memory_records: to_read_records(&event.y_memory_records),
            modulus_memory_records: to_read_records(&event.modulus_memory_records),
        }
    }
}

impl From<&Uint256MulEvent> for FfiUint256MulEvent {
    fn from(event: &Uint256MulEvent) -> Self {
        event.clone().into()
    }
}
