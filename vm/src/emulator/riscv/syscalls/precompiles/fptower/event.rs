use crate::{
    chips::{
        chips::riscv_memory::event::{MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord},
        gadgets::field::field_op::FieldOperation,
    },
    emulator::riscv::event_types::{RvAddr, RvChunk, RvClk, RvValue},
};
use serde::{Deserialize, Serialize};

/// Base field events
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct FpEvent {
    /// The chunk number.
    pub chunk: RvChunk,
    /// The clock cycle.
    pub clk: RvClk,
    /// The pointer to the x operand.
    pub x_ptr: RvAddr,
    /// The x operand in native guest-memory word form.
    pub x: Box<[RvValue]>,
    /// The pointer to the y operand.
    pub y_ptr: RvAddr,
    /// The y operand in native guest-memory word form.
    pub y: Box<[RvValue]>,
    /// The operation to perform.
    pub op: FieldOperation,
    /// The memory records for the x operand.
    pub x_memory_records: Box<[MemoryWriteRecord]>,
    /// The memory records for the y operand.
    pub y_memory_records: Box<[MemoryReadRecord]>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}

/// Fp2 addition and subtraction events
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Fp2AddSubEvent {
    /// The chunk number.
    pub chunk: RvChunk,
    /// The clock cycle.
    pub clk: RvClk,
    /// The pointer to the x operand.
    pub x_ptr: RvAddr,
    /// The x operand in native guest-memory dword form.
    pub x: Box<[RvValue]>,
    /// The pointer to the y operand.
    pub y_ptr: RvAddr,
    /// The y operand in native guest-memory dword form.
    pub y: Box<[RvValue]>,
    /// The operation to perform.
    pub op: FieldOperation,
    /// The memory records for the x operand.
    pub x_memory_records: Box<[MemoryWriteRecord]>,
    /// The memory records for the y operand.
    pub y_memory_records: Box<[MemoryReadRecord]>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}

/// Fp2 multiplication events
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Fp2MulEvent {
    /// The chunk number.
    pub chunk: RvChunk,
    /// The clock cycle.
    pub clk: RvClk,
    /// The pointer to the x operand.
    pub x_ptr: RvAddr,
    /// The x operand in native guest-memory dword form.
    pub x: Box<[RvValue]>,
    /// The pointer to the y operand.
    pub y_ptr: RvAddr,
    /// The y operand in native guest-memory dword form.
    pub y: Box<[RvValue]>,
    /// The memory records for the x operand.
    pub x_memory_records: Box<[MemoryWriteRecord]>,
    /// The memory records for the y operand.
    pub y_memory_records: Box<[MemoryReadRecord]>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}
