use serde::{Deserialize, Serialize};

use crate::{
    chips::{chips::riscv_memory::event::MemoryRecordEnum, ffi::FfiOption},
    compiler::riscv::instruction::Instruction,
    emulator::riscv::{
        event_types::{RvAddr, RvChunk, RvClk, RvValue},
        record::MemoryAccessRecord,
    },
};

/// CPU Event.
///
/// This object encapsulates the information needed to prove a CPU operation. This includes its
/// chunk, opcode, operands, and other relevant information.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, Default, PartialEq)]
#[repr(C)]
pub struct CpuEvent {
    /// The chunk number.
    pub chunk: RvChunk,
    /// The clock cycle.
    pub clk: RvClk,
    /// The program counter.
    pub pc: RvAddr,
    /// The next program counter.
    pub next_pc: RvAddr,
    /// The instruction.
    pub instruction: Instruction,
    /// The first operand.
    pub a: RvValue,
    /// The first operand memory record.
    pub a_record: FfiOption<MemoryRecordEnum>,
    /// The second operand.
    pub b: RvValue,
    /// The second operand memory record.
    pub b_record: FfiOption<MemoryRecordEnum>,
    /// The third operand.
    pub c: RvValue,
    /// The third operand memory record.
    pub c_record: FfiOption<MemoryRecordEnum>,
    /// The memory value.
    pub memory: FfiOption<RvValue>,
    /// The memory record.
    pub memory_record: FfiOption<MemoryRecordEnum>,
    /// The exit code.
    pub exit_code: u32,
}

/// Slimmed CpuEvent for GPU trace generation.
///
/// Excludes `memory`, `memory_record`, and `exit_code` which are not accessed
/// by the riscv_cpu CUDA kernel, reducing per-event size by ~24%.
#[derive(Debug, Copy, Clone, Default)]
#[repr(C)]
pub struct CpuEventSlim {
    pub chunk: RvChunk,
    pub clk: RvClk,
    pub pc: RvAddr,
    pub next_pc: RvAddr,
    pub instruction: Instruction,
    pub a: RvValue,
    pub a_record: FfiOption<MemoryRecordEnum>,
    pub b: RvValue,
    pub b_record: FfiOption<MemoryRecordEnum>,
    pub c: RvValue,
    pub c_record: FfiOption<MemoryRecordEnum>,
}

impl From<&CpuEvent> for CpuEventSlim {
    #[inline]
    fn from(e: &CpuEvent) -> Self {
        Self {
            chunk: e.chunk,
            clk: e.clk,
            pc: e.pc,
            next_pc: e.next_pc,
            instruction: e.instruction,
            a: e.a,
            a_record: e.a_record,
            b: e.b,
            b_record: e.b_record,
            c: e.c,
            c_record: e.c_record,
        }
    }
}

impl CpuEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chunk: RvChunk,
        clk: RvClk,
        pc: RvAddr,
        next_pc: RvAddr,
        instruction: Instruction,
        a: RvValue,
        b: RvValue,
        c: RvValue,
        memory: Option<RvValue>,
        record: MemoryAccessRecord,
        exit_code: u32,
    ) -> Self {
        Self {
            chunk,
            clk,
            pc,
            next_pc,
            instruction,
            a,
            a_record: record.a.into(), // TODO: consider changing the underlying type to FfiOption
            b,
            b_record: record.b.into(),
            c,
            c_record: record.c.into(),
            memory: memory.into(),
            memory_record: record.memory.into(),
            exit_code,
        }
    }

    /// The previous value of op_a's memory access — the syscall code on ECALL rows: a read keeps
    /// its value, a write exposes its `prev_value`, an absent record is 0.
    #[inline]
    pub fn op_a_prev_value(&self) -> u64 {
        match &self.a_record {
            FfiOption::Some(MemoryRecordEnum::Read(r)) => r.value,
            FfiOption::Some(MemoryRecordEnum::Write(w)) => w.prev_value,
            FfiOption::None => 0,
        }
    }

    /// The committed value of op_a: the memory record's value overwrites the event value when a
    /// record exists (they can differ, e.g. for `ENTER_UNCONSTRAINED` where the unconstrained
    /// block mutates registers before the event's operand snapshot is taken).
    #[inline]
    pub fn op_a_committed_value(&self) -> u64 {
        match &self.a_record {
            FfiOption::Some(r) => r.value(),
            FfiOption::None => self.a,
        }
    }

    /// The committed value of op_b: a READ record's value overwrites the event value; anything
    /// else keeps the event value.
    #[inline]
    pub fn op_b_committed_value(&self) -> u64 {
        match &self.b_record {
            FfiOption::Some(MemoryRecordEnum::Read(r)) => r.value,
            _ => self.b,
        }
    }

    /// The committed value of op_c (see [`Self::op_b_committed_value`]).
    #[inline]
    pub fn op_c_committed_value(&self) -> u64 {
        match &self.c_record {
            FfiOption::Some(MemoryRecordEnum::Read(r)) => r.value,
            _ => self.c,
        }
    }
}

/// ALU events one CPU row adds (see `CpuChip::count_cpu_event`). Shared with the GPU kernels,
/// which index the ALU buffers by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct CpuExtraEventIndices {
    pub add: usize,
    pub lt: usize,
}

#[cfg(test)]
mod tests {
    use super::CpuEvent;
    use crate::{
        chips::{
            chips::riscv_memory::event::{MemoryReadRecord, MemoryRecordEnum, MemoryWriteRecord},
            ffi::FfiOption,
        },
        compiler::riscv::{instruction::Instruction, opcode::Opcode},
        emulator::riscv::record::MemoryAccessRecord,
    };

    /// Memory accesses whose fields are all wide and all distinct, so a round-trip that drops or
    /// transposes one is visible.
    fn wide_access_record() -> MemoryAccessRecord {
        MemoryAccessRecord {
            a: Some(MemoryRecordEnum::Write(MemoryWriteRecord {
                value: 0x1122_3344_5566_7788,
                chunk: 11,
                timestamp: 0xFFFF_0001,
                prev_value: 0x99AA_BBCC_DDEE_FF00,
                prev_chunk: 10,
                prev_timestamp: 0xFFFF_0000,
            })),
            b: Some(MemoryRecordEnum::Read(MemoryReadRecord {
                value: 0xDEAD_BEEF_CAFE_BABE,
                chunk: 12,
                timestamp: 0xFFFF_0003,
                prev_chunk: 11,
                prev_timestamp: 0xFFFF_0002,
            })),
            c: None,
            memory: Some(MemoryRecordEnum::Read(MemoryReadRecord {
                value: 0x0F0F_0F0F_F0F0_F0F0,
                chunk: 13,
                timestamp: 0xFFFF_0005,
                prev_chunk: 12,
                prev_timestamp: 0xFFFF_0004,
            })),
        }
    }

    #[test]
    fn serde_roundtrip_preserves_wide_cpu_event_fields() {
        let record = wide_access_record();
        let event = CpuEvent::new(
            7,
            u64::from(u32::MAX) + 123,
            0x1_0000_0000,
            0x1_0000_0004,
            Instruction::new(Opcode::ADDW, 1, 2, 3, false, false),
            0xFFFF_FFFF_0000_0001,
            0x8000_0000_0000_0002,
            0x7FFF_FFFF_0000_0003,
            Some(0xABCD_EF01_2345_6789),
            record,
            0,
        );

        // The memory records must survive too: `new` copies them straight out of the access
        // record, so a widening or a field reorder there is only visible if they are populated
        // and compared.
        assert_eq!(event.a_record, FfiOption::from(record.a));
        assert_eq!(event.b_record, FfiOption::from(record.b));
        assert_eq!(event.c_record, FfiOption::from(record.c));
        assert_eq!(event.memory_record, FfiOption::from(record.memory));

        let encoded = serde_json::to_string(&event).expect("serialize cpu event");
        let decoded: CpuEvent = serde_json::from_str(&encoded).expect("deserialize cpu event");
        assert_eq!(decoded, event);
    }
}
