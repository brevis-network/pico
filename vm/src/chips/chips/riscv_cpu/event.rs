use serde::{Deserialize, Serialize};

use crate::{
    chips::chips::riscv_memory::event::MemoryRecordEnum,
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
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
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
    pub a_record: Option<MemoryRecordEnum>,
    /// The second operand.
    pub b: RvValue,
    /// The second operand memory record.
    pub b_record: Option<MemoryRecordEnum>,
    /// The third operand.
    pub c: RvValue,
    /// The third operand memory record.
    pub c_record: Option<MemoryRecordEnum>,
    /// The memory value.
    pub memory: Option<RvValue>,
    /// The memory record.
    pub memory_record: Option<MemoryRecordEnum>,
    /// The exit code.
    pub exit_code: u32,
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
            a_record: record.a,
            b,
            b_record: record.b,
            c,
            c_record: record.c,
            memory,
            memory_record: record.memory,
            exit_code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CpuEvent;
    use crate::{
        compiler::riscv::{instruction::Instruction, opcode::Opcode},
        emulator::riscv::record::MemoryAccessRecord,
    };

    #[test]
    fn serde_roundtrip_preserves_wide_cpu_event_fields() {
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
            MemoryAccessRecord::default(),
            0,
        );

        let encoded = serde_json::to_string(&event).expect("serialize cpu event");
        let decoded: CpuEvent = serde_json::from_str(&encoded).expect("deserialize cpu event");
        assert_eq!(decoded.clk, event.clk);
        assert_eq!(decoded.pc, event.pc);
        assert_eq!(decoded.next_pc, event.next_pc);
        assert_eq!(decoded.a, event.a);
        assert_eq!(decoded.b, event.b);
        assert_eq!(decoded.c, event.c);
        assert_eq!(decoded.memory, event.memory);
    }
}
