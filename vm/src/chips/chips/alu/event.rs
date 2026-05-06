use crate::{
    compiler::riscv::opcode::Opcode,
    emulator::riscv::event_types::{RvClk, RvValue},
};
use serde::{Deserialize, Serialize};

/// Arithmetic Logic Unit (ALU) Event.
///
/// This object encapsulated the information needed to prove an ALU operation. This includes its
/// opcode, operands, and other relevant information.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AluEvent {
    /// The clock cycle.
    pub clk: RvClk,
    /// The opcode.
    pub opcode: Opcode,
    /// The first operand.
    pub a: RvValue,
    /// The second operand.
    pub b: RvValue,
    /// The third operand.
    pub c: RvValue,
    /// Whether the instruction uses an immediate value (for shifts: SRLI/SRAI vs SRL/SRA).
    #[serde(default)]
    pub is_imm: bool,
}

impl Default for AluEvent {
    fn default() -> Self {
        Self {
            clk: 0,
            opcode: Opcode::ADD,
            a: 0,
            b: 0,
            c: 0,
            is_imm: false,
        }
    }
}

impl AluEvent {
    /// Create a new [`AluEvent`].
    #[must_use]
    pub fn new(
        clk: RvClk,
        opcode: Opcode,
        a: RvValue,
        b: RvValue,
        c: RvValue,
        is_imm: bool,
    ) -> Self {
        Self {
            clk,
            opcode,
            a,
            b,
            c,
            is_imm,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AluEvent;
    use crate::compiler::riscv::opcode::Opcode;

    #[test]
    fn serde_roundtrip_preserves_wide_alu_event_fields() {
        let event = AluEvent::new(
            u64::from(u32::MAX) + 321,
            Opcode::ADDW,
            0xFFFF_FFFF_0000_0001,
            0x8000_0000_0000_0002,
            0x7FFF_FFFF_0000_0003,
            true,
        );

        let encoded = serde_json::to_string(&event).expect("serialize alu event");
        let decoded: AluEvent = serde_json::from_str(&encoded).expect("deserialize alu event");
        assert_eq!(decoded.clk, event.clk);
        assert_eq!(decoded.a, event.a);
        assert_eq!(decoded.b, event.b);
        assert_eq!(decoded.c, event.c);
        assert_eq!(decoded.opcode, event.opcode);
        assert_eq!(decoded.is_imm, event.is_imm);
    }
}
