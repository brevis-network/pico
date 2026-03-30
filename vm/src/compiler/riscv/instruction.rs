//! Instructions for the Pico zkVM.

use crate::compiler::riscv::opcode::Opcode;
use core::fmt::Debug;
use serde::{Deserialize, Serialize};

/// RISC-V Instruction (RV32IM/RV64IM).
///
/// The structure of the instruction differs from the RISC-V ISA. We do not encode the instructions
/// as 32-bit words, but instead use a custom encoding that is more friendly to decode in the
/// Pico zkVM.
///
/// Field widths: `op_a` is `u8` (register index 0-31), `op_b`/`op_c` are `u64` to hold
/// full-width RV64 immediates without truncation.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct Instruction {
    /// The operation to emulate.
    pub opcode: Opcode,
    /// The first operand (destination register index, 0-31).
    pub op_a: u8,
    /// The second operand (register index or immediate).
    pub op_b: u64,
    /// The third operand (register index or immediate).
    pub op_c: u64,
    /// Whether the second operand is an immediate value.
    pub imm_b: bool,
    /// Whether the third operand is an immediate value.
    pub imm_c: bool,
}

impl Instruction {
    /// Create a new [`RiscvInstruction`].
    #[must_use]
    pub const fn new(
        opcode: Opcode,
        op_a: u8,
        op_b: u64,
        op_c: u64,
        imm_b: bool,
        imm_c: bool,
    ) -> Self {
        Self {
            opcode,
            op_a,
            op_b,
            op_c,
            imm_b,
            imm_c,
        }
    }

    /// Returns if the instruction is an ALU instruction.
    #[must_use]
    pub const fn is_alu_instruction(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::ADD
                | Opcode::SUB
                | Opcode::XOR
                | Opcode::OR
                | Opcode::AND
                | Opcode::SLL
                | Opcode::SRL
                | Opcode::SRA
                | Opcode::SLT
                | Opcode::SLTU
                | Opcode::MUL
                | Opcode::MULH
                | Opcode::MULHU
                | Opcode::MULHSU
                | Opcode::DIV
                | Opcode::DIVU
                | Opcode::REM
                | Opcode::REMU
                | Opcode::ADDW
                | Opcode::SUBW
                | Opcode::SLLW
                | Opcode::SRLW
                | Opcode::SRAW
                | Opcode::MULW
                | Opcode::DIVW
                | Opcode::DIVUW
                | Opcode::REMW
                | Opcode::REMUW
        )
    }

    /// Returns if the instruction is an ecall instruction.
    #[must_use]
    pub fn is_ecall_instruction(&self) -> bool {
        self.opcode == Opcode::ECALL
    }

    /// Returns if the instruction is a memory instruction.
    #[must_use]
    pub const fn is_memory_instruction(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::LB
                | Opcode::LH
                | Opcode::LW
                | Opcode::LBU
                | Opcode::LHU
                | Opcode::LWU
                | Opcode::LD
                | Opcode::SB
                | Opcode::SH
                | Opcode::SW
                | Opcode::SD
        )
    }

    /// Returns if the instruction is a branch instruction.
    #[must_use]
    pub const fn is_branch_instruction(&self) -> bool {
        matches!(
            self.opcode,
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU
        )
    }

    /// Returns if the instruction is a jump instruction.
    #[must_use]
    pub const fn is_jump_instruction(&self) -> bool {
        matches!(self.opcode, Opcode::JAL | Opcode::JALR)
    }
}

impl Debug for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mnemonic = self.opcode.mnemonic();
        let op_a_formatted = format!("%x{}", self.op_a);
        let op_b_formatted = if self.imm_b || self.opcode == Opcode::AUIPC {
            format!("{}", self.op_b as i64)
        } else {
            format!("%x{}", self.op_b)
        };
        let op_c_formatted = if self.imm_c {
            format!("{}", self.op_c as i64)
        } else {
            format!("%x{}", self.op_c)
        };

        let width = 10;
        write!(
            f,
            "{mnemonic:<width$} {op_a_formatted:<width$} {op_b_formatted:<width$} {op_c_formatted:<width$}"
        )
    }
}
