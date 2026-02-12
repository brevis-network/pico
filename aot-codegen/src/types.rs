//! Minimal type definitions for AOT code generation
//!
//! These types are duplicated from the main vm crate to avoid circular dependencies.
//! They contain only the subset of functionality needed for code generation.

use serde::{Deserialize, Serialize};

/// RISC-V opcode for AOT code generation
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum Opcode {
    ADD = 0,
    SUB = 1,
    XOR = 2,
    OR = 3,
    AND = 4,
    SLL = 5,
    SRL = 6,
    SRA = 7,
    SLT = 8,
    SLTU = 9,
    LB = 10,
    LH = 11,
    LW = 12,
    LBU = 13,
    LHU = 14,
    SB = 15,
    SH = 16,
    SW = 17,
    BEQ = 18,
    BNE = 19,
    BLT = 20,
    BGE = 21,
    BLTU = 22,
    BGEU = 23,
    JAL = 24,
    JALR = 25,
    AUIPC = 27,
    ECALL = 28,
    EBREAK = 29,
    MUL = 30,
    MULH = 31,
    MULHU = 32,
    MULHSU = 33,
    DIV = 34,
    DIVU = 35,
    REM = 36,
    REMU = 37,
    UNIMP = 39,
}

/// RISC-V instruction for AOT code generation
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Instruction {
    pub opcode: Opcode,
    pub op_a: u32,
    pub op_b: u32,
    pub op_c: u32,
    pub imm_b: bool,
    pub imm_c: bool,
}

impl Instruction {
    /// Create a new instruction
    pub const fn new(
        opcode: Opcode,
        op_a: u32,
        op_b: u32,
        op_c: u32,
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

    /// Decode R-type instruction: (rd, rs1, rs2)
    pub fn r_type(&self) -> (u32, u32, u32) {
        (self.op_a, self.op_b, self.op_c)
    }

    /// Decode I-type instruction: (rd, rs1, imm)
    pub fn i_type(&self) -> (u32, u32, u32) {
        (self.op_a, self.op_b, self.op_c)
    }

    /// Decode S-type instruction: (rs2, rs1, imm)
    pub fn s_type(&self) -> (u32, u32, u32) {
        (self.op_a, self.op_b, self.op_c)
    }

    /// Decode B-type instruction: (rs1, rs2, imm)
    pub fn b_type(&self) -> (u32, u32, u32) {
        (self.op_a, self.op_b, self.op_c)
    }

    /// Decode J-type instruction: (rd, imm)
    pub fn j_type(&self) -> (u32, u32) {
        (self.op_a, self.op_b)
    }

    /// Decode U-type instruction: (rd, imm)
    pub fn u_type(&self) -> (u32, u32) {
        (self.op_a, self.op_b)
    }
}

/// Minimal program information for AOT code generation
#[derive(Debug, Clone)]
pub struct ProgramInfo {
    /// The instruction stream
    pub instructions: Vec<Instruction>,
    /// Base address for instruction indexing
    pub pc_base: u32,
    /// Program entry point
    pub pc_start: u32,
}

impl ProgramInfo {
    /// Create a new program info
    pub fn new(instructions: Vec<Instruction>, pc_base: u32, pc_start: u32) -> Self {
        Self {
            instructions,
            pc_base,
            pc_start,
        }
    }
}
