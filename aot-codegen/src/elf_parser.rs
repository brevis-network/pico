//! ELF parsing for AOT code generation.
//!
//! AOT must share the exact decoded instruction stream used by the baseline VM.
//! We therefore compile ELFs through `pico-vm`'s authoritative RISC-V frontend
//! and then narrow that program representation into the lightweight AOT types.

use crate::types::{Instruction, Opcode, ProgramInfo};
use pico_vm::compiler::riscv::{
    compiler::{Compiler, SourceType},
    instruction::Instruction as VmInstruction,
    opcode::Opcode as VmOpcode,
};

/// Parse an ELF binary into ProgramInfo for AOT compilation
///
/// This function extracts the instruction stream, program counter base, and entry point
/// from a RISC-V ELF binary.
///
/// # Arguments
///
/// * `elf_bytes` - The raw ELF binary data
///
/// # Returns
///
/// A `ProgramInfo` containing the parsed instruction stream and metadata
///
/// # Panics
///
/// Panics if the ELF binary cannot be parsed or contains invalid RISC-V instructions
pub fn parse_elf(elf_bytes: &[u8]) -> ProgramInfo {
    let compiler = Compiler::new(SourceType::RISCV, elf_bytes)
        .expect("Failed to parse ELF through pico-vm compiler frontend");
    let program = compiler.compile();
    let instructions = program
        .instructions
        .iter()
        .copied()
        .map(convert_vm_instruction)
        .collect();

    ProgramInfo::new(instructions, program.pc_base, program.pc_start)
}

fn convert_vm_instruction(inst: VmInstruction) -> Instruction {
    Instruction::new(
        convert_vm_opcode(inst.opcode),
        u32::from(inst.op_a),
        narrow_vm_operand(inst.op_b, inst.imm_b),
        narrow_vm_operand(inst.op_c, inst.imm_c),
        inst.imm_b,
        inst.imm_c,
    )
}

fn narrow_vm_operand(value: u64, is_immediate: bool) -> u32 {
    if is_immediate {
        let narrowed = value as u32;
        let roundtrip = ((narrowed as i32) as i64) as u64;
        debug_assert_eq!(
            roundtrip, value,
            "immediate operand {value:#018x} does not round-trip through u32 storage"
        );
        narrowed
    } else {
        u32::try_from(value).expect("register operand does not fit in u32")
    }
}

fn convert_vm_opcode(opcode: VmOpcode) -> Opcode {
    match opcode {
        VmOpcode::ADD => Opcode::ADD,
        VmOpcode::SUB => Opcode::SUB,
        VmOpcode::XOR => Opcode::XOR,
        VmOpcode::OR => Opcode::OR,
        VmOpcode::AND => Opcode::AND,
        VmOpcode::SLL => Opcode::SLL,
        VmOpcode::SRL => Opcode::SRL,
        VmOpcode::SRA => Opcode::SRA,
        VmOpcode::SLT => Opcode::SLT,
        VmOpcode::SLTU => Opcode::SLTU,
        VmOpcode::LB => Opcode::LB,
        VmOpcode::LH => Opcode::LH,
        VmOpcode::LW => Opcode::LW,
        VmOpcode::LBU => Opcode::LBU,
        VmOpcode::LHU => Opcode::LHU,
        VmOpcode::SB => Opcode::SB,
        VmOpcode::SH => Opcode::SH,
        VmOpcode::SW => Opcode::SW,
        VmOpcode::BEQ => Opcode::BEQ,
        VmOpcode::BNE => Opcode::BNE,
        VmOpcode::BLT => Opcode::BLT,
        VmOpcode::BGE => Opcode::BGE,
        VmOpcode::BLTU => Opcode::BLTU,
        VmOpcode::BGEU => Opcode::BGEU,
        VmOpcode::JAL => Opcode::JAL,
        VmOpcode::JALR => Opcode::JALR,
        VmOpcode::AUIPC => Opcode::AUIPC,
        VmOpcode::ECALL => Opcode::ECALL,
        VmOpcode::EBREAK => Opcode::EBREAK,
        VmOpcode::MUL => Opcode::MUL,
        VmOpcode::MULH => Opcode::MULH,
        VmOpcode::MULHU => Opcode::MULHU,
        VmOpcode::MULHSU => Opcode::MULHSU,
        VmOpcode::DIV => Opcode::DIV,
        VmOpcode::DIVU => Opcode::DIVU,
        VmOpcode::REM => Opcode::REM,
        VmOpcode::REMU => Opcode::REMU,
        VmOpcode::UNIMP => Opcode::UNIMP,
        VmOpcode::ADDW => Opcode::ADDW,
        VmOpcode::SUBW => Opcode::SUBW,
        VmOpcode::SLLW => Opcode::SLLW,
        VmOpcode::SRLW => Opcode::SRLW,
        VmOpcode::SRAW => Opcode::SRAW,
        VmOpcode::LWU => Opcode::LWU,
        VmOpcode::LD => Opcode::LD,
        VmOpcode::SD => Opcode::SD,
        VmOpcode::MULW => Opcode::MULW,
        VmOpcode::DIVW => Opcode::DIVW,
        VmOpcode::DIVUW => Opcode::DIVUW,
        VmOpcode::REMW => Opcode::REMW,
        VmOpcode::REMUW => Opcode::REMUW,
    }
}
