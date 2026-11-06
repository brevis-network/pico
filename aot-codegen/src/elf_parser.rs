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
use sha2::{Digest, Sha256};

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
/// A `ProgramInfo` containing the parsed instruction stream and metadata, and the SHA-256 of
/// `elf_bytes`
///
/// # Panics
///
/// Panics if the ELF binary cannot be parsed or contains invalid RISC-V instructions
pub fn parse_elf(elf_bytes: &[u8]) -> ProgramInfo {
    try_parse_elf(elf_bytes).expect("Failed to parse ELF through pico-vm compiler frontend")
}

/// [`parse_elf`], returning the front end's error for bytes it cannot parse as an ELF.
pub fn try_parse_elf(elf_bytes: &[u8]) -> Result<ProgramInfo, String> {
    let compiler = Compiler::new(SourceType::RISCV, elf_bytes).map_err(|e| e.to_string())?;
    let program = compiler.compile();
    let instructions = program
        .instructions
        .iter()
        .copied()
        .map(convert_vm_instruction)
        .collect();

    Ok(ProgramInfo {
        elf_sha256: Sha256::digest(elf_bytes).into(),
        ..ProgramInfo::new(instructions, program.pc_base, program.pc_start)
    })
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

/// The inverse of `convert_vm_opcode`: the chunk-split leaf model (`chunk_split::insn_leaf`) is
/// keyed by the VM's opcode, and the compiler tallies each block's rows with it.
pub(crate) fn to_vm_opcode(opcode: Opcode) -> VmOpcode {
    match opcode {
        Opcode::ADD => VmOpcode::ADD,
        Opcode::SUB => VmOpcode::SUB,
        Opcode::XOR => VmOpcode::XOR,
        Opcode::OR => VmOpcode::OR,
        Opcode::AND => VmOpcode::AND,
        Opcode::SLL => VmOpcode::SLL,
        Opcode::SRL => VmOpcode::SRL,
        Opcode::SRA => VmOpcode::SRA,
        Opcode::SLT => VmOpcode::SLT,
        Opcode::SLTU => VmOpcode::SLTU,
        Opcode::LB => VmOpcode::LB,
        Opcode::LH => VmOpcode::LH,
        Opcode::LW => VmOpcode::LW,
        Opcode::LBU => VmOpcode::LBU,
        Opcode::LHU => VmOpcode::LHU,
        Opcode::SB => VmOpcode::SB,
        Opcode::SH => VmOpcode::SH,
        Opcode::SW => VmOpcode::SW,
        Opcode::BEQ => VmOpcode::BEQ,
        Opcode::BNE => VmOpcode::BNE,
        Opcode::BLT => VmOpcode::BLT,
        Opcode::BGE => VmOpcode::BGE,
        Opcode::BLTU => VmOpcode::BLTU,
        Opcode::BGEU => VmOpcode::BGEU,
        Opcode::JAL => VmOpcode::JAL,
        Opcode::JALR => VmOpcode::JALR,
        Opcode::AUIPC => VmOpcode::AUIPC,
        Opcode::ECALL => VmOpcode::ECALL,
        Opcode::EBREAK => VmOpcode::EBREAK,
        Opcode::MUL => VmOpcode::MUL,
        Opcode::MULH => VmOpcode::MULH,
        Opcode::MULHU => VmOpcode::MULHU,
        Opcode::MULHSU => VmOpcode::MULHSU,
        Opcode::DIV => VmOpcode::DIV,
        Opcode::DIVU => VmOpcode::DIVU,
        Opcode::REM => VmOpcode::REM,
        Opcode::REMU => VmOpcode::REMU,
        Opcode::UNIMP => VmOpcode::UNIMP,
        Opcode::ADDW => VmOpcode::ADDW,
        Opcode::SUBW => VmOpcode::SUBW,
        Opcode::SLLW => VmOpcode::SLLW,
        Opcode::SRLW => VmOpcode::SRLW,
        Opcode::SRAW => VmOpcode::SRAW,
        Opcode::LWU => VmOpcode::LWU,
        Opcode::LD => VmOpcode::LD,
        Opcode::SD => VmOpcode::SD,
        Opcode::MULW => VmOpcode::MULW,
        Opcode::DIVW => VmOpcode::DIVW,
        Opcode::DIVUW => VmOpcode::DIVUW,
        Opcode::REMW => VmOpcode::REMW,
        Opcode::REMUW => VmOpcode::REMUW,
    }
}
