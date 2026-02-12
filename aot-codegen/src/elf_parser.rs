//! ELF parsing for AOT code generation
//!
//! This module provides functionality to parse RISC-V ELF binaries and extract
//! the instruction stream needed for AOT compilation.

use crate::types::{Instruction, Opcode, ProgramInfo};
use elf::{
    abi::{EM_RISCV, ET_EXEC, PF_X, PT_LOAD},
    endian::LittleEndian,
    file::Class,
    ElfBytes,
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
    let elf = ElfBytes::<LittleEndian>::minimal_parse(elf_bytes).expect("Failed to parse ELF");

    // Keep parser invariants aligned with the VM's ELF parser.
    if elf.ehdr.class != Class::ELF32 {
        panic!("ELF must be 32-bit");
    } else if elf.ehdr.e_machine != EM_RISCV {
        panic!("ELF must target RISC-V");
    } else if elf.ehdr.e_type != ET_EXEC {
        panic!("ELF must be executable");
    }

    let pc_start = u32::try_from(elf.ehdr.e_entry).expect("ELF entry point does not fit in u32");
    let (pc_base, text_data) = extract_text_bytes(&elf);

    // Parse RISC-V instructions from .text section
    let mut instructions = Vec::new();
    let mut offset = 0;

    while offset + 4 <= text_data.len() {
        let word = u32::from_le_bytes([
            text_data[offset],
            text_data[offset + 1],
            text_data[offset + 2],
            text_data[offset + 3],
        ]);

        // Decode RISC-V instruction
        if let Some(inst) = decode_riscv_instruction(word) {
            instructions.push(inst);
        } else {
            // Unknown instruction - create UNIMP
            instructions.push(Instruction::new(Opcode::UNIMP, 0, 0, 0, false, false));
        }

        offset += 4;
    }

    ProgramInfo::new(instructions, pc_base, pc_start)
}

fn extract_text_bytes<'a>(elf: &'a ElfBytes<'a, LittleEndian>) -> (u32, &'a [u8]) {
    if let Ok((Some(section_headers), Some(strtab))) = elf.section_headers_with_strtab() {
        if let Some(section) = section_headers
            .iter()
            .find(|section| matches!(strtab.get(section.sh_name as usize), Ok(".text")))
        {
            let (section_data, _compression) = elf
                .section_data(&section)
                .expect("Failed to read .text section data");
            let pc_base =
                u32::try_from(section.sh_addr).expect(".text address does not fit in u32");
            return (pc_base, section_data);
        }
    }

    // Fallback for binaries without section names: use the lowest executable PT_LOAD segment.
    let segments = elf
        .segments()
        .expect("Failed to read ELF program headers for executable segment fallback");
    let executable_segment = segments
        .iter()
        .filter(|segment| segment.p_type == PT_LOAD && (segment.p_flags & PF_X) != 0)
        .min_by_key(|segment| segment.p_vaddr)
        .expect("No executable .text section or PT_LOAD segment found in ELF");
    let segment_data = elf
        .segment_data(&executable_segment)
        .expect("Failed to read executable PT_LOAD segment data");
    let pc_base =
        u32::try_from(executable_segment.p_vaddr).expect("Executable segment vaddr overflow");
    (pc_base, segment_data)
}

/// Decode a 32-bit RISC-V instruction word into our Instruction format
///
/// This is a simplified decoder that handles the RV32IM instruction set.
fn decode_riscv_instruction(word: u32) -> Option<Instruction> {
    let opcode_bits = word & 0x7F;
    let rd = (word >> 7) & 0x1F;
    let funct3 = (word >> 12) & 0x7;
    let rs1 = (word >> 15) & 0x1F;
    let rs2 = (word >> 20) & 0x1F;
    let funct7 = (word >> 25) & 0x7F;

    match opcode_bits {
        0b0110011 => {
            // R-type instructions
            let opcode = match (funct3, funct7) {
                (0x0, 0x00) => Opcode::ADD,
                (0x0, 0x20) => Opcode::SUB,
                (0x4, 0x00) => Opcode::XOR,
                (0x6, 0x00) => Opcode::OR,
                (0x7, 0x00) => Opcode::AND,
                (0x1, 0x00) => Opcode::SLL,
                (0x5, 0x00) => Opcode::SRL,
                (0x5, 0x20) => Opcode::SRA,
                (0x2, 0x00) => Opcode::SLT,
                (0x3, 0x00) => Opcode::SLTU,
                (0x0, 0x01) => Opcode::MUL,
                (0x1, 0x01) => Opcode::MULH,
                (0x2, 0x01) => Opcode::MULHSU,
                (0x3, 0x01) => Opcode::MULHU,
                (0x4, 0x01) => Opcode::DIV,
                (0x5, 0x01) => Opcode::DIVU,
                (0x6, 0x01) => Opcode::REM,
                (0x7, 0x01) => Opcode::REMU,
                _ => return None,
            };
            Some(Instruction::new(opcode, rd, rs1, rs2, false, false))
        }
        0b0010011 => {
            // I-type ALU instructions
            let imm = ((word as i32) >> 20) as u32;
            let opcode = match funct3 {
                0x0 => Opcode::ADD,                     // ADDI
                0x4 => Opcode::XOR,                     // XORI
                0x6 => Opcode::OR,                      // ORI
                0x7 => Opcode::AND,                     // ANDI
                0x1 => Opcode::SLL,                     // SLLI
                0x5 if (funct7 == 0x00) => Opcode::SRL, // SRLI
                0x5 if (funct7 == 0x20) => Opcode::SRA, // SRAI
                0x2 => Opcode::SLT,                     // SLTI
                0x3 => Opcode::SLTU,                    // SLTIU
                _ => return None,
            };
            Some(Instruction::new(opcode, rd, rs1, imm, false, true))
        }
        0b0000011 => {
            // Load instructions
            let imm = ((word as i32) >> 20) as u32;
            let opcode = match funct3 {
                0x0 => Opcode::LB,
                0x1 => Opcode::LH,
                0x2 => Opcode::LW,
                0x4 => Opcode::LBU,
                0x5 => Opcode::LHU,
                _ => return None,
            };
            Some(Instruction::new(opcode, rd, rs1, imm, false, true))
        }
        0b0100011 => {
            // Store instructions
            let imm = (((word >> 25) & 0x7F) << 5) | ((word >> 7) & 0x1F);
            let imm = ((imm as i32) << 20 >> 20) as u32; // Sign extend
            let opcode = match funct3 {
                0x0 => Opcode::SB,
                0x1 => Opcode::SH,
                0x2 => Opcode::SW,
                _ => return None,
            };
            Some(Instruction::new(opcode, rs2, rs1, imm, false, true))
        }
        0b1100011 => {
            // Branch instructions
            let imm = (((word >> 31) & 0x1) << 12)
                | (((word >> 7) & 0x1) << 11)
                | (((word >> 25) & 0x3F) << 5)
                | (((word >> 8) & 0xF) << 1);
            let imm = ((imm as i32) << 19 >> 19) as u32; // Sign extend
            let opcode = match funct3 {
                0x0 => Opcode::BEQ,
                0x1 => Opcode::BNE,
                0x4 => Opcode::BLT,
                0x5 => Opcode::BGE,
                0x6 => Opcode::BLTU,
                0x7 => Opcode::BGEU,
                _ => return None,
            };
            Some(Instruction::new(opcode, rs1, rs2, imm, false, true))
        }
        0b1101111 => {
            // JAL
            let imm = (((word >> 31) & 0x1) << 20)
                | (((word >> 12) & 0xFF) << 12)
                | (((word >> 20) & 0x1) << 11)
                | (((word >> 21) & 0x3FF) << 1);
            let imm = ((imm as i32) << 11 >> 11) as u32; // Sign extend
            Some(Instruction::new(Opcode::JAL, rd, imm, 0, true, false))
        }
        0b1100111 => {
            // JALR
            let imm = ((word as i32) >> 20) as u32;
            Some(Instruction::new(Opcode::JALR, rd, rs1, imm, false, true))
        }
        0b0010111 => {
            // AUIPC
            let imm = word & 0xFFFFF000;
            Some(Instruction::new(Opcode::AUIPC, rd, imm, 0, true, false))
        }
        0b0110111 => {
            // LUI - Load Upper Immediate
            // LUI is converted to ADD with both imm_b and imm_c set
            // rd = 0 + imm (where imm is the upper 20 bits)
            let imm = word & 0xFFFFF000;
            Some(Instruction::new(Opcode::ADD, rd, 0, imm, true, true))
        }
        0b1110011 => {
            // SYSTEM instructions
            match funct3 {
                0x0 => {
                    if word == 0x00000073 {
                        Some(Instruction::new(Opcode::ECALL, 0, 0, 0, false, false))
                    } else if word == 0x00100073 {
                        Some(Instruction::new(Opcode::EBREAK, 0, 0, 0, false, false))
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }
        0b0000000 if word == 0 => {
            // UNIMP (all zeros)
            Some(Instruction::new(Opcode::UNIMP, 0, 0, 0, false, false))
        }
        _ => None,
    }
}
