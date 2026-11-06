//! ELF parsing for AOT code generation.
//!
//! AOT must share the exact decoded instruction stream used by the baseline VM.
//! We therefore compile ELFs through `pico-vm`'s authoritative RISC-V frontend
//! and generate from that program representation as it is.

use crate::types::ProgramInfo;
use pico_vm::compiler::riscv::compiler::{Compiler, SourceType};
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

    Ok(ProgramInfo {
        elf_sha256: Sha256::digest(elf_bytes).into(),
        ..ProgramInfo::new(
            program.instructions.to_vec(),
            program.pc_base,
            program.pc_start,
        )
    })
}
