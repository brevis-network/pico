//! The program the code generator compiles, as `pico-vm` decodes it: every constant a block
//! carries, in either of its bodies, is the value the runtime fetches.

pub use pico_vm::compiler::riscv::{instruction::Instruction, opcode::Opcode};

/// Minimal program information for AOT code generation
#[derive(Debug, Clone)]
pub struct ProgramInfo {
    /// The instructions as `pico-vm` decodes them and the runtime fetches them.
    pub instructions: Vec<Instruction>,
    /// Base address for instruction indexing
    pub pc_base: u64,
    /// Program entry point
    pub pc_start: u64,
    /// SHA-256 of the ELF the program was parsed from, which the generated `AOT` carries so a
    /// host can refuse code generated from another ELF. All zero without an ELF, which is the
    /// bootstrap stub's digest, so such a program is refused at registration like the stub.
    pub elf_sha256: [u8; 32],
}

impl ProgramInfo {
    /// A program with no ELF behind it; [`crate::parse_elf`] records the digest.
    pub fn new(instructions: Vec<Instruction>, pc_base: u64, pc_start: u64) -> Self {
        Self {
            instructions,
            pc_base,
            pc_start,
            elf_sha256: [0; 32],
        }
    }
}
