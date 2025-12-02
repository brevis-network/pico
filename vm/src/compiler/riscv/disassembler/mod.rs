//! A disassembler for RISC-V ELFs.
mod elf;
mod rrs;

pub(crate) use elf::*;
pub(crate) use rrs::*;

// Public re-export for RISCOF testing
pub use elf::find_signature_region;
