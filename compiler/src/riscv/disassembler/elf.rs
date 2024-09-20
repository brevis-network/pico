use crate::{compiler::Compilable, program::Program};
use elf::{
    abi::{EM_RISCV, ET_EXEC, PF_X, PT_LOAD},
    endian::LittleEndian,
    file::Class,
    ElfBytes,
};
use std::{cmp::min, collections::BTreeMap, fs::File};

use crate::riscv::disassembler::transpile;
use std::io::Read;

/// The maximum size of the memory in bytes.
pub const MAXIMUM_MEMORY_SIZE: u32 = u32::MAX;

/// The size of a word in bytes.
pub const WORD_SIZE: usize = 4;

/// RISC-V 32IM ELF (Executable and Linkable Format) File.
///
/// This file represents a binary in the ELF format, specifically the RISC-V 32IM architecture
/// with the following extensions:
///
/// - Base Integer Instruction Set (I)
/// - Integer Multiplication and Division (M)
///
/// This format is commonly used in embedded systems and is supported by many compilers.
#[derive(Debug, Clone)]
pub(crate) struct Elf {
    /// The instructions of the program encoded as 32-bits.
    pub(crate) instructions: Vec<u32>,
    /// The start address of the program.
    pub(crate) pc_start: u32,
    /// The base address of the program.
    pub(crate) pc_base: u32,
    /// The initial memory image, useful for global constants.
    pub(crate) memory_image: BTreeMap<u32, u32>,
}

impl Elf {
    /// Create a new [Elf].
    ///
    /// Parse the ELF file into a vector of 32-bit encoded instructions and the first memory
    /// address.
    ///
    /// # Errors
    ///
    /// This function may return an error if the ELF is not valid.
    ///
    /// Reference: [Executable and Linkable Format](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)

    #[must_use]
    pub fn new(source_code: &[u8]) -> eyre::Result<Self> {
        // Decode the bytes as an ELF.
        let mut image: BTreeMap<u32, u32> = BTreeMap::new();

        // Parse the ELF file assuming that it is little-endian..
        let elf = ElfBytes::<LittleEndian>::minimal_parse(source_code)?;

        // Some sanity checks to make sure that the ELF file is valid.
        if elf.ehdr.class != Class::ELF32 {
            eyre::bail!("must be a 32-bit elf");
        } else if elf.ehdr.e_machine != EM_RISCV {
            eyre::bail!("must be a riscv machine");
        } else if elf.ehdr.e_type != ET_EXEC {
            eyre::bail!("must be executable");
        }

        // Get the entrypoint of the ELF file as an u32.
        let entry: u32 = elf.ehdr.e_entry.try_into()?;

        // Make sure the entrypoint is valid.
        if entry == MAXIMUM_MEMORY_SIZE || entry % WORD_SIZE as u32 != 0 {
            eyre::bail!("invalid entrypoint");
        }

        // Get the segments of the ELF file.
        let segments = elf
            .segments()
            .ok_or_else(|| eyre::eyre!("failed to get segments"))?;
        if segments.len() > 256 {
            eyre::bail!("too many program headers");
        }

        let mut instructions: Vec<u32> = Vec::new();
        let mut base_address = u32::MAX;

        // Only read segments that are executable instructions that are also PT_LOAD.
        for segment in segments.iter().filter(|x| x.p_type == PT_LOAD) {
            // Get the file size of the segment as an u32.
            let file_size: u32 = segment.p_filesz.try_into()?;
            if file_size == MAXIMUM_MEMORY_SIZE {
                eyre::bail!("invalid segment file_size");
            }

            // Get the memory size of the segment as an u32.
            let mem_size: u32 = segment.p_memsz.try_into()?;
            if mem_size == MAXIMUM_MEMORY_SIZE {
                eyre::bail!("Invalid segment mem_size");
            }

            // Get the virtual address of the segment as an u32.
            let vaddr: u32 = segment.p_vaddr.try_into()?;
            if vaddr % WORD_SIZE as u32 != 0 {
                eyre::bail!("vaddr {vaddr:08x} is unaligned");
            }

            // If the virtual address is less than the first memory address, then update the first
            // memory address.
            if (segment.p_flags & PF_X) != 0 && base_address > vaddr {
                base_address = vaddr;
            }

            // Get the offset to the segment.
            let offset: u32 = segment.p_offset.try_into()?;

            // Read the segment and decode each word as an instruction.
            for i in (0..mem_size).step_by(WORD_SIZE) {
                let addr = vaddr
                    .checked_add(i)
                    .ok_or_else(|| eyre::eyre!("vaddr overflow"))?;
                if addr == MAXIMUM_MEMORY_SIZE {
                    eyre::bail!(
                        "address [0x{addr:08x}] exceeds maximum address for guest programs [0x{MAXIMUM_MEMORY_SIZE:08x}]"
                    );
                }

                // If we are reading past the end of the file, then break.
                if i >= file_size {
                    image.insert(addr, 0);
                    continue;
                }

                // Get the word as an u32 but make sure we don't read past the end of the file.
                let mut word = 0;
                let len = min(file_size - i, WORD_SIZE as u32);
                for j in 0..len {
                    let offset = (offset + i + j) as usize;
                    let byte = source_code
                        .get(offset)
                        .ok_or_else(|| eyre::eyre!("failed to read segment offset"))?;
                    word |= u32::from(*byte) << (j * 8);
                }
                image.insert(addr, word);
                if (segment.p_flags & PF_X) != 0 {
                    instructions.push(word);
                }
            }
        }

        Ok(Self {
            instructions,
            pc_start: entry,
            pc_base: base_address,
            memory_image: image,
        })
    }

    pub fn compile(&self) -> Program {
        // Transpile the RV32IM instructions.
        let instructions = transpile(&self.instructions);

        // Return the program.
        // clone() may take much time, consider optimize in the future
        Program {
            instructions,
            pc_start: self.pc_start,
            pc_base: self.pc_base,
            memory_image: self.memory_image.clone(),
        }
    }
}
