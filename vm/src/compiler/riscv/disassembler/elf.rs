use crate::compiler::riscv::{disassembler::transpile, program::Program};
use alloc::sync::Arc;
use elf::{
    abi::{EM_RISCV, ET_EXEC, PF_X, PT_LOAD},
    endian::LittleEndian,
    file::Class,
    ElfBytes,
};
use std::collections::BTreeMap;

use crate::primitives::consts::WORD_SIZE;

// TODO(rv64im-3r4): remove or repurpose this generic ceiling once memory/event address handling is fully widened end-to-end.
/// The maximum size of the memory in bytes.
pub const MAXIMUM_MEMORY_SIZE: u64 = 0xFFFF_FFFF;

const WORD_SIZE_U64: u64 = WORD_SIZE as u64;
/// The current RISC-V emulator uses a contiguous SDK-limited memory model.
///
/// The backing storage (`ContiguousRiscvMemory`) allocates `0x7800_0000` bytes for
/// addressable guest memory. The disassembler must reject ELFs that place segments
/// outside this range to prevent out-of-bounds runtime accesses.
const EMULATOR_MEMORY_SIZE_BYTES: u64 = 0x7800_0000;
/// The last valid *word* start address for 4-byte reads/writes.
const MAX_GUEST_WORD_ADDR: u64 = EMULATOR_MEMORY_SIZE_BYTES - WORD_SIZE as u64;

/// RISC-V ELF (Executable and Linkable Format) File.
///
/// This file represents a binary in the ELF format for RISC-V (ELF32 or ELF64) with
/// the following extensions:
///
/// - Base Integer Instruction Set (I)
/// - Integer Multiplication and Division (M)
#[derive(Debug, Clone)]
pub struct Elf {
    /// The instructions of the program encoded as 32-bits.
    pub(crate) instructions: Vec<u32>,
    /// The start address of the program.
    pub(crate) pc_start: u64,
    /// The base address of the program.
    pub(crate) pc_base: u64,
    /// The initial memory image, useful for global constants.
    pub(crate) memory_image: Arc<BTreeMap<u64, u64>>,
}

/// Parse symbol table from ELF to extract signature region boundary for RISCOF testing.
/// Returns (begin, end) addresses as u64 to support both RV32 and RV64.
pub fn find_signature_region(elf_bytes: &[u8]) -> eyre::Result<(u64, u64)> {
    let mut begin_signature = None;
    let mut end_signature = None;

    let file = ElfBytes::<LittleEndian>::minimal_parse(elf_bytes)?;

    if let Some((symbol_table, string_table)) = file.symbol_table()? {
        for sym in symbol_table.iter() {
            if let Ok(name) = string_table.get(sym.st_name as usize) {
                match name {
                    "begin_signature" => begin_signature = Some(sym.st_value),
                    "end_signature" => end_signature = Some(sym.st_value),
                    _ => {}
                }
            }
        }
    }

    let begin =
        begin_signature.ok_or_else(|| eyre::eyre!("Missing begin_signature symbol in ELF"))?;
    let end = end_signature.ok_or_else(|| eyre::eyre!("Missing end_signature symbol in ELF"))?;

    Ok((begin, end))
}

impl Elf {
    #[inline(always)]
    fn to_guest_addr(value: u64, context: &str) -> eyre::Result<u64> {
        if value == MAXIMUM_MEMORY_SIZE {
            eyre::bail!(
                "{context} [0x{value:016x}] exceeds maximum address for guest programs [0x{MAXIMUM_MEMORY_SIZE:016x}]"
            );
        }
        // Keep parser constraints aligned with the emulator's actual memory capacity.
        // We enforce this here (instead of relying on later unchecked memory ops)
        // to turn potential UB into a deterministic parse error.
        if value > MAX_GUEST_WORD_ADDR {
            eyre::bail!(
                "{context} [0x{value:016x}] exceeds emulator memory limit [0x{MAX_GUEST_WORD_ADDR:016x}]"
            );
        }
        Ok(value)
    }

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
    pub fn new(source_code: &[u8]) -> eyre::Result<Self> {
        // Decode the bytes as an ELF.
        let mut image: BTreeMap<u64, u64> = BTreeMap::new();

        // Parse the ELF file assuming that it is little-endian..
        let elf = ElfBytes::<LittleEndian>::minimal_parse(source_code)?;

        // Some sanity checks to make sure that the ELF file is valid.
        // Support both ELF32 and ELF64 (truncate addresses for ELF64)
        if elf.ehdr.class != Class::ELF32 && elf.ehdr.class != Class::ELF64 {
            eyre::bail!("must be a 32-bit or 64-bit elf");
        } else if elf.ehdr.e_machine != EM_RISCV {
            eyre::bail!("must be a riscv machine");
        } else if elf.ehdr.e_type != ET_EXEC {
            eyre::bail!("must be executable");
        }

        // Parse entrypoint as u64 and preserve RV64 runtime surface.
        let entry_u64 = elf.ehdr.e_entry;

        // Make sure the entrypoint is valid.
        if entry_u64 == MAXIMUM_MEMORY_SIZE || !entry_u64.is_multiple_of(WORD_SIZE_U64) {
            eyre::bail!("invalid entrypoint");
        }
        let entry = Self::to_guest_addr(entry_u64, "entrypoint")?;

        // Get the segments of the ELF file.
        let segments = elf
            .segments()
            .ok_or_else(|| eyre::eyre!("failed to get segments"))?;
        if segments.len() > 256 {
            eyre::bail!("too many program headers");
        }

        let mut instructions: Vec<u32> = Vec::new();
        let mut base_address = None;

        // Only read segments that are executable instructions that are also PT_LOAD.
        for segment in segments.iter().filter(|x| x.p_type == PT_LOAD) {
            let file_size = segment.p_filesz;
            let mem_size = segment.p_memsz;
            let vaddr = segment.p_vaddr;
            let offset = segment.p_offset;

            if !vaddr.is_multiple_of(WORD_SIZE_U64) {
                eyre::bail!("vaddr {vaddr:08x} is unaligned");
            }

            // If the virtual address is less than the first memory address, then update the first
            // memory address.
            if (segment.p_flags & PF_X) != 0
                && (base_address.is_none() || vaddr < base_address.unwrap())
            {
                base_address = Some(vaddr);
            }

            // Read the segment and decode each word as an instruction.
            let mut i = 0u64;
            while i < mem_size {
                let addr_u64 = vaddr
                    .checked_add(i)
                    .ok_or_else(|| eyre::eyre!("vaddr overflow"))?;
                let addr = Self::to_guest_addr(addr_u64, "segment address")?;

                // If we are reading past the end of the file, then break.
                if i >= file_size {
                    // Create the block only when absent: `insert` replaces the whole 8-byte entry,
                    // so a segment whose file-backed data ends mid-block would have it erased by
                    // the BSS pass over the other half. The half covered here is already zero.
                    image.entry(addr - addr % 8).or_insert(0);
                } else {
                    // Get the word as an u32 but make sure we don't read past the end of the file.
                    let mut word = 0u32;
                    let len = (file_size - i).min(WORD_SIZE_U64);
                    let mut j = 0u64;
                    while j < len {
                        let file_offset = offset
                            .checked_add(i)
                            .ok_or_else(|| eyre::eyre!("offset overflow"))?
                            .checked_add(j)
                            .ok_or_else(|| eyre::eyre!("offset overflow"))?;
                        let byte = source_code
                            .get(file_offset as usize)
                            .ok_or_else(|| eyre::eyre!("failed to read segment offset"))?;
                        word |= u32::from(*byte) << ((j as u32) * 8);
                        j += 1;
                    }

                    if (segment.p_flags & PF_X) != 0 {
                        instructions.push(word);
                    }

                    let word = u64::from(word);
                    if addr.is_multiple_of(8) {
                        image
                            .entry(addr)
                            .and_modify(|value| {
                                *value += word;
                            })
                            .or_insert_with(|| word);
                    } else {
                        assert!(addr % 8 == 4);
                        image
                            .entry(addr - 4)
                            .and_modify(|value| {
                                *value += word << 32;
                            })
                            .or_insert_with(|| word << 32);
                    }
                }
                i = i
                    .checked_add(WORD_SIZE_U64)
                    .ok_or_else(|| eyre::eyre!("segment traversal overflow"))?;
            }
        }

        let pc_base = Self::to_guest_addr(
            base_address.ok_or_else(|| eyre::eyre!("no executable segment found"))?,
            "executable segment base address",
        )?;

        Ok(Self {
            instructions,
            pc_start: entry,
            pc_base,
            memory_image: image.into(),
        })
    }

    pub fn compile(&self) -> Arc<Program> {
        // Transpile the RV32IM instructions.
        let instructions = transpile(&self.instructions);

        // Return the program.
        // clone() may take much time, consider optimize in the future
        Program {
            instructions,
            pc_start: self.pc_start,
            pc_base: self.pc_base,
            memory_image: self.memory_image.clone(),
            preprocessed_shape: None,
        }
        .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elf::abi::{PF_R, PF_W};

    const EHDR_SIZE: usize = 64;
    const PHENT_SIZE: usize = 56;

    /// One `PT_LOAD` program header plus its file-backed bytes.
    struct Seg {
        flags: u32,
        vaddr: u64,
        /// File-backed bytes; `p_filesz` is its length.
        data: Vec<u8>,
        /// `p_memsz`; anything past `data.len()` is BSS.
        mem_size: u64,
    }

    impl Seg {
        fn text(vaddr: u64, words: &[u32]) -> Self {
            let data = words
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect::<Vec<_>>();
            let mem_size = data.len() as u64;
            Self {
                flags: PF_R | PF_X,
                vaddr,
                data,
                mem_size,
            }
        }

        fn data(vaddr: u64, data: Vec<u8>, mem_size: u64) -> Self {
            Self {
                flags: PF_R | PF_W,
                vaddr,
                data,
                mem_size,
            }
        }
    }

    /// Assemble a minimal little-endian ELF64 executable out of `segs`.
    fn build_elf(entry: u64, segs: &[Seg]) -> Vec<u8> {
        let phoff = EHDR_SIZE;
        let data_off = phoff + PHENT_SIZE * segs.len();

        let mut out = Vec::new();
        // e_ident: magic, ELFCLASS64, ELFDATA2LSB, EV_CURRENT, then padding.
        out.extend_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0]);
        out.extend_from_slice(&[0u8; 8]);
        out.extend_from_slice(&ET_EXEC.to_le_bytes());
        out.extend_from_slice(&EM_RISCV.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes()); // e_version
        out.extend_from_slice(&entry.to_le_bytes());
        out.extend_from_slice(&(phoff as u64).to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
        out.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        out.extend_from_slice(&(EHDR_SIZE as u16).to_le_bytes());
        out.extend_from_slice(&(PHENT_SIZE as u16).to_le_bytes());
        out.extend_from_slice(&(segs.len() as u16).to_le_bytes());
        out.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
        out.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
        out.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
        assert_eq!(out.len(), EHDR_SIZE, "ELF64 header must be 64 bytes");

        let mut off = data_off as u64;
        for seg in segs {
            out.extend_from_slice(&PT_LOAD.to_le_bytes());
            out.extend_from_slice(&seg.flags.to_le_bytes());
            out.extend_from_slice(&off.to_le_bytes());
            out.extend_from_slice(&seg.vaddr.to_le_bytes());
            out.extend_from_slice(&seg.vaddr.to_le_bytes()); // p_paddr
            out.extend_from_slice(&(seg.data.len() as u64).to_le_bytes());
            out.extend_from_slice(&seg.mem_size.to_le_bytes());
            out.extend_from_slice(&8u64.to_le_bytes()); // p_align
            off += seg.data.len() as u64;
        }
        assert_eq!(out.len(), data_off, "program headers must be contiguous");

        for seg in segs {
            out.extend_from_slice(&seg.data);
        }
        out
    }

    /// The image the ELF *means*: file bytes below `p_filesz`, zeros above. Built byte-wise and
    /// only then folded into 8-byte blocks, so it cannot mirror a block-level loader mistake.
    fn expected_image(segs: &[Seg]) -> BTreeMap<u64, u64> {
        let mut image = BTreeMap::new();
        for seg in segs {
            let mut bytes = seg.data.clone();
            bytes.resize(seg.mem_size as usize, 0);

            let mut i = 0u64;
            while i < seg.mem_size {
                let addr = seg.vaddr + i;
                let mut word = 0u32;
                for j in 0..WORD_SIZE_U64 {
                    if let Some(byte) = bytes.get((i + j) as usize) {
                        word |= u32::from(*byte) << (j * 8);
                    }
                }
                let entry = image.entry(addr - addr % 8).or_insert(0u64);
                if addr.is_multiple_of(8) {
                    *entry |= u64::from(word);
                } else {
                    *entry |= u64::from(word) << 32;
                }
                i += WORD_SIZE_U64;
            }
        }
        image
    }

    /// A two-instruction text segment, enough to give the ELF a `pc_base`.
    fn text_at(vaddr: u64) -> Seg {
        Seg::text(vaddr, &[0x0000_0013, 0x0000_0013]) // two `nop`s
    }

    /// BSS zero-fill must not erase file bytes sharing an 8-byte block. All `p_filesz % 8` are
    /// covered: only 1..=4 put the boundary mid-block, and the rest are the control.
    #[test]
    fn bss_zero_fill_preserves_file_backed_bytes_for_every_filesz_mod_8() {
        for file_size in 1..=16usize {
            // Nonzero bytes only: a zero byte cannot show the clobber.
            let data: Vec<u8> = (0..file_size).map(|i| 0xA1 + i as u8).collect();
            let segs = vec![text_at(0x1000), Seg::data(0x2000, data, 24)];
            let elf = build_elf(0x1000, &segs);

            let parsed = Elf::new(&elf).unwrap_or_else(|e| {
                panic!(
                    "p_filesz = {file_size} (mod 8 = {}) failed to parse: {e}",
                    file_size % 8
                )
            });

            assert_eq!(
                *parsed.memory_image,
                expected_image(&segs),
                "p_filesz = {file_size} (mod 8 = {}): committed image differs from the ELF",
                file_size % 8,
            );
        }
    }

    /// The same clobber across a segment boundary: `vaddr` need only be 4-aligned, so a segment at
    /// `4 (mod 8)` shares its first block with whatever precedes it.
    #[test]
    fn bss_zero_fill_does_not_clobber_the_preceding_segment() {
        let segs = vec![
            Seg::text(0x1000, &[0xDEAD_BEEF]), // occupies [0x1000, 0x1004)
            Seg::data(0x1004, Vec::new(), 4),  // pure BSS, shares block 0x1000
        ];
        let elf = build_elf(0x1000, &segs);
        let parsed = Elf::new(&elf).expect("adjacent segments are legal");

        assert_eq!(
            parsed.memory_image.get(&0x1000),
            Some(&0xDEAD_BEEFu64),
            "the BSS segment erased the preceding segment's word",
        );
        assert_eq!(*parsed.memory_image, expected_image(&segs));
    }

    /// Completeness control: the ordinary text + data-with-BSS shape a guest build produces.
    #[test]
    fn ordinary_text_plus_data_with_bss_is_accepted() {
        let segs = vec![
            text_at(0x1000),
            Seg::data(0x2000, vec![0xEF, 0xBE, 0xAD, 0xDE], 4096),
        ];
        let parsed = Elf::new(&build_elf(0x1000, &segs)).expect("the ordinary layout is legal");

        assert_eq!(parsed.memory_image.get(&0x2000), Some(&0xDEAD_BEEFu64));
        assert_eq!(*parsed.memory_image, expected_image(&segs));
    }
}
