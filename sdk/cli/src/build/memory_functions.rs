//! The check that a guest's `memcpy` / `memset` are the runtime's.
//!
//! Two implementations of each reach a guest link: `pico-sdk`'s assembly, and `compiler_builtins`'
//! Rust, weak in the toolchain's prebuilt `std` and turned on by
//! `-Z build-std-features=compiler-builtins-mem` when `std` is built from source. The runtime makes
//! its own win by putting them in `_start`'s object (`pico-sdk`'s `lib.rs`), and marks each with an
//! alias at the same address, `__pico_memcpy` / `__pico_memset`. Losing would leave a correct guest
//! that is slower: reth's ELF once kept `compiler_builtins`' and retired 5 % more instructions,
//! and nothing reported it.

use anyhow::{bail, Context, Result};
use elf::{
    abi::{PF_X, PT_LOAD, SHF_EXECINSTR},
    endian::LittleEndian,
    ElfBytes,
};
use std::path::Path;

/// The functions checked, and the alias the runtime puts on each.
const CHECKED: [(&str, &str); 2] = [("memcpy", "__pico_memcpy"), ("memset", "__pico_memset")];

/// Fails if the ELF at `path` carries a `memcpy` or `memset` other than the runtime's. A guest
/// without a symbol table, or built with a runtime from before the aliases, cannot be checked and
/// only gets a warning.
pub fn check_memory_functions(path: &Path) -> Result<()> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let elf = ElfBytes::<LittleEndian>::minimal_parse(&bytes)
        .with_context(|| format!("parsing {}", path.display()))?;
    let Some((symbols, strings)) = elf
        .symbol_table()
        .with_context(|| format!("reading the symbol table of {}", path.display()))?
    else {
        eprintln!(
            "warning: {} has no symbol table, so it cannot be checked that its memcpy / memset \
             are Pico's",
            path.display()
        );
        return Ok(());
    };
    let mut found: Vec<(String, u64)> = Vec::new();
    for symbol in symbols.iter() {
        let name = strings.get(symbol.st_name as usize).unwrap_or_default();
        if symbol.st_value != 0
            && CHECKED
                .iter()
                .any(|(f, alias)| name == *f || name == *alias)
        {
            found.push((name.to_owned(), symbol.st_value));
        }
    }
    // `_start`'s object carries both aliases, so a guest with neither was linked against a
    // runtime from before them, and there is nothing to compare with.
    if !found.iter().any(|(n, _)| n.starts_with("__pico_")) {
        eprintln!(
            "warning: {} was built with a pico-sdk older than this check, so it cannot be checked \
             that its memcpy / memset are Pico's",
            path.display()
        );
        return Ok(());
    }
    for (function, alias) in CHECKED {
        let addresses = |name: &str| -> Vec<u64> {
            found
                .iter()
                .filter(|(n, _)| n == name)
                .map(|(_, a)| *a)
                .collect()
        };
        check_one(function, &addresses(function), &addresses(alias))?;
    }
    Ok(())
}

/// Fails if the ELF's code holds an `A`-extension instruction (`lr`, `sc`, `amo*`, major opcode
/// `0x2f`), which the machine does not run. The toolchain's prebuilt `std` reaches atomics through
/// `pico-sdk`'s `__atomic_*` functions instead.
pub fn check_no_atomic_instructions(path: &Path) -> Result<()> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    match first_atomic_in_elf(&bytes).with_context(|| format!("reading {}", path.display()))? {
        Some(at) => bail!(
            "{} holds an atomic instruction at {at:#x}, which the machine does not run",
            path.display()
        ),
        None => Ok(()),
    }
}

/// The address of the first `A`-extension instruction in the ELF's code: its executable
/// sections, or its executable `PT_LOAD` segments when it has no section headers.
fn first_atomic_in_elf(bytes: &[u8]) -> Result<Option<u64>> {
    let elf = ElfBytes::<LittleEndian>::minimal_parse(bytes)?;
    let mut code: Vec<(u64, &[u8])> = Vec::new();
    if let Some(sections) = elf.section_headers() {
        for section in sections
            .iter()
            .filter(|s| s.sh_flags & u64::from(SHF_EXECINSTR) != 0)
        {
            code.push((section.sh_addr, elf.section_data(&section)?.0));
        }
    } else if let Some(segments) = elf.segments() {
        for segment in segments
            .iter()
            .filter(|p| p.p_type == PT_LOAD && p.p_flags & PF_X != 0)
        {
            code.push((segment.p_vaddr, elf.segment_data(&segment)?));
        }
    } else {
        bail!("it has neither section headers nor segments");
    }
    Ok(code
        .into_iter()
        .find_map(|(addr, bytes)| first_atomic(bytes).map(|at| addr + at as u64)))
}

/// The offset of the first `A`-extension instruction in `code`, a run of 32-bit instructions.
fn first_atomic(code: &[u8]) -> Option<usize> {
    code.as_chunks::<4>()
        .0
        .iter()
        .position(|w| u32::from_le_bytes(*w) & 0x7f == 0x2f)
        .map(|i| i * 4)
}

/// `function`'s definitions in the ELF must all be at the runtime's alias. None at all is fine:
/// the guest never calls it, and the link dropped both.
fn check_one(function: &str, at: &[u64], runtime: &[u64]) -> Result<()> {
    if at.is_empty() {
        return Ok(());
    }
    let Some(&ours) = runtime.first() else {
        bail!(
            "the guest's {function} is not Pico's: the link kept another definition, most likely \
             compiler_builtins', and dropped Pico's. The guest runs, but slower."
        );
    };
    if let Some(other) = at.iter().find(|&&a| a != ours) {
        bail!(
            "the guest's {function} is at {other:#x}, not at Pico's ({ours:#x}): another \
             definition won the link. The guest runs, but slower."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{check_one, first_atomic, first_atomic_in_elf};

    /// A minimal RV64 executable with no section headers: one `R|X` `PT_LOAD` holding `code`.
    fn segment_only_elf(code: &[u32]) -> Vec<u8> {
        let text: Vec<u8> = code.iter().flat_map(|w| w.to_le_bytes()).collect();
        let mut elf = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let half = |v: u16| v.to_le_bytes().to_vec();
        let word = |v: u32| v.to_le_bytes().to_vec();
        let xword = |v: u64| v.to_le_bytes().to_vec();
        for field in [half(2), half(0xf3), word(1)] {
            elf.extend(field); // e_type EXEC, e_machine RISC-V, e_version
        }
        for field in [xword(0x1000), xword(64), xword(0)] {
            elf.extend(field); // e_entry, e_phoff, e_shoff
        }
        for field in [
            word(0),
            half(64),
            half(56),
            half(1),
            half(64),
            half(0),
            half(0),
        ] {
            elf.extend(field); // e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, ...
        }
        let len = text.len() as u64;
        for field in [word(1), word(5)] {
            elf.extend(field); // p_type PT_LOAD, p_flags R|X
        }
        for field in [
            xword(120),
            xword(0x1000),
            xword(0x1000),
            xword(len),
            xword(len),
            xword(4),
        ] {
            elf.extend(field); // p_offset .. p_align
        }
        elf.extend(text);
        elf
    }

    #[test]
    fn an_elf_without_section_headers_is_read_by_its_segments() {
        let atomic = segment_only_elf(&[0x0015_0513, 0x00b6_252f]);
        assert_eq!(first_atomic_in_elf(&atomic).unwrap(), Some(0x1004));
        let clean = segment_only_elf(&[0x0015_0513, 0x0015_0513]);
        assert_eq!(first_atomic_in_elf(&clean).unwrap(), None);
    }

    #[test]
    fn an_atomic_instruction_is_found() {
        // addi a0, a0, 1; amoadd.w a0, a1, (a2); lr.d a0, (a1)
        let code: Vec<u8> = [0x0015_0513u32, 0x00b6_252f, 0x1005_b52f]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        assert_eq!(first_atomic(&code), Some(4));
        assert_eq!(first_atomic(&code[..4]), None);
    }

    #[test]
    fn the_runtimes_definition_passes() {
        check_one("memcpy", &[0x2015c0], &[0x2015c0]).unwrap();
    }

    #[test]
    fn a_guest_that_never_calls_it_passes() {
        check_one("memset", &[], &[]).unwrap();
    }

    #[test]
    fn another_definition_fails() {
        let err = check_one("memcpy", &[0x3000], &[0x2015c0]).unwrap_err();
        assert!(err.to_string().contains("another definition won"), "{err}");
    }

    #[test]
    fn a_dropped_runtime_definition_fails() {
        let err = check_one("memcpy", &[0x3000], &[]).unwrap_err();
        assert!(err.to_string().contains("dropped Pico's"), "{err}");
    }
}
