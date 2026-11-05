//! The check that a guest's `memcpy` / `memset` are the runtime's.
//!
//! Two implementations of each reach a guest link: `pico-sdk`'s assembly, and `compiler_builtins`'
//! Rust, which `-Z build-std-features=compiler-builtins-mem` turns on. The runtime makes its own
//! win by putting them in `_start`'s object (`pico-sdk`'s `lib.rs`), and marks each with an alias
//! at the same address, `__pico_memcpy` / `__pico_memset`. Losing would leave a correct guest
//! that is slower: reth's ELF once kept `compiler_builtins`' and retired 5 % more instructions,
//! and nothing reported it.

use anyhow::{bail, Context, Result};
use elf::{endian::LittleEndian, ElfBytes};
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
    use super::check_one;

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
