//! The guest memory layout: one definition for the emulator, the ELF loader and the guest runtime.
//!
//! The guest side reads it through the linker script, `sdk/sdk/pico.ld`, which `cargo pico build`
//! links every Rust guest with and which C guests link with directly. The script cannot import
//! these constants, so it carries its own copy of each and `tests::pico_ld_matches_this_layout`
//! fails if the two drift.
//!
//! ```text
//! 0x0000_0000 ┬ unusable: the register file and the memory chip's low-address guard
//! 0x0001_0000 ┼ MIN_SEGMENT_ADDR, the lowest address a segment may load at
//! 0x0020_0800 ┼ TEXT_START: code, then read-only data, then data and bss (pico.ld)
//!             ┼ _heap_start: the first byte after bss
//!             │ heap, growing up
//! 0x777f_0000 ┼ HEAP_END (_heap_end)
//!             │ stack guard, STACK_GUARD_SIZE: no valid access lands here
//! 0x7780_0000 ┼ STACK_BOTTOM
//!             │ stack, STACK_SIZE, growing down
//! 0x7800_0000 ┴ STACK_TOP = MEMORY_SIZE
//! ```

/// One past the highest guest address. Every address must stay below the KoalaBear prime
/// (`0x7f00_0001`) so that it is a single field element; this cap leaves room under it.
pub const MEMORY_SIZE: u64 = 0x7800_0000;

/// The lowest address a `PT_LOAD` segment may start at.
///
/// `[0, NUM_REGISTERS)` is the register file, and the memory chip's low-address guard
/// (`addr[1] + addr[2] != 0`, `riscv_memory/read_write/constraints.rs`) makes every data access
/// below `2^16` unprovable. A segment placed lower either aliases a register or lands where no
/// provable access can reach it.
pub const MIN_SEGMENT_ADDR: u64 = 1 << 16;

/// Where the linker script places the code.
pub const TEXT_START: u64 = 0x0020_0800;

/// The initial stack pointer: the stack occupies the top of memory and grows down.
pub const STACK_TOP: u64 = MEMORY_SIZE;

/// The stack's size, the same for every program, so a check on the guard below needs no
/// per-program input. reth's deepest stack is 52 KiB (sp never below `0x77ff_3490` on blocks
/// 17106222, 18884864, 24004465, 24005809 and 24600825), so this is about 150 times that.
pub const STACK_SIZE: u64 = 8 << 20;

/// The lowest stack address.
pub const STACK_BOTTOM: u64 = STACK_TOP - STACK_SIZE;

/// The gap between the heap and the stack. A stack that overflows by less than this lands here
/// rather than in the heap.
pub const STACK_GUARD_SIZE: u64 = 64 << 10;

/// One past the last heap byte (`_heap_end`).
pub const HEAP_END: u64 = STACK_BOTTOM - STACK_GUARD_SIZE;

const _: () = assert!(MIN_SEGMENT_ADDR < TEXT_START && TEXT_START < HEAP_END);

#[cfg(test)]
mod tests {
    use super::*;

    /// The value the script assigns to `name`, as written: `name = 0x...;`.
    fn assigned(script: &str, name: &str) -> u64 {
        let line = script
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with(name) && l[name.len()..].trim_start().starts_with('='))
            .unwrap_or_else(|| panic!("pico.ld assigns no `{name}`"));
        let value = line.split('=').nth(1).unwrap().trim().trim_end_matches(';');
        u64::from_str_radix(value.trim_start_matches("0x"), 16)
            .unwrap_or_else(|_| panic!("`{name}` in pico.ld is not a hex literal: {value}"))
    }

    #[test]
    fn pico_ld_matches_this_layout() {
        let script = include_str!("../../../sdk/sdk/pico.ld");
        assert_eq!(assigned(script, "__pico_memory_size"), MEMORY_SIZE);
        assert_eq!(assigned(script, "__pico_text_start"), TEXT_START);
        assert_eq!(assigned(script, "__pico_stack_size"), STACK_SIZE);
        assert_eq!(
            assigned(script, "__pico_stack_guard_size"),
            STACK_GUARD_SIZE
        );
    }
}
