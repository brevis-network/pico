//! A guest that makes the emulator abort on input it was given.
//!
//! It reads an `Option<u32>`. `Some(index)` issues the `COMMIT` ecall for digest word `index`
//! directly, without the entrypoint's commit tail; the public values hold eight words, and the
//! emulator panics on a ninth rather than returning an error. `None` issues nothing, so the guest
//! halts through the entrypoint and its run proves.
//!
//! `sdk/prover/src/tests/emulation_abort.rs` uses it to reach the prover's emulation-abort guard.
//! The built ELF ships as `perf/bench_data/rv64/commit-out-of-range-elf`.

#![no_main]
pico_sdk::entrypoint!(main);

pub fn main() {
    let index: Option<u32> = pico_sdk::io::read_as();
    if let Some(index) = index {
        commit_zero_word(index);
    }
}

#[cfg(target_os = "zkvm")]
fn commit_zero_word(index: u32) {
    // Both operands zero-extended, so the emulator rejects the index for its range and not for its
    // encoding.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("t0") pico_sdk::riscv_ecalls::COMMIT,
            in("a0") u64::from(index),
            in("a1") 0u64,
        );
    }
}

#[cfg(not(target_os = "zkvm"))]
fn commit_zero_word(_: u32) {
    unreachable!("the COMMIT ecall exists only on the zkVM target")
}
