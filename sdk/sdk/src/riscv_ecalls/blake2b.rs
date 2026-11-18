#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Runs rounds `0..rounds` of BLAKE2b's schedule (RFC 7693 §3.2) on the working vector
/// `state[0..16]`, with the message block `state[16..32]`, and writes the vector back: round `i`
/// reads the message in the order `SIGMA[i % 10]`. The message words are not written.
///
/// ### Safety
///
/// `state` is a valid, 8-byte aligned pointer, and `rounds` is in `1..=1000`. A longer run is a
/// sequence of calls of at most 1000 rounds each, every one but the last a multiple of ten, so
/// that each call starts at round 0 of the schedule as the syscall does.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_blake2b_rounds(state: *mut [u64; 32], rounds: u64) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::BLAKE2B_ROUNDS,
            in("a0") state,
            in("a1") rounds,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
