#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Executes the Poseidon2 permutation on the given state.
///
/// ### Safety
///
/// The caller must ensure that `state` is valid pointer to data that is aligned along a four
/// byte boundary.
///
/// Shelved: the proving chip for this precompile is out of the machine and the syscall is
/// unregistered, so a guest reaching here stops at `UnsupportedSyscall`. The definition stays
/// because it is the only one of the `#[no_mangle]` symbol that `pico-patch-libs` declares -- but
/// nothing in this VM will serve the call. The compile-time signal for guests is on
/// `pico_sdk::poseidon2_hash`; code that declares the symbol itself gets no signal at all.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_poseidon2_permute(x: *const [u32; 16], y: *mut [u32; 16]) {
    let syscall_id = crate::riscv_ecalls::POSEIDON2_PERMUTE;

    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") syscall_id,
            in("a0") x,
            in("a1") y
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
