#[cfg(target_os = "zkvm")]
use core::arch::asm;
use pico_patch_libs::Poseidon2State;

/// Executes the Poseidon2 permutation, reading the state from `x` and writing it to `y`.
///
/// ### Safety
///
/// The caller must ensure that `x` and `y` are valid pointers. Their **eight**-byte alignment
/// is carried by [`Poseidon2State`] rather than left to the caller: this VM's memory is 8-byte
/// granular and the precompile's address gadget range checks `addr / 8`, so a 4-aligned buffer
/// has no provable trace and the syscall rejects it. (This used to say "four byte boundary",
/// which was a leftover of the 32-bit origin of this ABI and was the reason the SDK's own
/// hasher could not be proved.)
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_poseidon2_permute(x: *const Poseidon2State, y: *mut Poseidon2State) {
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
