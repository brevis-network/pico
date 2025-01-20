#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Executes the Poseidon2 permutation on the given state.
///
/// ### Safety
///
/// The caller must ensure that `state` is valid pointer to data that is aligned along a four
/// byte boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_poseidon2_permute(x: *const [u32; 16], y: *mut [u32; 16]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::POSEIDON2_PERMUTE,
            in("a0") x,
            in("a1") y
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
