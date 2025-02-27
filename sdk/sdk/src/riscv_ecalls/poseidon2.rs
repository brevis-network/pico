#[cfg(target_os = "zkvm")]
use core::arch::asm;
use pico_patch_libs::SyscallType;

/// Executes the Poseidon2 permutation on the given state.
///
/// ### Safety
///
/// The caller must ensure that `state` is valid pointer to data that is aligned along a four
/// byte boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_poseidon2_permute(
    x: *const [u32; 16],
    y: *mut [u32; 16],
    syscall_type: SyscallType,
) {
    let syscall_id = match syscall_type {
        SyscallType::BabyBear => crate::riscv_ecalls::POSEIDON2_PERMUTE_BB,
        SyscallType::KoalaBear => crate::riscv_ecalls::POSEIDON2_PERMUTE_KB,
        SyscallType::M31 => crate::riscv_ecalls::POSEIDON2_PERMUTE_M31,
    };

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
