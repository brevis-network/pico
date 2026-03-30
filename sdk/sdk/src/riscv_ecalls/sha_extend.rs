#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Executes the SHA256 extend operation on the given word array.
///
/// ### Safety
///
/// The caller must ensure that `w` is valid pointer to data that is aligned along an eight byte
/// boundary. Each logical SHA word is taken from the low 32 bits of one `u64` slot.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_sha256_extend(w: *mut [u64; 64]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::SHA_EXTEND,
            in("a0") w,
            in("a1") 0
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
