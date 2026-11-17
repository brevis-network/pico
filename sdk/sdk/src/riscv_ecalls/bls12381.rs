#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Adds two Bls12381 points.
///
/// The result is stored in the first point.
///
/// ### Safety
///
/// The caller must ensure that `p` and `q` are valid pointers to data that is aligned along a four
/// byte boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_add(p: *mut [u64; 12], q: *const [u64; 12]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::BLS12381_ADD,
            in("a0") p,
            in("a1") q,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Double a Bls12381 point.
///
/// The result is stored in the first point.
///
/// ### Safety
///
/// The caller must ensure that `p` is valid pointer to data that is aligned along a four byte
/// boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_double(p: *mut [u64; 12]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::BLS12381_DOUBLE,
            in("a0") p,
            in("a1") 0,
        );
    }
}

/// Decompresses a compressed BLS12-381 point.
///
/// The array represents two field elements. When considered as a byte array, the representation is
/// big-endian. This means that the `u64`s are actually byte-reversed due to the little-endian
/// architecture. The reason the type signature requires a u64 array is because we want the pointers
/// to be aligned to the architecture's register bit widths.
///
/// The first half of the input array should contain the X coordinate. The second half of the input
/// array will be overwritten with the Y coordinate.
///
/// ### Safety
///
/// The caller must ensure that `point` is valid pointer to data that is aligned along a four byte
/// boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_decompress(point: &mut [u64; 12], sign_bit: bool) {
    #[cfg(target_os = "zkvm")]
    {
        // SAFETY: Both pointee types have the same size. The destination has a finer alignment than
        // the source.
        let point = unsafe { core::mem::transmute::<&mut [u64; 12], &mut [u8; 12 * 8]>(point) };
        // Memory system/FpOps are little endian so we'll just flip the whole array before/after
        point.reverse();
        let p = point.as_mut_ptr();
        unsafe {
            asm!(
                "ecall",
                in("t0") crate::riscv_ecalls::BLS12381_DECOMPRESS,
                in("a0") p,
                in("a1") sign_bit as u8,
            );
        }
        point.reverse();
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Adds two BLS12-381 G2 points, `p ← p + q`.
///
/// A point is `x.c0, x.c1, y.c0, y.c1`, each 48 little-endian bytes below the modulus.
///
/// ### Safety
///
/// `p` and `q` are valid, 8-byte aligned pointers to affine points with `p.x != q.x`, which rules
/// out `p == ±q`; there is no encoding of the point at infinity. The chord formula is applied as
/// is, so for points off the curve the result is not a curve point.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_g2_add(p: *mut [u64; 24], q: *const [u64; 24]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::BLS12381_G2_ADD,
            in("a0") p,
            in("a1") q,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Doubles a BLS12-381 G2 point, `p ← 2p`.
///
/// ### Safety
///
/// `p` is a valid, 8-byte aligned pointer to an affine point with `p.y != 0`, laid out as in
/// [`syscall_bls12381_g2_add`].
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_g2_double(p: *mut [u64; 24]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::BLS12381_G2_DOUBLE,
            in("a0") p,
            in("a1") 0,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
