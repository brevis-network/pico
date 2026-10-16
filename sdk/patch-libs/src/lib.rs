//! Wrapper syscall API for the Pico patches.
pub mod bls12381;
pub mod bn254;
pub mod ecdsa;
pub mod ed25519;
pub mod io;
pub mod secp256k1;
pub mod secp256r1;
pub mod unconstrained;
pub mod utils;
pub mod verify;

/// Field elements in one Poseidon2 permutation state.
pub const POSEIDON2_WIDTH: usize = 16;

/// A Poseidon2 permutation state, in the layout the precompile reads and writes.
///
/// # Why this is a type and not a bare `[u32; 16]`
///
/// The alignment is load-bearing. This VM's memory is 8-byte granular, and the precompile's
/// address gadget range checks `addr / 8`, so a buffer that lands 4 mod 8 has no provable
/// trace at all -- the syscall rejects such a pointer up front rather than emulating into a
/// proof that cannot be produced. Rust aligns a bare `[u32; 16]` to 4, so roughly half of
/// them -- including every stack local -- were unusable. Carrying the alignment in the type
/// makes an unaligned buffer unrepresentable instead of merely discouraged.
///
/// # Layout
///
/// `repr(C)` pins the array to offset 0, which is what the pointer handed to the syscall
/// means. The sixteen 32-bit words are **packed**: the chip reads them as eight dwords of two
/// words each (`STATE_NUM_DWORDS = POSEIDON2_WIDTH / 2` in `pico-vm`), so this must stay 64
/// bytes. Widening it to `[u64; 16]` -- the shape the sha256 syscalls use, where each 32-bit
/// word gets its own 8-byte slot -- would align just as well and silently break the chip.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poseidon2State(pub [u32; POSEIDON2_WIDTH]);

impl Poseidon2State {
    /// An all-zero state.
    #[must_use]
    pub const fn zero() -> Self {
        Self([0; POSEIDON2_WIDTH])
    }
}

impl Default for Poseidon2State {
    fn default() -> Self {
        Self::zero()
    }
}

extern "C" {
    /// Halts the program with the given exit code.
    pub fn syscall_halt(exit_code: u8) -> !;

    /// Writes the bytes in the given buffer to the given file descriptor.
    pub fn syscall_write(fd: u32, write_buf: *const u8, nbytes: usize);

    /// Reads the bytes from the given file descriptor into the given buffer.
    pub fn syscall_read(fd: u32, read_buf: *mut u8, nbytes: usize);

    /// Executes the SHA-256 extend operation on the given word array.
    /// Each logical SHA word is taken from the low 32 bits of one 8-byte-aligned `u64` slot.
    pub fn syscall_sha256_extend(w: *mut [u64; 64]);

    /// Executes the SHA-256 compress operation on the given word array and a given state.
    /// Each logical SHA word is taken from the low 32 bits of one 8-byte-aligned `u64` slot.
    pub fn syscall_sha256_compress(w: *mut [u64; 64], state: *mut [u64; 8]);

    /// Executes an Ed25519 curve addition on the given points.
    pub fn syscall_ed_add(p: *mut [u64; 8], q: *const [u64; 8]);

    /// Executes an Ed25519 curve decompression on the given point.
    pub fn syscall_ed_decompress(point: &mut [u64; 8]);

    /// Executes an Sepc256k1 curve addition on the given points.
    pub fn syscall_secp256k1_add(p: *mut [u64; 8], q: *const [u64; 8]);

    /// Executes an Secp256k1 curve doubling on the given point.
    pub fn syscall_secp256k1_double(p: *mut [u64; 8]);

    /// Executes an Secp256k1 curve decompression on the given point.
    pub fn syscall_secp256k1_decompress(point: &mut [u64; 8], is_odd: bool);

    /// Executes an Secp256r1 curve addition on the given points.
    pub fn syscall_secp256r1_add(p: *mut [u64; 8], q: *const [u64; 8]);

    /// Executes an Secp256r1 curve doubling on the given point.
    pub fn syscall_secp256r1_double(p: *mut [u64; 8]);

    /// Executes an Secp256r1 curve decompression on the given point.
    pub fn syscall_secp256r1_decompress(point: &mut [u64; 8], is_odd: bool);

    /// Executes a Bn254 curve addition on the given points.
    pub fn syscall_bn254_add(p: *mut [u64; 8], q: *const [u64; 8]);

    /// Executes a Bn254 curve doubling on the given point.
    pub fn syscall_bn254_double(p: *mut [u64; 8]);

    /// Executes a BLS12-381 curve addition on the given points.
    pub fn syscall_bls12381_add(p: *mut [u64; 12], q: *const [u64; 12]);

    /// Executes a BLS12-381 curve doubling on the given point.
    pub fn syscall_bls12381_double(p: *mut [u64; 12]);

    /// Executes the Keccak-256 permutation on the given state.
    pub fn syscall_keccak_permute(state: *mut [u64; 25]);

    /// Executes an uint256 multiplication on the given inputs.
    pub fn syscall_uint256_mulmod(x: *mut [u64; 4], y: *const [u64; 4]);

    /// Enters unconstrained mode.
    pub fn syscall_enter_unconstrained() -> bool;

    /// Exits unconstrained mode.
    pub fn syscall_exit_unconstrained();

    /// Defers the verification of a valid Pico zkVM proof.
    pub fn syscall_verify_pico_proof(vk_digest: &[u32; 8], pv_digest: &[u8; 32]);

    /// Returns the length of the next element in the hint stream.
    pub fn syscall_hint_len() -> usize;

    /// Reads the next element in the hint stream into the given buffer.
    pub fn syscall_hint_read(ptr: *mut u8, len: usize);

    /// Allocates a buffer aligned to the given alignment.
    pub fn sys_alloc_aligned(bytes: usize, align: usize) -> *mut u8;

    /// Decompresses a BLS12-381 point.
    pub fn syscall_bls12381_decompress(point: &mut [u64; 12], is_odd: bool);

    /// Computes a big integer operation with a modulus.
    pub fn sys_bigint(
        result: *mut [u64; 4],
        op: u64,
        x: *const [u64; 4],
        y: *const [u64; 4],
        modulus: *const [u64; 4],
    );

    /// Executes a BLS12-381 field addition on the given inputs.
    pub fn syscall_bls12381_fp_addmod(p: *mut u64, q: *const u64);

    /// Executes a BLS12-381 field subtraction on the given inputs.
    pub fn syscall_bls12381_fp_submod(p: *mut u64, q: *const u64);

    /// Executes a BLS12-381 field multiplication on the given inputs.
    pub fn syscall_bls12381_fp_mulmod(p: *mut u64, q: *const u64);

    /// Executes a BLS12-381 Fp2 addition on the given inputs.
    pub fn syscall_bls12381_fp2_addmod(p: *mut u64, q: *const u64);

    /// Executes a BLS12-381 Fp2 subtraction on the given inputs.
    pub fn syscall_bls12381_fp2_submod(p: *mut u64, q: *const u64);

    /// Executes a BLS12-381 Fp2 multiplication on the given inputs.
    pub fn syscall_bls12381_fp2_mulmod(p: *mut u64, q: *const u64);

    /// Executes a BN254 field addition on the given inputs.
    pub fn syscall_bn254_fp_addmod(p: *mut u64, q: *const u64);

    /// Executes a BN254 field subtraction on the given inputs.
    pub fn syscall_bn254_fp_submod(p: *mut u64, q: *const u64);

    /// Executes a BN254 field multiplication on the given inputs.
    pub fn syscall_bn254_fp_mulmod(p: *mut u64, q: *const u64);

    /// Executes a BN254 Fp2 addition on the given inputs.
    pub fn syscall_bn254_fp2_addmod(p: *mut u64, q: *const u64);

    /// Executes a BN254 Fp2 subtraction on the given inputs.
    pub fn syscall_bn254_fp2_submod(p: *mut u64, q: *const u64);

    /// Executes a BN254 Fp2 multiplication on the given inputs.
    pub fn syscall_bn254_fp2_mulmod(p: *mut u64, q: *const u64);

    /*
    /// Executes a Secp256k1 field addition on the given inputs.
    pub fn syscall_secp256k1_fp_addmod(p: *mut u32, q: *const u32);

    /// Executes a Secp256k1 field subtraction on the given inputs.
    pub fn syscall_secp256k1_fp_submod(p: *mut u32, q: *const u32);

    /// Executes a Secp256k1 field multiplication on the given inputs.
    pub fn syscall_secp256k1_fp_mulmod(p: *mut u32, q: *const u32);
    */

    /// Executes a poseidon2 permutation, reading the state from `x` and writing it to `y`.
    ///
    /// Both pointers must be 8-byte aligned, which [`Poseidon2State`] guarantees; see its docs
    /// for why that is a correctness requirement and not a performance hint.
    pub fn syscall_poseidon2_permute(x: *const Poseidon2State, y: *mut Poseidon2State);
}

#[cfg(test)]
mod poseidon2_state_tests {
    use super::{Poseidon2State, POSEIDON2_WIDTH};
    use core::mem::{align_of, size_of};

    /// The two properties the precompile depends on, neither of which is visible at the call
    /// site once a caller has a value of this type.
    ///
    /// Alignment: the VM's memory is 8-byte granular and the address gadget range checks
    /// `addr / 8`, so a 4-aligned buffer has no provable trace.
    ///
    /// Size: the chip reads the state as eight dwords of two 32-bit words each. Giving every
    /// word its own 8-byte slot -- the shape the sha256 syscalls use, and a natural-looking way
    /// to "fix" alignment -- would align correctly and write the wrong thing. That regression
    /// would be silent at this boundary, so it is pinned here.
    #[test]
    fn the_state_is_dword_aligned_and_packed() {
        assert_eq!(align_of::<Poseidon2State>(), 8, "must be 8-byte aligned");
        assert_eq!(
            size_of::<Poseidon2State>(),
            4 * POSEIDON2_WIDTH,
            "the words are packed two per dword; widening them breaks the chip's layout"
        );
    }

    /// `repr(C)` pins the array to offset 0, which is what the pointer passed to the syscall
    /// is taken to mean.
    #[test]
    fn the_words_start_at_the_struct_address() {
        let state = Poseidon2State::zero();
        assert_eq!(
            core::ptr::addr_of!(state).cast::<u32>(),
            state.0.as_ptr(),
            "the array must start at the struct's own address"
        );
        assert_eq!(state.0.as_ptr() as usize % 8, 0);
    }
}
