//! The functions of zkevm-standards' `zkvm_accelerators.h`, with C ABI: the precompiles a guest
//! built against the standard interface calls, for example an EL client's `zkvm-interface` crypto
//! provider.
//!
//! Each function returns [`ZKVM_EOK`], or [`ZKVM_EFAIL`] for an input the precompile rejects.
//! A NULL pointer panics, as the header asks, which ends the run abnormally; a NULL buffer whose
//! length is 0 is an empty one. Pointers need no alignment.
//!
//! The symbols are exported inside the zkVM only. On the host the functions are plain Rust, with
//! software in place of the syscalls, so they can be tested there.

mod blake2f;
mod bls12_381;
mod bn254;
mod ecdsa;
mod hash;
mod kzg;
mod modexp;

#[cfg(test)]
mod tests;

pub use blake2f::zkvm_blake2f;
pub use bls12_381::{
    zkvm_bls12_g1_add, zkvm_bls12_g1_msm, zkvm_bls12_g2_add, zkvm_bls12_g2_msm,
    zkvm_bls12_map_fp2_to_g2, zkvm_bls12_map_fp_to_g1, zkvm_bls12_pairing,
};
pub use bn254::{zkvm_bn254_g1_add, zkvm_bn254_g1_mul, zkvm_bn254_pairing};
pub use ecdsa::{zkvm_secp256k1_ecrecover, zkvm_secp256k1_verify, zkvm_secp256r1_verify};
pub use hash::{zkvm_keccak256, zkvm_ripemd160, zkvm_sha256};
pub use kzg::zkvm_kzg_point_eval;
pub use modexp::zkvm_modexp;

/// `zkvm_status`, a C enum.
pub type ZkvmStatus = core::ffi::c_int;
pub const ZKVM_EOK: ZkvmStatus = 0;
pub const ZKVM_EFAIL: ZkvmStatus = -1;

/// The header's pair structs. Its byte types are 8-byte aligned, but every size is a multiple of
/// 8, so these byte-aligned mirrors have the same layout and accept any pointer.
#[repr(C)]
pub struct Bn254PairingPair {
    pub g1: [u8; 64],
    pub g2: [u8; 128],
}

#[repr(C)]
pub struct Bls12G1MsmPair {
    pub point: [u8; 96],
    pub scalar: [u8; 32],
}

#[repr(C)]
pub struct Bls12G2MsmPair {
    pub point: [u8; 192],
    pub scalar: [u8; 32],
}

#[repr(C)]
pub struct Bls12PairingPair {
    pub g1: [u8; 96],
    pub g2: [u8; 192],
}

/// `*p`, copied out, so that an output may share its address. `T` is byte-aligned, so any
/// non-NULL pointer will do.
unsafe fn arg<T: Copy>(p: *const T, func: &str, name: &str) -> T {
    if p.is_null() {
        null(func, name)
    }
    p.read()
}

/// An output, written once every input has been read: the caller may pass an input's address.
struct Out<T>(*mut T);

impl<T> Out<T> {
    unsafe fn write(self, value: T) {
        self.0.write(value)
    }
}

unsafe fn out<T>(p: *mut T, func: &str, name: &str) -> Out<T> {
    if p.is_null() {
        null(func, name)
    }
    Out(p)
}

/// The `len` items at `p`; NULL is the empty list when `len` is 0.
unsafe fn items<'a, T>(p: *const T, len: usize, func: &str, name: &str) -> &'a [T] {
    if len == 0 {
        return &[];
    }
    if p.is_null() {
        null(func, name)
    }
    core::slice::from_raw_parts(p, len)
}

#[cold]
fn null(func: &str, name: &str) -> ! {
    panic!("{func}: `{name}` is NULL")
}

/// `true` if every byte is zero: the point at infinity in the EIP-196 and EIP-2537 encodings.
fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

/// Whether `bytes` is below `modulus`, both big-endian and of one length.
///
/// Checked before BLS12-381's `Fp::from_bytes` parses the bytes: it multiplies even a value it
/// then rejects, and inside the zkVM that multiplication is a field syscall, which cannot be
/// proved with an operand at or above the modulus.
fn below(bytes: &[u8], modulus: &[u8]) -> bool {
    debug_assert_eq!(bytes.len(), modulus.len());
    bytes < modulus
}

/// Lowercase hex as bytes, at compile time.
const fn hex_literal<const N: usize>(hex: &[u8]) -> [u8; N] {
    assert!(hex.len() == 2 * N);
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not lowercase hex"),
        }
    }
    let mut bytes = [0u8; N];
    let mut i = 0;
    while i < N {
        bytes[i] = nibble(hex[2 * i]) << 4 | nibble(hex[2 * i + 1]);
        i += 1;
    }
    bytes
}
