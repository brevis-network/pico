use num::{BigUint, One};

use crate::{
    chips::gadgets::{
        curves::edwards::ed25519::{ed25519_sqrt, Ed25519BaseField},
        utils::field_params::FieldParameters,
    },
    emulator::riscv::riscv_emulator::RiscvEmulator,
};

/// A non-quadratic residue in the Ed25519 base field.
///
/// `2` is a non-residue mod `2^255 - 19`. The guest uses it to turn "this is not a square" into
/// something it can check: the product of two non-residues is a residue, so exhibiting a root of
/// `2 * u/v` proves `u/v` itself is not one.
const NQR_CURVE_25519: u8 = 2;

/// Hints whether a compressed Edwards point can be decompressed, and if not, why.
///
/// `buf` is 64 bytes: the compressed point (sign bit still in the high bit of byte 31), followed
/// by the guest's `v = d*y^2 + 1`.
///
/// Returns `[[1]]` when the point decompresses, in which case the guest calls the syscall.
/// Returns `[[0]]` when it does not, followed — unless `y` was already non-canonical — by
/// `v_inv` and a root of `NQR * u/v`, the two witnesses the guest constrains to prove that
/// `u/v` is not a square.
///
/// WARNING: this only hints. Every value it returns is constrained on the guest side; nothing
/// here is trusted.
#[must_use]
pub fn ed_decompress(_: &RiscvEmulator, buf: &[u8]) -> Vec<Vec<u8>> {
    hint_ed_decompress(buf)
}

/// The hint itself, without the emulator the hook signature carries. Split out so the protocol
/// can be tested directly, and so the AOT runtime can answer with this function rather than a
/// copy of it: the guest reads a different number of values depending on the answer, so the two
/// emulators have to agree on every request.
#[must_use]
pub fn hint_ed_decompress(buf: &[u8]) -> Vec<Vec<u8>> {
    assert_eq!(
        buf.len(),
        64,
        "FD_EDDECOMPRESS expects 64 bytes (compressed point || v); a 32-byte write is the older \
         protocol, from a patched curve25519 crate that predates the RV64 migration"
    );

    let modulus = Ed25519BaseField::modulus();

    let mut bytes: [u8; 32] = buf[..32].try_into().expect("32 bytes checked above");
    // Mask the sign bit; the syscall takes it separately, in arg2.
    bytes[31] &= 0b0111_1111;

    // The chip constrains `y < p`, so a non-canonical `y` is not decompressable by this VM even
    // when the value it reduces to lies on the curve. Say so here rather than letting the guest
    // reach a syscall whose proof cannot be satisfied.
    let y = BigUint::from_bytes_le(&bytes);
    if y >= modulus {
        return vec![vec![0]];
    }

    let v = BigUint::from_bytes_le(&buf[32..]);
    // v = d*y^2 + 1 reduced, so the guest cannot present one outside the field.
    assert!(v < modulus, "v is not a valid field element");

    let v_inv = v.modpow(&(&modulus - BigUint::from(2u64)), &modulus);
    // u = y^2 - 1, kept non-negative for BigUint.
    let u = (&y * &y + &modulus - BigUint::one()) % &modulus;
    let u_div_v = (&u * &v_inv) % &modulus;

    if ed25519_sqrt(&u_div_v).is_some() {
        vec![vec![1]]
    } else {
        let qr = (u_div_v * NQR_CURVE_25519) % &modulus;
        let root = ed25519_sqrt(&qr).expect("NQR times a non-residue is a residue");
        vec![vec![0], pad_le_32(&v_inv), pad_le_32(&root)]
    }
}

/// `to_bytes_le` drops leading zero bytes; the guest reads a fixed 32.
fn pad_le_32(x: &BigUint) -> Vec<u8> {
    let bytes = x.to_bytes_le();
    let mut padded = [0u8; 32];
    padded[..bytes.len()].copy_from_slice(&bytes);
    padded.to_vec()
}
