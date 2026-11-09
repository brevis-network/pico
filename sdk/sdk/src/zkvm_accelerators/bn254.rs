//! BN254 (EIP-196, EIP-197) through Pico's patched `substrate-bn`: affine G1 arithmetic reaches
//! the curve syscalls, the pairing the field ones. Points use the EVM encoding: big-endian
//! coordinates, G2's as `(x_im, x_re, y_im, y_re)`, all zeros for the point at infinity.

use alloc::vec::Vec;

use substrate_bn::{pairing_batch, AffineG1, AffineG2, Fq, Fq2, Fr, Gt, G1, G2};

use super::{arg, is_zero, items, out, Bn254PairingPair, ZkvmStatus, ZKVM_EFAIL, ZKVM_EOK};

/// `zkvm_status zkvm_bn254_g1_add(const zkvm_bn254_g1_point* p1, const zkvm_bn254_g1_point* p2,
/// zkvm_bn254_g1_point* result)`.
///
/// # Safety
///
/// Each pointer points to 64 bytes.
#[cfg_attr(target_os = "zkvm", no_mangle)]
pub unsafe extern "C" fn zkvm_bn254_g1_add(
    p1: *const [u8; 64],
    p2: *const [u8; 64],
    result: *mut [u8; 64],
) -> ZkvmStatus {
    const F: &str = "zkvm_bn254_g1_add";
    let (p1, p2) = (arg(p1, F, "p1"), arg(p2, F, "p2"));
    let result = out(result, F, "result");
    let (Some(a), Some(b)) = (decode_g1(&p1), decode_g1(&p2)) else {
        return ZKVM_EFAIL;
    };
    result.write(encode_g1(add(a, b)));
    ZKVM_EOK
}

/// `zkvm_status zkvm_bn254_g1_mul(const zkvm_bn254_g1_point* point, const zkvm_bn254_scalar*
/// scalar, zkvm_bn254_g1_point* result)`. Any 256-bit scalar.
///
/// # Safety
///
/// `point` and `result` point to 64 bytes, `scalar` to 32.
#[cfg_attr(target_os = "zkvm", no_mangle)]
pub unsafe extern "C" fn zkvm_bn254_g1_mul(
    point: *const [u8; 64],
    scalar: *const [u8; 32],
    result: *mut [u8; 64],
) -> ZkvmStatus {
    const F: &str = "zkvm_bn254_g1_mul";
    let (point, scalar) = (arg(point, F, "point"), arg(scalar, F, "scalar"));
    let result = out(result, F, "result");
    let Some(p) = decode_g1(&point) else {
        return ZKVM_EFAIL;
    };
    // G1 has prime order r, so the scalar reduces mod r.
    let s = Fr::from_bytes_be_mod_order(&scalar).expect("32 bytes");
    result.write(encode_g1(match p {
        Some(p) if !s.is_zero() => Some(p * s),
        _ => None,
    }));
    ZKVM_EOK
}

/// `zkvm_status zkvm_bn254_pairing(const zkvm_bn254_pairing_pair* pairs, size_t num_pairs, bool*
/// verified)`: whether the product of the pairings is 1. No pairs verify true.
///
/// # Safety
///
/// `pairs` holds `num_pairs` pairs; `verified` points to a `bool`.
#[cfg_attr(target_os = "zkvm", no_mangle)]
pub unsafe extern "C" fn zkvm_bn254_pairing(
    pairs: *const Bn254PairingPair,
    num_pairs: usize,
    verified: *mut bool,
) -> ZkvmStatus {
    const F: &str = "zkvm_bn254_pairing";
    let pairs = items(pairs, num_pairs, F, "pairs");
    let verified = out(verified, F, "verified");
    let mut terms = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let (Some(g1), Some(g2)) = (decode_g1(&pair.g1), decode_g2(&pair.g2)) else {
            return ZKVM_EFAIL;
        };
        // A term with the point at infinity on either side contributes 1.
        if let (Some(g1), Some(g2)) = (g1, g2) {
            terms.push((Into::<G1>::into(g1), Into::<G2>::into(g2)));
        }
    }
    verified.write(pairing_batch(&terms) == Gt::one());
    ZKVM_EOK
}

/// The base field modulus, big-endian.
pub(super) const P: [u8; 32] =
    super::hex_literal(b"30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47");

/// A field element: big-endian and below the modulus.
fn fq(bytes: &[u8]) -> Option<Fq> {
    if !super::below(bytes, &P) {
        return None;
    }
    Fq::from_slice(bytes).ok()
}

/// A G1 point on the curve, `Some(None)` for infinity; `None` if the encoding is invalid.
fn decode_g1(bytes: &[u8; 64]) -> Option<Option<AffineG1>> {
    if is_zero(bytes) {
        return Some(None);
    }
    AffineG1::new(fq(&bytes[..32])?, fq(&bytes[32..])?)
        .ok()
        .map(Some)
}

/// A G2 point on the curve and in the subgroup, `Some(None)` for infinity.
fn decode_g2(bytes: &[u8; 128]) -> Option<Option<AffineG2>> {
    if is_zero(bytes) {
        return Some(None);
    }
    let x = Fq2::new(fq(&bytes[32..64])?, fq(&bytes[..32])?);
    let y = Fq2::new(fq(&bytes[96..])?, fq(&bytes[64..96])?);
    AffineG2::new(x, y).ok().map(Some)
}

fn encode_g1(p: Option<AffineG1>) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    if let Some(p) = p {
        p.x().to_big_endian(&mut bytes[..32]).unwrap();
        p.y().to_big_endian(&mut bytes[32..]).unwrap();
    }
    bytes
}

/// `a + b`. The crate's affine addition reaches the syscalls and handles infinity and `a == b`,
/// but not `a == -b`.
fn add(a: Option<AffineG1>, b: Option<AffineG1>) -> Option<AffineG1> {
    match (a, b) {
        (None, p) | (p, None) => p,
        (Some(a), Some(b)) if a.x() == b.x() && a.y() != b.y() => None,
        (Some(a), Some(b)) => Some(a + b),
    }
}
