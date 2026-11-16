//! BLS12-381 (EIP-2537) through Pico's patched `bls12_381`, whose field arithmetic reaches the
//! field syscalls. Encoding as EIP-2537 without its 16 bytes of zero padding: 48-byte big-endian
//! field elements, `Fp2` as `c0 || c1`, all zeros for the point at infinity. Addition takes any
//! point on the curve; MSM and the pairing also require the subgroup.

use alloc::vec::Vec;

use bls12_381::{
    fp::Fp, fp2::Fp2, hash_to_curve::MapToCurve, multi_miller_loop, G1Affine, G1Projective,
    G2Affine, G2Prepared, G2Projective, Gt, Scalar,
};

use super::{
    arg, is_zero, items, out, Bls12G1MsmPair, Bls12G2MsmPair, Bls12PairingPair, ZkvmStatus,
    ZKVM_EFAIL, ZKVM_EOK,
};

/// `zkvm_status zkvm_bls12_g1_add(const zkvm_bls12_381_g1_point* p1, const
/// zkvm_bls12_381_g1_point* p2, zkvm_bls12_381_g1_point* result)`.
///
/// # Safety
///
/// Each pointer points to 96 bytes.
#[cfg_attr(target_os = "zkvm", no_mangle)]
pub unsafe extern "C" fn zkvm_bls12_g1_add(
    p1: *const [u8; 96],
    p2: *const [u8; 96],
    result: *mut [u8; 96],
) -> ZkvmStatus {
    const F: &str = "zkvm_bls12_g1_add";
    let (p1, p2) = (arg(p1, F, "p1"), arg(p2, F, "p2"));
    let result = out(result, F, "result");
    let (Some(a), Some(b)) = (decode_g1(&p1, false), decode_g1(&p2, false)) else {
        return ZKVM_EFAIL;
    };
    result.write(encode_g1(G1Projective::from(a) + G1Projective::from(b)));
    ZKVM_EOK
}

/// `zkvm_status zkvm_bls12_g1_msm(const zkvm_bls12_381_g1_msm_pair* pairs, size_t num_pairs,
/// zkvm_bls12_381_g1_point* result)`. Scalars are any 256-bit big-endian values; no pairs fail.
///
/// # Safety
///
/// `pairs` holds `num_pairs` pairs; `result` points to 96 bytes.
#[cfg_attr(target_os = "zkvm", no_mangle)]
pub unsafe extern "C" fn zkvm_bls12_g1_msm(
    pairs: *const Bls12G1MsmPair,
    num_pairs: usize,
    result: *mut [u8; 96],
) -> ZkvmStatus {
    const F: &str = "zkvm_bls12_g1_msm";
    let pairs = items(pairs, num_pairs, F, "pairs");
    let result = out(result, F, "result");
    if pairs.is_empty() {
        return ZKVM_EFAIL;
    }
    let mut points = Vec::with_capacity(pairs.len());
    let mut scalars = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let Some(p) = decode_g1(&pair.point, true) else {
            return ZKVM_EFAIL;
        };
        points.push(G1Projective::from(p));
        scalars.push(scalar(&pair.scalar));
    }
    result.write(encode_g1(G1Projective::msm_variable_base(
        &points, &scalars,
    )));
    ZKVM_EOK
}

/// `zkvm_status zkvm_bls12_g2_add(const zkvm_bls12_381_g2_point* p1, const
/// zkvm_bls12_381_g2_point* p2, zkvm_bls12_381_g2_point* result)`.
///
/// # Safety
///
/// Each pointer points to 192 bytes.
#[cfg_attr(target_os = "zkvm", no_mangle)]
pub unsafe extern "C" fn zkvm_bls12_g2_add(
    p1: *const [u8; 192],
    p2: *const [u8; 192],
    result: *mut [u8; 192],
) -> ZkvmStatus {
    const F: &str = "zkvm_bls12_g2_add";
    let (p1, p2) = (arg(p1, F, "p1"), arg(p2, F, "p2"));
    let result = out(result, F, "result");
    let (Some(a), Some(b)) = (decode_g2(&p1, false), decode_g2(&p2, false)) else {
        return ZKVM_EFAIL;
    };
    result.write(encode_g2(G2Projective::from(a) + G2Projective::from(b)));
    ZKVM_EOK
}

/// `zkvm_status zkvm_bls12_g2_msm(const zkvm_bls12_381_g2_msm_pair* pairs, size_t num_pairs,
/// zkvm_bls12_381_g2_point* result)`. As [`zkvm_bls12_g1_msm`], in G2.
///
/// # Safety
///
/// `pairs` holds `num_pairs` pairs; `result` points to 192 bytes.
#[cfg_attr(target_os = "zkvm", no_mangle)]
pub unsafe extern "C" fn zkvm_bls12_g2_msm(
    pairs: *const Bls12G2MsmPair,
    num_pairs: usize,
    result: *mut [u8; 192],
) -> ZkvmStatus {
    const F: &str = "zkvm_bls12_g2_msm";
    let pairs = items(pairs, num_pairs, F, "pairs");
    let result = out(result, F, "result");
    if pairs.is_empty() {
        return ZKVM_EFAIL;
    }
    let mut points = Vec::with_capacity(pairs.len());
    let mut scalars = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let Some(p) = decode_g2(&pair.point, true) else {
            return ZKVM_EFAIL;
        };
        points.push(p);
        scalars.push(scalar(&pair.scalar));
    }
    result.write(encode_g2(G2Projective::msm_variable_base(
        &points, &scalars,
    )));
    ZKVM_EOK
}

/// `zkvm_status zkvm_bls12_pairing(const zkvm_bls12_381_pairing_pair* pairs, size_t num_pairs,
/// bool* verified)`: whether the product of the pairings is 1. No pairs fail, as in EIP-2537.
///
/// # Safety
///
/// `pairs` holds `num_pairs` pairs; `verified` points to a `bool`.
#[cfg_attr(target_os = "zkvm", no_mangle)]
pub unsafe extern "C" fn zkvm_bls12_pairing(
    pairs: *const Bls12PairingPair,
    num_pairs: usize,
    verified: *mut bool,
) -> ZkvmStatus {
    const F: &str = "zkvm_bls12_pairing";
    let pairs = items(pairs, num_pairs, F, "pairs");
    let verified = out(verified, F, "verified");
    if pairs.is_empty() {
        return ZKVM_EFAIL;
    }
    let mut g1s = Vec::with_capacity(pairs.len());
    let mut g2s = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let (Some(g1), Some(g2)) = (decode_g1(&pair.g1, true), decode_g2(&pair.g2, true)) else {
            return ZKVM_EFAIL;
        };
        g1s.push(g1);
        g2s.push(G2Prepared::from(g2));
    }
    let terms: Vec<_> = g1s.iter().zip(&g2s).collect();
    verified.write(multi_miller_loop(&terms).final_exponentiation() == Gt::identity());
    ZKVM_EOK
}

/// `zkvm_status zkvm_bls12_map_fp_to_g1(const zkvm_bls12_381_fp* field_element,
/// zkvm_bls12_381_g1_point* result)`: the simplified SWU map, then cofactor clearing.
///
/// # Safety
///
/// `field_element` points to 48 bytes, `result` to 96.
#[cfg_attr(target_os = "zkvm", no_mangle)]
pub unsafe extern "C" fn zkvm_bls12_map_fp_to_g1(
    field_element: *const [u8; 48],
    result: *mut [u8; 96],
) -> ZkvmStatus {
    const F: &str = "zkvm_bls12_map_fp_to_g1";
    let field_element = arg(field_element, F, "field_element");
    let result = out(result, F, "result");
    let Some(u) = fp(&field_element) else {
        return ZKVM_EFAIL;
    };
    result.write(encode_g1(G1Projective::map_to_curve(&u).clear_cofactor()));
    ZKVM_EOK
}

/// `zkvm_status zkvm_bls12_map_fp2_to_g2(const zkvm_bls12_381_fp2* field_element,
/// zkvm_bls12_381_g2_point* result)`. As [`zkvm_bls12_map_fp_to_g1`], in G2.
///
/// # Safety
///
/// `field_element` points to 96 bytes, `result` to 192.
#[cfg_attr(target_os = "zkvm", no_mangle)]
pub unsafe extern "C" fn zkvm_bls12_map_fp2_to_g2(
    field_element: *const [u8; 96],
    result: *mut [u8; 192],
) -> ZkvmStatus {
    const F: &str = "zkvm_bls12_map_fp2_to_g2";
    let field_element = arg(field_element, F, "field_element");
    let result = out(result, F, "result");
    let Some(u) = fp2(&field_element) else {
        return ZKVM_EFAIL;
    };
    result.write(if bool::from(u.is_zero()) {
        MAP_FP2_TO_G2_ZERO
    } else {
        encode_g2(G2Projective::map_to_curve(&u).clear_cofactor())
    });
    ZKVM_EOK
}

/// The image of 0 under the G2 map. The crate's simplified SWU takes the second branch for
/// `u = 0`, where every candidate is 0, and lands on infinity; RFC 9380 has `u = 0` on the first.
/// The value is EIP-2537's, from execution-specs' `test_valid[fp_0]`.
pub(super) const MAP_FP2_TO_G2_ZERO: [u8; 192] = super::hex_literal(
    b"018320896ec9eef9d5e619848dc29ce266f413d02dd31d9b9d44ec0c79cd61f18b075ddba6d7bd20b7ff27a4b324bfce\
      0a67d12118b5a35bb02d2e86b3ebfa7e23410db93de39fb06d7025fa95e96ffa428a7a27c3ae4dd4b40bd251ac658892\
      0260e03644d1a2c321256b3246bad2b895cad13890cbe6f85df55106a0d334604fb143c7a042d878006271865bc35941\
      04c69777a43f0bda07679d5805e63f18cf4e0e7c6112ac7f70266d199b4f76ae27c6269a3ceebdae30806e9a76aadf5c",
);

/// The base field modulus, big-endian.
pub(super) const P: [u8; 48] = super::hex_literal(
    b"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
);

/// A field element: 48 bytes, big-endian, below the modulus.
fn fp(bytes: &[u8]) -> Option<Fp> {
    if !super::below(bytes, &P) {
        return None;
    }
    Fp::from_bytes(bytes.try_into().unwrap()).into()
}

/// `c0 || c1`.
fn fp2(bytes: &[u8]) -> Option<Fp2> {
    Some(Fp2 {
        c0: fp(&bytes[..48])?,
        c1: fp(&bytes[48..])?,
    })
}

/// A G1 point on the curve, and in the subgroup if `subgroup`.
pub(super) fn decode_g1(bytes: &[u8; 96], subgroup: bool) -> Option<G1Affine> {
    if is_zero(bytes) {
        return Some(G1Affine::identity());
    }
    // Checked as field elements first: the zcash encoding below would read a non-canonical
    // top byte as its flags.
    fp(&bytes[..48])?;
    fp(&bytes[48..])?;
    let p = Option::<G1Affine>::from(G1Affine::from_uncompressed_unchecked(bytes))?;
    // Only a point on the curve reaches the subgroup check: inside the zkVM that check runs on
    // the curve syscalls, which an off-curve point (y = 0, say) would make unprovable.
    let valid = bool::from(p.is_on_curve()) && (!subgroup || bool::from(p.is_torsion_free()));
    valid.then_some(p)
}

/// A G2 point on the curve, and in the subgroup if `subgroup`.
pub(super) fn decode_g2(bytes: &[u8; 192], subgroup: bool) -> Option<G2Affine> {
    if is_zero(bytes) {
        return Some(G2Affine::identity());
    }
    let (x, y) = (fp2(&bytes[..96])?, fp2(&bytes[96..])?);
    let p = Option::<G2Affine>::from(G2Affine::from_uncompressed_unchecked(&zcash_g2(x, y)))?;
    let valid = bool::from(p.is_on_curve()) && (!subgroup || bool::from(p.is_torsion_free()));
    valid.then_some(p)
}

/// The zcash uncompressed encoding: `x.c1 || x.c0 || y.c1 || y.c0`, flags clear.
fn zcash_g2(x: Fp2, y: Fp2) -> [u8; 192] {
    let mut bytes = [0u8; 192];
    for (chunk, f) in bytes
        .as_chunks_mut::<48>()
        .0
        .iter_mut()
        .zip([x.c1, x.c0, y.c1, y.c0])
    {
        chunk.copy_from_slice(&f.to_bytes());
    }
    bytes
}

fn encode_g1(p: G1Projective) -> [u8; 96] {
    let p = G1Affine::from(p);
    if bool::from(p.is_identity()) {
        return [0; 96];
    }
    // Without the infinity flag, zcash's uncompressed encoding is `x || y`.
    p.to_uncompressed()
}

fn encode_g2(p: G2Projective) -> [u8; 192] {
    let p = G2Affine::from(p);
    if bool::from(p.is_identity()) {
        return [0; 192];
    }
    // Swap zcash's `c1 || c0` for EIP-2537's `c0 || c1`.
    let z = p.to_uncompressed();
    let mut bytes = [0u8; 192];
    for (i, j) in [(0, 48), (48, 0), (96, 144), (144, 96)] {
        bytes[i..i + 48].copy_from_slice(&z[j..j + 48]);
    }
    bytes
}

/// A 256-bit big-endian scalar, reduced mod r: the points it multiplies are in the subgroup.
fn scalar(bytes: &[u8; 32]) -> Scalar {
    let mut wide = [0u8; 64];
    for (w, b) in wide.iter_mut().zip(bytes.iter().rev()) {
        *w = *b;
    }
    Scalar::from_bytes_wide(&wide)
}
