use crate::emulator::AotEmulatorCore;
use pico_vm::chips::gadgets::{
    curves::{
        curve25519_dalek::CompressedEdwardsY,
        edwards::{ed25519::decompress, EdwardsParameters, WORDS_FIELD_ELEMENT},
        weierstrass::{
            bls381::bls12381_decompress, secp256k1::secp256k1_decompress,
            secp256r1::secp256r1_decompress,
        },
        AffinePoint, CurveType, EllipticCurve, COMPRESSED_POINT_BYTES,
    },
    utils::{
        conversions::{bytes_to_words_le, words_to_bytes_le},
        field_params::{NumLimbs, NumWords},
    },
};
use typenum::Unsigned;

// k256 imports for optimized secp256k1 operations
use k256::{
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    AffinePoint as K256AffinePoint, ProjectivePoint as K256ProjectivePoint,
};

// p256 imports for optimized secp256r1 operations
use p256::{
    elliptic_curve::Group, AffinePoint as P256AffinePoint, EncodedPoint as P256EncodedPoint,
    ProjectivePoint as P256ProjectivePoint,
};

// halo2curves imports for optimized BN254 operations
use halo2curves::{
    bn256::{Fq as Bn256Fq, G1Affine as Bn256G1Affine, G1 as Bn256G1},
    group::Curve,
    CurveAffine,
};

// bls12_381 imports for optimized BLS12-381 operations
use bls12_381::{G1Affine as Bls12381G1Affine, G1Projective as Bls12381G1Projective};

/// Edwards curve add syscall implementation.
pub fn edwards_add<E: EllipticCurve + EdwardsParameters>(
    core: &mut AotEmulatorCore,
    p_ptr: u32,
    q_ptr: u32,
) {
    assert!(p_ptr.is_multiple_of(4), "p_ptr is unaligned");
    assert!(q_ptr.is_multiple_of(4), "q_ptr is unaligned");

    let clk = core.clk;
    let num_words = <E::BaseField as NumWords>::WordsCurvePoint::USIZE;

    // Stack-allocated buffers (max 32 words = 128 bytes for curve points)
    let mut p_buf = [0u32; 32];
    let mut q_buf = [0u32; 32];

    core.read_mem_span_snapshot(p_ptr, &mut p_buf[..num_words]);
    core.read_mem_span_at_clk(q_ptr, &mut q_buf[..num_words], clk);

    let p_affine = AffinePoint::<E>::from_words_le(&p_buf[..num_words]);
    let q_affine = AffinePoint::<E>::from_words_le(&q_buf[..num_words]);
    let result_affine = p_affine + q_affine;
    let result_words = result_affine.to_words_le();

    core.write_mem_slice_at_clk(p_ptr, &result_words, clk + 1);
}

/// Edwards curve decompress syscall implementation.
pub fn edwards_decompress<E: EdwardsParameters>(
    core: &mut AotEmulatorCore,
    slice_ptr: u32,
    sign: u32,
) {
    assert!(
        slice_ptr.is_multiple_of(4),
        "Pointer must be 4-byte aligned."
    );
    assert!(sign <= 1, "Sign bit must be 0 or 1.");

    let clk = core.clk;

    // Stack-allocated buffer for Y coordinate
    let mut y_buf = [0u32; WORDS_FIELD_ELEMENT];
    core.read_mem_span_at_clk(slice_ptr + (COMPRESSED_POINT_BYTES as u32), &mut y_buf, clk);

    let y_bytes: [u8; COMPRESSED_POINT_BYTES] = words_to_bytes_le(&y_buf);

    // Re-insert sign bit into last bit of Y for CompressedEdwardsY format
    let mut compressed_edwards_y: [u8; COMPRESSED_POINT_BYTES] = y_bytes;
    compressed_edwards_y[compressed_edwards_y.len() - 1] &= 0b0111_1111;
    compressed_edwards_y[compressed_edwards_y.len() - 1] |= (sign as u8) << 7;

    // Compute actual decompressed X
    let compressed_y = CompressedEdwardsY(compressed_edwards_y);
    let decompressed =
        decompress(&compressed_y).expect("Decompression failed, syscall invariant violated.");

    let mut decompressed_x_bytes = decompressed.x.to_bytes_le();
    decompressed_x_bytes.resize(32, 0u8);
    let decompressed_x_words: [u32; WORDS_FIELD_ELEMENT] = bytes_to_words_le(&decompressed_x_bytes);

    // Write decompressed X into slice (no clk increment needed here per original)
    core.write_mem_slice_at_clk(slice_ptr, &decompressed_x_words, clk);
}

/// Weierstrass curve add syscall implementation.
pub fn weierstrass_add<E: EllipticCurve>(core: &mut AotEmulatorCore, p_ptr: u32, q_ptr: u32) {
    assert!(p_ptr.is_multiple_of(4), "p_ptr is unaligned");
    assert!(q_ptr.is_multiple_of(4), "q_ptr is unaligned");

    let clk = core.clk;
    let num_words = <E::BaseField as NumWords>::WordsCurvePoint::USIZE;

    // Stack-allocated buffers (max 32 words = 128 bytes for curve points)
    let mut p_buf = [0u32; 32];
    let mut q_buf = [0u32; 32];

    core.read_mem_span_snapshot(p_ptr, &mut p_buf[..num_words]);
    core.read_mem_span_at_clk(q_ptr, &mut q_buf[..num_words], clk);

    let p_affine = AffinePoint::<E>::from_words_le(&p_buf[..num_words]);
    let q_affine = AffinePoint::<E>::from_words_le(&q_buf[..num_words]);
    let result_affine = p_affine + q_affine;
    let result_words = result_affine.to_words_le();

    core.write_mem_slice_at_clk(p_ptr, &result_words, clk + 1);
}

/// Weierstrass curve double syscall implementation.
pub fn weierstrass_double<E: EllipticCurve>(core: &mut AotEmulatorCore, p_ptr: u32) {
    assert!(p_ptr.is_multiple_of(4), "p_ptr is unaligned");

    let clk = core.clk;
    let num_words = <E::BaseField as NumWords>::WordsCurvePoint::USIZE;

    // Stack-allocated buffer (max 32 words = 128 bytes for curve point)
    let mut p_buf = [0u32; 32];
    core.read_mem_span_snapshot(p_ptr, &mut p_buf[..num_words]);

    let p_affine = AffinePoint::<E>::from_words_le(&p_buf[..num_words]);
    let result_affine = E::ec_double(&p_affine);
    let result_words = result_affine.to_words_le();

    // No clk increment needed per original
    core.write_mem_slice_at_clk(p_ptr, &result_words, clk);
}

/// Weierstrass curve decompress syscall implementation.
pub fn weierstrass_decompress<E: EllipticCurve>(
    core: &mut AotEmulatorCore,
    slice_ptr: u32,
    sign_bit: u32,
) {
    assert!(
        slice_ptr.is_multiple_of(4),
        "slice_ptr must be 4-byte aligned"
    );
    assert!(sign_bit <= 1, "is_odd must be 0 or 1");

    let clk = core.clk;
    let num_limbs = <E::BaseField as NumLimbs>::Limbs::USIZE;
    let num_words_field_element = num_limbs / 4;

    // Stack-allocated buffer for X coordinate (max 48 bytes for BLS12-381)
    let mut x_buf = [0u32; 12];
    core.read_mem_span_at_clk(
        slice_ptr + (num_limbs as u32),
        &mut x_buf[..num_words_field_element],
        clk,
    );

    // Convert to bytes using fixed-size arrays
    let mut x_bytes = [0u8; 48];
    for i in 0..num_words_field_element {
        let word_bytes = x_buf[i].to_le_bytes();
        x_bytes[i * 4..(i + 1) * 4].copy_from_slice(&word_bytes);
    }
    let x_bytes_slice = &x_bytes[..num_limbs];

    // Reverse for BE format
    let mut x_bytes_be = [0u8; 48];
    x_bytes_be[..num_limbs].copy_from_slice(x_bytes_slice);
    x_bytes_be[..num_limbs].reverse();

    let decompress_fn = match E::CURVE_TYPE {
        CurveType::Bls12381 => bls12381_decompress::<E>,
        CurveType::Secp256k1 => secp256k1_decompress::<E>,
        CurveType::Secp256r1 => secp256r1_decompress::<E>,
        _ => panic!("Unsupported curve: {}", E::CURVE_TYPE),
    };

    let computed_point: AffinePoint<E> = decompress_fn(&x_bytes_be[..num_limbs], sign_bit);

    let mut decompressed_y_bytes = computed_point.y.to_bytes_le();
    decompressed_y_bytes.resize(num_limbs, 0u8);

    // Convert bytes to words using fixed-size conversion
    let mut y_words = [0u32; 12];
    for i in 0..num_words_field_element {
        y_words[i] = u32::from_le_bytes([
            decompressed_y_bytes[i * 4],
            decompressed_y_bytes.get(i * 4 + 1).copied().unwrap_or(0),
            decompressed_y_bytes.get(i * 4 + 2).copied().unwrap_or(0),
            decompressed_y_bytes.get(i * 4 + 3).copied().unwrap_or(0),
        ]);
    }

    // No clk increment needed per original
    core.write_mem_slice_at_clk(slice_ptr, &y_words[..num_words_field_element], clk);
}

// ============================================================================
// k256-Optimized Secp256k1 Operations
// ============================================================================

/// Optimized secp256k1 point addition using k256 native operations.
/// This provides 10-50x speedup over generic BigUint arithmetic by leveraging:
/// - Montgomery form arithmetic
/// - Optimized modular inversion
/// - Constant-time operations
/// - Page-aware span memory operations
pub fn secp256k1_add_optimized(core: &mut AotEmulatorCore, p_ptr: u32, q_ptr: u32) {
    assert!(p_ptr.is_multiple_of(4), "p_ptr is unaligned");
    assert!(q_ptr.is_multiple_of(4), "q_ptr is unaligned");

    let clk = core.clk;
    const NUM_WORDS: usize = 16; // 2 coordinates * 8 words per coordinate

    // Read points from memory using span operations (stack-allocated arrays)
    let mut p_words = [0u32; NUM_WORDS];
    let mut q_words = [0u32; NUM_WORDS];

    // Read points using snapshot-only span operations
    core.read_mem_span_snapshot(p_ptr, &mut p_words);
    core.read_mem_span_at_clk(q_ptr, &mut q_words, clk);

    // Convert to k256 format
    let p_k256 = words_to_k256_affine(&p_words);
    let q_k256 = words_to_k256_affine(&q_words);

    // Perform addition using k256's optimized implementation
    let result_k256 =
        (K256ProjectivePoint::from(p_k256) + K256ProjectivePoint::from(q_k256)).to_affine();

    // Convert back to words
    let result_words = k256_affine_to_words(&result_k256);

    // Write result back using span operation
    core.write_mem_span_at_clk(p_ptr, &result_words, clk + 1);
}

/// Optimized secp256k1 point doubling using k256 native operations with span memory.
pub fn secp256k1_double_optimized(core: &mut AotEmulatorCore, p_ptr: u32) {
    assert!(p_ptr.is_multiple_of(4), "p_ptr is unaligned");

    let clk = core.clk;
    const NUM_WORDS: usize = 16;

    // Read point from memory using span operation
    let mut p_words = [0u32; NUM_WORDS];
    core.read_mem_span_snapshot(p_ptr, &mut p_words);

    // Convert to k256 format
    let p_k256 = words_to_k256_affine(&p_words);

    // Perform doubling using k256's optimized implementation
    let result_k256 = (K256ProjectivePoint::from(p_k256).double()).to_affine();

    // Convert back to words
    let result_words = k256_affine_to_words(&result_k256);

    // Write result back using span operation
    core.write_mem_span_at_clk(p_ptr, &result_words, clk);
}

/// Convert 16 u32 words (x, y coordinates) to k256::AffinePoint.
/// Memory layout: [x0..x7, y0..y7] where each coordinate is 8 u32 words (32 bytes) in LE.
#[inline(always)]
fn words_to_k256_affine(words: &[u32]) -> K256AffinePoint {
    assert!(words.len() >= 16, "Need 16 words for secp256k1 point");

    // Extract x and y coordinates (each 32 bytes = 8 words)
    let mut x_bytes = [0u8; 32];
    let mut y_bytes = [0u8; 32];

    for i in 0..8 {
        let x_word = words[i];
        let y_word = words[i + 8];
        x_bytes[i * 4..(i + 1) * 4].copy_from_slice(&x_word.to_le_bytes());
        y_bytes[i * 4..(i + 1) * 4].copy_from_slice(&y_word.to_le_bytes());
    }

    // k256 uses big-endian for field elements, so we need to reverse
    x_bytes.reverse();
    y_bytes.reverse();

    // Create encoded point (uncompressed format: 0x04 || x || y)
    let mut encoded = [0u8; 65];
    encoded[0] = 0x04; // Uncompressed point tag
    encoded[1..33].copy_from_slice(&x_bytes);
    encoded[33..65].copy_from_slice(&y_bytes);

    K256AffinePoint::from_encoded_point(
        &k256::EncodedPoint::from_bytes(encoded).expect("Invalid point encoding"),
    )
    .expect("Invalid secp256k1 point")
}

/// Convert k256::AffinePoint to 16 u32 words (x, y coordinates in LE).
#[inline(always)]
fn k256_affine_to_words(point: &K256AffinePoint) -> [u32; 16] {
    let encoded = point.to_encoded_point(false); // Uncompressed format
    let x_bytes = encoded.x().expect("Point has no x coordinate");
    let y_bytes = encoded.y().expect("Point has no y coordinate");

    let mut result = [0u32; 16];

    // Convert x coordinate (BE to LE words)
    for (i, slot) in result.iter_mut().enumerate().take(8) {
        let be_idx = 28 - i * 4; // Read from end in groups of 4
        let word = u32::from_be_bytes([
            x_bytes[be_idx],
            x_bytes[be_idx + 1],
            x_bytes[be_idx + 2],
            x_bytes[be_idx + 3],
        ]);
        *slot = word;
    }

    // Convert y coordinate (BE to LE words)
    for i in 0..8 {
        let be_idx = 28 - i * 4;
        let word = u32::from_be_bytes([
            y_bytes[be_idx],
            y_bytes[be_idx + 1],
            y_bytes[be_idx + 2],
            y_bytes[be_idx + 3],
        ]);
        result[i + 8] = word;
    }

    result
}

// ============================================================================
// p256-Optimized Secp256r1 Operations
// ============================================================================

/// Optimized secp256r1 point addition using p256 native operations.
pub fn secp256r1_add_optimized(core: &mut AotEmulatorCore, p_ptr: u32, q_ptr: u32) {
    assert!(p_ptr.is_multiple_of(4), "p_ptr is unaligned");
    assert!(q_ptr.is_multiple_of(4), "q_ptr is unaligned");

    let clk = core.clk;
    const NUM_WORDS: usize = 16; // 2 coordinates * 8 words per coordinate

    let mut p_words = [0u32; NUM_WORDS];
    let mut q_words = [0u32; NUM_WORDS];

    core.read_mem_span_snapshot(p_ptr, &mut p_words);
    core.read_mem_span_at_clk(q_ptr, &mut q_words, clk);

    let p_p256 = words_to_p256_affine(&p_words);
    let q_p256 = words_to_p256_affine(&q_words);

    let result_p256 =
        (P256ProjectivePoint::from(p_p256) + P256ProjectivePoint::from(q_p256)).to_affine();
    let result_words = p256_affine_to_words(&result_p256);

    core.write_mem_span_at_clk(p_ptr, &result_words, clk + 1);
}

/// Optimized secp256r1 point doubling using p256 native operations.
pub fn secp256r1_double_optimized(core: &mut AotEmulatorCore, p_ptr: u32) {
    assert!(p_ptr.is_multiple_of(4), "p_ptr is unaligned");

    let clk = core.clk;
    const NUM_WORDS: usize = 16;

    let mut p_words = [0u32; NUM_WORDS];
    core.read_mem_span_snapshot(p_ptr, &mut p_words);

    let p_p256 = words_to_p256_affine(&p_words);
    let result_p256 = (P256ProjectivePoint::from(p_p256).double()).to_affine();
    let result_words = p256_affine_to_words(&result_p256);

    core.write_mem_span_at_clk(p_ptr, &result_words, clk);
}

/// Convert 16 u32 words (x, y coordinates) to p256::AffinePoint.
/// Memory layout: [x0..x7, y0..y7] where each coordinate is 8 u32 words (32 bytes) in LE.
#[inline(always)]
fn words_to_p256_affine(words: &[u32]) -> P256AffinePoint {
    assert!(words.len() >= 16, "Need 16 words for secp256r1 point");

    let mut x_bytes = [0u8; 32];
    let mut y_bytes = [0u8; 32];

    for i in 0..8 {
        let x_word = words[i];
        let y_word = words[i + 8];
        x_bytes[i * 4..(i + 1) * 4].copy_from_slice(&x_word.to_le_bytes());
        y_bytes[i * 4..(i + 1) * 4].copy_from_slice(&y_word.to_le_bytes());
    }

    x_bytes.reverse();
    y_bytes.reverse();

    let mut encoded = [0u8; 65];
    encoded[0] = 0x04;
    encoded[1..33].copy_from_slice(&x_bytes);
    encoded[33..65].copy_from_slice(&y_bytes);

    P256AffinePoint::from_encoded_point(
        &P256EncodedPoint::from_bytes(encoded).expect("Invalid point encoding"),
    )
    .expect("Invalid secp256r1 point")
}

/// Convert p256::AffinePoint to 16 u32 words (x, y coordinates in LE).
#[inline(always)]
fn p256_affine_to_words(point: &P256AffinePoint) -> [u32; 16] {
    let encoded = point.to_encoded_point(false);
    let x_bytes = encoded.x().expect("Point has no x coordinate");
    let y_bytes = encoded.y().expect("Point has no y coordinate");

    let mut result = [0u32; 16];

    for (i, slot) in result.iter_mut().enumerate().take(8) {
        let be_idx = 28 - i * 4;
        let word = u32::from_be_bytes([
            x_bytes[be_idx],
            x_bytes[be_idx + 1],
            x_bytes[be_idx + 2],
            x_bytes[be_idx + 3],
        ]);
        *slot = word;
    }

    for i in 0..8 {
        let be_idx = 28 - i * 4;
        let word = u32::from_be_bytes([
            y_bytes[be_idx],
            y_bytes[be_idx + 1],
            y_bytes[be_idx + 2],
            y_bytes[be_idx + 3],
        ]);
        result[i + 8] = word;
    }

    result
}

// ============================================================================
// halo2curves-Optimized BN254 Operations
// ============================================================================

/// Optimized BN254 point addition using halo2curves native operations.
/// This provides 10-30x speedup over generic BigUint arithmetic by leveraging:
/// - Montgomery form arithmetic
/// - Optimized field towers
/// - Assembly-optimized operations
/// - Page-aware span memory operations
pub fn bn254_add_optimized(core: &mut AotEmulatorCore, p_ptr: u32, q_ptr: u32) {
    assert!(p_ptr.is_multiple_of(4), "p_ptr is unaligned");
    assert!(q_ptr.is_multiple_of(4), "q_ptr is unaligned");

    let clk = core.clk;
    const NUM_WORDS: usize = 16; // 2 coordinates * 8 words per coordinate (256-bit each)

    // Read points from memory using span operations (stack-allocated arrays)
    let mut p_words = [0u32; NUM_WORDS];
    let mut q_words = [0u32; NUM_WORDS];

    // Read points using snapshot-only span operations
    core.read_mem_span_snapshot(p_ptr, &mut p_words);
    core.read_mem_span_at_clk(q_ptr, &mut q_words, clk);

    // Convert to halo2curves BN254 format
    let p_bn254 = words_to_bn254_affine(&p_words);
    let q_bn254 = words_to_bn254_affine(&q_words);

    // Perform addition using halo2curves' optimized implementation
    let result_bn254 = (Bn256G1::from(p_bn254) + Bn256G1::from(q_bn254)).to_affine();

    // Convert back to words
    let result_words = bn254_affine_to_words(&result_bn254);

    // Write result back using span operation
    core.write_mem_span_at_clk(p_ptr, &result_words, clk + 1);
}

/// Optimized BN254 point doubling using halo2curves native operations with span memory.
pub fn bn254_double_optimized(core: &mut AotEmulatorCore, p_ptr: u32) {
    assert!(p_ptr.is_multiple_of(4), "p_ptr is unaligned");

    let clk = core.clk;
    const NUM_WORDS: usize = 16;

    // Read point from memory using snapshot-only span operation
    let mut p_words = [0u32; NUM_WORDS];
    core.read_mem_span_snapshot(p_ptr, &mut p_words);

    // Convert to halo2curves BN254 format
    let p_bn254 = words_to_bn254_affine(&p_words);

    // Perform doubling using halo2curves' optimized implementation
    let result_bn254 = (Bn256G1::from(p_bn254) + Bn256G1::from(p_bn254)).to_affine();

    // Convert back to words
    let result_words = bn254_affine_to_words(&result_bn254);

    // Write result back using span operation
    core.write_mem_span_at_clk(p_ptr, &result_words, clk);
}

/// Convert 16 u32 words (x, y coordinates) to halo2curves BN254 G1Affine.
/// Memory layout: [x0..x7, y0..y7] where each coordinate is 8 u32 words (32 bytes) in LE.
#[inline(always)]
fn words_to_bn254_affine(words: &[u32]) -> Bn256G1Affine {
    assert!(words.len() >= 16, "Need 16 words for BN254 point");

    // Extract x and y coordinates (each 32 bytes = 8 words in LE)
    let mut x_bytes = [0u8; 32];
    let mut y_bytes = [0u8; 32];

    for i in 0..8 {
        let x_word = words[i];
        let y_word = words[i + 8];
        x_bytes[i * 4..(i + 1) * 4].copy_from_slice(&x_word.to_le_bytes());
        y_bytes[i * 4..(i + 1) * 4].copy_from_slice(&y_word.to_le_bytes());
    }

    // Convert to halo2curves field elements
    let x_fq = Bn256Fq::from_bytes(&x_bytes).expect("Invalid field element");
    let y_fq = Bn256Fq::from_bytes(&y_bytes).expect("Invalid field element");

    Bn256G1Affine::from_xy(x_fq, y_fq).unwrap()
}

/// Convert halo2curves BN254 G1Affine to 16 u32 words (x, y coordinates in LE).
#[inline(always)]
fn bn254_affine_to_words(point: &Bn256G1Affine) -> [u32; 16] {
    let x_bytes = point.x.to_bytes();
    let y_bytes = point.y.to_bytes();

    let mut result = [0u32; 16];

    // Convert x coordinate to LE words
    for (i, slot) in result.iter_mut().enumerate().take(8) {
        let start = i * 4;
        *slot = u32::from_le_bytes([
            x_bytes[start],
            x_bytes[start + 1],
            x_bytes[start + 2],
            x_bytes[start + 3],
        ]);
    }

    // Convert y coordinate to LE words
    for i in 0..8 {
        let start = i * 4;
        result[i + 8] = u32::from_le_bytes([
            y_bytes[start],
            y_bytes[start + 1],
            y_bytes[start + 2],
            y_bytes[start + 3],
        ]);
    }

    result
}

// ============================================================================
// bls12_381-Optimized BLS12-381 Operations
// ============================================================================

/// Optimized BLS12-381 point addition using bls12_381 native operations.
/// This provides 10-30x speedup over generic BigUint arithmetic by leveraging:
/// - Montgomery form arithmetic
/// - Optimized field towers (Fp, Fp2, Fp12)
/// - Assembly-optimized operations
/// - Page-aware span memory operations
pub fn bls12381_add_optimized(core: &mut AotEmulatorCore, p_ptr: u32, q_ptr: u32) {
    assert!(p_ptr.is_multiple_of(4), "p_ptr is unaligned");
    assert!(q_ptr.is_multiple_of(4), "q_ptr is unaligned");

    let clk = core.clk;
    const NUM_WORDS: usize = 24; // 2 coordinates * 12 words per coordinate (384-bit each)

    // Read points from memory using span operations (stack-allocated arrays)
    let mut p_words = [0u32; NUM_WORDS];
    let mut q_words = [0u32; NUM_WORDS];

    // Read points using snapshot-only span operations
    core.read_mem_span_snapshot(p_ptr, &mut p_words);
    core.read_mem_span_at_clk(q_ptr, &mut q_words, clk);

    // Convert to bls12_381 format
    let p_bls = words_to_bls12381_affine(&p_words);
    let q_bls = words_to_bls12381_affine(&q_words);

    // Perform addition using bls12_381's optimized implementation
    let result_bls = Bls12381G1Affine::from(
        Bls12381G1Projective::from(p_bls) + Bls12381G1Projective::from(q_bls),
    );

    // Convert back to words
    let result_words = bls12381_affine_to_words(&result_bls);

    // Write result back using span operation
    core.write_mem_span_at_clk(p_ptr, &result_words, clk + 1);
}

/// Optimized BLS12-381 point doubling using bls12_381 native operations with span memory.
pub fn bls12381_double_optimized(core: &mut AotEmulatorCore, p_ptr: u32) {
    assert!(p_ptr.is_multiple_of(4), "p_ptr is unaligned");

    let clk = core.clk;
    const NUM_WORDS: usize = 24;

    // Read point from memory using snapshot-only span operation
    let mut p_words = [0u32; NUM_WORDS];
    core.read_mem_span_snapshot(p_ptr, &mut p_words);

    // Convert to bls12_381 format
    let p_bls = words_to_bls12381_affine(&p_words);

    // Perform doubling using bls12_381's optimized implementation
    let result_bls = Bls12381G1Affine::from(Bls12381G1Projective::from(p_bls).double());

    // Convert back to words
    let result_words = bls12381_affine_to_words(&result_bls);

    // Write result back using span operation
    core.write_mem_span_at_clk(p_ptr, &result_words, clk);
}

/// Convert 24 u32 words (x, y coordinates) to bls12_381 G1Affine.
/// Memory layout: [x0..x11, y0..y11] where each coordinate is 12 u32 words (48 bytes) in LE.
#[inline(always)]
fn words_to_bls12381_affine(words: &[u32]) -> Bls12381G1Affine {
    assert!(words.len() >= 24, "Need 24 words for BLS12-381 point");

    // Extract x and y coordinates (each 48 bytes = 12 words in LE)
    let mut uncompressed = [0u8; 96];

    // Copy x coordinate (first 48 bytes)
    for i in 0..12 {
        let word = words[i];
        uncompressed[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }

    // Copy y coordinate (next 48 bytes)
    for i in 0..12 {
        let word = words[i + 12];
        uncompressed[48 + i * 4..48 + (i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }

    // bls12_381 expects big-endian, so reverse each coordinate
    uncompressed[..48].reverse();
    uncompressed[48..].reverse();

    Bls12381G1Affine::from_uncompressed(&uncompressed).unwrap()
}

/// Convert bls12_381 G1Affine to 24 u32 words (x, y coordinates in LE).
#[inline(always)]
fn bls12381_affine_to_words(point: &Bls12381G1Affine) -> [u32; 24] {
    let mut uncompressed = point.to_uncompressed();

    // bls12_381 returns big-endian, convert to little-endian
    uncompressed[..48].reverse();
    uncompressed[48..].reverse();

    let mut result = [0u32; 24];

    // Convert x coordinate (first 48 bytes) to LE words
    for (i, slot) in result.iter_mut().enumerate().take(12) {
        let start = i * 4;
        *slot = u32::from_le_bytes([
            uncompressed[start],
            uncompressed[start + 1],
            uncompressed[start + 2],
            uncompressed[start + 3],
        ]);
    }

    // Convert y coordinate (next 48 bytes) to LE words
    for i in 0..12 {
        let start = 48 + i * 4;
        result[i + 12] = u32::from_le_bytes([
            uncompressed[start],
            uncompressed[start + 1],
            uncompressed[start + 2],
            uncompressed[start + 3],
        ]);
    }

    result
}
