use crate::emulator::AotEmulatorCore;
use ark_bls12_381::{Fq as Bls381Fq, Fq2 as Bls381Fq2};
use ark_bn254::{Fq as Bn254Fq, Fq2 as Bn254Fq2};
use ark_ff::{BigInt, PrimeField};
use ark_secp256k1::Fq as Secp256k1Fq;
use hybrid_array::typenum::Unsigned;
use pico_vm::chips::gadgets::{
    field::field_op::FieldOperation,
    utils::field_params::{FpOpField, NumWords},
};

/// Field operation (Fp) syscall implementation with span memory operations.
#[inline(always)]
pub fn fp_op<P: FpOpField>(core: &mut AotEmulatorCore, op: FieldOperation, x_ptr: u64, y_ptr: u64) {
    assert!(x_ptr.is_multiple_of(4), "x_ptr is unaligned");
    assert!(y_ptr.is_multiple_of(4), "y_ptr is unaligned");

    use pico_vm::chips::gadgets::utils::field_params::FieldType;

    let clk = core.clk;
    let num_words = <P as NumWords>::WordsFieldElement::USIZE;

    // Dispatch based on field type to use appropriate limb size
    match P::FIELD_TYPE {
        FieldType::Secp256k1 => fp_op_secp256k1(core, op, x_ptr, y_ptr, clk, num_words),
        FieldType::Bn254 => fp_op_bn254(core, op, x_ptr, y_ptr, clk, num_words),
        FieldType::Bls381 => fp_op_bls381(core, op, x_ptr, y_ptr, clk, num_words),
    }
}

fn fp_op_secp256k1(
    core: &mut AotEmulatorCore,
    op: FieldOperation,
    x_ptr: u64,
    y_ptr: u64,
    clk: u32,
    num_words: usize,
) {
    let mut x_buf = [0u32; 8];
    let mut y_buf = [0u32; 8];

    core.read_mem_word_span_snapshot(x_ptr, &mut x_buf[..num_words * 2]);
    core.read_mem_word_span_at_clk(y_ptr, &mut y_buf[..num_words * 2], clk);

    let a_bytes = words_to_bytes_32(&x_buf);
    let b_bytes = words_to_bytes_32(&y_buf);
    let a = Secp256k1Fq::from_le_bytes_mod_order(&a_bytes);
    let b = Secp256k1Fq::from_le_bytes_mod_order(&b_bytes);

    let result = match op {
        FieldOperation::Add => a + b,
        FieldOperation::Sub => a - b,
        FieldOperation::Mul => a * b,
        _ => panic!("Unsupported operation"),
    };

    let result_words = fq_to_words_32(result);
    core.write_mem_word_span_at_clk(x_ptr, &result_words[..num_words * 2], clk + 1);
}

fn fp_op_bn254(
    core: &mut AotEmulatorCore,
    op: FieldOperation,
    x_ptr: u64,
    y_ptr: u64,
    clk: u32,
    num_words: usize,
) {
    assert!(x_ptr.is_multiple_of(8), "x_ptr is unaligned");
    assert!(y_ptr.is_multiple_of(8), "y_ptr is unaligned");
    let num_dwords = num_words;
    let mut x_buf = [0u64; 4];
    let mut y_buf = [0u64; 4];

    core.read_mem_dword_span_snapshot(x_ptr, &mut x_buf[..num_dwords]);
    core.read_mem_dword_span_at_clk(y_ptr, &mut y_buf[..num_dwords], clk);

    let a_bytes = dwords_to_bytes(&x_buf[..num_dwords]);
    let b_bytes = dwords_to_bytes(&y_buf[..num_dwords]);
    let a = Bn254Fq::from_le_bytes_mod_order(&a_bytes);
    let b = Bn254Fq::from_le_bytes_mod_order(&b_bytes);

    let result = match op {
        FieldOperation::Add => a + b,
        FieldOperation::Sub => a - b,
        FieldOperation::Mul => a * b,
        _ => panic!("Unsupported operation"),
    };

    let result_words = fq_to_words_32(result);
    let result_dwords = pack_words_to_packed_dwords(&result_words[..num_words * 2]);
    core.write_mem_dword_span_at_clk(x_ptr, &result_dwords, clk + 1);
}

fn fp_op_bls381(
    core: &mut AotEmulatorCore,
    op: FieldOperation,
    x_ptr: u64,
    y_ptr: u64,
    clk: u32,
    num_words: usize,
) {
    assert!(x_ptr.is_multiple_of(8), "x_ptr is unaligned");
    assert!(y_ptr.is_multiple_of(8), "y_ptr is unaligned");
    let num_dwords = num_words;
    let mut x_buf = [0u64; 6];
    let mut y_buf = [0u64; 6];

    core.read_mem_dword_span_snapshot(x_ptr, &mut x_buf[..num_dwords]);
    core.read_mem_dword_span_at_clk(y_ptr, &mut y_buf[..num_dwords], clk);

    let a_bytes = dwords_to_bytes(&x_buf[..num_dwords]);
    let b_bytes = dwords_to_bytes(&y_buf[..num_dwords]);
    let a = Bls381Fq::from_le_bytes_mod_order(&a_bytes);
    let b = Bls381Fq::from_le_bytes_mod_order(&b_bytes);

    let result = match op {
        FieldOperation::Add => a + b,
        FieldOperation::Sub => a - b,
        FieldOperation::Mul => a * b,
        _ => panic!("Unsupported operation"),
    };

    let result_words = fq_to_words_48(result);
    let result_dwords = pack_words_to_packed_dwords(&result_words[..num_words * 2]);
    core.write_mem_dword_span_at_clk(x_ptr, &result_dwords, clk + 1);
}

/// Field operation (Fp2 Add/Sub) syscall implementation with span operations.
#[inline(always)]
pub fn fp2_addsub<P: FpOpField>(
    core: &mut AotEmulatorCore,
    op: FieldOperation,
    x_ptr: u64,
    y_ptr: u64,
) {
    assert!(x_ptr.is_multiple_of(4), "x_ptr is unaligned");
    assert!(y_ptr.is_multiple_of(4), "y_ptr is unaligned");

    use pico_vm::chips::gadgets::utils::field_params::FieldType;

    let clk = core.clk;
    let num_words = <P as NumWords>::WordsCurvePoint::USIZE;

    // Dispatch based on field type
    match P::FIELD_TYPE {
        FieldType::Secp256k1 => fp2_addsub_secp256k1(core, op, x_ptr, y_ptr, clk, num_words),
        FieldType::Bn254 => fp2_addsub_bn254(core, op, x_ptr, y_ptr, clk, num_words),
        FieldType::Bls381 => fp2_addsub_bls381(core, op, x_ptr, y_ptr, clk, num_words),
    }
}

fn fp2_addsub_secp256k1(
    _core: &mut AotEmulatorCore,
    _op: FieldOperation,
    _x_ptr: u64,
    _y_ptr: u64,
    _clk: u32,
    _num_words: usize,
) {
    panic!("secp256k1 does not use Fp2");
}

fn fp2_addsub_bn254(
    core: &mut AotEmulatorCore,
    op: FieldOperation,
    x_ptr: u64,
    y_ptr: u64,
    clk: u32,
    num_words: usize,
) {
    assert!(x_ptr.is_multiple_of(8), "x_ptr is unaligned");
    assert!(y_ptr.is_multiple_of(8), "y_ptr is unaligned");
    let num_dwords = num_words;
    let mut x_buf = [0u64; 8];
    let mut y_buf = [0u64; 8];

    core.read_mem_dword_span_snapshot(x_ptr, &mut x_buf[..num_dwords]);
    core.read_mem_dword_span_at_clk(y_ptr, &mut y_buf[..num_dwords], clk);

    let half = num_dwords / 2;
    let ac0 = Bn254Fq::from_le_bytes_mod_order(&dwords_to_bytes(&x_buf[..half]));
    let ac1 = Bn254Fq::from_le_bytes_mod_order(&dwords_to_bytes(&x_buf[half..num_dwords]));
    let bc0 = Bn254Fq::from_le_bytes_mod_order(&dwords_to_bytes(&y_buf[..half]));
    let bc1 = Bn254Fq::from_le_bytes_mod_order(&dwords_to_bytes(&y_buf[half..num_dwords]));

    let a = Bn254Fq2::new(ac0, ac1);
    let b = Bn254Fq2::new(bc0, bc1);

    let result = match op {
        FieldOperation::Add => a + b,
        FieldOperation::Sub => a - b,
        _ => panic!("Invalid operation"),
    };

    let c0_words = fq_to_words_32(result.c0);
    let c1_words = fq_to_words_32(result.c1);
    let mut result_buf = [0u64; 8];
    result_buf[..half].copy_from_slice(&pack_words_to_packed_dwords(&c0_words[..half * 2]));
    result_buf[half..num_dwords]
        .copy_from_slice(&pack_words_to_packed_dwords(&c1_words[..half * 2]));

    core.write_mem_dword_span_at_clk(x_ptr, &result_buf[..num_dwords], clk + 1);
}

/// Field operation (Fp2 Mul) syscall implementation with span operations.
#[inline(always)]
pub fn fp2_mul<P: FpOpField>(core: &mut AotEmulatorCore, x_ptr: u64, y_ptr: u64) {
    assert!(x_ptr.is_multiple_of(4), "x_ptr is unaligned");
    assert!(y_ptr.is_multiple_of(4), "y_ptr is unaligned");

    use pico_vm::chips::gadgets::utils::field_params::FieldType;

    let clk = core.clk;
    let num_words = <P as NumWords>::WordsCurvePoint::USIZE;

    // Dispatch based on field type
    match P::FIELD_TYPE {
        FieldType::Secp256k1 => fp2_mul_secp256k1(core, x_ptr, y_ptr, clk, num_words),
        FieldType::Bn254 => fp2_mul_bn254(core, x_ptr, y_ptr, clk, num_words),
        FieldType::Bls381 => fp2_mul_bls381(core, x_ptr, y_ptr, clk, num_words),
    }
}

fn fp2_mul_secp256k1(
    _core: &mut AotEmulatorCore,
    _x_ptr: u64,
    _y_ptr: u64,
    _clk: u32,
    _num_words: usize,
) {
    panic!("secp256k1 does not use Fp2");
}

fn fp2_mul_bn254(core: &mut AotEmulatorCore, x_ptr: u64, y_ptr: u64, clk: u32, num_words: usize) {
    assert!(x_ptr.is_multiple_of(8), "x_ptr is unaligned");
    assert!(y_ptr.is_multiple_of(8), "y_ptr is unaligned");
    let num_dwords = num_words;
    let mut x_buf = [0u64; 8];
    let mut y_buf = [0u64; 8];

    core.read_mem_dword_span_snapshot(x_ptr, &mut x_buf[..num_dwords]);
    core.read_mem_dword_span_at_clk(y_ptr, &mut y_buf[..num_dwords], clk);

    let half = num_dwords / 2;
    let ac0 = Bn254Fq::from_le_bytes_mod_order(&dwords_to_bytes(&x_buf[..half]));
    let ac1 = Bn254Fq::from_le_bytes_mod_order(&dwords_to_bytes(&x_buf[half..num_dwords]));
    let bc0 = Bn254Fq::from_le_bytes_mod_order(&dwords_to_bytes(&y_buf[..half]));
    let bc1 = Bn254Fq::from_le_bytes_mod_order(&dwords_to_bytes(&y_buf[half..num_dwords]));

    let a = Bn254Fq2::new(ac0, ac1);
    let b = Bn254Fq2::new(bc0, bc1);
    let result = a * b;

    let c0_words = fq_to_words_32(result.c0);
    let c1_words = fq_to_words_32(result.c1);
    let mut result_buf = [0u64; 8];
    result_buf[..half].copy_from_slice(&pack_words_to_packed_dwords(&c0_words[..half * 2]));
    result_buf[half..num_dwords]
        .copy_from_slice(&pack_words_to_packed_dwords(&c1_words[..half * 2]));

    core.write_mem_dword_span_at_clk(x_ptr, &result_buf[..num_dwords], clk + 1);
}

fn fp2_addsub_bls381(
    core: &mut AotEmulatorCore,
    op: FieldOperation,
    x_ptr: u64,
    y_ptr: u64,
    clk: u32,
    num_words: usize,
) {
    assert!(x_ptr.is_multiple_of(8), "x_ptr is unaligned");
    assert!(y_ptr.is_multiple_of(8), "y_ptr is unaligned");
    let num_dwords = num_words;
    let mut x_buf = [0u64; 12];
    let mut y_buf = [0u64; 12];

    core.read_mem_dword_span_snapshot(x_ptr, &mut x_buf[..num_dwords]);
    core.read_mem_dword_span_at_clk(y_ptr, &mut y_buf[..num_dwords], clk);

    let half = num_dwords / 2;
    let ac0 = Bls381Fq::from_le_bytes_mod_order(&dwords_to_bytes(&x_buf[..half]));
    let ac1 = Bls381Fq::from_le_bytes_mod_order(&dwords_to_bytes(&x_buf[half..num_dwords]));
    let bc0 = Bls381Fq::from_le_bytes_mod_order(&dwords_to_bytes(&y_buf[..half]));
    let bc1 = Bls381Fq::from_le_bytes_mod_order(&dwords_to_bytes(&y_buf[half..num_dwords]));

    let a = Bls381Fq2::new(ac0, ac1);
    let b = Bls381Fq2::new(bc0, bc1);
    let result = match op {
        FieldOperation::Add => a + b,
        FieldOperation::Sub => a - b,
        _ => panic!("Invalid operation"),
    };

    let c0_words = fq_to_words_48(result.c0);
    let c1_words = fq_to_words_48(result.c1);
    let mut result_buf = [0u64; 12];
    result_buf[..half].copy_from_slice(&pack_words_to_packed_dwords(&c0_words[..half * 2]));
    result_buf[half..num_dwords]
        .copy_from_slice(&pack_words_to_packed_dwords(&c1_words[..half * 2]));

    core.write_mem_dword_span_at_clk(x_ptr, &result_buf[..num_dwords], clk + 1);
}

fn fp2_mul_bls381(core: &mut AotEmulatorCore, x_ptr: u64, y_ptr: u64, clk: u32, num_words: usize) {
    assert!(x_ptr.is_multiple_of(8), "x_ptr is unaligned");
    assert!(y_ptr.is_multiple_of(8), "y_ptr is unaligned");
    let num_dwords = num_words;
    let mut x_buf = [0u64; 12];
    let mut y_buf = [0u64; 12];

    core.read_mem_dword_span_snapshot(x_ptr, &mut x_buf[..num_dwords]);
    core.read_mem_dword_span_at_clk(y_ptr, &mut y_buf[..num_dwords], clk);

    let half = num_dwords / 2;
    let ac0 = Bls381Fq::from_le_bytes_mod_order(&dwords_to_bytes(&x_buf[..half]));
    let ac1 = Bls381Fq::from_le_bytes_mod_order(&dwords_to_bytes(&x_buf[half..num_dwords]));
    let bc0 = Bls381Fq::from_le_bytes_mod_order(&dwords_to_bytes(&y_buf[..half]));
    let bc1 = Bls381Fq::from_le_bytes_mod_order(&dwords_to_bytes(&y_buf[half..num_dwords]));

    let a = Bls381Fq2::new(ac0, ac1);
    let b = Bls381Fq2::new(bc0, bc1);
    let result = a * b;

    let c0_words = fq_to_words_48(result.c0);
    let c1_words = fq_to_words_48(result.c1);
    let mut result_buf = [0u64; 12];
    result_buf[..half].copy_from_slice(&pack_words_to_packed_dwords(&c0_words[..half * 2]));
    result_buf[half..num_dwords]
        .copy_from_slice(&pack_words_to_packed_dwords(&c1_words[..half * 2]));

    core.write_mem_dword_span_at_clk(x_ptr, &result_buf[..num_dwords], clk + 1);
}

fn dwords_to_bytes(values: &[u64]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect::<Vec<u8>>()
}

fn pack_words_to_packed_dwords(words: &[u32]) -> Vec<u64> {
    words
        .chunks_exact(2)
        .map(|pair| u64::from(pair[0]) | (u64::from(pair[1]) << 32))
        .collect()
}

#[inline(always)]
fn words_to_bytes_32(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&words[i].to_le_bytes());
    }
    bytes
}

#[inline(always)]
fn fq_to_words_32<F: PrimeField<BigInt = BigInt<4>>>(value: F) -> [u32; 8] {
    let limbs = value.into_bigint().0;
    let mut words = [0u32; 8];
    for (i, limb) in limbs.iter().enumerate() {
        let lo = *limb as u32;
        let hi = (*limb >> 32) as u32;
        words[i * 2] = lo;
        words[i * 2 + 1] = hi;
    }
    words
}

#[inline(always)]
fn fq_to_words_48<F: PrimeField<BigInt = BigInt<6>>>(value: F) -> [u32; 12] {
    let limbs = value.into_bigint().0;
    let mut words = [0u32; 12];
    for (i, limb) in limbs.iter().enumerate() {
        let lo = *limb as u32;
        let hi = (*limb >> 32) as u32;
        words[i * 2] = lo;
        words[i * 2 + 1] = hi;
    }
    words
}

#[cfg(test)]
mod tests {
    use super::{dwords_to_bytes, fq_to_words_32, fq_to_words_48, pack_words_to_packed_dwords};
    use ark_bls12_381::{Fq as Bls381Fq, Fq2 as Bls381Fq2};
    use ark_bn254::Fq as Bn254Fq;
    use ark_ff::PrimeField;

    #[test]
    fn phase5_bn_fp_round_trip_uses_packed_dwords() {
        let value = Bn254Fq::from(0x1234_5678_u64) * Bn254Fq::from(0x0102_0304_u64);
        let words = fq_to_words_32(value);
        let dwords = pack_words_to_packed_dwords(&words);
        let round_trip = Bn254Fq::from_le_bytes_mod_order(&dwords_to_bytes(&dwords));

        assert_eq!(round_trip, value);
    }

    #[test]
    fn phase5_bls_fp2_round_trip_uses_packed_dwords() {
        let value = Bls381Fq2::new(Bls381Fq::from(3_u64), Bls381Fq::from(9_u64));
        let c0 = fq_to_words_48(value.c0);
        let c1 = fq_to_words_48(value.c1);

        let mut dwords = pack_words_to_packed_dwords(&c0).to_vec();
        dwords.extend(pack_words_to_packed_dwords(&c1));
        let bytes = dwords_to_bytes(&dwords);
        let (c0_bytes, c1_bytes) = bytes.split_at(bytes.len() / 2);

        assert_eq!(Bls381Fq::from_le_bytes_mod_order(c0_bytes), value.c0);
        assert_eq!(Bls381Fq::from_le_bytes_mod_order(c1_bytes), value.c1);
    }
}
