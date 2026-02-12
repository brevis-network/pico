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
pub fn fp_op<P: FpOpField>(core: &mut AotEmulatorCore, op: FieldOperation, x_ptr: u32, y_ptr: u32) {
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
    x_ptr: u32,
    y_ptr: u32,
    clk: u32,
    num_words: usize,
) {
    let mut x_buf = [0u32; 8];
    let mut y_buf = [0u32; 8];

    core.read_mem_span_snapshot(x_ptr, &mut x_buf[..num_words]);
    core.read_mem_span_at_clk(y_ptr, &mut y_buf[..num_words], clk);

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
    core.write_mem_span_at_clk(x_ptr, &result_words[..num_words], clk + 1);
}

fn fp_op_bn254(
    core: &mut AotEmulatorCore,
    op: FieldOperation,
    x_ptr: u32,
    y_ptr: u32,
    clk: u32,
    num_words: usize,
) {
    let mut x_buf = [0u32; 8];
    let mut y_buf = [0u32; 8];

    core.read_mem_span_snapshot(x_ptr, &mut x_buf[..num_words]);
    core.read_mem_span_at_clk(y_ptr, &mut y_buf[..num_words], clk);

    let a_bytes = words_to_bytes_32(&x_buf);
    let b_bytes = words_to_bytes_32(&y_buf);
    let a = Bn254Fq::from_le_bytes_mod_order(&a_bytes);
    let b = Bn254Fq::from_le_bytes_mod_order(&b_bytes);

    let result = match op {
        FieldOperation::Add => a + b,
        FieldOperation::Sub => a - b,
        FieldOperation::Mul => a * b,
        _ => panic!("Unsupported operation"),
    };

    let result_words = fq_to_words_32(result);
    core.write_mem_span_at_clk(x_ptr, &result_words[..num_words], clk + 1);
}

fn fp_op_bls381(
    core: &mut AotEmulatorCore,
    op: FieldOperation,
    x_ptr: u32,
    y_ptr: u32,
    clk: u32,
    num_words: usize,
) {
    let mut x_buf = [0u32; 12];
    let mut y_buf = [0u32; 12];

    core.read_mem_span_snapshot(x_ptr, &mut x_buf[..num_words]);
    core.read_mem_span_at_clk(y_ptr, &mut y_buf[..num_words], clk);

    let a_bytes = words_to_bytes_48(&x_buf);
    let b_bytes = words_to_bytes_48(&y_buf);
    let a = Bls381Fq::from_le_bytes_mod_order(&a_bytes);
    let b = Bls381Fq::from_le_bytes_mod_order(&b_bytes);

    let result = match op {
        FieldOperation::Add => a + b,
        FieldOperation::Sub => a - b,
        FieldOperation::Mul => a * b,
        _ => panic!("Unsupported operation"),
    };

    let result_words = fq_to_words_48(result);
    core.write_mem_span_at_clk(x_ptr, &result_words[..num_words], clk + 1);
}

/// Field operation (Fp2 Add/Sub) syscall implementation with span operations.
#[inline(always)]
pub fn fp2_addsub<P: FpOpField>(
    core: &mut AotEmulatorCore,
    op: FieldOperation,
    x_ptr: u32,
    y_ptr: u32,
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
    _x_ptr: u32,
    _y_ptr: u32,
    _clk: u32,
    _num_words: usize,
) {
    panic!("secp256k1 does not use Fp2");
}

fn fp2_addsub_bn254(
    core: &mut AotEmulatorCore,
    op: FieldOperation,
    x_ptr: u32,
    y_ptr: u32,
    clk: u32,
    num_words: usize,
) {
    let mut x_buf = [0u32; 16];
    let mut y_buf = [0u32; 16];

    core.read_mem_span_snapshot(x_ptr, &mut x_buf[..num_words]);
    core.read_mem_span_at_clk(y_ptr, &mut y_buf[..num_words], clk);

    let half = num_words / 2;
    let ac0 = Bn254Fq::from_le_bytes_mod_order(&words_to_bytes_32(
        &x_buf[..half].try_into().expect("bn254 c0 size"),
    ));
    let ac1 = Bn254Fq::from_le_bytes_mod_order(&words_to_bytes_32(
        &x_buf[half..num_words].try_into().expect("bn254 c1 size"),
    ));
    let bc0 = Bn254Fq::from_le_bytes_mod_order(&words_to_bytes_32(
        &y_buf[..half].try_into().expect("bn254 c0 size"),
    ));
    let bc1 = Bn254Fq::from_le_bytes_mod_order(&words_to_bytes_32(
        &y_buf[half..num_words].try_into().expect("bn254 c1 size"),
    ));

    let a = Bn254Fq2::new(ac0, ac1);
    let b = Bn254Fq2::new(bc0, bc1);

    let result = match op {
        FieldOperation::Add => a + b,
        FieldOperation::Sub => a - b,
        _ => panic!("Invalid operation"),
    };

    let c0_words = fq_to_words_32(result.c0);
    let c1_words = fq_to_words_32(result.c1);
    let mut result_buf = [0u32; 16];
    result_buf[..half].copy_from_slice(&c0_words[..half]);
    result_buf[half..num_words].copy_from_slice(&c1_words[..half]);

    core.write_mem_span_at_clk(x_ptr, &result_buf[..num_words], clk + 1);
}

/// Field operation (Fp2 Mul) syscall implementation with span operations.
#[inline(always)]
pub fn fp2_mul<P: FpOpField>(core: &mut AotEmulatorCore, x_ptr: u32, y_ptr: u32) {
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
    _x_ptr: u32,
    _y_ptr: u32,
    _clk: u32,
    _num_words: usize,
) {
    panic!("secp256k1 does not use Fp2");
}

fn fp2_mul_bn254(core: &mut AotEmulatorCore, x_ptr: u32, y_ptr: u32, clk: u32, num_words: usize) {
    let mut x_buf = [0u32; 16];
    let mut y_buf = [0u32; 16];

    core.read_mem_span_snapshot(x_ptr, &mut x_buf[..num_words]);
    core.read_mem_span_at_clk(y_ptr, &mut y_buf[..num_words], clk);

    let half = num_words / 2;
    let ac0 = Bn254Fq::from_le_bytes_mod_order(&words_to_bytes_32(
        &x_buf[..half].try_into().expect("bn254 c0 size"),
    ));
    let ac1 = Bn254Fq::from_le_bytes_mod_order(&words_to_bytes_32(
        &x_buf[half..num_words].try_into().expect("bn254 c1 size"),
    ));
    let bc0 = Bn254Fq::from_le_bytes_mod_order(&words_to_bytes_32(
        &y_buf[..half].try_into().expect("bn254 c0 size"),
    ));
    let bc1 = Bn254Fq::from_le_bytes_mod_order(&words_to_bytes_32(
        &y_buf[half..num_words].try_into().expect("bn254 c1 size"),
    ));

    let a = Bn254Fq2::new(ac0, ac1);
    let b = Bn254Fq2::new(bc0, bc1);
    let result = a * b;

    let c0_words = fq_to_words_32(result.c0);
    let c1_words = fq_to_words_32(result.c1);
    let mut result_buf = [0u32; 16];
    result_buf[..half].copy_from_slice(&c0_words[..half]);
    result_buf[half..num_words].copy_from_slice(&c1_words[..half]);

    core.write_mem_span_at_clk(x_ptr, &result_buf[..num_words], clk + 1);
}

fn fp2_addsub_bls381(
    core: &mut AotEmulatorCore,
    op: FieldOperation,
    x_ptr: u32,
    y_ptr: u32,
    clk: u32,
    num_words: usize,
) {
    let mut x_buf = [0u32; 24];
    let mut y_buf = [0u32; 24];

    core.read_mem_span_snapshot(x_ptr, &mut x_buf[..num_words]);
    core.read_mem_span_at_clk(y_ptr, &mut y_buf[..num_words], clk);

    let half = num_words / 2;
    let ac0 = Bls381Fq::from_le_bytes_mod_order(&words_to_bytes_48(
        &x_buf[..half].try_into().expect("bls381 c0 size"),
    ));
    let ac1 = Bls381Fq::from_le_bytes_mod_order(&words_to_bytes_48(
        &x_buf[half..num_words].try_into().expect("bls381 c1 size"),
    ));
    let bc0 = Bls381Fq::from_le_bytes_mod_order(&words_to_bytes_48(
        &y_buf[..half].try_into().expect("bls381 c0 size"),
    ));
    let bc1 = Bls381Fq::from_le_bytes_mod_order(&words_to_bytes_48(
        &y_buf[half..num_words].try_into().expect("bls381 c1 size"),
    ));

    let a = Bls381Fq2::new(ac0, ac1);
    let b = Bls381Fq2::new(bc0, bc1);
    let result = match op {
        FieldOperation::Add => a + b,
        FieldOperation::Sub => a - b,
        _ => panic!("Invalid operation"),
    };

    let c0_words = fq_to_words_48(result.c0);
    let c1_words = fq_to_words_48(result.c1);
    let mut result_buf = [0u32; 24];
    result_buf[..half].copy_from_slice(&c0_words[..half]);
    result_buf[half..num_words].copy_from_slice(&c1_words[..half]);

    core.write_mem_span_at_clk(x_ptr, &result_buf[..num_words], clk + 1);
}

fn fp2_mul_bls381(core: &mut AotEmulatorCore, x_ptr: u32, y_ptr: u32, clk: u32, num_words: usize) {
    let mut x_buf = [0u32; 24];
    let mut y_buf = [0u32; 24];

    core.read_mem_span_snapshot(x_ptr, &mut x_buf[..num_words]);
    core.read_mem_span_at_clk(y_ptr, &mut y_buf[..num_words], clk);

    let half = num_words / 2;
    let ac0 = Bls381Fq::from_le_bytes_mod_order(&words_to_bytes_48(
        &x_buf[..half].try_into().expect("bls381 c0 size"),
    ));
    let ac1 = Bls381Fq::from_le_bytes_mod_order(&words_to_bytes_48(
        &x_buf[half..num_words].try_into().expect("bls381 c1 size"),
    ));
    let bc0 = Bls381Fq::from_le_bytes_mod_order(&words_to_bytes_48(
        &y_buf[..half].try_into().expect("bls381 c0 size"),
    ));
    let bc1 = Bls381Fq::from_le_bytes_mod_order(&words_to_bytes_48(
        &y_buf[half..num_words].try_into().expect("bls381 c1 size"),
    ));

    let a = Bls381Fq2::new(ac0, ac1);
    let b = Bls381Fq2::new(bc0, bc1);
    let result = a * b;

    let c0_words = fq_to_words_48(result.c0);
    let c1_words = fq_to_words_48(result.c1);
    let mut result_buf = [0u32; 24];
    result_buf[..half].copy_from_slice(&c0_words[..half]);
    result_buf[half..num_words].copy_from_slice(&c1_words[..half]);

    core.write_mem_span_at_clk(x_ptr, &result_buf[..num_words], clk + 1);
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
fn words_to_bytes_48(words: &[u32; 12]) -> [u8; 48] {
    let mut bytes = [0u8; 48];
    for i in 0..12 {
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
