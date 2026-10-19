use super::{
    columns::{
        ExpBitsLenCols, ExpBitsLenPreprocessedCols, NUM_BITS_MAX_PLUS_ONE, NUM_EXP_BITS_LEN_COLS,
        NUM_EXP_BITS_LEN_PREPROCESSED_COLS,
    },
    ExpBitsLenChip,
};
use crate::{
    compiler::recursion::{
        instruction::Instruction,
        program::RecursionProgram,
        types::{Address, ExpBitsLenEvent, ExpBitsLenInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::chip::ChipBehavior,
};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;
use std::borrow::Borrow;

type F = KoalaBear;

/// Reference implementation of the chip's semantic equation, mirroring the host `sample_bits`:
/// `result = base^(canonical(bit_src) & ((1 << num_bits) - 1))`.
fn expected_result(base: F, bit_src: F, num_bits: usize) -> F {
    let v = bit_src.as_canonical_u32();
    let mask = if num_bits >= 32 {
        u32::MAX
    } else {
        (1u32 << num_bits) - 1
    };
    base.exp_u64((v & mask) as u64)
}

fn run_case(base_u: u32, bit_src_u: u32, num_bits: usize) {
    let base = F::from_u32(base_u);
    let bit_src = F::from_u32(bit_src_u);

    let chip = ExpBitsLenChip::<F>::default();
    let mut record = RecursionRecord::<F>::default();
    record.exp_bits_len_events.push(ExpBitsLenEvent {
        base,
        bit_src,
        num_bits: num_bits as u32,
    });

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);

    assert_eq!(trace.width(), NUM_EXP_BITS_LEN_COLS);
    assert!(trace.height() >= NUM_BITS_MAX_PLUS_ONE);

    // Row 0 (is_first) carries the anchored inputs and the final result.
    let row0 = trace.row_slice(0).unwrap();
    let first: &ExpBitsLenCols<F> = (*row0).borrow();
    assert_eq!(first.bit_idx, F::ZERO);
    assert_eq!(first.base, base);
    assert_eq!(first.bit_src, bit_src);
    assert_eq!(
        first.result,
        expected_result(base, bit_src, num_bits),
        "result mismatch for base={base_u}, bit_src={bit_src_u}, num_bits={num_bits}",
    );

    // Each decomposition row j (0..=30) exports the j-th canonical bit.
    let canonical = bit_src.as_canonical_u32();
    for j in 0..NUM_BITS_MAX_PLUS_ONE - 1 {
        let row = trace.row_slice(j).unwrap();
        let cols: &ExpBitsLenCols<F> = (*row).borrow();
        let want = (canonical >> j) & 1;
        assert_eq!(
            cols.bit_src_mod_2,
            F::from_u32(want),
            "bit {j} mismatch for bit_src={bit_src_u}",
        );
    }

    // Terminal row (row 31) anchors.
    let last = trace.row_slice(NUM_BITS_MAX_PLUS_ONE - 1).unwrap();
    let term: &ExpBitsLenCols<F> = (*last).borrow();
    assert_eq!(term.bit_idx, F::from_usize(NUM_BITS_MAX_PLUS_ONE - 1));
    assert_eq!(term.bit_src, F::ZERO);
    assert_eq!(term.num_bits, F::ZERO);
    assert_eq!(term.result, F::ONE);
    assert_eq!(term.result_multiplier, F::ONE);
    // Canonicality terminal check must hold: high_bits_all_one * (1 - low_bits_are_zero) == 0.
    let hi = term.high_bits_all_one;
    let lo = term.low_bits_are_zero;
    assert_eq!(hi * (F::ONE - lo), F::ZERO);
}

#[test]
fn test_exp_bits_len_result_matches_spec() {
    // Small values.
    run_case(3, 0b1011, 4); // 3^(11)
    run_case(5, 0b1101, 2); // only low 2 bits => 5^1
    run_case(7, 12345, 10);
    // num_bits == 0 => result must be 1 regardless of bit_src.
    run_case(9, 987654, 0);
    // A value >= 2^24 to exercise the KoalaBear high-region canonicity path.
    run_case(2, (1u32 << 24) + 12345, 31);
    run_case(11, (1u32 << 30) + 7, 31);
    // Full-width decomposition of a large canonical element.
    run_case(6, KoalaBear::ORDER_U32 - 1, 31);
}

#[test]
fn test_exp_bits_len_preprocessed_dimensions() {
    let chip = ExpBitsLenChip::<F>::default();

    let mk = |v: u32| Address(F::from_u32(v));
    // 31 bit-output addresses (one per decomposition row).
    let bit_outs: Vec<(Address<F>, F)> = (0..NUM_BITS_MAX_PLUS_ONE - 1)
        .map(|i| (mk(100 + i as u32), F::ONE))
        .collect();

    let instr = ExpBitsLenInstr {
        base: F::from_u32(3),
        num_bits: 8,
        bit_src_in_addr: mk(5),
        result_out_addr: mk(6),
        result_mult: F::from_u32(2),
        bit_outs_addrs_mults: bit_outs,
    };

    let program = RecursionProgram {
        instructions: vec![Instruction::ExpBitsLen(Box::new(instr))],
        ..Default::default()
    };

    let preprocessed = chip.generate_preprocessed(&program).unwrap();
    assert_eq!(preprocessed.width(), NUM_EXP_BITS_LEN_PREPROCESSED_COLS);
    assert!(preprocessed.height() >= NUM_BITS_MAX_PLUS_ONE);

    // Row 0 = is_first; row 31 = is_last.
    let row0 = preprocessed.row_slice(0).unwrap();
    let p0: &ExpBitsLenPreprocessedCols<F> = (*row0).borrow();
    assert_eq!(p0.is_first, F::ONE);
    assert_eq!(p0.is_last, F::ZERO);
    assert_eq!(p0.is_real, F::ONE);
    assert_eq!(p0.bit_src_in.addr.0, F::from_u32(5));
    assert_eq!(p0.bit_src_in.mult, F::NEG_ONE); // read on first row
    assert_eq!(p0.result_out.addr.0, F::from_u32(6));
    assert_eq!(p0.result_out.mult, F::from_u32(2)); // write count on first row
    assert_eq!(p0.base_const, F::from_u32(3));
    assert_eq!(p0.num_bits_const, F::from_u32(8));

    let row31 = preprocessed.row_slice(NUM_BITS_MAX_PLUS_ONE - 1).unwrap();
    let p31: &ExpBitsLenPreprocessedCols<F> = (*row31).borrow();
    assert_eq!(p31.is_first, F::ZERO);
    assert_eq!(p31.is_last, F::ONE);
    assert_eq!(p31.is_real, F::ONE);
    assert_eq!(p31.bit_src_in.mult, F::ZERO); // no read off the first row
    assert_eq!(p31.result_out.mult, F::ZERO); // no write off the first row
    assert_eq!(p31.bit_out.mult, F::ZERO); // terminal row exports no bit
}
