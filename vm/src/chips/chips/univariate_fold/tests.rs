use super::{UnivariateFoldChip, MAX_COEFFS};
use crate::{
    compiler::recursion::{
        instruction::Instruction,
        ir::Block,
        program::RecursionProgram,
        types::{Address, UnivariateFoldEvent, UnivariateFoldInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::chip::ChipBehavior,
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;

type F = KoalaBear;

fn b(v: u32) -> Block<F> {
    Block([F::from_u32(v), F::ZERO, F::ZERO, F::ZERO])
}

#[test]
fn test_univariate_fold_trace_dimensions() {
    let chip = UnivariateFoldChip::<F>::default();

    // Stacking domain-sum constraint: (coeffs[0] + coeffs[omega_order]) * omega_order == claimed_sum.
    // omega_order = (MAX_COEFFS+1)/2 = 16.  Only 3 non-zero coefficients (rest zero-padded):
    //   coeffs[0] = 1, coeffs[16] = 0 → domain_sum = (1+0)*16 = 16.
    // poly(r) = poly(2) = 1 + 2*2 + 3*4 = 17.
    let event = UnivariateFoldEvent {
        coeffs: vec![b(1), b(2), b(3)],
        claimed_sum: b(16),
        r: b(2),
        next_sum: b(17),
    };

    let mut record = RecursionRecord::<F>::default();
    record.univariate_fold_events.push(event);

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);

    assert!(trace.height() >= 16);
    assert_eq!(trace.width(), super::columns::NUM_UNIVARIATE_FOLD_COLS);
}

#[test]
fn test_univariate_fold_preprocessed_dimensions() {
    let chip = UnivariateFoldChip::<F>::default();

    let mut coeffs_addrs = [Address(F::ZERO); MAX_COEFFS];
    for (i, addr) in coeffs_addrs.iter_mut().enumerate() {
        *addr = Address(F::from_u32(20 + i as u32));
    }

    let instr = UnivariateFoldInstr {
        coeffs_addrs: coeffs_addrs[..3].to_vec(),
        claimed_sum_addr: Address(F::from_u32(35)),
        r_addr: Address(F::from_u32(36)),
        next_sum_addr: Address(F::from_u32(37)),
        mult: F::ONE,
    };

    let program = RecursionProgram {
        instructions: vec![Instruction::UnivariateFold(Box::new(instr))],
        ..Default::default()
    };

    let preprocessed = chip.generate_preprocessed(&program).unwrap();
    assert!(preprocessed.height() >= 16);
    assert_eq!(
        preprocessed.width(),
        super::columns::NUM_UNIVARIATE_FOLD_PREPROCESSED_COLS
    );
    assert_eq!(preprocessed.row_slice(0).unwrap()[0], F::ONE); // is_real
}

#[test]
fn test_univariate_fold_eval_columns() {
    let chip = UnivariateFoldChip::<F>::default();

    // eval_at_0 = coeffs[0] = 1; eval_at_1 = coeffs[omega_order=16] = 0 (zero-padded).
    let event = UnivariateFoldEvent {
        coeffs: vec![b(1), b(2), b(3)],
        claimed_sum: b(16), // (1 + 0) * 16 = 16
        r: b(2),
        next_sum: b(17),
    };

    let mut record = RecursionRecord::<F>::default();
    record.univariate_fold_events.push(event);

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);
    let row = trace.row_slice(0).unwrap();

    // eval_at_0 offset: after MAX_COEFFS blocks of 4 + 3 blocks of 4 = (MAX_COEFFS+3)*4
    let eval_at_0_offset = (MAX_COEFFS + 3) * 4;
    let eval_at_1_offset = eval_at_0_offset + 4;
    assert_eq!(row[eval_at_0_offset], F::from_u32(1)); // eval_at_0 = coeffs[0] = 1
    assert_eq!(row[eval_at_1_offset], F::from_u32(0)); // eval_at_1 = coeffs[16] = 0 (zero-padded)
}
