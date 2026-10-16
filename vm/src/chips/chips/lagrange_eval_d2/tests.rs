use super::LagrangeEvalD2Chip;
use crate::{
    compiler::recursion::{
        instruction::Instruction,
        ir::Block,
        program::RecursionProgram,
        types::{Address, LagrangeEvalD2Event, LagrangeEvalD2Instr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::chip::ChipBehavior,
};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;

type F = KoalaBear;

fn b(v: u32) -> Block<F> {
    Block([F::from_u32(v), F::ZERO, F::ZERO, F::ZERO])
}

/// Reference quadratic interpolation on the base lane:
/// p(r) with p(0) = claim - s1, p(1) = s1, p(2) = s2.
fn interp_d2(claim: F, s1: F, s2: F, r: F) -> F {
    let s0 = claim - s1;
    let inv2 = F::TWO.inverse();
    let one = F::ONE;
    let two = F::TWO;
    s0 * (r - one) * (r - two) * inv2 - s1 * r * (r - two) + s2 * r * (r - one) * inv2
}

#[test]
fn test_lagrange_eval_d2_trace_dimensions() {
    let chip = LagrangeEvalD2Chip::<F>::default();

    // claim = 5, s1 = 2 → s0 = 3; s2 = 7; r = 4.
    let claim = F::from_u32(5);
    let s1 = F::from_u32(2);
    let s2 = F::from_u32(7);
    let r = F::from_u32(4);
    let next = interp_d2(claim, s1, s2, r);

    let event = LagrangeEvalD2Event {
        claim: b(5),
        s1: b(2),
        s2: b(7),
        r: b(4),
        next_claim: Block([next, F::ZERO, F::ZERO, F::ZERO]),
    };

    let mut record = RecursionRecord::<F>::default();
    record.lagrange_eval_d2_events.push(event);

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);

    assert!(trace.height() >= 16);
    assert_eq!(trace.width(), super::columns::NUM_LAGRANGE_EVAL_D2_COLS);
    // Columns: [claim(4), s1(4), s2(4), r(4), next_claim(4)]
    let row = trace.row_slice(0).unwrap();
    assert_eq!(row[0], claim);
    assert_eq!(row[4], s1);
    assert_eq!(row[8], s2);
    assert_eq!(row[12], r);
    assert_eq!(row[16], next);
}

#[test]
fn test_lagrange_eval_d2_interp_matches_node_values() {
    // The interpolation must reproduce the node values at r = 0, 1, 2.
    let claim = F::from_u32(11);
    let s1 = F::from_u32(4);
    let s2 = F::from_u32(9);
    let s0 = claim - s1;
    assert_eq!(interp_d2(claim, s1, s2, F::ZERO), s0);
    assert_eq!(interp_d2(claim, s1, s2, F::ONE), s1);
    assert_eq!(interp_d2(claim, s1, s2, F::TWO), s2);
    // And satisfy the AIR identity 2*p(r) == s0*(r-1)(r-2) - 2*s1*r*(r-2) + s2*r*(r-1).
    let r = F::from_u32(1234567);
    let p = interp_d2(claim, s1, s2, r);
    let one = F::ONE;
    let two = F::TWO;
    let rhs = s0 * (r - one) * (r - two) - two * s1 * r * (r - two) + s2 * r * (r - one);
    assert_eq!(two * p, rhs);
}

#[test]
fn test_lagrange_eval_d2_preprocessed_dimensions() {
    let chip = LagrangeEvalD2Chip::<F>::default();

    let instr = LagrangeEvalD2Instr {
        claim_addr: Address(F::from_u32(10)),
        s1_addr: Address(F::from_u32(11)),
        s2_addr: Address(F::from_u32(12)),
        r_addr: Address(F::from_u32(13)),
        next_claim_addr: Address(F::from_u32(14)),
        mult: F::ONE,
    };

    let program = RecursionProgram {
        instructions: vec![Instruction::LagrangeEvalD2(instr)],
        ..Default::default()
    };

    let preprocessed = chip.generate_preprocessed(&program).unwrap();
    assert!(preprocessed.height() >= 16);
    assert_eq!(
        preprocessed.width(),
        super::columns::NUM_LAGRANGE_EVAL_D2_PREPROCESSED_COLS
    );
    // is_real should be 1 for the first (instruction) row and 0 for padding rows.
    assert_eq!(preprocessed.row_slice(0).unwrap()[0], F::ONE);
    assert_eq!(preprocessed.row_slice(1).unwrap()[0], F::ZERO);
}
