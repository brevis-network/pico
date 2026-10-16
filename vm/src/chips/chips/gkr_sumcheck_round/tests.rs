use super::GkrSumcheckRoundChip;
use crate::{
    compiler::recursion::{
        instruction::Instruction,
        ir::Block,
        program::RecursionProgram,
        types::{Address, GkrSumcheckRoundEvent, GkrSumcheckRoundInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::chip::ChipBehavior,
};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;
use pico_mle_core::poly::interpolate_cubic_at_0123;

type F = KoalaBear;

fn b(v: u32) -> Block<F> {
    Block([F::from_u32(v), F::ZERO, F::ZERO, F::ZERO])
}

/// The chip's closed-form cubic interpolation (base lane), for cross-checking
/// against the host verifier's Newton-form `interpolate_cubic_at_0123`.
fn chip_interp_d3(claim: F, s1: F, s2: F, s3: F, r: F) -> F {
    let s0 = claim - s1;
    let one = F::ONE;
    let two = F::TWO;
    let three = F::from_u32(3);
    let a = (r - one) * (r - two) * (r - three);
    let bb = r * (r - two) * (r - three);
    let c = r * (r - one) * (r - three);
    let d = r * (r - one) * (r - two);
    let num = three * s1 * bb + s3 * d - s0 * a - three * s2 * c;
    num * F::from_u32(6).inverse()
}

#[test]
fn test_gkr_round_matches_host_interpolation() {
    let claim = F::from_u32(1234);
    let s1 = F::from_u32(777);
    let s2 = F::from_u32(31337);
    let s3 = F::from_u32(99991);
    let s0 = claim - s1;
    // Node values reproduce.
    assert_eq!(chip_interp_d3(claim, s1, s2, s3, F::ZERO), s0);
    assert_eq!(chip_interp_d3(claim, s1, s2, s3, F::ONE), s1);
    assert_eq!(chip_interp_d3(claim, s1, s2, s3, F::TWO), s2);
    assert_eq!(chip_interp_d3(claim, s1, s2, s3, F::from_u32(3)), s3);
    // Random point agrees with the host verifier's Newton form.
    for r in [5u32, 42, 65537, 998244353] {
        let r = F::from_u32(r);
        assert_eq!(
            chip_interp_d3(claim, s1, s2, s3, r),
            interpolate_cubic_at_0123(&[s0, s1, s2, s3], r)
        );
    }
}

#[test]
fn test_gkr_round_trace_dimensions_and_r_sq() {
    let chip = GkrSumcheckRoundChip::<F>::default();

    let r = F::from_u32(9);
    let xi = F::from_u32(3);
    let eq_in = F::from_u32(2);
    // eq_factor(xi, r) = 2*xi*r - xi - r + 1 = 54 - 3 - 9 + 1 = 43; eq_out = 86.
    let eq_out = eq_in * (F::TWO * xi * r - xi - r + F::ONE);
    let claim = F::from_u32(100);
    let s1 = F::from_u32(40);
    let s2 = F::from_u32(50);
    let s3 = F::from_u32(60);
    let next = chip_interp_d3(claim, s1, s2, s3, r);

    let event = GkrSumcheckRoundEvent {
        claim: b(100),
        s1: b(40),
        s2: b(50),
        s3: b(60),
        r: b(9),
        xi: b(3),
        eq_in: b(2),
        next_claim: Block([next, F::ZERO, F::ZERO, F::ZERO]),
        eq_out: Block([eq_out, F::ZERO, F::ZERO, F::ZERO]),
    };

    let mut record = RecursionRecord::<F>::default();
    record.gkr_sumcheck_round_events.push(event);

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);

    assert!(trace.height() >= 16);
    assert_eq!(trace.width(), super::columns::NUM_GKR_SUMCHECK_ROUND_COLS);
    // Columns: [claim, s1, s2, s3, r, xi, eq_in, r_sq, next_claim, eq_out] x Block(4).
    let row = trace.row_slice(0).unwrap();
    assert_eq!(row[0], claim);
    assert_eq!(row[4 * 4], r);
    assert_eq!(row[7 * 4], r * r); // r_sq recomputed by tracegen
    assert_eq!(row[8 * 4], next);
    assert_eq!(row[9 * 4], eq_out);
}

#[test]
fn test_gkr_round_preprocessed_dimensions() {
    let chip = GkrSumcheckRoundChip::<F>::default();

    let instr = GkrSumcheckRoundInstr {
        claim_addr: Address(F::from_u32(10)),
        s1_addr: Address(F::from_u32(11)),
        s2_addr: Address(F::from_u32(12)),
        s3_addr: Address(F::from_u32(13)),
        r_addr: Address(F::from_u32(14)),
        xi_addr: Address(F::from_u32(15)),
        eq_in_addr: Address(F::from_u32(16)),
        next_claim_addr: Address(F::from_u32(17)),
        eq_out_addr: Address(F::from_u32(18)),
        mult_next: F::ONE,
        mult_eq: F::ONE,
    };

    let program = RecursionProgram {
        instructions: vec![Instruction::GkrSumcheckRound(Box::new(instr))],
        ..Default::default()
    };

    let preprocessed = chip.generate_preprocessed(&program).unwrap();
    assert!(preprocessed.height() >= 16);
    assert_eq!(
        preprocessed.width(),
        super::columns::NUM_GKR_SUMCHECK_ROUND_PREPROCESSED_COLS
    );
    assert_eq!(preprocessed.row_slice(0).unwrap()[0], F::ONE); // is_real
    assert_eq!(preprocessed.row_slice(1).unwrap()[0], F::ZERO); // padding
}
