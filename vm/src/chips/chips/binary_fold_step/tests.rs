use super::BinaryFoldStepChip;
use crate::{
    compiler::recursion::{
        instruction::Instruction,
        ir::Block,
        program::RecursionProgram,
        types::{Address, BinaryFoldStepEvent, BinaryFoldStepInstr},
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

#[test]
fn test_binary_fold_step_trace_values() {
    let chip = BinaryFoldStepChip::<F>::default();

    let tw = F::from_u32(3);
    let xi = F::from_u32(5);
    let inv_tw = tw.inverse();
    let xi_inv = xi.inverse();
    let alpha = F::from_u32(11);
    let v_lo = F::from_u32(100);
    let v_hi = F::from_u32(60);
    // out = v_lo + (alpha - tw*xi) * (v_lo - v_hi) * (inv_tw * xi_inv / 2)
    let out = v_lo + (alpha - tw * xi) * (v_lo - v_hi) * (inv_tw * xi_inv * F::TWO.inverse());

    let event = BinaryFoldStepEvent {
        tw,
        xi,
        inv_tw,
        xi_inv,
        alpha: b(11),
        v_lo: b(100),
        v_hi: b(60),
        out: Block([out, F::ZERO, F::ZERO, F::ZERO]),
    };

    let mut record = RecursionRecord::<F>::default();
    record.binary_fold_step_events.push(event);

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);
    assert!(trace.height() >= 16);
    assert_eq!(trace.width(), super::columns::NUM_BINARY_FOLD_STEP_COLS);
    // Layout: [tw, xi, inv_tw, xi_inv, alpha(4), v_lo(4), v_hi(4), amt(4), tih, out(4)]
    let row = trace.row_slice(0).unwrap();
    assert_eq!(row[0], tw);
    assert_eq!(row[4], alpha); // alpha[0]
    assert_eq!(row[16], alpha - tw * xi); // amt[0]
    assert_eq!(row[20], inv_tw * xi_inv * F::TWO.inverse()); // tih
    assert_eq!(row[21], out); // out[0]
}

#[test]
fn test_binary_fold_step_preprocessed_dimensions() {
    let chip = BinaryFoldStepChip::<F>::default();

    let mk_addr = |v: u32| Address(F::from_u32(v));
    let instr = BinaryFoldStepInstr {
        tw_addr: mk_addr(1),
        xi_addr: mk_addr(2),
        inv_tw_addr: mk_addr(3),
        xi_inv_addr: mk_addr(4),
        alpha_addr: mk_addr(5),
        v_lo_addr: mk_addr(6),
        v_hi_addr: mk_addr(7),
        out_addr: mk_addr(8),
        mult: F::ONE,
    };

    let program = RecursionProgram {
        instructions: vec![Instruction::BinaryFoldStep(Box::new(instr))],
        ..Default::default()
    };

    let preprocessed = chip.generate_preprocessed(&program).unwrap();
    assert!(preprocessed.height() >= 16);
    assert_eq!(
        preprocessed.width(),
        super::columns::NUM_BINARY_FOLD_STEP_PREPROCESSED_COLS
    );
    assert_eq!(preprocessed.row_slice(0).unwrap()[0], F::ONE); // is_real
    assert_eq!(preprocessed.row_slice(1).unwrap()[0], F::ZERO); // padding
}
