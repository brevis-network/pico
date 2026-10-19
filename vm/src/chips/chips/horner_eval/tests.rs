use super::HornerEvalChip;
use crate::{
    compiler::recursion::{
        instruction::Instruction,
        ir::Block,
        program::RecursionProgram,
        types::{Address, HornerEvalEvent, HornerEvalInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::chip::ChipBehavior,
    primitives::consts::HORNER_EVAL_DATAPAR,
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;

type F = KoalaBear;
const D: usize = HORNER_EVAL_DATAPAR;

fn b(v: u32) -> Block<F> {
    Block([F::from_u32(v), F::ZERO, F::ZERO, F::ZERO])
}

#[test]
fn test_horner_eval_trace_row_acc_and_powers() {
    let chip = HornerEvalChip::<F>::default();

    // One row: coefficients [5, 3, 2, 7] (evaluation order) at x = 2:
    // acc = ((5*2+3)*2+2)*2+7 = 5*8 + 3*4 + 2*2 + 7 = 63.
    let coeffs = [b(5), b(3), b(2), b(7)];
    let x = F::from_u32(2);
    let acc = F::from_u32(5 * 8 + 3 * 4 + 2 * 2 + 7);

    let mut record = RecursionRecord::<F>::default();
    record.horner_eval_events.push(HornerEvalEvent {
        coeffs,
        x: b(2),
        acc: Block([acc, F::ZERO, F::ZERO, F::ZERO]),
    });

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);
    assert!(trace.height() >= 16);
    assert_eq!(trace.width(), super::columns::NUM_HORNER_EVAL_COLS);
    // Layout: [coeffs(4*D), x(4), x2(4), x3(4), x4(4), acc(4)]
    let row = trace.row_slice(0).unwrap();
    assert_eq!(row[0], F::from_u32(5));
    assert_eq!(row[4 * D], x);
    assert_eq!(row[4 * D + 4], x * x); // x2
    assert_eq!(row[4 * D + 8], x * x * x); // x3
    assert_eq!(row[4 * D + 12], x * x * x * x); // x4
    assert_eq!(row[4 * D + 16], acc);
}

#[test]
fn test_horner_eval_preprocessed_segmentation() {
    let chip = HornerEvalChip::<F>::default();

    let mk_addr = |v: u32| Address(F::from_u32(v));
    // Two rows (2*D coefficients) then a single-row instruction.
    let instr1 = HornerEvalInstr {
        coeff_addrs: (0..2 * D as u32).map(|i| mk_addr(100 + i)).collect(),
        x_addr: mk_addr(40),
        out_addr: mk_addr(50),
        mult: F::TWO,
    };
    let instr2 = HornerEvalInstr {
        coeff_addrs: (0..D as u32).map(|i| mk_addr(300 + i)).collect(),
        x_addr: mk_addr(41),
        out_addr: mk_addr(51),
        mult: F::ONE,
    };

    let program = RecursionProgram {
        instructions: vec![
            Instruction::HornerEval(Box::new(instr1)),
            Instruction::HornerEval(Box::new(instr2)),
        ],
        ..Default::default()
    };

    let preprocessed = chip.generate_preprocessed(&program).unwrap();
    assert_eq!(
        preprocessed.width(),
        super::columns::NUM_HORNER_EVAL_PREPROCESSED_COLS
    );
    // Column layout: [is_real, is_start, is_end, coeff_addrs[D], x_addr, out_addr, mult]
    let expect = [
        (F::ONE, F::ONE, F::ZERO, F::ZERO),
        (F::ONE, F::ZERO, F::ONE, F::TWO),
        (F::ONE, F::ONE, F::ONE, F::ONE),     // single-row segment
        (F::ZERO, F::ZERO, F::ZERO, F::ZERO), // padding
    ];
    let mult_col = 3 + D + 2;
    for (i, &(is_real, is_start, is_end, mult)) in expect.iter().enumerate() {
        let row = preprocessed.row_slice(i).unwrap();
        assert_eq!(row[0], is_real, "row {i} is_real");
        assert_eq!(row[1], is_start, "row {i} is_start");
        assert_eq!(row[2], is_end, "row {i} is_end");
        assert_eq!(row[mult_col], mult, "row {i} mult");
    }
}
