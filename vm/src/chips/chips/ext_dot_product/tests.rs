use super::ExtDotProductChip;
use crate::{
    compiler::recursion::{
        instruction::Instruction,
        ir::Block,
        program::RecursionProgram,
        types::{Address, ExtDotProductEvent, ExtDotProductInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::chip::ChipBehavior,
    primitives::consts::{EXT_DOT_PRODUCT_DATAPAR, EXT_DOT_PRODUCT_GROUPS},
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;

type F = KoalaBear;
const D: usize = EXT_DOT_PRODUCT_DATAPAR;
const G: usize = EXT_DOT_PRODUCT_GROUPS;

fn b(v: u32) -> Block<F> {
    Block([F::from_u32(v), F::ZERO, F::ZERO, F::ZERO])
}

#[test]
fn test_ext_dot_product_trace_row_acc() {
    let chip = ExtDotProductChip::<F>::default();

    // One row: G packed value blocks (lanes all 2) and D mus = 1..D
    // -> acc = 2 * (1+..+D).
    let mus: [Block<F>; D] = std::array::from_fn(|j| b(j as u32 + 1));
    let vals: [Block<F>; G] = std::array::from_fn(|_| Block([F::from_u32(2); 4]));
    let sum = 2 * (D * (D + 1) / 2) as u32;

    let mut record = RecursionRecord::<F>::default();
    record.ext_dot_product_events.push(ExtDotProductEvent {
        mus,
        vals,
        acc: b(sum),
    });

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);
    assert!(trace.height() >= 16);
    assert_eq!(trace.width(), super::columns::NUM_EXT_DOT_PRODUCT_COLS);
    // Column layout: [mus[D] (4 lanes each), vals[G] (4 lanes each), acc]
    let row = trace.row_slice(0).unwrap();
    assert_eq!(row[0], F::from_u32(1)); // mus[0] lane 0
    assert_eq!(row[4 * D], F::from_u32(2)); // vals[0] lane 0
    assert_eq!(row[4 * D + 1], F::from_u32(2)); // vals[0] lane 1 (packed!)
    assert_eq!(row[4 * D + 4 * G], F::from_u32(sum)); // acc
}

#[test]
fn test_ext_dot_product_preprocessed_segmentation() {
    let chip = ExtDotProductChip::<F>::default();

    let mk_addr = |v: u32| Address(F::from_u32(v));
    // Two rows (2*G packed groups = 2*D elements) in one instruction, then a
    // single-row instruction.
    let instr1 = ExtDotProductInstr {
        mu_addrs: (0..2 * D as u32).map(|i| mk_addr(100 + i)).collect(),
        val_addrs: (0..2 * G as u32).map(|i| mk_addr(200 + i)).collect(),
        acc_addr: mk_addr(50),
        mult: F::TWO,
    };
    let instr2 = ExtDotProductInstr {
        mu_addrs: (0..D as u32).map(|i| mk_addr(300 + i)).collect(),
        val_addrs: (0..G as u32).map(|i| mk_addr(400 + i)).collect(),
        acc_addr: mk_addr(51),
        mult: F::ONE,
    };

    let program = RecursionProgram {
        instructions: vec![
            Instruction::ExtDotProduct(Box::new(instr1)),
            Instruction::ExtDotProduct(Box::new(instr2)),
        ],
        ..Default::default()
    };

    let preprocessed = chip.generate_preprocessed(&program).unwrap();
    assert_eq!(
        preprocessed.width(),
        super::columns::NUM_EXT_DOT_PRODUCT_PREPROCESSED_COLS
    );
    // Column layout: [is_real, is_end, mu_addrs[D], val_addrs[G], acc_addr, mult]
    let expect = [
        (F::ONE, F::ZERO, F::ZERO),
        (F::ONE, F::ONE, F::TWO),
        (F::ONE, F::ONE, F::ONE),
        (F::ZERO, F::ZERO, F::ZERO), // padding
    ];
    let mult_col = 2 + D + G + 1;
    for (i, &(is_real, is_end, mult)) in expect.iter().enumerate() {
        let row = preprocessed.row_slice(i).unwrap();
        assert_eq!(row[0], is_real, "row {i} is_real");
        assert_eq!(row[1], is_end, "row {i} is_end");
        assert_eq!(row[mult_col], mult, "row {i} mult");
    }
}
