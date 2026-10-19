use super::MleOpenChip;
use crate::{
    compiler::recursion::{
        instruction::Instruction,
        ir::Block,
        program::RecursionProgram,
        types::{Address, MleOpenEvent, MleOpenInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::chip::ChipBehavior,
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;

type F = KoalaBear;

#[test]
fn test_mle_open_trace_dimensions() {
    let chip = MleOpenChip::<F>::default();

    let event = MleOpenEvent {
        col_ref: (1u32 << 16) | 3, // air_id=1, col_id=3
        opening_value: Block([F::from_u32(42), F::ZERO, F::ZERO, F::ZERO]),
    };

    let mut record = RecursionRecord::<F>::default();
    record.mle_open_events.push(event);

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);

    assert!(trace.height() >= 16);
    assert_eq!(trace.width(), super::columns::NUM_MLE_OPEN_COLS);
    // opening_value[0] = 42 in the first row
    assert_eq!(trace.row_slice(0).unwrap()[0], F::from_u32(42));
}

#[test]
fn test_mle_open_preprocessed_dimensions() {
    let chip = MleOpenChip::<F>::default();

    let instr = MleOpenInstr {
        col_ref: (5u32 << 16) | 7,
        opening_value_addr: Address(F::from_u32(100)),
    };

    let program = RecursionProgram {
        instructions: vec![Instruction::MleOpen(instr)],
        ..Default::default()
    };

    let preprocessed = chip.generate_preprocessed(&program).unwrap();
    assert!(preprocessed.height() >= 16);
    assert_eq!(
        preprocessed.width(),
        super::columns::NUM_MLE_OPEN_PREPROCESSED_COLS
    );
    let row = preprocessed.row_slice(0).unwrap();
    assert_eq!(row[0], F::ONE); // is_real
    assert_eq!(row[1], F::from_u32((5u32 << 16) | 7)); // col_ref
}
