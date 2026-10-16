use super::AssertZeroExtChip;
use crate::{
    compiler::recursion::{
        instruction::Instruction,
        ir::Block,
        program::RecursionProgram,
        types::{Address, AssertZeroExtEvent, AssertZeroExtInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::chip::ChipBehavior,
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;

type F = KoalaBear;

#[test]
fn test_assert_zero_ext_trace_dimensions() {
    let chip = AssertZeroExtChip::<F>::default();

    // The asserted value is zero (an honest row).
    let event = AssertZeroExtEvent {
        val: Block([F::ZERO; 4]),
    };

    let mut record = RecursionRecord::<F>::default();
    record.assert_zero_ext_events.push(event);

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);

    // pad_to_power_of_two enforces a minimum of 16 rows.
    assert!(trace.height() >= 16);
    assert_eq!(trace.width(), super::columns::NUM_ASSERT_ZERO_EXT_COLS);
    // val[0] == 0 in the first row.
    assert_eq!(trace.row_slice(0).unwrap()[0], F::ZERO);
}

#[test]
fn test_assert_zero_ext_preprocessed_dimensions() {
    let chip = AssertZeroExtChip::<F>::default();

    let instr = AssertZeroExtInstr {
        addr: Address(F::from_u32(42)),
    };

    let program = RecursionProgram {
        instructions: vec![Instruction::AssertZeroExt(instr)],
        ..Default::default()
    };

    let preprocessed = chip.generate_preprocessed(&program).unwrap();
    assert!(preprocessed.height() >= 16);
    assert_eq!(
        preprocessed.width(),
        super::columns::NUM_ASSERT_ZERO_EXT_PREPROCESSED_COLS
    );
    let row = preprocessed.row_slice(0).unwrap();
    assert_eq!(row[0], F::ONE); // is_real
    assert_eq!(row[1], F::from_u32(42)); // addr
}
