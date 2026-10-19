use super::DigestSelectChip;
use crate::{
    compiler::recursion::{
        instruction::Instruction,
        program::RecursionProgram,
        types::{Address, DigestSelectEvent, DigestSelectInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::chip::ChipBehavior,
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;

type F = KoalaBear;

#[test]
fn test_digest_select_trace_values() {
    let chip = DigestSelectChip::<F>::default();

    let in1: [F; 8] = std::array::from_fn(|i| F::from_u32(100 + i as u32));
    let in2: [F; 8] = std::array::from_fn(|i| F::from_u32(200 + i as u32));

    // bit = 1 selects in2.
    let mut record = RecursionRecord::<F>::default();
    record.digest_select_events.push(DigestSelectEvent {
        bit: F::ONE,
        in1,
        in2,
        out: in2,
    });

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);
    assert!(trace.height() >= 16);
    assert_eq!(trace.width(), super::columns::NUM_DIGEST_SELECT_COLS);
    // Group 0 layout: [bit, in1[8], in2[8], out[8]] = 25 cols.
    let row = trace.row_slice(0).unwrap();
    assert_eq!(row[0], F::ONE);
    assert_eq!(row[1], in1[0]);
    assert_eq!(row[9], in2[0]);
    assert_eq!(row[17], in2[0]); // out = in2 since bit = 1
    assert_eq!(row[25], F::ZERO); // group 1 empty
}

#[test]
fn test_digest_select_preprocessed_groups() {
    let chip = DigestSelectChip::<F>::default();

    let mk_addr = |v: u32| Address(F::from_u32(v));
    let mk_instr = |base: u32| {
        Instruction::DigestSelect(Box::new(DigestSelectInstr {
            bit_addr: mk_addr(base),
            in1_addrs: std::array::from_fn(|i| mk_addr(base + 10 + i as u32)),
            in2_addrs: std::array::from_fn(|i| mk_addr(base + 20 + i as u32)),
            out_addrs: std::array::from_fn(|i| mk_addr(base + 30 + i as u32)),
            mults: [F::TWO; 2],
        }))
    };

    let program = RecursionProgram {
        instructions: vec![mk_instr(100), mk_instr(200), mk_instr(300)],
        ..Default::default()
    };

    let preprocessed = chip.generate_preprocessed(&program).unwrap();
    assert!(preprocessed.height() >= 16);
    assert_eq!(
        preprocessed.width(),
        super::columns::NUM_DIGEST_SELECT_PREPROCESSED_COLS
    );
    // Group layout: [is_real, bit_addr, in1[2], in2[2], out[2], mults[2]] = 10 cols.
    let row0 = preprocessed.row_slice(0).unwrap();
    assert_eq!(row0[0], F::ONE); // group 0 is_real
    assert_eq!(row0[10], F::ONE); // group 1 is_real
    let row1 = preprocessed.row_slice(1).unwrap();
    assert_eq!(row1[0], F::ONE); // leftover
    assert_eq!(row1[10], F::ZERO); // empty group
}
