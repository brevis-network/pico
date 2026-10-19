use super::PackBlockChip;
use crate::{
    compiler::recursion::{
        instruction::Instruction,
        program::RecursionProgram,
        types::{Address, PackBlockEvent, PackBlockInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::chip::ChipBehavior,
    primitives::consts::PACK_BLOCK_DATAPAR,
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;

type F = KoalaBear;

#[test]
fn test_pack_block_trace_values() {
    let chip = PackBlockChip::<F>::default();

    let mut record = RecursionRecord::<F>::default();
    // DATAPAR+1 events -> 2 rows, second row partially filled.
    for e in 0..PACK_BLOCK_DATAPAR as u32 + 1 {
        record.pack_block_events.push(PackBlockEvent {
            lanes: std::array::from_fn(|i| F::from_u32(10 * e + i as u32)),
        });
    }

    let mut output = RecursionRecord::<F>::default();
    let trace = chip.generate_main(&record, &mut output);
    assert!(trace.height() >= 16);
    assert_eq!(trace.width(), super::columns::NUM_PACK_BLOCK_COLS);
    let row0 = trace.row_slice(0).unwrap();
    assert_eq!(row0[0], F::ZERO); // group 0 lane 0 = 0
    assert_eq!(row0[4 + 1], F::from_u32(11)); // group 1 lane 1
    let row1 = trace.row_slice(1).unwrap();
    assert_eq!(row1[0], F::from_u32(10 * PACK_BLOCK_DATAPAR as u32));
}

#[test]
fn test_pack_block_preprocessed_groups() {
    let chip = PackBlockChip::<F>::default();

    let mk = |v: u32| Address(F::from_u32(v));
    let instrs: Vec<Instruction<F>> = (0..PACK_BLOCK_DATAPAR as u32 + 1)
        .map(|e| {
            Instruction::PackBlock(Box::new(PackBlockInstr {
                in_addrs: std::array::from_fn(|i| mk(100 * e + i as u32)),
                out_addr: mk(1000 + e),
                mult: F::ONE,
            }))
        })
        .collect();

    let program = RecursionProgram {
        instructions: instrs,
        ..Default::default()
    };

    let preprocessed = chip.generate_preprocessed(&program).unwrap();
    assert_eq!(
        preprocessed.width(),
        super::columns::NUM_PACK_BLOCK_PREPROCESSED_COLS
    );
    // Group layout: [is_real, in_addrs[4], out_addr, mult] = 7 cols per group.
    let row0 = preprocessed.row_slice(0).unwrap();
    assert_eq!(row0[0], F::ONE); // group 0 is_real
    assert_eq!(row0[7], F::ONE); // group 1 is_real
    let row1 = preprocessed.row_slice(1).unwrap();
    assert_eq!(row1[0], F::ONE); // leftover group is_real
    assert_eq!(row1[7], F::ZERO); // empty group
}
