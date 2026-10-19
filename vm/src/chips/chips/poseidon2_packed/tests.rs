use super::FieldSpecificPoseidon2PackedChip;
use crate::{
    compiler::recursion::{
        instruction::Instruction,
        program::RecursionProgram,
        types::{Address, Poseidon2PackedInstr},
    },
    machine::chip::ChipBehavior,
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;

type F = KoalaBear;

#[test]
fn test_poseidon2_packed_preprocessed_dimensions() {
    let chip = FieldSpecificPoseidon2PackedChip::<F>::default();

    let mk_addr = |v: u32| Address(F::from_u32(v));
    let instr = Poseidon2PackedInstr {
        input_addrs: std::array::from_fn(|i| mk_addr(10 + i as u32)),
        output_addrs: std::array::from_fn(|i| mk_addr(20 + i as u32)),
        mults: [F::TWO; 4],
    };

    let program = RecursionProgram {
        instructions: vec![Instruction::Poseidon2Packed(Box::new(instr))],
        ..Default::default()
    };

    let preprocessed = chip.generate_preprocessed(&program).unwrap();
    assert!(preprocessed.height() >= 16);
    assert_eq!(
        preprocessed.width(),
        super::columns::NUM_POSEIDON2_PACKED_PREPROCESSED_COLS
    );
    // Layout: [is_real, input[4], output[4] (addr, mult pairs)]
    let row = preprocessed.row_slice(0).unwrap();
    assert_eq!(row[0], F::ONE); // is_real
    assert_eq!(row[1], F::from_u32(10)); // input[0]
    assert_eq!(row[5], F::from_u32(20)); // output[0].addr
    assert_eq!(row[6], F::TWO); // output[0].mult
    assert_eq!(preprocessed.row_slice(1).unwrap()[0], F::ZERO); // padding
}
