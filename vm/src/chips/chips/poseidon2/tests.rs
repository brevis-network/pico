use crate::{
    chips::chips::poseidon2::FieldSpecificPoseidon2Chip,
    machine::{builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder},
};
use p3_air::{Air, BaseAir};
use p3_koala_bear::KoalaBear;

#[test]
fn test_poseidon2_chip_simple_eval() {
    let chip: FieldSpecificPoseidon2Chip<KoalaBear> = FieldSpecificPoseidon2Chip::default();
    let preprocessed_width = chip.preprocessed_width();
    let width = chip.width();
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 148);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 32);
}
