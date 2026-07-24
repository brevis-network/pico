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
    let num_public_values = builder.public_values().len();
    let num_constraints = builder.constraints().len();

    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);
    let (looking, looked) = builder.lookups();
    let num_lookups = looking.len() + looked.len();

    assert_eq!(num_constraints, 148);
    assert_eq!(num_public_values, 119);
    assert_eq!(num_lookups, 32);
}
