use super::FieldSpecificPrecompilePoseidon2Chip;
use crate::machine::{
    builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder,
};
use p3_air::{Air, BaseAir};
use p3_koala_bear::KoalaBear;

#[test]
fn test_poseidon2_permute_chip_simple_eval() {
    let chip: FieldSpecificPrecompilePoseidon2Chip<KoalaBear> =
        FieldSpecificPrecompilePoseidon2Chip::default();
    let (preprocessed_width, width) = (chip.preprocessed_width(), chip.width());
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);
    let num_public_values = builder.public_values().len();
    let num_constraints = builder.constraints().len();

    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);
    let (looking, looked) = builder.lookups();
    let num_lookups = looking.len() + looked.len();

    assert_eq!(num_constraints, 309);
    assert_eq!(num_public_values, 119);
    assert_eq!(num_lookups, 129);
}
