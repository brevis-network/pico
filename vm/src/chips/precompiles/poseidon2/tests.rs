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

    assert_eq!(builder.num_constraints(), 335);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 185);
}
