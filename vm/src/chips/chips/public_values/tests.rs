use super::*;
use crate::machine::{
    builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder,
};
use p3_air::{Air, BaseAir};
use p3_koala_bear::KoalaBear;

#[test]
fn test_public_values_chip_simple_eval() {
    let chip: PublicValuesChip<KoalaBear> = PublicValuesChip::default();
    let preprocessed_width = chip.preprocessed_width();
    let width = chip.width();
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 8);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 1);
}
