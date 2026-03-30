use super::*;
use crate::machine::{
    builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder,
};
use p3_air::{Air, BaseAir};
use p3_koala_bear::KoalaBear;

#[test]
fn test_batch_fri_chip_simple_eval() {
    let chip: BatchFRIChip<KoalaBear> = BatchFRIChip::default();
    let preprocessed_width = chip.preprocessed_width();
    let width = chip.width();
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 12);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 4);
}
