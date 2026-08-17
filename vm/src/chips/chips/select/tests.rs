use crate::{
    chips::chips::select::SelectChip,
    machine::{builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder},
};
use p3_air::{Air, BaseAir};
use p3_koala_bear::KoalaBear;

#[test]
fn test_select_chip_simple_eval() {
    let chip: SelectChip<KoalaBear> = SelectChip::default();
    let preprocessed_width = chip.preprocessed_width();
    let width = chip.width();
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 6);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 10);
}
