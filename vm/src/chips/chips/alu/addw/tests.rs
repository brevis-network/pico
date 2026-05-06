use crate::{
    chips::chips::alu::addw::AddwChip,
    machine::{builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder},
};
use p3_air::{Air, BaseAir};
use p3_koala_bear::KoalaBear;

#[test]
fn test_addw_chip_simple_eval() {
    let chip: AddwChip<KoalaBear> = AddwChip::default();
    let preprocessed_width = chip.preprocessed_width();
    let width = chip.width();
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 6);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 4);
}
