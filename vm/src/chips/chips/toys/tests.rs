use crate::{
    chips::chips::toys::lookup_toy::{AddLookedChip, AddLookingChip},
    machine::{builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder},
};
use p3_air::{Air, BaseAir};
use p3_koala_bear::KoalaBear;

#[test]
fn test_add_looking_chip_simple_eval() {
    let chip: AddLookingChip<KoalaBear> = AddLookingChip::default();
    let preprocessed_width = chip.preprocessed_width();
    let width = chip.width();
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 0);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 1);
}

#[test]
fn test_add_looked_chip_simple_eval() {
    let chip: AddLookedChip<KoalaBear> = AddLookedChip::default();
    let preprocessed_width = chip.preprocessed_width();
    let width = chip.width();
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 1);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 1);
}

#[test]
fn test_toy_chip_simple_eval() {
    use crate::chips::chips::toys::toy::ToyChip;
    let chip: ToyChip<KoalaBear> = ToyChip::default();
    let preprocessed_width = chip.preprocessed_width();
    let width = chip.width();
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 2);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 0);
}
