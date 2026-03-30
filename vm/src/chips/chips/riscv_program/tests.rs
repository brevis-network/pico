use crate::{
    chips::chips::riscv_program::ProgramChip,
    machine::{builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder},
};
use p3_air::{Air, BaseAir};
use p3_koala_bear::KoalaBear;

#[test]
fn test_program_chip_simple_eval() {
    let chip: ProgramChip<KoalaBear> = ProgramChip::default();
    let preprocessed_width = chip.preprocessed_width();
    let width = chip.width();
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 0);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 1);
}
