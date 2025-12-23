use super::LtChip;
use crate::machine::{chip::ChipBehavior, folder::SymbolicConstraintFolder};
use p3_air::{Air, BaseAir};
use p3_koala_bear::KoalaBear;

#[test]
fn test_lt_chip_simple_eval() {
    // crate a less-than chip
    let chip: LtChip<KoalaBear> = LtChip::default();

    // get the preprocessed and main trace widths
    let preprocessed_width = chip.preprocessed_width();
    let width = chip.width();

    // create a constraint builder and evaluate with the chip
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    // check the constraints and public values
    assert_eq!(builder.constraints.len(), 32);
    assert_eq!(builder.public_values.len(), 231);

    // check the looking (sending) and looked (receiving) lookups
    let (looking, looked) = builder.lookups();
    assert_eq!(looking.len(), 3);
    assert_eq!(looked.len(), 1);

    // TODO: check the details of evaluated result
}
