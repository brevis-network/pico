use super::DivRemChip;
use crate::machine::{chip::ChipBehavior, folder::SymbolicConstraintFolder};
use p3_air::{Air, BaseAir};
use p3_koala_bear::KoalaBear;

#[test]
fn test_div_rem_chip_simple_eval() {
    // crate a divrem chip
    let chip: DivRemChip<KoalaBear> = DivRemChip::default();

    // get the preprocessed and main trace widths
    let preprocessed_width = chip.preprocessed_width();
    let width = chip.width();

    // create a constraint builder and evaluate with the chip
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    // check the constraints and public values
    assert_eq!(builder.constraints.len(), 131);
    assert_eq!(builder.public_values.len(), 231);

    // check the looking (sending) and looked (receiving) lookups
    let (looking, looked) = builder.lookups();
    assert_eq!(looking.len(), 16);
    assert_eq!(looked.len(), 1);

    // TODO: check the details of evaluated result
}
