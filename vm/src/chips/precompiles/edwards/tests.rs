use super::ed_decompress::EdDecompressChip;
use crate::{
    chips::gadgets::curves::edwards::ed25519::Ed25519,
    machine::{builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder},
};
use p3_air::{Air, BaseAir};
use p3_koala_bear::KoalaBear;

#[test]
#[ignore = "pending u64 upgrade / fix for limbs_from_prev_access"]
fn test_ed_decompress_chip_simple_eval() {
    let chip: EdDecompressChip<KoalaBear, Ed25519> = EdDecompressChip::default();
    let (preprocessed_width, width) = (chip.preprocessed_width(), chip.width());
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 324);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 330);
}
