use crate::{
    chips::chips::riscv_memory::read_write::MemoryReadWriteChip,
    machine::{builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder},
};
use p3_air::{Air, BaseAir};
use p3_koala_bear::KoalaBear;

#[test]
fn test_memory_read_write_chip_simple_eval() {
    let chip: MemoryReadWriteChip<KoalaBear> = MemoryReadWriteChip::default();
    let preprocessed_width = chip.preprocessed_width();
    let width = chip.width();
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 85);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 16);
}
