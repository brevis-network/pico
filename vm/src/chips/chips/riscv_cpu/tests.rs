use crate::{
    chips::chips::riscv_cpu::CpuChip,
    machine::{
        builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder,
        lookup::LookupType,
    },
};
use p3_air::{Air, BaseAir};
use p3_koala_bear::KoalaBear;

#[test]
fn test_cpu_chip_simple_eval() {
    let chip: CpuChip<KoalaBear> = CpuChip::default();
    let preprocessed_width = chip.preprocessed_width();
    let width = chip.width();
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 217);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 35);

    let (looking, _) = builder.lookups();
    assert!(looking
        .iter()
        .any(|lookup| lookup.kind == LookupType::Memory && lookup.values.len() == 27));
}
