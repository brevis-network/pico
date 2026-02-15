use crate::{
    chips::chips::riscv_cpu::{columns::CpuCols, CpuChip},
    machine::{chip::ChipBehavior, folder::SymbolicConstraintFolder},
};
use p3_air::{AirBuilder, BaseAir};
use p3_koala_bear::KoalaBear;
use p3_matrix::Matrix;
use std::borrow::Borrow;

#[test]
fn test_jump_instruction_simple_eval() {
    // crate a riscv-cpu chip
    let chip: CpuChip<KoalaBear> = CpuChip::default();

    // get the preprocessed and main trace widths
    let preprocessed_width = chip.preprocessed_width();
    let width = chip.width();

    // create a constraint builder and evaluate with the chip
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    let main = builder.main();
    let (local, next) = (main.row_slice(0), main.row_slice(1));
    let local: &CpuCols<_> = (*local).borrow();
    let next: &CpuCols<_> = (*next).borrow();

    // evaluate jump instruction
    chip.eval_jump_ops(&mut builder, local, next);

    // check the constraints and public values
    assert_eq!(builder.constraints.len(), 49);
    assert_eq!(builder.public_values.len(), 231);

    // check the looking (sending) and looked (receiving) lookups
    let (looking, looked) = builder.lookups();
    assert_eq!(looking.len(), 2);
    assert_eq!(looked.len(), 0);
}
