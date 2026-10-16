use crate::{
    chips::chips::{
        riscv_cpu::{
            instruction::columns::InstructionCols, opcode_selector::columns::OpcodeSelectorCols,
        },
        riscv_program::{
            columns::{ProgramMultiplicityCols, ProgramPreprocessedCols, NUM_PROGRAM_MULT_COLS},
            ProgramChip,
        },
    },
    compiler::addr::Pc,
    machine::{
        builder::ChipBuilder,
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
};
use core::borrow::Borrow;
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::Field;

impl<F: Field> BaseAir<F> for ProgramChip<F> {
    fn width(&self) -> usize {
        NUM_PROGRAM_MULT_COLS
    }
}

impl<F: Field, CB: ChipBuilder<F>> Air<CB> for ProgramChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let preprocessed = builder.preprocessed().clone();

        let prep_local = preprocessed.current_slice();
        let prep_local: &ProgramPreprocessedCols<CB::Var> = (*prep_local).borrow();
        let mult_local = main.current_slice();
        let mult_local: &ProgramMultiplicityCols<CB::Var> = (*mult_local).borrow();

        // Contrain the interaction with CPU table.
        self.looked_program(
            builder,
            prep_local.pc,
            prep_local.instruction,
            prep_local.selectors,
            prep_local.pc_carry,
            mult_local.multiplicity,
        );
    }
}

impl<F: Field> ProgramChip<F> {
    /// Receiving end of the Program lookup. The message is `pc(2) ++ [opcode] ++
    /// InstructionCols(9) ++ OpcodeSelectorCols(13) ++ [pc_carry]`, 26 elements, assembled from
    /// the same `into_iter` implementations as the Cpu chip's send side
    /// (`riscv_cpu/constraints.rs`, `looking_program`), so a layout change on either type moves
    /// both ends together. The trailing `pc_carry` is a preprocessed column, so the Cpu row's
    /// carry witness is pinned to the table's `[pc[0] >= 0xFFFC]`.
    fn looked_program<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        pc: Pc<CB::Var>,
        instruction: InstructionCols<impl Into<CB::Expr> + Copy>,
        selectors: OpcodeSelectorCols<impl Into<CB::Expr> + Copy>,
        pc_carry: impl Into<CB::Expr>,
        multiplicity: impl Into<CB::Expr>,
    ) {
        let values: Vec<CB::Expr> = pc
            .into_iter()
            .map(|x| x.into())
            .chain(std::iter::once(instruction.opcode.into()))
            .chain(instruction.into_iter().map(|x| x.into()))
            .chain(selectors.into_iter().map(|x| x.into()))
            .chain(std::iter::once(pc_carry.into()))
            .collect();

        builder.looked(SymbolicLookup::new(
            values,
            multiplicity.into(),
            LookupType::Program,
            LookupScope::Regional,
        ))
    }
}
