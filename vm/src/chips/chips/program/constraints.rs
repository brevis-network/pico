use crate::{
    chips::chips::{
        cpu::{
            instruction::columns::InstructionCols, opcode_selector::columns::OpcodeSelectorCols,
        },
        program::{
            columns::{ProgramMultiplicityCols, ProgramPreprocessedCols, NUM_PROGRAM_MULT_COLS},
            ProgramChip,
        },
    },
    machine::{
        builder::ChipBuilder,
        lookup::{LookupType, SymbolicLookup},
    },
};
use core::borrow::Borrow;
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::Matrix;
use std::iter::once;

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
        let preprocessed = builder.preprocessed();

        let prep_local = preprocessed.row_slice(0);
        let prep_local: &ProgramPreprocessedCols<CB::Var> = (*prep_local).borrow();
        let mult_local = main.row_slice(0);
        let mult_local: &ProgramMultiplicityCols<CB::Var> = (*mult_local).borrow();

        // Contrain the interaction with CPU table.
        self.looked_program(
            builder,
            prep_local.pc,
            prep_local.instruction,
            prep_local.selectors,
            mult_local.chunk,
            mult_local.multiplicity,
        );
    }
}

impl<F: Field> ProgramChip<F> {
    fn looked_program<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        pc: impl Into<CB::Expr>,
        instruction: InstructionCols<impl Into<CB::Expr> + Copy>,
        selectors: OpcodeSelectorCols<impl Into<CB::Expr> + Copy>,
        chunk: impl Into<CB::Expr> + Copy,
        multiplicity: impl Into<CB::Expr>,
    ) {
        let values: Vec<CB::Expr> = once(pc.into())
            .chain(once(instruction.opcode.into()))
            .chain(instruction.into_iter().map(|x| x.into()))
            .chain(selectors.into_iter().map(|x| x.into()))
            .chain(once(chunk.into()))
            .collect();

        builder.looked(SymbolicLookup::new(
            values,
            multiplicity.into(),
            LookupType::Program,
        ))
    }
}
