//! Recursion lookup associating builder functions

use super::ChipBuilder;
use crate::{
    chips::chips::recursion_cpu::{InstructionCols, OpcodeSelectorCols},
    machine::lookup::{LookupScope, LookupType, SymbolicLookup},
};
use p3_field::Field;
use std::iter::once;

pub trait RecursionLookupBuilder<F: Field>: ChipBuilder<F> {
    fn recursion_looking_program<E: Into<Self::Expr> + Copy>(
        &mut self,
        pc: impl Into<Self::Expr>,
        instruction: InstructionCols<E>,
        selectors: OpcodeSelectorCols<E>,
        is_real: impl Into<Self::Expr>,
    ) {
        let program_interaction_vals = once(pc.into())
            .chain(instruction.into_iter().map(|x| x.into()))
            .chain(selectors.into_iter().map(|x| x.into()))
            .collect::<Vec<_>>();
        self.looking(SymbolicLookup::new(
            program_interaction_vals,
            is_real.into(),
            LookupType::Program,
            LookupScope::Global,
        ));
    }

    fn recursion_looked_program<E: Into<Self::Expr> + Copy>(
        &mut self,
        pc: impl Into<Self::Expr>,
        instruction: InstructionCols<E>,
        selectors: OpcodeSelectorCols<E>,
        is_real: impl Into<Self::Expr>,
    ) {
        let program_interaction_vals = once(pc.into())
            .chain(instruction.into_iter().map(|x| x.into()))
            .chain(selectors.into_iter().map(|x| x.into()))
            .collect::<Vec<_>>();
        self.looked(SymbolicLookup::new(
            program_interaction_vals,
            is_real.into(),
            LookupType::Program,
            LookupScope::Global,
        ));
    }

    fn recursion_looking_table<E: Into<Self::Expr> + Clone>(
        &mut self,
        opcode: impl Into<Self::Expr>,
        table: &[E],
        is_real: impl Into<Self::Expr>,
    ) {
        let table_interaction_vals = table.iter().map(|x| x.clone().into());
        let values = once(opcode.into()).chain(table_interaction_vals).collect();
        self.looking(SymbolicLookup::new(
            values,
            is_real.into(),
            LookupType::Syscall,
            LookupScope::Regional,
        ));
    }

    fn recursion_looked_table<E: Into<Self::Expr> + Clone>(
        &mut self,
        opcode: impl Into<Self::Expr>,
        table: &[E],
        is_real: impl Into<Self::Expr>,
    ) {
        let table_interaction_vals = table.iter().map(|x| x.clone().into());
        let values = once(opcode.into()).chain(table_interaction_vals).collect();
        self.looked(SymbolicLookup::new(
            values,
            is_real.into(),
            LookupType::Syscall,
            LookupScope::Regional,
        ));
    }
}
