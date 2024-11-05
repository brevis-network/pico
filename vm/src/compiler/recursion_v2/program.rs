use super::instruction::Instruction;
use crate::{compiler::program::ProgramBehavior, machine::chip::ChipBehavior};
use backtrace::Backtrace;
use p3_field::Field;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecursionProgram<F> {
    pub instructions: Vec<Instruction<F>>,
    pub total_memory: usize,
    #[serde(skip)]
    pub traces: Vec<Option<Backtrace>>,
}

impl<F: Field> ProgramBehavior<F> for RecursionProgram<F> {
    fn pc_start(&self) -> F {
        F::zero()
    }

    fn default() -> Self {
        Self {
            instructions: Vec::new(),
            total_memory: 0,
            traces: Vec::new(),
        }
    }

    fn clone(&self) -> Self {
        Self {
            instructions: self.instructions.clone(),
            total_memory: 0,
            traces: self.traces.clone(),
        }
    }
}

impl<F: Field> RecursionProgram<F> {
    #[inline]
    pub fn fixed_log2_rows<A: ChipBehavior<F>>(&self, air: &A) -> Option<usize> {
        // TODO, support shape
        None
    }
}
