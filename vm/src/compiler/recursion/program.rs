use super::instruction::Instruction;
use crate::compiler::program::ProgramBehavior;
use backtrace::Backtrace;
use p3_field::Field;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecursionProgram<F> {
    pub instructions: Vec<Instruction<F>>,
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
            traces: Vec::new(),
        }
    }

    fn clone(&self) -> Self {
        Self {
            instructions: self.instructions.clone(),
            traces: self.traces.clone(),
        }
    }
}
