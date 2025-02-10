use super::instruction::Instruction;
use crate::{
    compiler::program::ProgramBehavior,
    instances::compiler::shapes::compress_shape::RecursionPadShape, machine::septic::SepticDigest,
};
use backtrace::Backtrace;
use hashbrown::HashMap;
use p3_field::Field;
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecursionProgram<F> {
    pub instructions: Vec<Instruction<F>>,
    pub total_memory: usize,
    #[serde(skip)]
    pub traces: Vec<Option<Backtrace>>,
    pub shape: Option<RecursionPadShape>,
}

impl<F: Field> ProgramBehavior<F> for RecursionProgram<F> {
    fn pc_start(&self) -> F {
        F::ZERO
    }

    fn clone(&self) -> Self {
        Self {
            instructions: self.instructions.clone(),
            total_memory: 0,
            traces: self.traces.clone(),
            shape: self.shape.clone(),
        }
    }

    fn initial_global_cumulative_sum(&self) -> SepticDigest<F> {
        SepticDigest::<F>::zero()
    }
}

impl<F: Field> RecursionProgram<F> {
    #[inline]
    pub fn fixed_log2_rows(&self, chip_name: &String) -> Option<usize> {
        self.shape
            .as_ref()
            .map(|shape| {
                shape
                    .inner
                    .get(chip_name)
                    .unwrap_or_else(|| panic!("Chip {} not found in specified shape", chip_name))
            })
            .copied()
    }

    // compute number of each type of instructions in the program
    pub fn stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        for instr in &self.instructions {
            let key = match instr {
                Instruction::BaseAlu(_) => "BaseAlu",
                Instruction::ExtAlu(_) => "ExtAlu",
                Instruction::Mem(_) => "Mem",
                Instruction::Poseidon2(_) => "Poseidon2",
                Instruction::Select(_) => "Select",
                Instruction::ExpReverseBitsLen(_) => "ExpReverseBitsLen",
                Instruction::BatchFRI(_) => "BatchFRI",
                Instruction::HintBits(_) => "HintBits",
                Instruction::Print(_) => "Print",
                Instruction::HintExt2Felts(_) => "HintExt2Felts",
                Instruction::CommitPublicValues(_) => "CommitPublicValues",
                Instruction::HintAddCurve(_) => "HintAddCurve",
                Instruction::Hint(_) => "Hint",
            };
            *stats.entry(key.to_string()).or_insert(0) += 1;
        }
        stats
    }

    // print stats of the program
    pub fn print_stats(&self) {
        let stats = self.stats();
        debug!("Program stats:");
        for (key, value) in stats {
            debug!("   |- {:<26}: {}", key, value);
        }
    }
}
