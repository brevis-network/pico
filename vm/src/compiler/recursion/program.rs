use super::{instruction::Instruction, prep_rows::PrepRowCounts};
use crate::{
    compiler::program::ProgramBehavior,
    instances::compiler::shapes::recursion_shape::RecursionPadShape, machine::septic::SepticDigest,
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
    /// Lazy [`PrepRowCounts`] over `instructions`; read through [`Self::prep_row_counts`].
    /// Not serialized — deriving it on demand leaves no way for the two to disagree.
    #[serde(skip)]
    pub(crate) prep_row_counts_cache: std::sync::OnceLock<PrepRowCounts>,

    /// Instruction ranges the recursion emulator may replay independently, recorded by the only
    /// builder that knows them; empty on a program built any other way, and the emulator then runs
    /// serially. Not serialized: a property of how the program was built, so a program that
    /// arrives without it must fall back rather than trust a stale range.
    #[serde(skip)]
    pub child_spans: Vec<(usize, usize)>,

    /// Backing store for [`Self::const_write_positions`]. A pure derivation of `instructions`,
    /// like `prep_row_counts_cache`, and not serialized for the same reason.
    #[serde(skip)]
    pub(crate) const_writes_cache: std::sync::OnceLock<Vec<u32>>,
}

impl<F: Field> ProgramBehavior<F> for RecursionProgram<F> {
    fn pc_start(&self) -> [F; 3] {
        [F::ZERO; 3]
    }

    fn clone(&self) -> Self {
        Clone::clone(self)
    }

    fn initial_global_cumulative_sum(&self) -> SepticDigest<F> {
        SepticDigest::<F>::zero()
    }
}

impl<F> RecursionProgram<F> {
    /// Positions of the instructions that write a constant, tallied on first call.
    ///
    /// Cached, and `instructions` is public: editing a program after this has been called
    /// leaves the cache describing the old one. Build the program, then read it.
    pub fn const_write_positions(&self) -> &[u32] {
        self.const_writes_cache.get_or_init(|| {
            self.instructions
                .iter()
                .enumerate()
                .filter(|(_, i)| crate::emulator::recursion::emulator::is_const_write(i))
                .map(|(i, _)| i as u32)
                .collect()
        })
    }

    /// Unpadded preprocessed row counts for every MLE recursion chip, tallied on first call in a
    /// single pass over `instructions` and cached.
    pub(crate) fn prep_row_counts(&self) -> &PrepRowCounts {
        self.prep_row_counts_cache
            .get_or_init(|| PrepRowCounts::from_instructions(&self.instructions))
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

    /// Padded preprocessed height for `chip_name` given its unpadded row count: the declared
    /// shape's height if the program carries a shape, else the next power of two above a 16-row
    /// floor. `machine::utils::padded_row_count` applies the same floor-then-check and so agrees
    /// by construction; `chips::utils::next_power_of_two` does not apply the floor before checking
    /// a declared shape, so a shape below 2^4 would be rejected here and accepted there. Nothing
    /// is wired below 2^4.
    ///
    /// **An undersized shape must be rejected here, not rounded up.** Callers size a buffer from
    /// this and then fill it from a loop bounded by the instruction count, so a `1 << log2_rows`
    /// leaves that loop writing outside the slice it was given. Rounding up would hide the mismatch
    /// declared shape and the program it was declared for, which is exactly what the caller wants
    /// to hear about. Keeping the assert in one place is why this is a method rather than a match
    /// repeated per chip.
    #[inline]
    pub(crate) fn padded_prep_rows(&self, chip_name: &String, nb_rows: usize) -> usize {
        let nb_rows = nb_rows.max(16);
        match self.fixed_log2_rows(chip_name) {
            Some(log2_rows) => {
                let padded = 1usize << log2_rows;
                assert!(
                    padded >= nb_rows,
                    "fixed_log2_rows too small for {chip_name}: 2^{log2_rows}={padded} < \
                     {nb_rows} real rows"
                );
                padded
            }
            None => nb_rows.next_power_of_two(),
        }
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
                Instruction::AssertZeroExt(_) => "AssertZeroExt",
                Instruction::FracFold(_) => "FracFold",
                Instruction::UnivariateFold(_) => "UnivariateFold",
                Instruction::MleOpen(_) => "MleOpen",
                Instruction::LagrangeEvalD2(_) => "LagrangeEvalD2",
                Instruction::GkrSumcheckRound(_) => "GkrSumcheckRound",
                Instruction::ExtDotProduct(_) => "ExtDotProduct",
                Instruction::HornerEval(_) => "HornerEval",
                Instruction::DigestSelect(_) => "DigestSelect",
                Instruction::BinaryFoldStep(_) => "BinaryFoldStep",
                Instruction::PackBlock(_) => "PackBlock",
                Instruction::UnpackBlock(_) => "UnpackBlock",
                Instruction::Poseidon2Packed(_) => "Poseidon2Packed",
                Instruction::ExpBitsLen(_) => "ExpBitsLen",
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
