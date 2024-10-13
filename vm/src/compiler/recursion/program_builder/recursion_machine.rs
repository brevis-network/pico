use crate::{
    configs::config::{StarkGenericConfig, Val},
    machine::{
        chip::{ChipBehavior, MetaChip},
        proof::BaseProof,
    },
};
use itertools::Itertools;
use p3_maybe_rayon::prelude::ParallelIterator;

/// A STARK for proving a recursion machine.
// TODO: Unify with SimpleMachine?
pub struct RecursionMachine<SC: StarkGenericConfig, C> {
    /// The STARK settings for the recursion STARK.
    config: SC,
    /// The chips that make up the recursion STARK machine, in order of their execution.
    chips: Vec<MetaChip<Val<SC>, C>>,

    /// The number of public values elements that the machine uses
    num_pv_elts: usize,
}

impl<SC: StarkGenericConfig, A> RecursionMachine<SC, A> {
    /// Creates a new [`RecursionMachine`].
    pub const fn new(config: SC, chips: Vec<MetaChip<Val<SC>, A>>, num_pv_elts: usize) -> Self {
        Self {
            config,
            chips,
            num_pv_elts,
        }
    }
}

impl<SC: StarkGenericConfig, C: ChipBehavior<Val<SC>>> RecursionMachine<SC, C> {
    /// Get an array containing a `ChipRef` for all the chips of this RISC-V STARK machine.
    pub fn chips(&self) -> &[MetaChip<SC::Val, C>] {
        &self.chips
    }

    /// Returns the number of public values elements.
    pub const fn num_pv_elts(&self) -> usize {
        self.num_pv_elts
    }

    /// Returns the id of all chips in the machine that have preprocessed columns.
    pub fn preprocessed_chip_ids(&self) -> Vec<usize> {
        self.chips
            .iter()
            .enumerate()
            .filter(|(_, chip)| chip.preprocessed_width() > 0)
            .map(|(i, _)| i)
            .collect()
    }

    /// Returns the indices of the chips in the machine that are included in the given chunk.
    pub fn chips_sorted_indices(&self, proof: &BaseProof<SC>) -> Vec<Option<usize>> {
        self.chips()
            .iter()
            .map(|chip| proof.main_chip_ordering.get(&chip.name()).copied())
            .collect()
    }

    /// Returns the config of the machine.
    pub const fn config(&self) -> &SC {
        &self.config
    }
}
