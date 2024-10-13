use crate::{
    configs::config::{StarkGenericConfig, Val},
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, BaseVerifyingKey},
        machine::{BaseMachine, MachineBehavior},
        proof::{EnsembleProof, MetaProof},
    },
};
use p3_air::Air;
use p3_maybe_rayon::prelude::ParallelIterator;
use std::any::type_name;

pub struct SimpleRecursionMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    /// The STARK settings for the recursion STARK.
    config: SC,

    /// The chips that make up the recursion STARK machine, in order of their execution.
    chips: Vec<MetaChip<Val<SC>, C>>,

    /// Base proving machine
    base_machine: BaseMachine<SC, C>,
}

impl<SC, C> MachineBehavior<SC, C, EnsembleProof<SC>> for SimpleRecursionMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    /// Get the name of the machine.
    fn name(&self) -> String {
        format!("SimpleRecursionMachine<{}>", type_name::<SC>())
    }

    fn num_public_values(&self) -> usize {
        self.base_machine.num_public_values
    }

    /// Get the configuration of the machine.
    fn config(&self) -> &SC {
        &self.config
    }

    /// Get the chips of the machine.
    fn chips(&self) -> &[MetaChip<Val<SC>, C>] {
        &self.chips
    }

    /// Setup prover, verifier and keys.
    fn setup_keys(
        &self,
        program: &<C as ChipBehavior<<SC as StarkGenericConfig>::Val>>::Program,
    ) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>) {
        self.base_machine
            .setup_keys(self.config(), self.chips(), program)
    }

    /// Get the prover of the machine.
    fn prove(
        &self,
        pk: &BaseProvingKey<SC>,
        records: &[C::Record],
    ) -> MetaProof<SC, EnsembleProof<SC>> {
        let proofs = self
            .base_machine
            .prove_ensemble(self.config(), self.chips(), pk, records);

        MetaProof::new(self.config(), EnsembleProof::new(proofs))
    }

    /// Verify the proof.
    fn verify(
        &self,
        vk: &BaseVerifyingKey<SC>,
        proof: &MetaProof<SC, EnsembleProof<SC>>,
    ) -> anyhow::Result<()> {
        self.base_machine
            .verify_ensemble(self.config(), self.chips(), vk, proof.proofs())?;

        Ok(())
    }
}

impl<SC, C> SimpleRecursionMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    /// Creates a new [`SimpleRecursionMachine`].
    pub fn new(config: SC, num_public_values: usize, chips: Vec<MetaChip<Val<SC>, C>>) -> Self {
        Self {
            config,
            chips,
            base_machine: BaseMachine::<SC, C>::new(num_public_values),
        }
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
}
