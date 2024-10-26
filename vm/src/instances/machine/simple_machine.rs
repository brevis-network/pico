use crate::{
    configs::config::StarkGenericConfig,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, BaseVerifyingKey},
        machine::{BaseMachine, MachineBehavior},
        proof::{BaseProof, EnsembleProof, MetaProof},
        witness::ProvingWitness,
    },
};
use anyhow::Result;
use hashbrown::HashMap;
use itertools::Itertools;
use log::info;
use p3_air::Air;
use std::{any::type_name, time::Instant};

pub struct SimpleMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    /// Configuration of the machine.
    config: SC,

    /// Chips of the machine.
    chips: Vec<MetaChip<SC::Val, C>>,

    /// Base proving machine
    base_machine: BaseMachine<SC, C>,
}

impl<SC, C> MachineBehavior<SC, C, SC, C, EnsembleProof<SC>, Vec<u8>> for SimpleMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    /// Get the name of the machine.
    fn name(&self) -> String {
        format!("SimpleMachine<{}>", type_name::<SC>())
    }

    /// Get the configuration of the machine.
    fn config(&self) -> &SC {
        &self.config
    }

    /// Get the number of public values.
    fn num_public_values(&self) -> usize {
        self.base_machine.num_public_values()
    }

    /// Get the chips of the machine.
    fn chips(&self) -> &[MetaChip<SC::Val, C>] {
        &self.chips
    }

    /// setup prover, verifier and keys.
    fn setup_keys(
        &self,
        program: &<C as ChipBehavior<<SC as StarkGenericConfig>::Val>>::Program,
    ) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>) {
        info!("PERF-machine=simple");
        let begin = Instant::now();

        let (pk, vk) = self
            .base_machine
            .setup_keys(self.config(), self.chips(), program);

        info!(
            "PERF-step=setup_keys-user_time={}",
            begin.elapsed().as_millis(),
        );

        (pk, vk)
    }

    /// Get the prover of the machine.
    fn prove(
        &self,
        pk: &BaseProvingKey<SC>,
        witness: &ProvingWitness<SC, C, SC, C, Vec<u8>>,
    ) -> MetaProof<SC, EnsembleProof<SC>> {
        info!("PERF-machine=simple");
        let begin = Instant::now();

        let proofs =
            self.base_machine
                .prove_ensemble(self.config(), self.chips(), pk, witness.records());

        info!("PERF-step=prove-user_time={}", begin.elapsed().as_millis());

        let proof = MetaProof::new(self.config(), EnsembleProof::new(proofs));

        proof
    }

    /// Verify the proof.
    fn verify(
        &self,
        vk: &BaseVerifyingKey<SC>,
        proof: &MetaProof<SC, EnsembleProof<SC>>,
    ) -> Result<()> {
        // panic if proofs is empty
        info!("PERF-machine=simple");
        let begin = Instant::now();
        if proof.proofs().is_empty() {
            panic!("proofs is empty");
        }
        self.base_machine
            .verify_ensemble(self.config(), self.chips(), vk, proof.proofs())?;

        info!("PERF-step=verify-user_time={}", begin.elapsed().as_millis(),);

        Ok(())
    }
}

impl<SC, C> SimpleMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    pub fn new(config: SC, num_public_values: usize, chips: Vec<MetaChip<SC::Val, C>>) -> Self {
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
