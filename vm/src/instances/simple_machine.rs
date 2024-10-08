use crate::{
    compiler::program::Program,
    configs::config::{StarkGenericConfig, Val},
    emulator::riscv::record::EmulationRecord,
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip},
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, BaseVerifyingKey},
        machine::{BaseMachine, MachineBehavior},
        proof::{EnsembleProof, MetaProof},
    },
};
use anyhow::Result;
use p3_air::Air;
use std::any::type_name;

pub struct SimpleMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    /// Configuration of the machine.
    config: SC,

    /// Chips of the machine.
    chips: Vec<MetaChip<Val<SC>, C>>,

    /// Base proving machine
    base_machine: BaseMachine<SC, C>,
}

impl<SC, C> MachineBehavior<SC, C, EnsembleProof<SC>> for SimpleMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
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
        self.base_machine.num_public_values
    }

    /// Get the chips of the machine.
    fn chips(&self) -> &[MetaChip<Val<SC>, C>] {
        &self.chips
    }

    /// setup prover, verifier and keys.
    fn setup_keys(&self, program: &Program) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>) {
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
    ) -> Result<()> {
        self.base_machine
            .verify_ensemble(self.config(), self.chips(), vk, proof.proofs())?;

        Ok(())
    }
}

impl<SC, C> SimpleMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    pub fn new(config: SC, num_public_values: usize, chips: Vec<MetaChip<Val<SC>, C>>) -> Self {
        Self {
            config,
            chips,
            base_machine: BaseMachine::<SC, C>::new(num_public_values),
        }
    }
}
