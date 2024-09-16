use anyhow::Result;
use p3_air::Air;
use pico_compiler::program::Program;
use pico_configs::config::{StarkGenericConfig, Val};
use pico_emulator::record::EmulationRecord;
use pico_machine::{
    chip::{ChipBehavior, ChipBuilder, MetaChip},
    folder::{ProverConstraintFolder, VerifierConstraintFolder},
    keys::{BaseProvingKey, BaseVerifyingKey},
    machine::{BaseMachine, MachineBehavior},
    proof::{EnsembleProof, MetaProof},
};
use std::any::type_name;

pub struct RiscvMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    config: SC,

    chips: Vec<MetaChip<Val<SC>, C>>,

    base_machine: BaseMachine<SC, C>,
}

impl<SC, C> MachineBehavior<SC, C, EnsembleProof<SC>> for RiscvMachine<SC, C>
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

    /// Get the chips of the machine.
    fn chips(&self) -> &[MetaChip<Val<SC>, C>] {
        &self.chips
    }

    /// setup prover, verifier and keys.
    fn setup_keys(&self, program: &Program) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>) {
        // todo: implement specific key setup logic here
        self.base_machine
            .setup_keys(self.config(), self.chips(), program)
    }

    /// Get the prover of the machine.
    fn prove(
        &self,
        pk: &BaseProvingKey<SC>,
        records: &[EmulationRecord],
    ) -> MetaProof<SC, EnsembleProof<SC>> {
        // todo: implement specific proving logic here

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
        // todo: implement specific verification logic here

        Ok(())
    }
}

impl<SC, C> RiscvMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    pub fn new(config: SC, chips: Vec<MetaChip<Val<SC>, C>>) -> Self {
        Self {
            config,
            chips,
            base_machine: BaseMachine::<SC, C>::new(),
        }
    }
}
