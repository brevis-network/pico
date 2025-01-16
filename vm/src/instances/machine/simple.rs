use crate::{
    configs::config::{Com, PcsProof, PcsProverData, StarkGenericConfig, Val},
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{DebugConstraintFolder, ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseVerifyingKey,
        machine::{BaseMachine, MachineBehavior},
        proof::{BaseProof, MetaProof},
        witness::ProvingWitness,
    },
};
use anyhow::Result;
use p3_air::Air;
use p3_field::PrimeField32;
use std::{any::type_name, time::Instant};
use tracing::info;

pub struct SimpleMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    /// Base proving machine
    base_machine: BaseMachine<SC, C>,
}

impl<SC, C> MachineBehavior<SC, C, Vec<u8>> for SimpleMachine<SC, C>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: PrimeField32,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    BaseProof<SC>: Send + Sync,
    PcsProof<SC>: Send + Sync,
    BaseVerifyingKey<SC>: Send + Sync,
    C: ChipBehavior<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
{
    /// Get the name of the machine.
    fn name(&self) -> String {
        format!("SimpleMachine<{}>", type_name::<SC>())
    }

    /// Get the base machine
    fn base_machine(&self) -> &BaseMachine<SC, C> {
        &self.base_machine
    }

    /// Get the prover of the machine.
    fn prove(&self, witness: &ProvingWitness<SC, C, Vec<u8>>) -> MetaProof<SC>
    where
        C: for<'a> Air<DebugConstraintFolder<'a, SC::Val, SC::Challenge>>
            + for<'a> Air<ProverConstraintFolder<'a, SC>>,
    {
        info!("PERF-machine=simple");
        let begin = Instant::now();

        let proofs = self
            .base_machine
            .prove_ensemble(witness.pk(), witness.records());

        info!("PERF-step=prove-user_time={}", begin.elapsed().as_millis());

        // Construct the metaproof with proofs and vks where vks is a repetition of the same witness.vk
        let vks = vec![witness.vk.clone().unwrap()].into();
        MetaProof::new(proofs.into(), vks, None)
    }

    /// Verify the proof.
    fn verify(&self, proof: &MetaProof<SC>) -> Result<()>
    where
        C: for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    {
        // panic if proofs is empty
        info!("PERF-machine=simple");
        let begin = Instant::now();
        if proof.proofs().is_empty() {
            panic!("proofs is empty");
        }

        assert_eq!(proof.vks().len(), 1);

        self.base_machine
            .verify_ensemble(&(proof.vks()[0]), &proof.proofs())?;

        info!("PERF-step=verify-user_time={}", begin.elapsed().as_millis(),);

        Ok(())
    }
}

impl<SC, C> SimpleMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
{
    pub fn new(config: SC, chips: Vec<MetaChip<SC::Val, C>>, num_public_values: usize) -> Self {
        info!("PERF-machine=simple");
        Self {
            base_machine: BaseMachine::<SC, C>::new(config, chips, num_public_values),
        }
    }
}
