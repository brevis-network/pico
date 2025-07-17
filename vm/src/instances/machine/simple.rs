use crate::{
    configs::config::{Com, PcsProverData, StarkGenericConfig, Val},
    cuda_adaptor::setup_keys_gm::BaseProvingKeyCuda,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{DebugConstraintFolder, ProverConstraintFolder, VerifierConstraintFolder},
        keys::HashableKey,
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
};
use anyhow::Result;
use cudart::{memory_pools::CudaMemPool, stream::CudaStream};
use p3_air::Air;
use p3_field::PrimeField32;
use std::any::type_name;

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
    SC: StarkGenericConfig + Send + Sync + 'static,
    C: ChipBehavior<Val<SC>>,
    Val<SC>: PrimeField32,
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
            + Air<ProverConstraintFolder<SC>>,
    {
        let proofs = self
            .base_machine
            .prove_ensemble(witness.pk(), witness.records());

        // Construct the metaproof with proofs and vks where vks is a repetition of the same witness.vk
        let vks = vec![witness.vk.clone().unwrap()].into();
        MetaProof::new(proofs.into(), vks, None)
    }

    fn prove_cuda(
        &self,
        _witness: &ProvingWitness<SC, C, Vec<u8>>,
        _pk_cuda: Option<&BaseProvingKeyCuda<SC>>,
        _stream: &'static CudaStream,
        _mem_pool: &CudaMemPool,
        _dev_id: usize,
    ) -> MetaProof<SC>
    where
        C: for<'a> Air<
                DebugConstraintFolder<
                    'a,
                    <SC as StarkGenericConfig>::Val,
                    <SC as StarkGenericConfig>::Challenge,
                >,
            > + Air<ProverConstraintFolder<SC>>,
    {
        unreachable!();
    }

    /// Verify the proof.
    fn verify(&self, proof: &MetaProof<SC>, _riscv_vk: &dyn HashableKey<SC::Val>) -> Result<()>
    where
        C: for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    {
        // panic if proofs is empty
        if proof.proofs().is_empty() {
            panic!("proofs is empty");
        }

        assert_eq!(proof.vks().len(), 1);

        self.base_machine
            .verify_ensemble(&(proof.vks()[0]), &proof.proofs())?;

        Ok(())
    }
}

impl<SC, C> SimpleMachine<SC, C>
where
    SC: StarkGenericConfig + 'static,
    C: ChipBehavior<SC::Val>,
{
    pub fn new(config: SC, chips: Vec<MetaChip<SC::Val, C>>, num_public_values: usize) -> Self {
        Self {
            base_machine: BaseMachine::<SC, C>::new(config, chips, num_public_values),
        }
    }
}
