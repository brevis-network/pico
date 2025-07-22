use crate::{
    compiler::recursion::{circuit::hash::FieldHasher, program::RecursionProgram},
    configs::config::{Com, PcsProof, PcsProverData, StarkGenericConfig, Val},
    emulator::{
        record::RecordBehavior,
        recursion::{emulator::RecursionRecord, public_values::RecursionPublicValues},
    },
    instances::compiler::vk_merkle::{stdin::RecursionStdinVariant, HasStaticVkManager},
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{DebugConstraintFolder, ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseVerifyingKey, HashableKey},
        machine::{BaseMachine, MachineBehavior},
        proof::{BaseProof, MetaProof},
        utils::{assert_recursion_public_values_valid, assert_riscv_vk_digest},
        witness::ProvingWitness,
    },
    primitives::consts::EXTENSION_DEGREE,
};
use p3_air::Air;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{extension::BinomiallyExtendable, PrimeField32, TwoAdicField};
use std::{any::type_name, borrow::Borrow};
use tracing::{debug, debug_span, instrument};

pub struct CompressMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<
        Val<SC>,
        Program = RecursionProgram<Val<SC>>,
        Record = RecursionRecord<Val<SC>>,
    >,
{
    base_machine: BaseMachine<SC, C>,
}

impl<F, SC, C> MachineBehavior<SC, C, RecursionStdinVariant<'_, SC, C>> for CompressMachine<SC, C>
where
    F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + TwoAdicField,
    SC: StarkGenericConfig<Val = F, Domain = TwoAdicMultiplicativeCoset<F>>
        + Send
        + Sync
        + FieldHasher<Val<SC>>
        + HasStaticVkManager
        + 'static,
    Val<SC>: PrimeField32,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    BaseProof<SC>: Send + Sync,
    PcsProof<SC>: Send + Sync,
    BaseVerifyingKey<SC>: HashableKey<SC::Val> + Send + Sync,
    C: ChipBehavior<
            Val<SC>,
            Program = RecursionProgram<Val<SC>>,
            Record = RecursionRecord<Val<SC>>,
        > + Air<ProverConstraintFolder<SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>
        + Send
        + Sync,
{
    /// Get the name of the machine.
    fn name(&self) -> String {
        format!("Compress Machine <{}>", type_name::<SC>())
    }

    /// Get the base machine
    fn base_machine(&self) -> &BaseMachine<SC, C> {
        &self.base_machine
    }

    /// Get the prover of the machine.
    #[instrument(name = "COMPRESS MACHINE PROVE", level = "debug", skip_all)]
    fn prove(&self, witness: &ProvingWitness<SC, C, RecursionStdinVariant<SC, C>>) -> MetaProof<SC>
    where
        C: for<'c> Air<
            DebugConstraintFolder<
                'c,
                <SC as StarkGenericConfig>::Val,
                <SC as StarkGenericConfig>::Challenge,
            >,
        >,
    {
        let mut records = witness.records().to_vec();
        debug_span!("complement record").in_scope(|| self.complement_record(&mut records));

        debug!("COMPRESS record stats");
        let stats = records[0].stats();
        for (key, value) in &stats {
            debug!("   |- {:<28}: {}", key, value);
        }

        let proofs = debug_span!("prove_ensemble")
            .in_scope(|| self.base_machine.prove_ensemble(witness.pk(), &records));

        // construct meta proof
        let vks = vec![witness.vk.clone().unwrap()].into();

        debug!("COMPRESS chip log degrees:");
        proofs.iter().enumerate().for_each(|(i, proof)| {
            debug!("Proof {}", i);
            proof
                .main_chip_ordering
                .iter()
                .for_each(|(chip_name, idx)| {
                    debug!(
                        "   |- {:<20} main: {:<8}",
                        chip_name, proof.opened_values.chips_opened_values[*idx].log_main_degree,
                    );
                });
        });

        MetaProof::new(proofs.into(), vks, None)
    }

    /// Verify the proof.
    fn verify(
        &self,
        proof: &MetaProof<SC>,
        riscv_vk: &dyn HashableKey<SC::Val>,
    ) -> anyhow::Result<()> {
        let vk = proof.vks().first().unwrap();
        assert_eq!(proof.num_proofs(), 1);

        let public_values: &RecursionPublicValues<_> =
            proof.proofs[0].public_values.as_ref().borrow();

        // assert completion
        if public_values.flag_complete != <Val<SC>>::ONE {
            panic!("flag_complete is not 1");
        }

        assert_recursion_public_values_valid(self.config().as_ref(), public_values);
        assert_riscv_vk_digest(proof, riscv_vk);

        // Recursion Vk Verification
        let vk_manager = <SC as HasStaticVkManager>::static_vk_manager();
        if vk_manager.vk_verification_enabled() {
            assert!(
                vk_manager.is_vk_allowed(vk.hash_field()),
                "Recursion Vk Verification failed"
            );
            assert_eq!(public_values.vk_root, vk_manager.merkle_root, "Recursion circuit vk_root mismatch!")
        }

        // verify
        self.base_machine.verify_ensemble(vk, &proof.proofs())?;

        Ok(())
    }
}

impl<SC, C> CompressMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<
        Val<SC>,
        Program = RecursionProgram<Val<SC>>,
        Record = RecursionRecord<Val<SC>>,
    >,
{
    pub fn new(config: SC, chips: Vec<MetaChip<Val<SC>, C>>, num_public_values: usize) -> Self {
        Self {
            base_machine: BaseMachine::<SC, C>::new(config, chips, num_public_values),
        }
    }
}
