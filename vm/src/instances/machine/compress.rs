use crate::{
    compiler::recursion_v2::program::RecursionProgram,
    configs::config::{Com, PcsProof, PcsProverData, StarkGenericConfig, Val},
    emulator::record::RecordBehavior,
    instances::compiler_v2::recursion_circuit::stdin::RecursionStdin,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{DebugConstraintFolder, ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseVerifyingKey,
        machine::{BaseMachine, MachineBehavior},
        proof::{BaseProof, MetaProof},
        witness::ProvingWitness,
    },
    primitives::consts::EXTENSION_DEGREE,
    recursion_v2::{air::RecursionPublicValues, runtime::RecursionRecord},
};
use p3_air::Air;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{extension::BinomiallyExtendable, PrimeField32, TwoAdicField};
use std::{any::type_name, borrow::Borrow, time::Instant};
use tracing::{info, instrument, trace};

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

impl<F, SC, C> MachineBehavior<SC, C, RecursionStdin<'_, SC, C>> for CompressMachine<SC, C>
where
    F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + TwoAdicField,
    SC: StarkGenericConfig<Val = F, Domain = TwoAdicMultiplicativeCoset<F>> + Send + Sync,
    Val<SC>: PrimeField32,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    BaseProof<SC>: Send + Sync,
    PcsProof<SC>: Send + Sync,
    BaseVerifyingKey<SC>: Send + Sync,
    C: ChipBehavior<
            Val<SC>,
            Program = RecursionProgram<Val<SC>>,
            Record = RecursionRecord<Val<SC>>,
        > + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>
        + Send
        + Sync,
    BaseVerifyingKey<SC>: Send + Sync,
    BaseProof<SC>: Send + Sync,
{
    /// Get the name of the machine.
    fn name(&self) -> String {
        format!("Compress Recursion Machine <{}>", type_name::<SC>())
    }

    /// Get the base machine
    fn base_machine(&self) -> &BaseMachine<SC, C> {
        &self.base_machine
    }

    /// Get the prover of the machine.
    #[instrument(name = "compress_prove", level = "debug", skip_all)]
    fn prove(&self, witness: &ProvingWitness<SC, C, RecursionStdin<SC, C>>) -> MetaProof<SC>
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
        self.complement_record(&mut records);

        info!("COMPRESS record stats");
        let stats = records[0].stats();
        for (key, value) in &stats {
            info!("   |- {:<28}: {}", key, value);
        }

        let proofs = self.base_machine.prove_ensemble(witness.pk(), &records);

        // construct meta proof
        let vks = vec![witness.vk.clone().unwrap()].into();
        MetaProof::new(proofs.into(), vks, None)
    }

    /// Verify the proof.
    fn verify(&self, proof: &MetaProof<SC>) -> anyhow::Result<()> {
        let vk = proof.vks().first().unwrap();

        info!("PERF-machine=convert");
        let begin = Instant::now();

        assert_eq!(proof.num_proofs(), 1);

        let public_values: &RecursionPublicValues<_> =
            proof.proofs[0].public_values.as_ref().borrow();
        trace!("public values: {:?}", public_values);

        // assert completion
        if public_values.flag_complete != <Val<SC>>::ONE {
            panic!("flag_complete is not 1");
        }

        // todo: assert public values digest

        // verify
        self.base_machine.verify_ensemble(vk, &proof.proofs())?;

        info!("PERF-step=verify-user_time={}", begin.elapsed().as_millis());

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
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
{
    pub fn new(config: SC, chips: Vec<MetaChip<Val<SC>, C>>, num_public_values: usize) -> Self {
        Self {
            base_machine: BaseMachine::<SC, C>::new(config, chips, num_public_values),
        }
    }
}
