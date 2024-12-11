#[cfg(feature = "debug")]
use crate::machine::debug::constraints::IncrementalConstraintDebugger;
#[cfg(feature = "debug-lookups")]
use crate::machine::debug::lookups::IncrementalLookupDebugger;
use crate::{
    compiler::recursion::program::RecursionProgram,
    configs::config::{Challenge, Com, PcsProverData, StarkGenericConfig, Val},
    emulator::record::RecordBehavior,
    instances::configs::embed_bb_bn254_poseidon2::StarkConfig as EmbedSC,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{DebugConstraintFolder, ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, BaseVerifyingKey},
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    recursion::{air::RecursionPublicValues, runtime::RecursionRecord},
};
use p3_air::Air;
use p3_challenger::CanObserve;
use p3_field::FieldAlgebra;
use std::{any::type_name, borrow::Borrow, time::Instant};
use tracing::{debug, info, instrument, trace};

pub struct RecursionEmbedMachine<SC, C, I>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<
            Val<SC>,
            Program = RecursionProgram<Val<SC>>,
            Record = RecursionRecord<Val<SC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    base_machine: BaseMachine<SC, C>,

    phantom: std::marker::PhantomData<I>,
}

impl<C, I> MachineBehavior<EmbedSC, C, I> for RecursionEmbedMachine<EmbedSC, C, I>
where
    C: ChipBehavior<
            Val<EmbedSC>,
            Program = RecursionProgram<Val<EmbedSC>>,
            Record = RecursionRecord<Val<EmbedSC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, EmbedSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, EmbedSC>>,
{
    /// Get the name of the machine.
    fn name(&self) -> String {
        format!("Embed Recursion Machine <{}>", type_name::<EmbedSC>())
    }

    /// Get the base machine
    fn base_machine(&self) -> &BaseMachine<EmbedSC, C> {
        &self.base_machine
    }

    // todo: I is actually not used here
    /// Get the prover of the machine.
    #[instrument(name = "embed_prove", level = "debug", skip_all)]
    fn prove(
        &self,
        pk: &BaseProvingKey<EmbedSC>,
        witness: &ProvingWitness<EmbedSC, C, I>,
    ) -> MetaProof<EmbedSC>
    where
        C: for<'c> Air<DebugConstraintFolder<'c, Val<EmbedSC>, Challenge<EmbedSC>>>,
    {
        info!("PERF-machine=embed");
        let begin = Instant::now();

        // used for collect all records for debugging
        #[cfg(feature = "debug")]
        let mut debug_challenger = self.config().challenger();
        #[cfg(feature = "debug")]
        let mut constraint_debugger = IncrementalConstraintDebugger::new(pk, &mut debug_challenger);
        #[cfg(feature = "debug-lookups")]
        let mut lookup_debugger = IncrementalLookupDebugger::new(pk, None);

        let mut records = witness.records().to_vec();

        // let mut recursion_emulator = MetaEmulator::setup_recursion(witness, 1);
        //
        // let (record, _) = recursion_emulator.next();
        // let mut records = vec![record];

        self.complement_record(&mut records);

        #[cfg(feature = "debug")]
        constraint_debugger.debug_incremental(&self.chips(), &records);
        #[cfg(feature = "debug-lookups")]
        lookup_debugger.debug_incremental(&self.chips(), &records);

        debug!("recursion embed record stats");
        let stats = records[0].stats();
        for (key, value) in &stats {
            debug!("   |- {:<28}: {}", key, value);
        }

        // commit main
        let commitment = self.base_machine.commit(&records[0]);

        // setup challenger
        let mut challenger = self.config().challenger();
        pk.observed_by(&mut challenger);
        challenger.observe(commitment.commitment);
        challenger.observe_slice(&commitment.public_values[..self.num_public_values()]);

        let proof = self.base_machine.prove_plain(
            pk,
            &mut challenger.clone(),
            commitment,
            records[0].chunk_index(),
        );

        info!("PERF-step=prove-user_time={}", begin.elapsed().as_millis(),);

        // construct meta proof
        let proof = MetaProof::new([proof].into());
        let proof_size = bincode::serialize(&proof).unwrap().len();
        info!("PERF-step=proof_size-{}", proof_size);

        #[cfg(feature = "debug")]
        constraint_debugger.print_results();
        #[cfg(feature = "debug-lookups")]
        lookup_debugger.print_results();

        proof
    }

    /// Verify the proof.
    fn verify(
        &self,
        vk: &BaseVerifyingKey<EmbedSC>,
        proof: &MetaProof<EmbedSC>,
    ) -> anyhow::Result<()> {
        info!("PERF-machine=embed");
        let begin = Instant::now();

        assert_eq!(proof.num_proofs(), 1);

        let public_values: &RecursionPublicValues<_> =
            proof.proofs[0].public_values.as_ref().borrow();
        trace!("public values: {:?}", public_values);

        // assert completion
        if public_values.flag_complete != <Val<EmbedSC>>::ONE {
            panic!("flag_complete is not 1");
        }

        // verify
        self.base_machine.verify_ensemble(vk, proof.proofs())?;

        info!("PERF-step=verify-user_time={}", begin.elapsed().as_millis());

        Ok(())
    }
}

impl<SC, C, I> RecursionEmbedMachine<SC, C, I>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<
            Val<SC>,
            Program = RecursionProgram<Val<SC>>,
            Record = RecursionRecord<Val<SC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
{
    pub fn new(config: SC, chips: Vec<MetaChip<Val<SC>, C>>, num_public_values: usize) -> Self {
        info!("PERF-machine=embed");
        Self {
            base_machine: BaseMachine::<SC, C>::new(config, chips, num_public_values),
            phantom: std::marker::PhantomData,
        }
    }
}
