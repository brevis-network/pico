#[cfg(feature = "debug")]
use crate::machine::debug::constraints::IncrementalConstraintDebugger;
#[cfg(feature = "debug-lookups")]
use crate::machine::debug::lookups::IncrementalLookupDebugger;
use crate::{
    compiler::recursion::program::RecursionProgram,
    configs::config::{Com, PcsProverData, StarkGenericConfig, Val},
    emulator::{emulator::MetaEmulator, record::RecordBehavior},
    instances::{
        chiptype::riscv_chiptype::RiscvChipType,
        compiler::riscv_circuit::stdin::RiscvRecursionStdin,
        configs::{recur_config::StarkConfig as RecursionSC, riscv_config::StarkConfig as RiscvSC},
    },
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
use anyhow::Result;
use p3_air::Air;
use p3_challenger::CanObserve;
use p3_field::Field;
use p3_maybe_rayon::prelude::*;
use std::{any::type_name, borrow::Borrow, time::Instant};
use tracing::{debug, info, instrument, trace};

pub struct RiscvRecursionMachine<SC, C>
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
}

impl<C> MachineBehavior<RecursionSC, C, RiscvRecursionStdin<RiscvSC, RiscvChipType<Val<RiscvSC>>>>
    for RiscvRecursionMachine<RecursionSC, C>
where
    C: Send
        + ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'a> Air<ProverConstraintFolder<'a, RecursionSC>>
        + for<'a> Air<VerifierConstraintFolder<'a, RecursionSC>>,
{
    /// Get the name of the machine.
    fn name(&self) -> String {
        format!("Riscv Compress Machine <{}>", type_name::<RecursionSC>())
    }

    /// Get the base machine.
    fn base_machine(&self) -> &BaseMachine<RecursionSC, C> {
        &self.base_machine
    }

    /// Get the prover of the machine.
    #[instrument(name = "riscv_recursion", level = "debug", skip_all)]
    fn prove(
        &self,
        pk: &BaseProvingKey<RecursionSC>,
        witness: &ProvingWitness<
            RecursionSC,
            C,
            RiscvRecursionStdin<RiscvSC, RiscvChipType<Val<RiscvSC>>>,
        >,
    ) -> MetaProof<RecursionSC>
    where
        C: for<'c> Air<
            DebugConstraintFolder<
                'c,
                <RecursionSC as StarkGenericConfig>::Val,
                <RecursionSC as StarkGenericConfig>::Challenge,
            >,
        >,
    {
        info!("PERF-machine=recursion");
        let begin = Instant::now();

        // First
        // Generate batch records and commit to challenger

        let mut recursion_emulator = MetaEmulator::setup_riscv_compress(witness);
        let mut all_proofs = vec![];

        // used for collect all records for debugging
        #[cfg(feature = "debug")]
        let mut debug_challenger = self.config().challenger();
        #[cfg(feature = "debug")]
        let mut constraint_debugger = IncrementalConstraintDebugger::new(pk, &mut debug_challenger);
        #[cfg(feature = "debug-lookups")]
        let mut lookup_debugger = IncrementalLookupDebugger::new(pk, None);

        let mut chunk_index = 1;
        loop {
            let (mut batch_records, done) = recursion_emulator.next_batch();

            self.complement_record(batch_records.as_mut_slice());

            #[cfg(feature = "debug")]
            constraint_debugger.debug_incremental(&self.chips(), &batch_records);
            #[cfg(feature = "debug-lookups")]
            lookup_debugger.debug_incremental(&self.chips(), &batch_records);

            for record in &mut *batch_records {
                record.index = chunk_index;
                chunk_index += 1;
                debug!(
                    "riscv recursion record stats: chunk {}",
                    record.chunk_index()
                );
                let stats = record.stats();
                for (key, value) in &stats {
                    debug!("   |- {:<28}: {}", key, value);
                }
            }

            let batch_proofs = batch_records
                .into_par_iter()
                .map(|record| {
                    info!("PERF-phase=1-chunk={}", record.chunk_index());

                    let commitment = self.base_machine.commit(&record);

                    let mut challenger = self.config().challenger();
                    pk.observed_by(&mut challenger);

                    challenger.observe(commitment.commitment);
                    challenger.observe_slice(&commitment.public_values[..self.num_public_values()]);

                    self.base_machine.prove_plain(
                        pk,
                        &mut challenger.clone(),
                        commitment,
                        record.chunk_index(),
                    )
                })
                .collect::<Vec<_>>();

            all_proofs.extend(batch_proofs);

            if done {
                break;
            }
        }

        #[cfg(feature = "debug")]
        constraint_debugger.print_results();
        #[cfg(feature = "debug-lookups")]
        lookup_debugger.print_results();

        info!("PERF-step=prove-user_time={}", begin.elapsed().as_millis(),);

        // construct meta proof
        let proof = MetaProof::new(all_proofs.into());
        let proof_size = bincode::serialize(&proof).unwrap().len();
        info!("PERF-step=proof_size-{}", proof_size);

        proof
    }

    /// Verify the proof.
    fn verify(
        &self,
        vk: &BaseVerifyingKey<RecursionSC>,
        proof: &MetaProof<RecursionSC>,
    ) -> Result<()> {
        info!("PERF-machine=recursion");
        let begin = Instant::now();

        for each_proof in proof.proofs().iter() {
            let public_values: &RecursionPublicValues<_> =
                each_proof.public_values.as_ref().borrow();

            trace!("public values: {:?}", public_values);

            let mut challenger = self.config().challenger();
            // observe all preprocessed and main commits and pv's
            vk.observed_by(&mut challenger);
            challenger.observe(each_proof.commitments.main_commit);
            challenger.observe_slice(&each_proof.public_values[..self.num_public_values()]);

            self.base_machine
                .verify_plain(vk, &mut challenger, each_proof)?;
        }

        // compute sum of each proof.cumulative_sum() and add them up and judge if it is zero
        let sum = proof
            .proofs()
            .iter()
            .map(|proof| proof.cumulative_sum())
            .sum::<<RecursionSC as StarkGenericConfig>::Challenge>();

        if !sum.is_zero() {
            panic!("verify_ensemble:lookup cumulative sum is not zero");
        }

        info!("PERF-step=verify-user_time={}", begin.elapsed().as_millis(),);

        Ok(())
    }
}

impl<SC, C> RiscvRecursionMachine<SC, C>
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
        info!("PERF-machine=recursion");
        Self {
            base_machine: BaseMachine::<SC, C>::new(config, chips, num_public_values),
        }
    }
}
