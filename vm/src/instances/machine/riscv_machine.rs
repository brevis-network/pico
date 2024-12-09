#[cfg(feature = "debug")]
use crate::machine::debug::constraints::IncrementalConstraintDebugger;
#[cfg(feature = "debug-lookups")]
use crate::machine::debug::lookups::IncrementalLookupDebugger;
use crate::{
    compiler::{riscv::program::Program, word::Word},
    configs::config::{Com, PcsProverData, StarkGenericConfig, Val},
    emulator::{
        emulator::MetaEmulator,
        record::RecordBehavior,
        riscv::{public_values::PublicValues, record::EmulationRecord},
    },
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{DebugConstraintFolder, ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, BaseVerifyingKey},
        machine::{BaseMachine, MachineBehavior},
        proof::{BaseProof, MetaProof},
        witness::ProvingWitness,
    },
    primitives::consts::MAX_LOG_CHUNK_SIZE,
};
use anyhow::Result;
use p3_air::Air;
use p3_challenger::CanObserve;
use p3_field::FieldAlgebra;
use p3_maybe_rayon::prelude::*;
use std::{any::type_name, borrow::Borrow, time::Instant};
use tracing::{debug, info, instrument};

pub struct RiscvMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    base_machine: BaseMachine<SC, C>,
}

impl<SC, C> MachineBehavior<SC, C, Vec<u8>> for RiscvMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>, Program = Program, Record = EmulationRecord>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    BaseProof<SC>: Send + Sync,
{
    /// Get the name of the machine.
    fn name(&self) -> String {
        format!("RiscvMachine <{}>", type_name::<SC>())
    }

    /// Get the base machine.
    fn base_machine(&self) -> &BaseMachine<SC, C> {
        &self.base_machine
    }

    /// Get the prover of the machine.
    #[instrument(name = "riscv_prove", level = "debug", skip_all)]
    fn prove(
        &self,
        pk: &BaseProvingKey<SC>,
        witness: &ProvingWitness<SC, C, Vec<u8>>,
    ) -> MetaProof<SC>
    where
        C: for<'a> Air<
            DebugConstraintFolder<
                'a,
                <SC as StarkGenericConfig>::Val,
                <SC as StarkGenericConfig>::Challenge,
            >,
        >,
    {
        info!("PERF-machine=riscv");
        let begin = Instant::now();

        let mut challenger = self.config().challenger();
        pk.observed_by(&mut challenger);

        // TODO: checkpoint batch records and apply pipeline parallelism

        // First phase
        // Generate batch records and commit to challenger

        let mut emulator = MetaEmulator::setup_riscv(witness);
        loop {
            let (batch_records, done) = emulator.next_batch();

            self.complement_record(batch_records);

            for record in &mut *batch_records {
                debug!("riscv record stats: chunk {}", record.chunk_index());
                let stats = record.stats();
                for (key, value) in &stats {
                    debug!("   |- {:<25}: {}", key, value);
                }
            }

            let commitments = batch_records
                .into_par_iter()
                .map(|record| {
                    info!("PERF-phase=1-chunk={}", record.chunk_index());
                    self.base_machine.commit(record)
                })
                .collect::<Vec<_>>();

            for commitment in commitments {
                challenger.observe(commitment.commitment);
                challenger.observe_slice(&commitment.public_values[..self.num_public_values()]);
            }

            if done {
                break;
            }
        }

        // Second phase
        // Generate batch records and generate proofs

        let mut emulator = MetaEmulator::setup_riscv(witness);

        // all_proofs is a vec that contains BaseProof's. Initialized to be empty.
        let mut all_proofs = vec![];

        // used for collect all records for debugging
        #[cfg(feature = "debug")]
        let mut debug_challenger = self.config().challenger();
        #[cfg(feature = "debug")]
        let mut constraint_debugger = IncrementalConstraintDebugger::new(pk, &mut debug_challenger);
        #[cfg(feature = "debug-lookups")]
        let mut lookup_debugger = IncrementalLookupDebugger::new(pk, None);

        loop {
            let (batch_records, done) = emulator.next_batch();

            self.complement_record(batch_records);

            #[cfg(feature = "debug")]
            constraint_debugger.debug_incremental(self.chips(), &batch_records);
            #[cfg(feature = "debug-lookups")]
            lookup_debugger.debug_incremental(self.chips(), &batch_records);

            let batch_main_commitments = batch_records
                .into_par_iter()
                .map(|record| {
                    info!("PERF-phase=2-chunk={}", record.chunk_index(),);
                    // generate and commit main trace
                    self.base_machine.commit(record)
                })
                .collect::<Vec<_>>();

            let batch_proofs = batch_main_commitments
                .into_par_iter()
                .enumerate()
                .map(|(i, commitment)| {
                    info!("PERF-phase=2-chunk={}", batch_records[i].chunk_index(),);

                    self.base_machine.prove_plain(
                        pk,
                        &mut challenger.clone(),
                        commitment,
                        batch_records[i].chunk_index(),
                    )
                })
                .collect::<Vec<_>>();

            // extend all_proofs to include batch_proofs
            all_proofs.extend(batch_proofs);

            if done {
                break;
            }
        }
        info!("PERF-step=prove-user_time={}", begin.elapsed().as_millis(),);

        // construct meta proof
        let proof = MetaProof::new(all_proofs);
        let proof_size = bincode::serialize(&proof).unwrap().len();
        info!("PERF-step=proof_size-{}", proof_size);

        #[cfg(feature = "debug")]
        constraint_debugger.print_results();
        #[cfg(feature = "debug-lookups")]
        lookup_debugger.print_results();

        proof
    }

    /// Verify the proof.
    fn verify(&self, vk: &BaseVerifyingKey<SC>, proof: &MetaProof<SC>) -> Result<()> {
        info!("PERF-machine=riscv");
        let begin = Instant::now();

        // initialize bookkeeping
        let mut proof_count = <Val<SC>>::ZERO;
        let mut execution_proof_count = <Val<SC>>::ZERO;
        let mut prev_next_pc = vk.pc_start;
        let mut prev_last_initialize_addr_bits = [<Val<SC>>::ZERO; 32];
        let mut prev_last_finalize_addr_bits = [<Val<SC>>::ZERO; 32];

        let mut flag_extra = true;
        let mut committed_value_digest_prev = Default::default();
        let mut deferred_proofs_digest_prev = Default::default();
        let zero_cvd = Default::default();
        let zero_dpd = Default::default();

        for (i, each_proof) in proof.proofs().iter().enumerate() {
            let public_values: &PublicValues<Word<_>, _> =
                each_proof.public_values.as_slice().borrow();

            // beginning constraints
            if i == 0 && !each_proof.includes_chip("Cpu") {
                panic!("First proof does not include Cpu chip");
            }

            // conditional constraints
            proof_count += <Val<SC>>::ONE;
            // hack to make execution chunk consistent

            if each_proof.includes_chip("Cpu") {
                execution_proof_count += <Val<SC>>::ONE;

                if each_proof.log_main_degree() > MAX_LOG_CHUNK_SIZE {
                    panic!("Cpu log degree too large");
                }

                if public_values.start_pc == <Val<SC>>::ZERO {
                    panic!("First proof start_pc is zero");
                }
            } else {
                if public_values.start_pc != public_values.next_pc {
                    panic!("Non-Cpu proof start_pc is not equal to next_pc");
                }
                if flag_extra {
                    execution_proof_count += <Val<SC>>::ONE;
                    flag_extra = false;
                }
            }
            if !each_proof.includes_chip("MemoryInitialize")
                && public_values.previous_initialize_addr_bits
                    != public_values.last_initialize_addr_bits
            {
                panic!("Previous initialize addr bits mismatch");
            }

            if !each_proof.includes_chip("MemoryFinalize")
                && public_values.previous_finalize_addr_bits
                    != public_values.last_finalize_addr_bits
            {
                panic!("Previous finalize addr bits mismatch");
            }

            // ending constraints
            if i == proof.proofs().len() - 1 && public_values.next_pc != <Val<SC>>::ZERO {
                panic!("Last proof next_pc is not zero");
            }

            // global constraints
            if public_values.start_pc != prev_next_pc {
                panic!("PC mismatch");
            }
            if public_values.chunk != proof_count {
                panic!("Chunk number mismatch");
            }
            if public_values.execution_chunk != execution_proof_count {
                panic!("Execution chunk number mismatch");
            }
            if public_values.exit_code != <Val<SC>>::ZERO {
                panic!("Exit code is not zero");
            }
            if public_values.previous_initialize_addr_bits != prev_last_initialize_addr_bits {
                panic!("Previous init addr bits mismatch");
            }
            if public_values.previous_finalize_addr_bits != prev_last_finalize_addr_bits {
                panic!("Previous finalize addr bits mismatch");
            }

            // update bookkeeping
            prev_next_pc = public_values.next_pc;
            prev_last_initialize_addr_bits = public_values.last_initialize_addr_bits;
            prev_last_finalize_addr_bits = public_values.last_finalize_addr_bits;
            // println!("public values: {:?}", public_values);

            // committed_value_digest and deferred_proofs_digest checks
            transition_with_condition(
                &mut committed_value_digest_prev,
                &public_values.committed_value_digest,
                &zero_cvd,
                each_proof.includes_chip("Cpu"),
                "committed_value_digest",
                i,
            );
            transition_with_condition(
                &mut deferred_proofs_digest_prev,
                &public_values.deferred_proofs_digest,
                &zero_dpd,
                each_proof.includes_chip("Cpu"),
                "deferred_proofs_digest",
                i,
            );
        }

        self.base_machine.verify_ensemble(vk, proof.proofs())?;

        info!("PERF-step=verify-user_time={}", begin.elapsed().as_millis(),);

        Ok(())
    }
}

// Digest constraints.
//
// Initialization:
// - `committed_value_digest` should be zero.
// - `deferred_proofs_digest` should be zero.
//
// Transition:
// - If `commited_value_digest_prev` is not zero, then `committed_value_digest` should equal
//   `commited_value_digest_prev`.
// - If `deferred_proofs_digest_prev` is not zero, then `deferred_proofs_digest` should equal
//   `deferred_proofs_digest_prev`.
// - If it's not a shard with "CPU", then `commited_value_digest` should not change from the
//   previous shard.
// - If it's not a shard with "CPU", then `deferred_proofs_digest` should not change from the
//   previous shard.
//
// This is replaced with the following impl.
// 1. prev is initialized as 0
// 2. if prev != 0, then cur == prev
// 3. else, prev == 0, assign if cond
// 4. if not cond, then cur must be some default value, because if prev was non-zero, it would
//    trigger the initial condition
fn transition_with_condition<'a, T: Copy + core::fmt::Debug + Eq>(
    prev: &'a mut T,
    cur: &'a T,
    default: &T,
    cond: bool,
    desc: &str,
    pos: usize,
) {
    if prev != default {
        assert_eq!(
            prev, cur,
            "discrepancy between {} at position {}",
            desc, pos
        );
    } else if cond {
        *prev = *cur;
    } else {
        assert_eq!(cur, default, "{} not zeroed on failed condition", desc);
    }
}

impl<SC, C> RiscvMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
{
    pub fn new(config: SC, chips: Vec<MetaChip<SC::Val, C>>, num_public_values: usize) -> Self {
        info!("PERF-machine=riscv");
        Self {
            base_machine: BaseMachine::<SC, C>::new(config, chips, num_public_values),
        }
    }
}
