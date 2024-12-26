use crate::{
    compiler::{riscv::program::Program, word::Word},
    configs::config::{Com, PcsProverData, StarkGenericConfig, Val},
    emulator::{
        emulator_v2::MetaEmulator,
        record::RecordBehavior,
        riscv::{public_values::PublicValues, record::EmulationRecord},
    },
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{DebugConstraintFolder, ProverConstraintFolder, VerifierConstraintFolder},
        lookup::LookupScope,
        machine::{BaseMachine, MachineBehavior},
        proof::{BaseProof, MetaProof},
        witness::ProvingWitness,
    },
    primitives::consts::MAX_LOG_CHUNK_SIZE,
};
use anyhow::Result;
use p3_air::Air;
use p3_challenger::CanObserve;
use p3_field::{FieldAlgebra, PrimeField32, PrimeField64};
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
    SC: Send + StarkGenericConfig,
    Val<SC>: PrimeField32,
    C: Send
        + ChipBehavior<Val<SC>, Program = Program, Record = EmulationRecord>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    BaseProof<SC>: Send + Sync,
    SC::Domain: Send + Sync,
    SC::Val: PrimeField64,
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
    fn prove(&self, witness: &ProvingWitness<SC, C, Vec<u8>>) -> MetaProof<SC>
    where
        C: for<'a> Air<
            DebugConstraintFolder<
                'a,
                <SC as StarkGenericConfig>::Val,
                <SC as StarkGenericConfig>::Challenge,
            >,
        >,
    {
        let start_p1 = Instant::now();
        // Initialize the challenger.
        let mut challenger = self.config().challenger();

        // Get pk from witness and observe with challenger
        let pk = witness.pk();
        pk.observed_by(&mut challenger);

        /*
        First phase
         */

        let mut emulator = MetaEmulator::setup_riscv(witness);
        loop {
            let (batch_records, done) = emulator.next_record_batch();
            self.complement_record(batch_records);

            //#[cfg(feature = "debug")]
            for record in &mut *batch_records {
                debug!("riscv record stats: chunk {}", record.chunk_index());
                let stats = record.stats();
                for (key, value) in &stats {
                    debug!("   |- {:<26}: {}", key, value);
                }
            }

            let commitments = batch_records
                .into_par_iter()
                .map(|record| {
                    self.base_machine
                        .commit(record, LookupScope::Global)
                        .unwrap()
                })
                .collect::<Vec<_>>();

            // todo optimize: parallel
            for commitment in commitments {
                challenger.observe(commitment.commitment);
                challenger.observe_slice(&commitment.public_values[..self.num_public_values()]);
            }

            if done {
                break;
            }
        }
        info!("--- Finish riscv phase 1 in {:?}", start_p1.elapsed());

        /*
        Second phase
        */

        let mut emulator = MetaEmulator::setup_riscv(witness);

        // all_proofs is a vec that contains BaseProof's. Initialized to be empty.
        let mut all_proofs = vec![];

        #[cfg(feature = "debug")]
        let mut constraint_debugger = crate::machine::debug::IncrementalConstraintDebugger::new(
            pk,
            &mut self.config().challenger(),
        );
        #[cfg(feature = "debug-lookups")]
        let mut global_lookup_debugger =
            crate::machine::debug::IncrementalLookupDebugger::new(pk, LookupScope::Global, None);

        let start_p2 = Instant::now();
        let mut batch_num = 1;
        let mut chunk_num = 0;
        loop {
            let start_local = Instant::now();
            let (batch_records, done) = emulator.next_record_batch();
            self.complement_record(batch_records);
            info!(
                "--- Generate riscv records for batch {}, chunk {}-{} in {:?}",
                batch_num,
                chunk_num + 1,
                chunk_num + batch_records.len() as u32,
                start_local.elapsed()
            );
            chunk_num += batch_records.len() as u32;

            #[cfg(feature = "debug")]
            constraint_debugger.debug_incremental(&self.chips(), batch_records);
            #[cfg(feature = "debug-lookups")]
            {
                crate::machine::debug::debug_regional_lookups(
                    pk,
                    &self.chips(),
                    batch_records,
                    None,
                );
                global_lookup_debugger.debug_incremental(&self.chips(), batch_records);
            }

            let batch_proofs = batch_records
                .into_par_iter()
                .map(|record| {
                    let start_chunk = Instant::now();

                    let regional_commitment = self
                        .base_machine
                        .commit(record, LookupScope::Regional)
                        .unwrap();
                    let global_commitment = self.base_machine.commit(record, LookupScope::Global);

                    let proof = self.base_machine.prove_plain(
                        witness.pk(),
                        &mut challenger.clone(),
                        record.chunk_index(),
                        regional_commitment,
                        global_commitment,
                    );

                    info!(
                        "--- Prove riscv batch {} chunk {} in {:?}",
                        batch_num,
                        record.chunk_index(),
                        start_chunk.elapsed()
                    );
                    proof
                })
                .collect::<Vec<_>>();

            // extend all_proofs to include batch_proofs
            all_proofs.extend(batch_proofs);

            info!(
                "--- Finish riscv batch {} in {:?}",
                batch_num,
                start_local.elapsed()
            );

            batch_num += 1;

            if done {
                break;
            }
        }
        info!("--- Finish riscv phase 2 in {:?}", start_p2.elapsed());

        // construct meta proof
        let vks = vec![witness.vk.clone().unwrap()];

        #[cfg(feature = "debug")]
        constraint_debugger.print_results();
        #[cfg(feature = "debug-lookups")]
        global_lookup_debugger.print_results();

        // TODO: print more summary numbers
        let riscv_emulator = emulator.emulator.unwrap();
        info!("RiscV execution report:");
        info!("|- cycles:           {}", riscv_emulator.state.global_clk);
        info!("|- chunk_num:        {}", all_proofs.len());
        info!("|- chunk_size:       {}", riscv_emulator.chunk_size);
        info!("|- chunk_batch_size: {}", riscv_emulator.chunk_batch_size);

        MetaProof::new(all_proofs.into(), vks.into())
    }

    /// Verify the proof.
    fn verify(&self, proof: &MetaProof<SC>) -> Result<()> {
        // Assert single vk
        assert_eq!(proof.vks().len(), 1);

        // Get vk from proof
        let vk = proof.vks().first().unwrap();

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
                each_proof.public_values.as_ref().borrow();

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

        // Verify the proofs.
        self.base_machine.verify_ensemble(vk, &proof.proofs())?;

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
// - If it's not a chunk with "CPU", then `commited_value_digest` should not change from the
//   previous chunk.
// - If it's not a chunk with "CPU", then `deferred_proofs_digest` should not change from the
//   previous chunk.
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
        Self {
            base_machine: BaseMachine::<SC, C>::new(config, chips, num_public_values),
        }
    }
}
