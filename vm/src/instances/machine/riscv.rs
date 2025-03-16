use crate::{
    compiler::{riscv::program::Program, word::Word},
    configs::config::{Com, StarkGenericConfig, Val},
    emulator::{
        emulator::MetaEmulator,
        record::RecordBehavior,
        riscv::{public_values::PublicValues, record::EmulationRecord},
    },
    instances::compiler::shapes::riscv_shape::RiscvShapeConfig,
    iter::{IntoPicoIterator, PicoExtend, PicoIterator},
    machine::{
        chip::{ChipBehavior, MetaChip},
        field::FieldSpecificPoseidon2Config,
        folder::{DebugConstraintFolder, ProverConstraintFolder, VerifierConstraintFolder},
        keys::HashableKey,
        machine::{BaseMachine, MachineBehavior},
        proof::{BaseProof, MetaProof},
        witness::ProvingWitness,
    },
    primitives::{consts::MAX_LOG_CHUNK_SIZE, Poseidon2Init},
};
use anyhow::Result;
use p3_air::Air;
use p3_field::{FieldAlgebra, PrimeField32};
use p3_symmetric::Permutation;
use std::{any::type_name, borrow::Borrow, time::Instant};
use tracing::{debug, debug_span, info, instrument};

pub struct RiscvMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>,
{
    base_machine: BaseMachine<SC, C>,
}

impl<SC, C> RiscvMachine<SC, C>
where
    SC: Send + StarkGenericConfig,
    Val<SC>: PrimeField32 + FieldSpecificPoseidon2Config + Poseidon2Init,
    <Val<SC> as Poseidon2Init>::Poseidon2: Permutation<[Val<SC>; 16]>,
    C: Send + ChipBehavior<Val<SC>, Program = Program, Record = EmulationRecord>,
    Com<SC>: Send + Sync,
    BaseProof<SC>: Send + Sync,
{
    /// Prove with shape config
    #[instrument(name = "RISCV MACHINE PROVE", level = "debug", skip_all)]
    pub fn prove_with_shape_cycles(
        &self,
        witness: &ProvingWitness<SC, C, Vec<u8>>,
        shape_config: Option<&RiscvShapeConfig<SC::Val>>,
    ) -> (MetaProof<SC>, u64)
    where
        C: for<'a> Air<
                DebugConstraintFolder<
                    'a,
                    <SC as StarkGenericConfig>::Val,
                    <SC as StarkGenericConfig>::Challenge,
                >,
            > + Air<ProverConstraintFolder<SC>>,
    {
        // Initialize the challenger.
        let mut challenger = self.config().challenger();

        // Get pk from witness and observe with challenger
        let pk = witness.pk();
        pk.observed_by(&mut challenger);

        let mut emulator = MetaEmulator::setup_riscv(witness);

        // all_proofs is a vec that contains BaseProof's. Initialized to be empty.
        let mut all_proofs = vec![];

        #[cfg(feature = "debug")]
        let mut constraint_debugger = crate::machine::debug::IncrementalConstraintDebugger::new(
            pk,
            &mut self.config().challenger(),
            self.base_machine.has_global(),
        );
        #[cfg(feature = "debug-lookups")]
        let mut global_lookup_debugger = crate::machine::debug::IncrementalLookupDebugger::new(
            pk,
            crate::machine::lookup::LookupScope::Global,
            None,
        );

        let start_p2 = Instant::now();
        let mut batch_num = 1;
        let mut chunk_num = 0;

        loop {
            let loop_span =
                debug_span!(parent: &tracing::Span::current(), "riscv batch prove loop", batch_num)
                    .entered();

            let start_local = Instant::now();
            let (mut batch_records, done) = emulator.next_record_batch();
            debug_span!("complement_record")
                .in_scope(|| self.complement_record(&mut batch_records));

            if let Some(shape_config) = shape_config {
                for record in batch_records.iter_mut() {
                    shape_config
                        .padding_shape(record)
                        .expect("padding_shape failed");
                }
            }

            debug!(
                "--- Generate riscv records for batch {}, chunk {}-{} in {:?}",
                batch_num,
                chunk_num + 1,
                chunk_num + batch_records.len() as u32,
                start_local.elapsed()
            );
            chunk_num += batch_records.len() as u32;

            // set index for each record
            for record in batch_records.iter() {
                let stats = record.stats();
                debug!("RISCV record stats: chunk {}", record.chunk_index());
                for (key, value) in &stats {
                    debug!("   |- {:<28}: {}", key, value);
                }
            }

            #[cfg(feature = "debug")]
            constraint_debugger.debug_incremental(&self.chips(), &batch_records);
            #[cfg(feature = "debug-lookups")]
            {
                crate::machine::debug::debug_regional_lookups(
                    pk,
                    &self.chips(),
                    &batch_records,
                    None,
                );
                global_lookup_debugger.debug_incremental(&self.chips(), &batch_records);
            }

            let batch_proofs = batch_records.into_pico_iter().map(|record| {
                let start_chunk = Instant::now();
                let chunk_index = record.chunk_index();
                let main_commitment =
                    debug_span!(parent: &loop_span, "generate_and_commit_main_traces", chunk_index)
                        .in_scope(|| self.base_machine.commit(&record).unwrap());

                let proof =
                    debug_span!(parent: &loop_span, "prove_plain", chunk_index).in_scope(|| {
                        self.base_machine.prove_plain(
                            pk,
                            &mut challenger.clone(),
                            chunk_index,
                            main_commitment,
                        )
                    });

                debug!(
                    "--- Prove riscv batch {} chunk {} in {:?}",
                    batch_num,
                    chunk_index,
                    start_chunk.elapsed()
                );

                proof
            });

            // extend all_proofs to include batch_proofs
            all_proofs.pico_extend(batch_proofs);

            debug!(
                "--- Finish riscv batch {} in {:?}",
                batch_num,
                start_local.elapsed()
            );

            batch_num += 1;

            if done {
                break;
            }
            loop_span.exit();
        }
        let cycles = emulator.cycles();
        debug!("--- Finish riscv phase 2 in {:?}", start_p2.elapsed());

        // construct meta proof
        let vks = vec![witness.vk.clone().unwrap()];

        #[cfg(feature = "debug")]
        constraint_debugger.print_results();
        #[cfg(feature = "debug-lookups")]
        global_lookup_debugger.print_results();

        debug!("RISCV chip log degrees:");
        all_proofs.iter().enumerate().for_each(|(i, proof)| {
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

        let pv_stream = emulator.get_pv_stream();
        let riscv_emulator = emulator.emulator.unwrap();

        info!("RiscV execution report:");
        info!("|- cycles:           {}", riscv_emulator.state.global_clk);
        info!("|- chunk_num:        {}", all_proofs.len());
        info!("|- chunk_size:       {}", riscv_emulator.opts.chunk_size);
        info!(
            "|- chunk_batch_size: {}",
            riscv_emulator.opts.chunk_batch_size
        );

        (
            MetaProof::new(all_proofs.into(), vks.into(), Some(pv_stream)),
            cycles,
        )
    }

    pub fn prove_with_shape(
        &self,
        witness: &ProvingWitness<SC, C, Vec<u8>>,
        shape_config: Option<&RiscvShapeConfig<SC::Val>>,
    ) -> (MetaProof<SC>, u64)
    where
        C: for<'a> Air<
                DebugConstraintFolder<
                    'a,
                    <SC as StarkGenericConfig>::Val,
                    <SC as StarkGenericConfig>::Challenge,
                >,
            > + Air<ProverConstraintFolder<SC>>,
    {
        self.prove_with_shape_cycles(witness, shape_config)
    }

    pub fn prove_cycles(&self, witness: &ProvingWitness<SC, C, Vec<u8>>) -> (MetaProof<SC>, u64)
    where
        C: for<'a> Air<
                DebugConstraintFolder<
                    'a,
                    <SC as StarkGenericConfig>::Val,
                    <SC as StarkGenericConfig>::Challenge,
                >,
            > + Air<ProverConstraintFolder<SC>>,
    {
        self.prove_with_shape_cycles(witness, None)
    }
}

impl<SC, C> MachineBehavior<SC, C, Vec<u8>> for RiscvMachine<SC, C>
where
    SC: Send + StarkGenericConfig,
    Val<SC>: PrimeField32 + Poseidon2Init,
    <Val<SC> as Poseidon2Init>::Poseidon2: Permutation<[Val<SC>; 16]>,
    C: Send + ChipBehavior<Val<SC>, Program = Program, Record = EmulationRecord>,
    Com<SC>: Send + Sync,
    BaseProof<SC>: Send + Sync,
{
    /// Get the name of the machine.
    fn name(&self) -> String {
        format!("RISCV machine <{}>", type_name::<SC>())
    }

    /// Get the base machine.
    fn base_machine(&self) -> &BaseMachine<SC, C> {
        &self.base_machine
    }

    fn prove(&self, _witness: &ProvingWitness<SC, C, Vec<u8>>) -> MetaProof<SC>
    where
        C: for<'a> Air<
                DebugConstraintFolder<
                    'a,
                    <SC as StarkGenericConfig>::Val,
                    <SC as StarkGenericConfig>::Challenge,
                >,
            > + Air<ProverConstraintFolder<SC>>,
    {
        // Please use prove_cycles instead
        unreachable!();
    }

    /// Verify the proof.
    fn verify(&self, proof: &MetaProof<SC>, _riscv_vk: &dyn HashableKey<SC::Val>) -> Result<()>
    where
        C: for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    {
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

        // let mut flag_extra = true;
        let mut committed_value_digest_prev = Default::default();
        let zero_cvd = Default::default();

        for (i, each_proof) in proof.proofs().iter().enumerate() {
            let public_values: &PublicValues<Word<_>, _> =
                each_proof.public_values.as_ref().borrow();

            debug!(
                "chunk: {}, execution chunk: {}",
                public_values.chunk, public_values.execution_chunk
            );

            // beginning constraints
            if i == 0 && !each_proof.includes_chip("Cpu") {
                panic!("First proof does not include Cpu chip");
            }

            // conditional constraints
            proof_count += <Val<SC>>::ONE;
            // hack to make execution chunk consistent

            if each_proof.includes_chip("Cpu") {
                execution_proof_count += <Val<SC>>::ONE;

                if public_values.execution_chunk != execution_proof_count {
                    println!(
                        "execution chunk: {}, execution_proof_count: {}",
                        public_values.execution_chunk, execution_proof_count
                    );
                    panic!("Execution chunk number mismatch");
                }

                if each_proof.log_main_degree() > MAX_LOG_CHUNK_SIZE {
                    panic!("Cpu log degree too large");
                }

                if public_values.start_pc == <Val<SC>>::ZERO {
                    panic!("First proof start_pc is zero");
                }
            } else if public_values.start_pc != public_values.next_pc {
                panic!("Non-Cpu proof start_pc is not equal to next_pc");
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

            // committed_value_digest checks
            transition_with_condition(
                &mut committed_value_digest_prev,
                &public_values.committed_value_digest,
                &zero_cvd,
                each_proof.includes_chip("Cpu"),
                "committed_value_digest",
                i,
            );
        }

        // Verify the proofs.
        self.base_machine.verify_riscv(vk, &proof.proofs())?;

        Ok(())
    }
}

// Digest constraints.
//
// Initialization:
// - `committed_value_digest` should be zero.
//
// Transition:
// - If `commited_value_digest_prev` is not zero, then `committed_value_digest` should equal
//   `commited_value_digest_prev`.
// - If it's not a chunk with "CPU", then `commited_value_digest` should not change from the
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
    C: ChipBehavior<SC::Val>,
{
    pub fn new(config: SC, chips: Vec<MetaChip<SC::Val, C>>, num_public_values: usize) -> Self {
        Self {
            base_machine: BaseMachine::<SC, C>::new(config, chips, num_public_values),
        }
    }
}
