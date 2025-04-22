use crate::{
    compiler::{riscv::program::Program, word::Word},
    configs::config::{Com, StarkGenericConfig, Val},
    emulator::{
        emulator::MetaEmulator,
        riscv::{public_values::PublicValues, record::EmulationRecord},
    },
    instances::compiler::{
        shapes::riscv_shape::RiscvShapeConfig, vk_merkle::vk_verification_enabled,
    },
    iter::{IntoPicoIterator, PicoIterator},
    machine::{
        chip::{ChipBehavior, MetaChip},
        field::FieldSpecificPoseidon2Config,
        folder::{DebugConstraintFolder, ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, HashableKey},
        machine::{BaseMachine, MachineBehavior},
        proof::{BaseProof, MetaProof},
        witness::ProvingWitness,
    },
    messages::{
        gateway::GatewayMsg,
        riscv::{RiscvMsg, RiscvRequest},
    },
    primitives::{consts::MAX_LOG_CHUNK_SIZE, Poseidon2Init},
    thread::channel::DuplexUnboundedEndpoint,
};
use anyhow::Result;
use crossbeam::channel::{bounded, Receiver, Sender};
use p3_air::Air;
use p3_field::{FieldAlgebra, PrimeField32};
use p3_maybe_rayon::prelude::IndexedParallelIterator;
use p3_symmetric::Permutation;
use std::{any::type_name, borrow::Borrow, cmp::min, mem, thread, time::Instant};
use tracing::{debug, debug_span, info, instrument};

/// Maximum number of pending emulation record for proving
const MAX_PENDING_PROVING_RECORDS: usize = 32;

pub struct RiscvMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>,
{
    base_machine: BaseMachine<SC, C>,
}

impl<SC, C> RiscvMachine<SC, C>
where
    SC: Send + StarkGenericConfig + 'static,
    Val<SC>: PrimeField32 + FieldSpecificPoseidon2Config + Poseidon2Init,
    <Val<SC> as Poseidon2Init>::Poseidon2: Permutation<[Val<SC>; 16]>,
    C: Send + ChipBehavior<Val<SC>, Program = Program, Record = EmulationRecord> + 'static,
    Com<SC>: Send + Sync,
    BaseProof<SC>: Send + Sync,
{
    /// Prove with shape config
    #[instrument(name = "RISCV MACHINE PROVE", level = "debug", skip_all)]
    pub fn prove_with_shape_cycles(
        &self,
        witness: &ProvingWitness<SC, C, Vec<u8>>,
        shape_config: Option<&RiscvShapeConfig<SC::Val>>,
        coord_endpoint: Option<&DuplexUnboundedEndpoint<GatewayMsg<SC>, GatewayMsg<SC>>>,
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
        let start_global = Instant::now();

        // Initialize the challenger.
        let mut challenger = self.config().challenger();

        // Get PK from witness and observe with challenger.
        let pk = witness.pk();
        pk.observed_by(&mut challenger);

        // Initialize the emulator.
        let mut emulator = MetaEmulator::setup_riscv(witness);

        let channel_capacity = (4 * witness
            .opts
            .as_ref()
            .map(|opts| opts.chunk_batch_size)
            .unwrap_or(64)) as usize;
        // Initialize the channel for sending emulation records from the emulator thread to prover.
        let (record_sender, record_receiver): (Sender<_>, Receiver<_>) = bounded(channel_capacity);

        // Start the emulator thread.
        let emulator_handle = thread::spawn(move || {
            let mut batch_num = 1;
            loop {
                let start_local = Instant::now();

                let done = emulator.next_record_batch(&mut |record| {
                    record_sender.send(record).expect(
                        "Failed to send an emulation record from emulator thread to prover thread",
                    )
                });

                debug!(
                    "--- Generate riscv records for batch-{} in {:?}",
                    batch_num,
                    start_local.elapsed(),
                );

                if done {
                    break;
                }

                batch_num += 1;
            }

            // Move and return the emulator for futher usage.
            emulator

            // `record_sender` will be dropped when the emulator thread completes.
        });

        let all_proofs = if cfg!(feature = "distributed") {
            self.prove_remote(record_receiver, coord_endpoint.unwrap())
        } else {
            self.prove_local(
                pk,
                &challenger,
                shape_config,
                record_receiver,
                &start_global,
            )
        };

        let mut emulator = emulator_handle.join().unwrap();
        let cycles = emulator.cycles();

        debug!("--- Finish riscv in {:?}", start_global.elapsed());

        let vks = vec![witness.vk.clone().unwrap()];

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
        coord_endpoint: Option<&DuplexUnboundedEndpoint<GatewayMsg<SC>, GatewayMsg<SC>>>,
    ) -> (MetaProof<SC>, u64)
    where
        C: for<'a> Air<
                DebugConstraintFolder<
                    'a,
                    <SC as StarkGenericConfig>::Val,
                    <SC as StarkGenericConfig>::Challenge,
                >,
            > + Air<ProverConstraintFolder<SC>>,
        <SC as StarkGenericConfig>::Domain: Send,
    {
        self.prove_with_shape_cycles(witness, shape_config, coord_endpoint)
    }

    /// Generate RiscV proof for one emulation record.
    pub fn prove_record(
        &self,
        chunk_index: usize,
        pk: &BaseProvingKey<SC>,
        challenger: &SC::Challenger,
        shape_config: Option<&RiscvShapeConfig<SC::Val>>,
        mut record: EmulationRecord,
    ) -> BaseProof<SC>
    where
        C: Air<ProverConstraintFolder<SC>>,
    {
        // Complete the record.
        let chips = self.chips();
        RiscvMachine::complement_record_static(chips.clone(), &mut record);

        // Pad the shape.
        if vk_verification_enabled() {
            if let Some(shape_config) = shape_config {
                shape_config.padding_shape(&mut record).unwrap();
            }
        }

        // Commit the record.
        let main_commitment = self.base_machine.commit(&record).unwrap();

        // Generate the proof.
        self.base_machine
            .prove_plain(pk, &mut challenger.clone(), chunk_index, main_commitment)
    }

    /// Generate the RiscV proofs for the emulation records.
    fn prove_records(
        &self,
        base_chunk: usize,
        pk: &BaseProvingKey<SC>,
        challenger: &SC::Challenger,
        shape_config: Option<&RiscvShapeConfig<SC::Val>>,
        records: Vec<EmulationRecord>,
    ) -> Vec<BaseProof<SC>>
    where
        C: Air<ProverConstraintFolder<SC>>,
    {
        let record_len = records.len();
        let local_span =
                debug_span!(parent: &tracing::Span::current(), "riscv chunks prove loop", base_chunk, record_len)
                    .entered();

        let chips = self.chips();
        let proofs = records
            .into_pico_iter()
            .enumerate()
            .map(|(i, mut record)| {
                let chunk_index = base_chunk + i;
                // Complete the record.
                debug_span!(parent: &local_span, "complement_record", chunk_index).in_scope(|| {
                    RiscvMachine::complement_record_static(chips.clone(), &mut record)
                });

                // Pad the shape.
                if vk_verification_enabled() {
                    if let Some(shape_config) = shape_config {
                        debug_span!(parent: &local_span, "padding_shape", chunk_index)
                            .in_scope(|| shape_config.padding_shape(&mut record).unwrap());
                    }
                }

                // Commit the record.
                let main_commitment =
                    debug_span!(parent: &local_span, "generate_and_commit_main_traces", chunk_index)
                        .in_scope(|| self.base_machine.commit(&record).unwrap());

                // Generate the proof.
                debug_span!(parent: &local_span, "prove_plain", chunk_index).in_scope(|| {
                    self.base_machine.prove_plain(
                        pk,
                        &mut challenger.clone(),
                        chunk_index,
                        main_commitment,
                    )
                })
            })
            .collect();

        local_span.exit();

        proofs
    }

    fn prove_local(
        &self,
        pk: &BaseProvingKey<SC>,
        challenger: &SC::Challenger,
        shape_config: Option<&RiscvShapeConfig<SC::Val>>,
        record_receiver: Receiver<EmulationRecord>,
        start_global: &Instant,
    ) -> Vec<BaseProof<SC>>
    where
        C: for<'a> Air<
                DebugConstraintFolder<
                    'a,
                    <SC as StarkGenericConfig>::Val,
                    <SC as StarkGenericConfig>::Challenge,
                >,
            > + Air<ProverConstraintFolder<SC>>,
    {
        // Generate the proofs.
        let mut current_chunk = 0;

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

        let mut all_proofs = Vec::with_capacity(MAX_PENDING_PROVING_RECORDS);
        let max_pending_num = min(num_cpus::get(), MAX_PENDING_PROVING_RECORDS);
        let mut pending_records = Vec::with_capacity(max_pending_num);

        while let Ok(record) = record_receiver.recv() {
            pending_records.push(record);

            debug!(
                "Current riscv records queue size: {}",
                record_receiver.len()
            );

            // Generate the proofs for pending records.
            if pending_records.len() >= max_pending_num {
                debug!(
                    "--- Start to prove chunks {}-{} at {:?}",
                    current_chunk,
                    current_chunk + max_pending_num - 1,
                    start_global.elapsed(),
                );

                let records = mem::take(&mut pending_records);

                #[cfg(feature = "debug")]
                constraint_debugger.debug_incremental(&self.chips(), &records);
                #[cfg(feature = "debug-lookups")]
                {
                    crate::machine::debug::debug_regional_lookups(
                        pk,
                        &self.chips(),
                        &records,
                        None,
                    );
                    global_lookup_debugger.debug_incremental(&self.chips(), &records);
                }

                let proofs =
                    self.prove_records(current_chunk, pk, challenger, shape_config, records);
                all_proofs.extend(proofs);

                debug!(
                    "--- Finish proving chunks {}-{} at {:?}",
                    current_chunk,
                    current_chunk + max_pending_num - 1,
                    start_global.elapsed(),
                );

                current_chunk += max_pending_num;
            }
        }

        // Generate the proofs for remaining records.
        {
            let pending_len = pending_records.len();
            debug!(
                "--- Start to prove chunks {}-{} at {:?}",
                current_chunk,
                current_chunk + pending_len - 1,
                start_global.elapsed(),
            );

            #[cfg(feature = "debug")]
            constraint_debugger.debug_incremental(&self.chips(), &pending_records);
            #[cfg(feature = "debug-lookups")]
            {
                crate::machine::debug::debug_regional_lookups(
                    pk,
                    &self.chips(),
                    &pending_records,
                    None,
                );
                global_lookup_debugger.debug_incremental(&self.chips(), &pending_records);
            }

            let proofs =
                self.prove_records(current_chunk, pk, challenger, shape_config, pending_records);
            all_proofs.extend(proofs);

            debug!(
                "--- Finish proving chunks {}-{} at {:?}",
                current_chunk,
                current_chunk + pending_len - 1,
                start_global.elapsed(),
            );
        }

        #[cfg(feature = "debug")]
        constraint_debugger.print_results();
        #[cfg(feature = "debug-lookups")]
        global_lookup_debugger.print_results();

        all_proofs
    }

    fn prove_remote(
        &self,
        record_receiver: Receiver<EmulationRecord>,
        coord_endpoint: &DuplexUnboundedEndpoint<GatewayMsg<SC>, GatewayMsg<SC>>,
    ) -> Vec<BaseProof<SC>> {
        let mut chunk_index = 0;

        while let Ok(record) = record_receiver.recv() {
            let req = RiscvRequest {
                chunk_index,
                record,
            };

            debug!("send emulation record-{chunk_index}");
            coord_endpoint
                .send(GatewayMsg::Riscv(
                    RiscvMsg::Request(req),
                    // TODO: fix to id and ip address
                    chunk_index.to_string(),
                    "".to_string(),
                ))
                .unwrap();

            chunk_index += 1;
        }

        let mut proofs = Vec::with_capacity(chunk_index);
        proofs.resize(chunk_index, None);

        while let Ok(msg) = coord_endpoint.recv() {
            match msg {
                GatewayMsg::Riscv(RiscvMsg::Response(res), _, _) => {
                    let chunk_index = res.chunk_index;
                    debug!("receive riscv proof-{chunk_index}");

                    proofs[chunk_index] = Some(res.proof);
                    if proofs.iter().all(|p| p.is_some()) {
                        break;
                    }
                }
                GatewayMsg::Exit => break,
                _ => panic!("unsupported"),
            }
        }

        proofs.into_iter().map(|p| p.unwrap()).collect()
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
