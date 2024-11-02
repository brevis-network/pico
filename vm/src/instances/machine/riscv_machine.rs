use crate::{
    compiler::{riscv::program::Program, word::Word},
    configs::config::StarkGenericConfig,
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
        proof::MetaProof,
        witness::ProvingWitness,
    },
    primitives::consts::MAX_LOG_CHUNK_SIZE,
};

use crate::{configs::config::Val, instances::configs::riscv_config::StarkConfig as RiscvSC};
use anyhow::Result;
use log::{debug, info};
use p3_air::Air;
use p3_challenger::CanObserve;
use p3_field::AbstractField;
use std::{any::type_name, borrow::Borrow, time::Instant};

#[cfg(feature = "debug")]
use crate::machine::utils::debug_all_chips_constraints;

pub struct RiscvMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    base_machine: BaseMachine<SC, C>,
}

impl<C> MachineBehavior<RiscvSC, C, Vec<u8>> for RiscvMachine<RiscvSC, C>
where
    C: ChipBehavior<Val<RiscvSC>, Program = Program, Record = EmulationRecord>
        + for<'a> Air<ProverConstraintFolder<'a, RiscvSC>>
        + for<'a> Air<VerifierConstraintFolder<'a, RiscvSC>>,
{
    /// Get the name of the machine.
    fn name(&self) -> String {
        format!("RiscvMachine <{}>", type_name::<RiscvSC>())
    }

    /// Get the base machine.
    fn base_machine(&self) -> &BaseMachine<RiscvSC, C> {
        &self.base_machine
    }

    /// Get the prover of the machine.
    fn prove(
        &self,
        pk: &BaseProvingKey<RiscvSC>,
        witness: &ProvingWitness<RiscvSC, C, Vec<u8>>,
    ) -> MetaProof<RiscvSC>
    where
        C: for<'a> Air<
            DebugConstraintFolder<
                'a,
                <RiscvSC as StarkGenericConfig>::Val,
                <RiscvSC as StarkGenericConfig>::Challenge,
            >,
        >,
    {
        info!("PERF-machine=riscv");
        let begin = Instant::now();

        let ProvingWitness {
            // program,
            // stdin,
            opts,
            // context,
            ..
        } = witness;

        let mut challenger = self.config().challenger();
        pk.observed_by(&mut challenger);

        // First phase
        // Generate batch records and commit to challenger

        let mut emulator = MetaEmulator::setup_riscv(witness, opts.unwrap().chunk_batch_size);
        loop {
            let (batch_records, done) = emulator.next_batch();

            self.complement_record(batch_records);

            for (i, record) in batch_records.iter().enumerate() {
                debug!("record {} stats", i);
                let stats = record.stats();
                for (key, value) in &stats {
                    debug!("{:<25}: {}", key, value);
                }

                info!("PERF-phase=1-chunk={}", record.chunk_index(),);
                let commitment = self.base_machine.commit(record);

                challenger.observe(commitment.commitment.clone());
                challenger.observe_slice(&commitment.public_values[..self.num_public_values()]);
            }

            if done {
                break;
            }
        }

        // Second phase
        // Generate batch records and generate proofs

        let mut emulator = MetaEmulator::setup_riscv(witness, opts.unwrap().chunk_batch_size);

        // all_proofs is a vec that contains BaseProof's. Initialized to be empty.
        let mut all_proofs = vec![];

        #[cfg(feature = "debug-lookup")]
        let mut all_records = Vec::new();
        loop {
            let (batch_records, done) = emulator.next_batch();

            self.complement_record(batch_records);
            #[cfg(feature = "debug-lookup")]
            all_records.extend_from_slice(batch_records);

            #[cfg(feature = "debug")]
            {
                let mut debug_challenger = self.config().challenger();
                debug_all_chips_constraints(
                    &self.chips(),
                    pk,
                    batch_records,
                    &mut debug_challenger,
                );
            }

            let batch_main_commitments = batch_records
                .iter()
                .map(|record| {
                    info!("PERF-phase=2-chunk={}", record.chunk_index(),);
                    // generate and commit main trace
                    self.base_machine.commit(record)
                })
                .collect::<Vec<_>>();

            let batch_proofs = batch_main_commitments
                .into_iter()
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

        #[cfg(feature = "debug-lookup")]
        {
            use crate::machine::debug::lookup::DebugLookup;
            DebugLookup::debug_all(&self.chips, pk, &all_records, None);
        }

        proof
    }

    /// Verify the proof.
    fn verify(&self, vk: &BaseVerifyingKey<RiscvSC>, proof: &MetaProof<RiscvSC>) -> Result<()> {
        info!("PERF-machine=riscv");
        let begin = Instant::now();

        // initialize bookkeeping
        let mut proof_count = <Val<RiscvSC>>::zero();
        let mut execution_proof_count = <Val<RiscvSC>>::zero();
        let mut prev_next_pc = vk.pc_start;
        let mut prev_last_initialize_addr_bits = [<Val<RiscvSC>>::zero(); 32];
        let mut prev_last_finalize_addr_bits = [<Val<RiscvSC>>::zero(); 32];

        let mut flag_extra = true;

        for (i, each_proof) in proof.proofs().iter().enumerate() {
            let public_values: &PublicValues<Word<_>, _> =
                each_proof.public_values.as_slice().borrow();

            // beginning constraints
            if i == 0 {
                if !each_proof.includes_chip("Cpu") {
                    panic!("First proof does not include Cpu chip");
                }
            }

            // conditional constraints
            proof_count += <Val<RiscvSC>>::one();
            // hack to make execution chunk consistent

            if each_proof.includes_chip("Cpu") {
                execution_proof_count += <Val<RiscvSC>>::one();

                if each_proof.log_main_degree() > MAX_LOG_CHUNK_SIZE as usize {
                    panic!("Cpu log degree too large");
                }

                if public_values.start_pc == <Val<RiscvSC>>::zero() {
                    panic!("First proof start_pc is zero");
                }
            } else {
                if public_values.start_pc != public_values.next_pc {
                    panic!("Non-Cpu proof start_pc is not equal to next_pc");
                }
                if flag_extra {
                    execution_proof_count += <Val<RiscvSC>>::one();
                    flag_extra = false;
                }
            }
            if !each_proof.includes_chip("MemoryInitialize") {
                if public_values.previous_initialize_addr_bits
                    != public_values.last_initialize_addr_bits
                {
                    panic!("Previous initialize addr bits mismatch");
                }
            }
            if !each_proof.includes_chip("MemoryFinalize") {
                if public_values.previous_finalize_addr_bits
                    != public_values.last_finalize_addr_bits
                {
                    panic!("Previous finalize addr bits mismatch");
                }
            }

            // ending constraints
            if i == proof.proofs().len() - 1 {
                if public_values.next_pc != <Val<RiscvSC>>::zero() {
                    panic!("Last proof next_pc is not zero");
                }
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
            if public_values.exit_code != <Val<RiscvSC>>::zero() {
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
        }

        // TODO: add committed_value_digest support

        self.base_machine.verify_ensemble(vk, proof.proofs())?;

        info!("PERF-step=verify-user_time={}", begin.elapsed().as_millis(),);

        Ok(())
    }
}

impl<SC, C> RiscvMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    pub fn new(config: SC, chips: Vec<MetaChip<SC::Val, C>>, num_public_values: usize) -> Self {
        Self {
            base_machine: BaseMachine::<SC, C>::new(config, chips, num_public_values),
        }
    }
}
