use crate::{
    compiler::{riscv::program::Program, word::Word},
    configs::config::StarkGenericConfig,
    emulator::{
        context::EmulatorContext,
        emulator::MetaEmulator,
        opts::EmulatorOpts,
        record::RecordBehavior,
        riscv::{
            public_values::PublicValues,
            record::EmulationRecord,
            riscv_emulator::{EmulatorMode, RiscvEmulator},
            stdin::EmulatorStdin,
        },
    },
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, BaseVerifyingKey},
        machine::{BaseMachine, MachineBehavior},
        perf::{Perf, PerfContext},
        proof::{EnsembleProof, MetaProof},
        witness::ProvingWitness,
    },
    primitives::consts::MAX_LOG_CHUNK_SIZE,
};

use crate::emulator::emulator::EmulatorType;
use anyhow::Result;
use log::{debug, info};
use p3_air::Air;
use p3_challenger::CanObserve;
use p3_field::AbstractField;
use std::{any::type_name, borrow::Borrow};

pub struct RiscvMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    config: SC,

    chips: Vec<MetaChip<SC::Val, C>>,

    base_machine: BaseMachine<SC, C>,
}

impl<SC, C> MachineBehavior<SC, C, SC, C, EnsembleProof<SC>, Vec<u8>> for RiscvMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val, Program = Program, Record = EmulationRecord>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    /// Get the name of the machine.
    fn name(&self) -> String {
        format!("Riscv Machine<{}>", type_name::<SC>())
    }

    /// Get the configuration of the machine.
    fn config(&self) -> &SC {
        &self.config
    }

    /// Get the number of public values
    fn num_public_values(&self) -> usize {
        self.base_machine.num_public_values()
    }

    /// Get the chips of the machine.
    fn chips(&self) -> &[MetaChip<SC::Val, C>] {
        &self.chips
    }

    /// setup prover, verifier and keys.
    fn setup_keys(&self, program: &C::Program) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>) {
        self.base_machine
            .setup_keys(self.config(), self.chips(), program)
    }

    /// Get the prover of the machine.
    fn prove(
        &self,
        pk: &BaseProvingKey<SC>,
        witness: &ProvingWitness<SC, C, SC, C, Vec<u8>>,
    ) -> MetaProof<SC, EnsembleProof<SC>> {
        let ProvingWitness {
            program,
            stdin,
            opts,
            context,
            ..
        } = witness;

        info!("challenger observe pk");
        let mut challenger = self.config().challenger();
        pk.observed_by(&mut challenger);

        // First phase
        // Generate batch records and commit to challenger
        info!("phase 1 - BEGIN");

        let mut emulator = MetaEmulator::setup_riscv(witness, opts.unwrap().chunk_batch_size);

        loop {
            let (batch_records, done) = emulator.next_batch();

            debug!("phase 1 complement records");
            self.complement_record(batch_records);

            for (i, record) in batch_records.iter().enumerate() {
                debug!("record {} stats", i);
                let stats = record.stats();
                for (key, value) in &stats {
                    debug!("{:<25}: {}", key, value);
                }

                debug!("phase 1 generate commitments for batch records");
                let mut perf_ctx = PerfContext::default();
                perf_ctx.set_chunk(Some(i as u32 + 1));
                let commitment =
                    self.base_machine
                        .commit(self.config(), &self.chips, record, &perf_ctx);

                challenger.observe(commitment.commitment.clone());
                challenger.observe_slice(&commitment.public_values[..self.num_public_values()]);
            }

            if done {
                break;
            }
        }
        info!("phase 1 - END");

        // Second phase
        // Generate batch records and generate proofs
        info!("phase 2 - BEGIN");

        let mut emulator = MetaEmulator::setup_riscv(witness, opts.unwrap().chunk_batch_size);

        // all_proofs is a vec that contains BaseProof's. Initialized to be empty.
        let mut all_proofs = vec![];
        loop {
            let (batch_records, done) = emulator.next_batch();

            debug!("phase 2 complement records");
            self.complement_record(batch_records);

            info!("phase 2 generate commitments for batch records");
            let batch_main_commitments = batch_records
                .iter()
                .enumerate()
                .map(|(i, record)| {
                    let mut perf_ctx = PerfContext::default();
                    perf_ctx.set_chunk(Some(i as u32 + 1));

                    // generate and commit main trace
                    self.base_machine
                        .commit(self.config(), &self.chips, record, &perf_ctx)
                })
                .collect::<Vec<_>>();

            info!("phase 2 prove batch records");
            let batch_proofs = batch_main_commitments
                .into_iter()
                .enumerate()
                .map(|(i, commitment)| {
                    let mut perf_ctx = PerfContext::default();
                    perf_ctx.set_chunk(Some(i as u32 + 1));

                    self.base_machine.prove_plain(
                        self.config(),
                        &self.chips,
                        pk,
                        &mut challenger.clone(),
                        commitment,
                        &perf_ctx,
                    )
                })
                .collect::<Vec<_>>();

            // extend all_proofs to include batch_proofs
            all_proofs.extend(batch_proofs);

            if done {
                break;
            }
        }
        info!("phase 2 - END");

        // construct meta proof
        MetaProof::new(self.config(), EnsembleProof::new(all_proofs))
    }

    /// Verify the proof.
    fn verify(
        &self,
        vk: &BaseVerifyingKey<SC>,
        proof: &MetaProof<SC, EnsembleProof<SC>>,
    ) -> Result<()> {
        // initialize bookkeeping
        let mut proof_count = <SC::Val>::zero();
        let mut execution_proof_count = <SC::Val>::zero();
        let mut prev_next_pc = vk.pc_start;
        let mut prev_last_initialize_addr_bits = [<SC::Val>::zero(); 32];
        let mut prev_last_finalize_addr_bits = [<SC::Val>::zero(); 32];

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
            proof_count += <SC::Val>::one();
            if each_proof.includes_chip("Cpu") {
                execution_proof_count += <SC::Val>::one();

                if each_proof.log_main_degree() > MAX_LOG_CHUNK_SIZE as usize {
                    panic!("Cpu log degree too large");
                }

                if public_values.start_pc == <SC::Val>::zero() {
                    panic!("First proof start_pc is zero");
                }
            } else {
                if public_values.start_pc != public_values.next_pc {
                    panic!("Non-Cpu proof start_pc is not equal to next_pc");
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
                if public_values.next_pc != <SC::Val>::zero() {
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
            if public_values.exit_code != <SC::Val>::zero() {
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

        self.base_machine
            .verify_ensemble(self.config(), self.chips(), vk, proof.proofs())?;

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
    pub fn new(config: SC, num_public_values: usize, chips: Vec<MetaChip<SC::Val, C>>) -> Self {
        Self {
            config,
            chips,
            base_machine: BaseMachine::<SC, C>::new(num_public_values),
        }
    }

    /// Returns the id of all chips in the machine that have preprocessed columns.
    pub fn preprocessed_chip_ids(&self) -> Vec<usize> {
        self.chips
            .iter()
            .enumerate()
            .filter(|(_, chip)| chip.preprocessed_width() > 0)
            .map(|(i, _)| i)
            .collect()
    }
}
