use crate::{
    compiler::{program::Program, word::Word},
    configs::config::{StarkGenericConfig, Val},
    emulator::{
        context::EmulatorContext,
        opts::EmulatorOpts,
        record::RecordBehavior,
        riscv::{
            public_values::PublicValues,
            record::EmulationRecord,
            riscv_emulator::{EmulatorMode, RiscvEmulator},
        },
        stdin::EmulatorStdin,
    },
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip},
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, BaseVerifyingKey},
        machine::{BaseMachine, MachineBehavior},
        proof::{EnsembleProof, MetaProof},
    },
};
use anyhow::Result;
use log::{debug, info};
use p3_air::Air;
use p3_challenger::CanObserve;
use p3_field::AbstractField;
use std::{any::type_name, borrow::Borrow};

const MAX_LOG_CHUNK_SIZE: i32 = 22;

pub struct RiscvMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    config: SC,

    chips: Vec<MetaChip<Val<SC>, C>>,

    base_machine: BaseMachine<SC, C>,
}

impl<SC, C> MachineBehavior<SC, C, EnsembleProof<SC>> for RiscvMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    /// Get the name of the machine.
    fn name(&self) -> String {
        format!("RiscvMachine<{}>", type_name::<SC>())
    }

    /// Get the configuration of the machine.
    fn config(&self) -> &SC {
        &self.config
    }

    /// Get the number of public values
    fn num_public_values(&self) -> usize {
        self.base_machine.num_public_values
    }

    /// Get the chips of the machine.
    fn chips(&self) -> &[MetaChip<Val<SC>, C>] {
        &self.chips
    }

    /// setup prover, verifier and keys.
    fn setup_keys(&self, program: &Program) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>) {
        // todo: implement specific key setup logic here
        self.base_machine
            .setup_keys(self.config(), self.chips(), program)
    }

    /// Get the prover of the machine.
    fn prove(
        &self,
        _pk: &BaseProvingKey<SC>,
        _records: &[C::Record],
    ) -> MetaProof<SC, EnsembleProof<SC>> {
        panic!("should not be called!")
    }

    /// Verify the proof.
    fn verify(
        &self,
        vk: &BaseVerifyingKey<SC>,
        proof: &MetaProof<SC, EnsembleProof<SC>>,
    ) -> Result<()> {
        // initialize bookkeeping
        let mut proof_count = <Val<SC>>::zero();
        let mut execution_proof_count = <Val<SC>>::zero();
        let mut prev_next_pc = vk.pc_start;
        let mut prev_last_initialize_addr_bits = [<Val<SC>>::zero(); 32];
        let mut prev_last_finalize_addr_bits = [<Val<SC>>::zero(); 32];

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
            proof_count += <Val<SC>>::one();
            if each_proof.includes_chip("Cpu") {
                execution_proof_count += <Val<SC>>::one();

                if each_proof.log_main_degree() > MAX_LOG_CHUNK_SIZE as usize {
                    panic!("Cpu log degree too large");
                }

                if public_values.start_pc == <Val<SC>>::zero() {
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
                if public_values.next_pc != <Val<SC>>::zero() {
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
            if public_values.exit_code != <Val<SC>>::zero() {
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
    C: ChipBehavior<Val<SC>, Record = EmulationRecord>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    pub fn new(config: SC, num_public_values: usize, chips: Vec<MetaChip<Val<SC>, C>>) -> Self {
        Self {
            config,
            chips,
            base_machine: BaseMachine::<SC, C>::new(num_public_values),
        }
    }

    // TODO: consider refactor or merge with prove()
    pub fn emulate_and_prove(
        &self,
        pk: &BaseProvingKey<SC>,
        program: Program,
        stdin: &EmulatorStdin,
        opts: EmulatorOpts,
        context: EmulatorContext,
    ) -> MetaProof<SC, EnsembleProof<SC>> {
        info!("challenger observe pk");
        let mut challenger = self.config().challenger();
        pk.observed_by(&mut challenger);

        // First phase
        // Generate batch records and commit to challenger
        info!("phase 1 - BEGIN");
        let mut emulator = RiscvEmulator::new(program.clone(), opts);
        emulator.emulator_mode = EmulatorMode::Trace;
        for input in &stdin.buffer {
            emulator.state.input_stream.push(input.clone());
        }

        let mut done = false;

        loop {
            if emulator.emulate_to_batch().unwrap() {
                done = true;
            }

            // println!("emulater batch: {:?}", emulator.batch_records);

            debug!("phase 1 complement records");
            self.complement_record(&mut emulator.batch_records);

            for (i, record) in emulator.batch_records.iter().enumerate() {
                debug!("record {} stats", i);
                let stats = record.stats();
                for (key, value) in &stats {
                    debug!("{:<25}: {}", key, value);
                }

                debug!("phase 1 generate commitments for batch records");
                let commitment = self.base_machine.prover.commit_main(
                    self.config(),
                    record,
                    self.base_machine.prover.generate_main(&self.chips, record),
                );
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
        let mut emulator = RiscvEmulator::new(program, opts);
        emulator.emulator_mode = EmulatorMode::Trace;
        for input in &stdin.buffer {
            emulator.state.input_stream.push(input.clone());
        }
        let mut done = false;

        // all_proofs is a vec that contains BaseProof's. Initialized to be empty.
        let mut all_proofs = vec![];
        let mut proof_num = 0;
        loop {
            if emulator.emulate_to_batch().unwrap() {
                done = true;
            }

            debug!("phase 2 complement records");
            self.complement_record(&mut emulator.batch_records);

            info!("phase 2 generate commitments for batch records");
            let batch_main_commitments = emulator
                .batch_records
                .iter()
                .map(|record| {
                    // generate and commit main trace
                    self.base_machine.prover.commit_main(
                        self.config(),
                        record,
                        self.base_machine.prover.generate_main(&self.chips, record),
                    )
                })
                .collect::<Vec<_>>();

            info!("phase 2 prove batch records");
            let batch_proofs = batch_main_commitments
                .into_iter()
                .map(|commitment| {
                    self.base_machine.prove_plain(
                        self.config(),
                        &self.chips,
                        pk,
                        &mut challenger.clone(),
                        commitment,
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
}
