use crate::{
    compiler::{
        recursion::{program::RecursionProgram, program_builder::hints::hintable::Hintable},
        riscv::program::Program,
        word::Word,
    },
    configs::{
        config::{StarkGenericConfig, Val},
        stark_config::bb_poseidon2::BabyBearPoseidon2,
    },
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
    instances::{
        compiler::riscv_circuit::stdin::RiscvRecursionStdin,
        configs::{recur_config::StarkConfig as RecursionSC, riscv_config::StarkConfig as RiscvSC},
        machine::riscv_machine::RiscvMachine,
    },
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{
            ProverConstraintFolder, RecursiveVerifierConstraintFolder, VerifierConstraintFolder,
        },
        keys::{BaseProvingKey, BaseVerifyingKey},
        machine::{BaseMachine, MachineBehavior},
        proof::{EnsembleProof, MetaProof},
        witness::ProvingWitness,
    },
    primitives::consts::MAX_LOG_CHUNK_SIZE,
    recursion::{air::RecursionPublicValues, runtime::RecursionRecord},
};
use anyhow::Result;
use log::{debug, info};
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_challenger::{CanObserve, DuplexChallenger};
use p3_field::AbstractField;
use std::{any::type_name, borrow::Borrow, marker::PhantomData, time::Instant};

pub struct RiscvRecursionMachine<NC, C>
where
    NC: ChipBehavior<Val<RiscvSC>, Program = Program, Record = EmulationRecord>
        + for<'b> Air<ProverConstraintFolder<'b, RiscvSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RiscvSC>>,
    C: ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, RecursionSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RecursionSC>>,
{
    config: RecursionSC,

    chips: Vec<MetaChip<Val<RecursionSC>, C>>,

    base_machine: BaseMachine<RecursionSC, C>,

    _phantom: PhantomData<NC>,
}

impl<'a, NC, C>
    MachineBehavior<
        RiscvSC,
        NC,
        RecursionSC,
        C,
        EnsembleProof<RecursionSC>,
        RiscvRecursionStdin<'a, RiscvSC, NC>,
    > for RiscvRecursionMachine<NC, C>
where
    NC: ChipBehavior<Val<RiscvSC>, Program = Program, Record = EmulationRecord>
        + for<'b> Air<ProverConstraintFolder<'b, RiscvSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RiscvSC>>,
    C: ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, RecursionSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RecursionSC>>,
{
    /// Get the name of the machine.
    fn name(&self) -> String {
        format!("Riscv Compress Machine <{}>", type_name::<RecursionSC>())
    }

    /// Get the configuration of the machine.
    fn config(&self) -> &RecursionSC {
        &self.config
    }

    /// Get the number of public values
    fn num_public_values(&self) -> usize {
        self.base_machine.num_public_values()
    }

    /// Get the chips of the machine.
    fn chips(&self) -> &[MetaChip<Val<RecursionSC>, C>] {
        &self.chips
    }

    /// setup prover, verifier and keys.
    fn setup_keys(
        &self,
        program: &C::Program,
    ) -> (BaseProvingKey<RecursionSC>, BaseVerifyingKey<RecursionSC>) {
        info!("PERF-machine=recursion");
        let begin = Instant::now();

        let (pk, vk) = self
            .base_machine
            .setup_keys(self.config(), self.chips(), program);

        info!(
            "PERF-step=setup_keys-user_time={}",
            begin.elapsed().as_millis()
        );

        (pk, vk)
    }

    /// Get the prover of the machine.
    fn prove(
        &self,
        pk: &BaseProvingKey<RecursionSC>,
        witness: &ProvingWitness<RiscvSC, NC, RecursionSC, C, RiscvRecursionStdin<RiscvSC, NC>>,
    ) -> MetaProof<RecursionSC, EnsembleProof<RecursionSC>> {
        info!("PERF-machine=recursion");
        let begin = Instant::now();

        let mut challenger = self.config().challenger();
        pk.observed_by(&mut challenger);

        // First phase
        // Generate batch records and commit to challenger

        let mut chunk = 1;
        let mut recursion_emulator = MetaEmulator::setup_riscv_compress(witness, 1);
        loop {
            let (record, done) = recursion_emulator.next();
            let mut records = vec![record];

            // read slice of records and complement them
            self.complement_record(records.as_mut_slice());

            debug!("record stats");
            let stats = records[0].stats();
            for (key, value) in &stats {
                debug!("{:<25}: {}", key, value);
            }

            info!("PERF-chunk={chunk}-phase=1");

            let commitment = self
                .base_machine
                .commit(self.config(), &self.chips, &records[0]);

            challenger.observe(commitment.commitment.clone());
            challenger.observe_slice(&commitment.public_values[..self.num_public_values()]);

            if done {
                break;
            }

            chunk += 1;
        }

        // Second phase
        // Generate batch records and generate proofs

        let mut recursion_emulator = MetaEmulator::setup_riscv_compress(witness, 1);
        let mut all_proofs = vec![];
        let mut chunk = 1;
        loop {
            let (record, done) = recursion_emulator.next();
            let mut records = vec![record];

            self.complement_record(records.as_mut_slice());

            info!("PERF-chunk={chunk}-phase=2");
            let commitment = self
                .base_machine
                .commit(self.config(), &self.chips, &records[0]);

            let proof = self.base_machine.prove_plain(
                self.config(),
                &self.chips,
                pk,
                &mut challenger.clone(),
                commitment,
            );

            // extend all_proofs to include batch_proofs
            all_proofs.push(proof);

            if done {
                break;
            }

            chunk += 1;
        }

        info!("PERF-step=prove-user_time={}", begin.elapsed().as_millis(),);

        // construct meta proof
        let proof = MetaProof::new(self.config(), EnsembleProof::new(all_proofs));
        let proof_size = bincode::serialize(&proof).unwrap().len();
        info!("PERF-step=proof_size-{}", proof_size);

        proof
    }

    /// Verify the proof.
    fn verify(
        &self,
        vk: &BaseVerifyingKey<RecursionSC>,
        proof: &MetaProof<RecursionSC, EnsembleProof<RecursionSC>>,
    ) -> Result<()> {
        info!("PERF-machine=recursion");
        let begin = Instant::now();

        for each_proof in proof.proofs().iter() {
            let public_values: &RecursionPublicValues<_> =
                each_proof.public_values.as_slice().borrow();

            debug!("public values: {:?}", public_values);
        }

        self.base_machine
            .verify_ensemble(self.config(), self.chips(), vk, proof.proofs())?;

        info!("PERF-step=verify-user_time={}", begin.elapsed().as_millis(),);

        Ok(())
    }
}

impl<RiscvC, C> RiscvRecursionMachine<RiscvC, C>
where
    RiscvC: ChipBehavior<Val<RiscvSC>, Program = Program, Record = EmulationRecord>
        + for<'b> Air<ProverConstraintFolder<'b, RiscvSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RiscvSC>>,
    C: ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, RecursionSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RecursionSC>>,
{
    pub fn new(
        config: RecursionSC,
        num_public_values: usize,
        chips: Vec<MetaChip<Val<RecursionSC>, C>>,
    ) -> Self {
        Self {
            config,
            chips,
            base_machine: BaseMachine::<RecursionSC, C>::new(num_public_values),
            _phantom: PhantomData,
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
