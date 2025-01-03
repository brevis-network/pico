use crate::{
    compiler::{
        recursion_v2::{circuit::witness::witnessable::Witnessable, program::RecursionProgram},
        riscv::program::Program,
    },
    configs::config::{Challenge, StarkGenericConfig, Val},
    emulator::riscv::{
        record::EmulationRecord,
        riscv_emulator::{EmulatorMode, RiscvEmulator},
        stdin::EmulatorStdin,
    },
    instances::{
        chiptype::riscv_chiptype::RiscvChipType,
        compiler_v2::{
            recursion_circuit::stdin::RecursionStdin, riscv_circuit::stdin::ConvertStdin,
            vk_merkle::stdin::RecursionVkStdin,
        },
        configs::{
            recur_config::{FieldConfig as RecursionFC, StarkConfig as RecursionSC},
            riscv_config::StarkConfig as RiscvSC,
        },
    },
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, BaseVerifyingKey},
        machine::BaseMachine,
        witness::ProvingWitness,
    },
    primitives::consts::{BABYBEAR_S_BOX_DEGREE, PERMUTATION_WIDTH},
    recursion_v2::runtime::{RecursionRecord, Runtime},
};
use p3_air::Air;
use p3_field::PrimeField32;
use std::sync::Arc;

// todo: refactor

// Meta emulator that encapsulates multiple emulators
// SC and C for configs in the emulated machine
// P and I for the native program and input types
// E for the emulator type
pub struct MetaEmulator<'a, SC, C, P, I, E>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub stdin: &'a EmulatorStdin<P, I>,
    pub emulator: Option<E>,
    pub batch_size: usize, // max parallelism
    pointer: usize,
    machine: Option<&'a BaseMachine<SC, C>>, // used for setting-up and generating keys
}

// MetaEmulator for riscv
impl<'a, SC, C> MetaEmulator<'a, SC, C, Program, Vec<u8>, RiscvEmulator>
where
    SC: StarkGenericConfig,
    SC::Val: PrimeField32,
    C: ChipBehavior<Val<SC>, Program = Program, Record = EmulationRecord>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub fn setup_riscv(proving_witness: &'a ProvingWitness<SC, C, Vec<u8>>) -> Self {
        // create a new emulator based on the emulator type
        let opts = proving_witness.opts.unwrap();
        let mut emulator =
            RiscvEmulator::new::<SC::Val>(proving_witness.program.clone().unwrap(), opts);
        emulator.emulator_mode = EmulatorMode::Trace;
        for each in proving_witness
            .stdin
            .as_ref()
            .unwrap()
            .inputs
            .iter()
            .cloned()
        {
            emulator.state.input_stream.push(each);
        }

        Self {
            stdin: proving_witness.stdin.as_ref().unwrap(),
            emulator: Some(emulator),
            batch_size: opts.chunk_batch_size,
            pointer: 0,
            machine: None,
        }
    }

    pub fn next_record_batch(&mut self) -> (&mut [EmulationRecord], bool) {
        let emulator = self.emulator.as_mut().unwrap();
        let mut done = false;
        if emulator.emulate_to_batch().unwrap() {
            done = true;
        }
        (emulator.batch_records.as_mut_slice(), done)
    }
}

// MetaEmulator for convert
impl<'a, C>
    MetaEmulator<
        'a,
        RecursionSC,
        C,
        RecursionProgram<Val<RecursionSC>>,
        ConvertStdin<'a, RiscvSC, RiscvChipType<Val<RiscvSC>>>,
        RecursionEmulator<RecursionSC>,
    >
where
    C: ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, RecursionSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RecursionSC>>,
{
    pub fn setup_convert(
        proving_witness: &'a ProvingWitness<
            RecursionSC,
            C,
            ConvertStdin<'a, RiscvSC, RiscvChipType<Val<RiscvSC>>>,
        >,
        machine: &'a BaseMachine<RecursionSC, C>,
    ) -> Self {
        let batch_size = match proving_witness.opts {
            Some(opts) => opts.chunk_batch_size,
            None => 0,
        };
        Self {
            stdin: proving_witness.stdin.as_ref().unwrap(),
            emulator: None,
            batch_size,
            pointer: 0,
            machine: Some(machine),
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next_record_keys(
        &mut self,
    ) -> (
        RecursionRecord<Val<RecursionSC>>,
        BaseProvingKey<RecursionSC>,
        BaseVerifyingKey<RecursionSC>,
        bool,
    ) {
        let (program, input, done) = self.stdin.get_program_and_input(self.pointer);
        let (pk, vk) = self.machine.unwrap().setup_keys(program);
        let mut emulator = RecursionEmulator::<RecursionSC> {
            recursion_program: program.clone().into(),
            config: self.machine.unwrap().config(),
        };
        let record = emulator.run_riscv(input);
        self.pointer += 1;
        (record, pk, vk, done)
    }

    #[allow(clippy::type_complexity)]
    pub fn next_record_keys_batch(
        &mut self,
    ) -> (
        Vec<RecursionRecord<Val<RecursionSC>>>,
        Vec<BaseProvingKey<RecursionSC>>,
        Vec<BaseVerifyingKey<RecursionSC>>,
        bool,
    ) {
        let mut batch_records = vec![];
        let mut batch_pks = vec![];
        let mut batch_vks = vec![];
        loop {
            let (record, pk, vk, done) = self.next_record_keys();
            batch_records.push(record);
            batch_pks.push(pk);
            batch_vks.push(vk);
            if done {
                return (batch_records, batch_pks, batch_vks, true);
            }
            if batch_records.len() >= self.batch_size {
                break;
            }
        }
        (batch_records, batch_pks, batch_vks, false)
    }
}

// MetaEmulator for recursion combine
impl<'a, C, PrevC>
    MetaEmulator<
        'a,
        RecursionSC,
        C,
        RecursionProgram<Val<RecursionSC>>,
        RecursionStdin<'a, RecursionSC, PrevC>,
        RecursionEmulator<RecursionSC>,
    >
where
    PrevC: ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, RecursionSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RecursionSC>>,
    C: ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, RecursionSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RecursionSC>>,
{
    pub fn setup_combine(
        proving_witness: &'a ProvingWitness<RecursionSC, C, RecursionStdin<'a, RecursionSC, PrevC>>,
        machine: &'a BaseMachine<RecursionSC, C>,
    ) -> Self {
        let batch_size = match proving_witness.opts {
            Some(opts) => opts.chunk_batch_size,
            None => 0,
        };
        Self {
            stdin: proving_witness.stdin.as_ref().unwrap(),
            emulator: None,
            batch_size,
            pointer: 0,
            machine: Some(machine),
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next_record_keys(
        &mut self,
    ) -> (
        RecursionRecord<Val<RecursionSC>>,
        BaseProvingKey<RecursionSC>,
        BaseVerifyingKey<RecursionSC>,
        bool,
    ) {
        let (program, input, done) = self.stdin.get_program_and_input(self.pointer);
        let (pk, vk) = self.machine.unwrap().setup_keys(program);
        let mut emulator = RecursionEmulator::<RecursionSC> {
            recursion_program: program.clone().into(),
            config: self.machine.unwrap().config(),
        };
        let record = emulator.run_recursion(input);
        self.pointer += 1;
        (record, pk, vk, done)
    }

    #[allow(clippy::type_complexity)]
    pub fn next_record_keys_batch(
        &mut self,
    ) -> (
        Vec<RecursionRecord<Val<RecursionSC>>>,
        Vec<BaseProvingKey<RecursionSC>>,
        Vec<BaseVerifyingKey<RecursionSC>>,
        bool,
    ) {
        let mut batch_records = vec![];
        let mut batch_pks = vec![];
        let mut batch_vks = vec![];
        loop {
            let (record, pk, vk, done) = self.next_record_keys();
            batch_records.push(record);
            batch_pks.push(pk);
            batch_vks.push(vk);
            if done {
                return (batch_records, batch_pks, batch_vks, true);
            }
            if batch_records.len() >= self.batch_size {
                break;
            }
        }
        (batch_records, batch_pks, batch_vks, false)
    }
}

// MetaEmulator for recursion combine
impl<'a, C, PrevC>
    MetaEmulator<
        'a,
        RecursionSC,
        C,
        RecursionProgram<Val<RecursionSC>>,
        RecursionVkStdin<'a, RecursionSC, PrevC>,
        RecursionEmulator<RecursionSC>,
    >
where
    PrevC: ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, RecursionSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RecursionSC>>,
    C: ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, RecursionSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RecursionSC>>,
{
    pub fn setup_combine_vk(
        proving_witness: &'a ProvingWitness<
            RecursionSC,
            C,
            RecursionVkStdin<'a, RecursionSC, PrevC>,
        >,
        machine: &'a BaseMachine<RecursionSC, C>,
    ) -> Self {
        let batch_size = match proving_witness.opts {
            Some(opts) => opts.chunk_batch_size,
            None => 0,
        };
        Self {
            stdin: proving_witness.stdin.as_ref().unwrap(),
            emulator: None,
            batch_size,
            pointer: 0,
            machine: Some(machine),
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next_record_keys(
        &mut self,
    ) -> (
        RecursionRecord<Val<RecursionSC>>,
        BaseProvingKey<RecursionSC>,
        BaseVerifyingKey<RecursionSC>,
        bool,
    ) {
        let (program, input, done) = self.stdin.get_program_and_input(self.pointer);
        let (pk, vk) = self.machine.unwrap().setup_keys(program);
        let mut emulator = RecursionEmulator::<RecursionSC> {
            recursion_program: program.clone().into(),
            config: self.machine.unwrap().config(),
        };
        let record = emulator.run_recursion_vk(input);
        self.pointer += 1;
        (record, pk, vk, done)
    }

    #[allow(clippy::type_complexity)]
    pub fn next_record_keys_batch(
        &mut self,
    ) -> (
        Vec<RecursionRecord<Val<RecursionSC>>>,
        Vec<BaseProvingKey<RecursionSC>>,
        Vec<BaseVerifyingKey<RecursionSC>>,
        bool,
    ) {
        let mut batch_records = vec![];
        let mut batch_pks = vec![];
        let mut batch_vks = vec![];
        loop {
            let (record, pk, vk, done) = self.next_record_keys();
            batch_records.push(record);
            batch_pks.push(pk);
            batch_vks.push(vk);
            if done {
                return (batch_records, batch_pks, batch_vks, true);
            }
            if batch_records.len() >= self.batch_size {
                break;
            }
        }
        (batch_records, batch_pks, batch_vks, false)
    }
}

// Recursion emulator
pub struct RecursionEmulator<SC>
where
    SC: StarkGenericConfig,
{
    pub recursion_program: Arc<RecursionProgram<Val<SC>>>,
    pub config: Arc<SC>,
}

impl RecursionEmulator<RecursionSC> {
    pub fn run_riscv<RiscvC>(
        &mut self,
        stdin: &ConvertStdin<RiscvSC, RiscvC>,
    ) -> RecursionRecord<Val<RecursionSC>>
    where
        RiscvC: ChipBehavior<Val<RiscvSC>, Program = Program, Record = EmulationRecord>
            + for<'b> Air<ProverConstraintFolder<'b, RiscvSC>>
            + for<'b> Air<VerifierConstraintFolder<'b, RiscvSC>>,
    {
        let mut witness_stream = Vec::new();
        Witnessable::<RecursionFC>::write(&stdin, &mut witness_stream);

        let mut runtime = Runtime::<
            Val<RecursionSC>,
            Challenge<RecursionSC>,
            _,
            _,
            PERMUTATION_WIDTH,
            BABYBEAR_S_BOX_DEGREE,
        >::new(self.recursion_program.clone(), self.config.perm.clone());

        runtime.witness_stream = witness_stream.into();
        runtime.run().unwrap();
        runtime.record
    }

    pub fn run_recursion<RecursionC>(
        &mut self,
        stdin: &RecursionStdin<RecursionSC, RecursionC>,
    ) -> RecursionRecord<Val<RecursionSC>>
    where
        RecursionC: ChipBehavior<
                Val<RecursionSC>,
                Program = RecursionProgram<Val<RecursionSC>>,
                Record = RecursionRecord<Val<RecursionSC>>,
            > + for<'b> Air<ProverConstraintFolder<'b, RecursionSC>>
            + for<'b> Air<VerifierConstraintFolder<'b, RecursionSC>>,
    {
        let mut witness_stream = Vec::new();
        Witnessable::<RecursionFC>::write(&stdin, &mut witness_stream);

        let mut runtime = Runtime::<
            Val<RecursionSC>,
            Challenge<RecursionSC>,
            _,
            _,
            PERMUTATION_WIDTH,
            BABYBEAR_S_BOX_DEGREE,
        >::new(self.recursion_program.clone(), self.config.perm.clone());
        runtime.witness_stream = witness_stream.into();
        runtime.run().unwrap();
        runtime.record
    }

    pub fn run_recursion_vk<RecursionC>(
        &mut self,
        stdin: &RecursionVkStdin<RecursionSC, RecursionC>,
    ) -> RecursionRecord<Val<RecursionSC>>
    where
        RecursionC: ChipBehavior<
                Val<RecursionSC>,
                Program = RecursionProgram<Val<RecursionSC>>,
                Record = RecursionRecord<Val<RecursionSC>>,
            > + for<'b> Air<ProverConstraintFolder<'b, RecursionSC>>
            + for<'b> Air<VerifierConstraintFolder<'b, RecursionSC>>,
    {
        let mut witness_stream = Vec::new();
        Witnessable::<RecursionFC>::write(&stdin, &mut witness_stream);

        let mut runtime = Runtime::<
            Val<RecursionSC>,
            Challenge<RecursionSC>,
            _,
            _,
            PERMUTATION_WIDTH,
            BABYBEAR_S_BOX_DEGREE,
        >::new(self.recursion_program.clone(), self.config.perm.clone());
        runtime.witness_stream = witness_stream.into();
        runtime.run().unwrap();
        runtime.record
    }
}
