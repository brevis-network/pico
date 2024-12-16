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
            recursion_circuit::stdin::RecursionStdin, riscv_circuit::stdin::RiscvRecursionStdin,
        },
        configs::{
            recur_config::{FieldConfig as RecursionFC, StarkConfig as RecursionSC},
            riscv_config::StarkConfig as RiscvSC,
        },
    },
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        witness::ProvingWitness,
    },
    primitives::consts::{BABYBEAR_S_BOX_DEGREE, PERMUTATION_WIDTH},
    recursion_v2::runtime::{RecursionRecord, Runtime},
};
use p3_air::Air;
use p3_baby_bear::BabyBear;
use std::sync::Arc;

pub enum EmulatorType {
    Riscv,
    RiscvCompress,
    Combine,
}

// Meta emulator that encapsulates multiple emulators
pub struct MetaEmulator<'a, SC, C, I, E> {
    pub kind: EmulatorType,
    pub stdin: &'a EmulatorStdin<I>,
    pub emulator: E,
    pub batch_size: usize, // max parallelism
    ptr: usize,
    phantom: std::marker::PhantomData<(SC, C)>,
}

// MetaEmulator for riscv
impl<'a, SC, C> MetaEmulator<'a, SC, C, Vec<u8>, RiscvEmulator>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>, Program = Program, Record = EmulationRecord>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub fn setup_riscv(input: &'a ProvingWitness<SC, C, Vec<u8>>) -> Self {
        // create a new emulator based on the emulator type
        let opts = input.opts.unwrap();
        let mut emulator = RiscvEmulator::new::<BabyBear>(input.program.clone(), opts);
        emulator.emulator_mode = EmulatorMode::Trace;
        for each in input.stdin.as_ref().unwrap().buffer.to_vec() {
            emulator.state.input_stream.push(each);
        }

        Self {
            kind: EmulatorType::Riscv,
            stdin: &input.stdin.as_ref().unwrap(),
            emulator,
            batch_size: opts.chunk_batch_size,
            ptr: 0,
            phantom: std::marker::PhantomData,
        }
    }

    pub fn next_batch(&mut self) -> (&mut [EmulationRecord], bool) {
        let mut done = false;
        if self.emulator.emulate_to_batch().unwrap() {
            done = true;
        }
        (self.emulator.batch_records.as_mut_slice(), done)
    }
}

// MetaEmulator for riscv-compress
impl<'a, C>
    MetaEmulator<
        'a,
        RecursionSC,
        C,
        RiscvRecursionStdin<'a, RiscvSC, RiscvChipType<Val<RiscvSC>>>,
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
    pub fn setup_riscv_compress(
        input: &'a ProvingWitness<
            RecursionSC,
            C,
            RiscvRecursionStdin<'a, RiscvSC, RiscvChipType<Val<RiscvSC>>>,
        >,
    ) -> Self {
        let emulator = RecursionEmulator {
            recursion_program: input.program.clone(),
            config: input.config.clone().unwrap(),
        };

        let batch_size = match input.opts {
            Some(opts) => opts.chunk_batch_size,
            None => 0,
        };
        Self {
            kind: EmulatorType::RiscvCompress,
            stdin: input.stdin.as_ref().unwrap(),
            emulator,
            batch_size,
            ptr: 0,
            phantom: std::marker::PhantomData,
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> (RecursionRecord<Val<RecursionSC>>, bool) {
        let (stdin, done) = self.stdin.get(self.ptr);
        let record = self.emulator.run_riscv(stdin);
        self.ptr += 1;
        (record, done)
    }

    pub fn next_batch(&mut self) -> (Vec<RecursionRecord<Val<RecursionSC>>>, bool) {
        let mut batch_records = vec![];
        loop {
            let (record, done) = self.next();
            batch_records.push(record);
            if done {
                return (batch_records, true);
            }
            if batch_records.len() >= self.batch_size {
                break;
            }
        }
        (batch_records, false)
    }
}

// MetaEmulator for recursion combine
impl<'a, C, RecursionC>
    MetaEmulator<
        'a,
        RecursionSC,
        C,
        RecursionStdin<'a, RecursionSC, RecursionC>,
        RecursionEmulator<RecursionSC>,
    >
where
    C: ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, RecursionSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RecursionSC>>,
    RecursionC: ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, RecursionSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RecursionSC>>,
{
    pub fn setup_recursion(
        input: &'a ProvingWitness<RecursionSC, C, RecursionStdin<'a, RecursionSC, RecursionC>>,
    ) -> Self {
        let emulator = RecursionEmulator {
            recursion_program: input.program.clone(),
            config: input.config.clone().unwrap(),
        };

        let batch_size = match input.opts {
            Some(opts) => opts.chunk_batch_size,
            None => 0,
        };

        Self {
            kind: EmulatorType::Combine,
            stdin: &input.stdin.as_ref().unwrap(),
            emulator,
            batch_size,
            ptr: 0,
            phantom: std::marker::PhantomData,
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> (RecursionRecord<Val<RecursionSC>>, bool) {
        let (stdin, done) = self.stdin.get(self.ptr);
        let record = self.emulator.run_recursion(stdin);
        self.ptr += 1;
        (record, done)
    }

    pub fn next_batch(&mut self) -> (Vec<RecursionRecord<Val<RecursionSC>>>, bool) {
        let mut batch_records = Vec::new();
        loop {
            let (record, done) = self.next();
            batch_records.push(record);
            if done {
                return (batch_records, true);
            }
            if batch_records.len() >= self.batch_size {
                break;
            }
        }
        (batch_records, false)
    }

    pub fn num_stdin(&self) -> usize {
        self.stdin.buffer.len()
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
        stdin: &RiscvRecursionStdin<RiscvSC, RiscvC>,
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
}
