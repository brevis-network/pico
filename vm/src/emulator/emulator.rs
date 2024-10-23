use crate::{
    compiler::{
        recursion::{program::RecursionProgram, program_builder::hints::hintable::Hintable},
        riscv::program::Program,
    },
    configs::{
        config::{Challenge, StarkGenericConfig, Val},
        stark_config::bb_poseidon2::BabyBearPoseidon2,
    },
    emulator::{
        opts::EmulatorOpts,
        riscv::{
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
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseVerifyingKey,
        machine::MachineBehavior,
        proof::{BaseProof, MetaProof},
        witness::ProvingWitness,
    },
    recursion::runtime::{RecursionRecord, Runtime, PERMUTATION_WIDTH, POSEIDON2_SBOX_DEGREE},
};
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_field::{extension::BinomialExtensionField, ExtensionField, PrimeField32};
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};

pub enum EmulatorType {
    Riscv,
    RiscvCompress,
}

// Meta emulator that encapsulates multiple emulators
// P for specific Program type
// E for specific Emulator type
// R for specific Record type
// C for specific Chip
pub struct MetaEmulator<'a, NSC, NC, SC, C, I, E> {
    pub kind: EmulatorType,
    pub stdin: &'a EmulatorStdin<I>,
    pub emulator: E,
    pub batch_size: usize,
    ptr: usize,
    phantom: std::marker::PhantomData<(NSC, NC, SC, C)>,
}

impl<'a, SC, C> MetaEmulator<'a, SC, C, SC, C, Vec<u8>, RiscvEmulator>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>, Program = Program, Record = EmulationRecord>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub fn setup_riscv(
        input: &'a ProvingWitness<'a, SC, C, SC, C, Vec<u8>>,
        batch_size: usize,
    ) -> Self {
        // create a new emulator based on the emulator type
        let mut emulator = RiscvEmulator::new(input.program.clone(), input.opts.unwrap());
        emulator.emulator_mode = EmulatorMode::Trace;
        for each in input.stdin.unwrap().buffer.clone() {
            emulator.state.input_stream.push(each);
        }
        assert_eq!(emulator.chunk_batch_size, batch_size as u32);

        Self {
            kind: EmulatorType::Riscv,
            stdin: input.stdin.unwrap(),
            emulator,
            batch_size,
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

// here SC should be field_config Stark config
impl<'a, NC, C>
    MetaEmulator<
        'a,
        RiscvSC,
        NC,
        RecursionSC,
        C,
        RiscvRecursionStdin<'a, RiscvSC, NC>,
        RecursionEmulator<'a, RiscvSC, NC, RecursionSC>,
    >
where
    NC: ChipBehavior<Val<RiscvSC>, Program = Program, Record = EmulationRecord>
        + for<'b> Air<ProverConstraintFolder<'b, RiscvSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RiscvSC>>,
    C: ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, RiscvSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RiscvSC>>,
{
    pub fn setup_riscv_compress(
        input: &'a ProvingWitness<
            'a,
            RiscvSC,
            NC,
            RecursionSC,
            C,
            RiscvRecursionStdin<'a, RiscvSC, NC>,
        >,
        batch_size: usize,
    ) -> Self {
        let mut emulator = RecursionEmulator {
            recursion_program: input.program.clone(),
            config: input.config.unwrap(),
            phantom: std::marker::PhantomData,
        };

        Self {
            kind: EmulatorType::RiscvCompress,
            stdin: input.stdin.unwrap(),
            emulator,
            batch_size,
            ptr: 0,
            phantom: std::marker::PhantomData,
        }
    }

    pub fn next(&mut self) -> (RecursionRecord<Val<RecursionSC>>, bool) {
        let (mut stdin, done) = self.stdin.get(self.ptr);
        let record = self.emulator.run_riscv(stdin);
        self.ptr += 1;
        (record, done)
    }
}

// Here SC should be field_config Stark config
pub struct RecursionEmulator<'a, NSC, NC, SC>
where
    SC: StarkGenericConfig,
{
    pub recursion_program: RecursionProgram<Val<SC>>,

    pub config: &'a SC,

    pub phantom: std::marker::PhantomData<(NSC, NC)>,
}

impl<'a, NC> RecursionEmulator<'a, RiscvSC, NC, RecursionSC>
where
    NC: ChipBehavior<Val<RiscvSC>, Program = Program, Record = EmulationRecord>
        + for<'b> Air<ProverConstraintFolder<'b, RiscvSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RiscvSC>>,
{
    pub fn run_riscv(
        &mut self,
        stdin: &RiscvRecursionStdin<RiscvSC, NC>,
    ) -> RecursionRecord<Val<RecursionSC>> {
        let mut witness_stream = Vec::new();
        witness_stream.extend(stdin.write());

        let mut runtime = Runtime::<Val<RecursionSC>, Challenge<RecursionSC>, _>::new(
            &self.recursion_program,
            self.config.perm.clone(),
        );
        runtime.witness_stream = witness_stream.into();
        runtime.run().unwrap();
        runtime.record
    }
}

//
// impl<C> MetaEmulator<
//     RecursionProgram<Val<RiscvSC>>,
//     RecursionEmulator<RiscvRecursionStdin<RiscvSC, C>, C, Val<RiscvSC>, Challenge<RiscvSC>, _,>,
//     RecursionRecord<Val<RiscvSC>>,
//     C,
// > {
//     pub fn initialize(
//         kind: EmulatorType,
//         program: RecursionProgram<Val<RiscvSC>>,
//         input: RiscvCompressEmulatorInput<C>,
//         batch_size: usize
//     ) -> Self {
//         match kind {
//             EmulatorType::RiscvCompress => {
//                 assert_eq!(batch_size, 1);
//                 let mut challenger = DuplexChallenger::new(input.machine.config().perm.clone());
//                 let recursion_stdin_iter = RiscvRecursionStdin::construct_for_compress(
//                     &input.vk,
//                     &input.machine,
//                     &input.proofs,
//                     &mut challenger,
//                 ).chunks(batch_size).into_iter();
//
//                 Self {
//                     kind,
//                     emulator,
//                     batch_size,
//                     phantom: std::marker::PhantomData,
//                 }
//             }
//             _ => panic!("Invalid EmulatorType"),
//         }
//     }
// }
//

//
// impl<C> RecursionEmulator<
//     Val<RiscvSC>,
//     Challenge<RiscvSC>,
//     RiscvRecursionStdin<RiscvSC, C>,
//     C,
//     _,
// > {
//     pub fn initialize(
//         recursion_program: RecursionProgram<Val<RiscvSC>>,
//         input: RiscvCompressEmulatorInput<C>,
//     ) -> Self {
//         let mut challenger = DuplexChallenger::new(input.machine.config().perm.clone());
//         let recursion_stdin = RiscvRecursionStdin::construct_for_compress(
//             &input.vk,
//             &input.machine,
//             &input.proofs,
//             &mut challenger,
//         );
//
//         let total = recursion_stdin.len();
//
//         Self {
//             recursion_program,
//             recursion_stdin,
//             perm: input.machine.config().perm.clone(),
//             current_ptr: 0,
//             total,
//         }
//     }
//
//     pub fn next_batch(&mut self) -> (&mut [RecursionRecord<BabyBear>], bool) {
//         let flag_last = self.current_ptr == self.total - 1;
//
//         if self.current_ptr < self.total {
//             let current_ptr = self.current_ptr;
//             self.current_ptr += 1;
//             let current_stdin = &self.recursion_stdin[current_ptr];
//
//             let mut witness_stream = Vec::new();
//             witness_stream.extend(current_stdin.write());
//
//             let mut runtime = Runtime::<
//                 BabyBear,
//                 BinomialExtensionField<BabyBear, 4>,
//                 _,
//             >::new(
//                 &self.recursion_program, self.perm.clone()
//             );
//             runtime.witness_stream = witness_stream.into();
//             runtime.run().unwrap();
//
//             (runtime.record, flag_last)
//         } else {
//             panic!("No more batch to process");
//         }
//     }
// }
//
// pub struct RiscvCompressEmulatorInput<C>
// where
//     C: ChipBehavior<Val<RiscvSC>>
//         + for<'a> Air<ProverConstraintFolder<'a, RiscvSC>>
//         + for<'a> Air<VerifierConstraintFolder<'a, RiscvSC>>,
// {
//     vk: BaseVerifyingKey<RiscvSC>,
//     machine: RiscvMachine<RiscvSC, C>,
//     proofs: Vec<BaseProof<RiscvSC>>
// }

//
// impl<C> crate::emulator::emulator::EmulatorInput<C>
// where
//     C: ChipBehavior<BabyBear>
//         + for<'a> Air<ProverConstraintFolder<'a, BabyBearPoseidon2>>
//         + for<'a> Air<VerifierConstraintFolder<'a, BabyBearPoseidon2>>,
// {
//     pub fn new_riscv(
//         opts: EmulatorOpts,
//         stdin: EmulatorStdin,
//     ) -> Self {
//         Self { opts, stdin, ..Default::default() }
//     }
//
//     pub fn new_riscv_compress(
//         opts: EmulatorOpts,
//         stdin: EmulatorStdin,
//         vk: BaseVerifyingKey<RiscvSC>,
//         machine: RiscvMachine<RiscvSC, C>,
//         proofs: Vec<BaseProof<RiscvSC>>,
//     ) -> Self {
//         Self { opts, stdin, vk, machine, proofs }
//     }
// }
