use crate::{
    compiler::{
        recursion::{circuit::witness::witnessable::Witnessable, program::RecursionProgram},
        riscv::program::Program,
    },
    configs::{
        config::{Challenge, StarkGenericConfig, Val},
        field_config::{BabyBearSimple, KoalaBearSimple},
        stark_config::{BabyBearPoseidon2, KoalaBearPoseidon2},
    },
    emulator::{
        recursion::emulator::{RecursionRecord, Runtime},
        riscv::{
            record::EmulationRecord,
            riscv_emulator::{EmulatorMode, RiscvEmulator},
        },
        stdin::EmulatorStdin,
    },
    instances::{
        chiptype::riscv_chiptype::RiscvChipType,
        compiler::{
            recursion_circuit::stdin::RecursionStdin, riscv_circuit::stdin::ConvertStdin,
            vk_merkle::stdin::RecursionVkStdin,
        },
    },
    machine::{
        chip::ChipBehavior,
        keys::{BaseProvingKey, BaseVerifyingKey},
        machine::BaseMachine,
        witness::ProvingWitness,
    },
    primitives::{
        consts::{BABYBEAR_S_BOX_DEGREE, KOALABEAR_S_BOX_DEGREE},
        Poseidon2Init,
    },
};
use alloc::sync::Arc;
use p3_field::PrimeField32;
use p3_symmetric::Permutation;
use std::marker::PhantomData;
use tracing::debug_span;

// Meta emulator that encapsulates multiple emulators
// SC and C for configs in the emulated machine
// P and I for the native program and input types
// E for the emulator type
pub struct MetaEmulator<SC, C, P, I, E>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    pub stdin: EmulatorStdin<P, I>,
    pub emulator: Option<E>,
    pub batch_size: u32, // max parallelism
    pub _sc_and_chip: PhantomData<(SC, C)>,
}

// MetaEmulator for riscv
impl<SC, C> MetaEmulator<SC, C, Program, Vec<u8>, RiscvEmulator>
where
    SC: StarkGenericConfig,
    SC::Val: PrimeField32 + Poseidon2Init,
    <SC::Val as Poseidon2Init>::Poseidon2: Permutation<[SC::Val; 16]>,
    C: ChipBehavior<Val<SC>, Program = Program, Record = EmulationRecord>,
{
    pub fn setup_riscv(proving_witness: &ProvingWitness<SC, C, Vec<u8>>) -> Self {
        // create a new emulator based on the emulator type
        let opts = proving_witness.opts.unwrap();
        let mut emulator =
            RiscvEmulator::new::<SC::Val>(proving_witness.program.clone().unwrap(), opts);
        emulator.emulator_mode = EmulatorMode::Trace;
        emulator.write_stdin(proving_witness.stdin.as_ref().unwrap());

        Self {
            stdin: proving_witness.stdin.clone().unwrap(),
            emulator: Some(emulator),
            batch_size: opts.chunk_batch_size,
            _sc_and_chip: PhantomData,
        }
    }

    pub fn next_record_batch(&mut self) -> (Vec<EmulationRecord>, bool) {
        let emulator = self.emulator.as_mut().unwrap();
        emulator.emulate_batch().unwrap()
    }

    pub fn cycles(&self) -> u64 {
        self.emulator.as_ref().unwrap().state.global_clk
    }

    pub fn get_pv_stream_with_dryrun(&mut self) -> Vec<u8> {
        loop {
            let (_, done) = self.next_record_batch();
            if done {
                break;
            }
        }
        self.emulator
            .as_ref()
            .unwrap()
            .state
            .public_values_stream
            .clone()
    }

    pub fn get_pv_stream(&mut self) -> Vec<u8> {
        self.emulator
            .as_ref()
            .unwrap()
            .state
            .public_values_stream
            .clone()
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

macro_rules! impl_emulator {
    ($emul_name:ident, $riscv_sc:ident, $recur_cc:ident, $recur_sc:ident, $s_box_degree:ident) => {
        // Meta emulator for recursive circuits.
        // P and I for the native program and input types
        // E for the emulator type
        pub struct $emul_name<'a, C, P, I, E>
        where
            C: ChipBehavior<Val<$recur_sc>>,
        {
            pub stdin: &'a EmulatorStdin<P, I>,
            pub emulator: Option<E>,
            pub batch_size: u32, // max parallelism
            pointer: usize,
            machine: Option<&'a BaseMachine<$recur_sc, C>>, // used for setting-up and generating keys
        }

        // MetaEmulator for convert
        impl<'a, C>
            $emul_name<
                'a,
                C,
                RecursionProgram<Val<$recur_sc>>,
                ConvertStdin<$riscv_sc, RiscvChipType<Val<$riscv_sc>>>,
                RecursionEmulator<$recur_sc>,
            >
        where
            C: ChipBehavior<
                Val<$recur_sc>,
                Program = RecursionProgram<Val<$recur_sc>>,
                Record = RecursionRecord<Val<$recur_sc>>,
            >,
        {
            pub fn setup_convert(
                proving_witness: &'a ProvingWitness<
                    $recur_sc,
                    C,
                    ConvertStdin<$riscv_sc, RiscvChipType<Val<$riscv_sc>>>,
                >,
                machine: &'a BaseMachine<$recur_sc, C>,
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
                RecursionRecord<Val<$recur_sc>>,
                BaseProvingKey<$recur_sc>,
                BaseVerifyingKey<$recur_sc>,
                bool,
            ) {
                let (program, input, done) = self.stdin.get_program_and_input(self.pointer);
                let (pk, vk) = self.machine.unwrap().setup_keys(program);
                let mut emulator = RecursionEmulator::<$recur_sc> {
                    recursion_program: program.clone().into(),
                    config: self.machine.unwrap().config(),
                };
                let record = debug_span!("emulator run").in_scope(|| emulator.run_riscv(input));
                self.pointer += 1;
                (record, pk, vk, done)
            }

            #[allow(clippy::type_complexity)]
            pub fn next_record_keys_batch(
                &mut self,
            ) -> (
                Vec<RecursionRecord<Val<$recur_sc>>>,
                Vec<BaseProvingKey<$recur_sc>>,
                Vec<BaseVerifyingKey<$recur_sc>>,
                bool,
            ) {
                let mut batch_records = vec![];
                let mut batch_pks = vec![];
                let mut batch_vks = vec![];
                loop {
                    let (record, pk, vk, done) =
                        debug_span!("emulate record").in_scope(|| self.next_record_keys());
                    batch_records.push(record);
                    batch_pks.push(pk);
                    batch_vks.push(vk);
                    if done {
                        return (batch_records, batch_pks, batch_vks, true);
                    }
                    if batch_records.len() >= self.batch_size as usize {
                        break;
                    }
                }
                (batch_records, batch_pks, batch_vks, false)
            }
        }

        // MetaEmulator for recursion combine
        impl<'a, C, PrevC>
            $emul_name<
                'a,
                C,
                RecursionProgram<Val<$recur_sc>>,
                RecursionStdin<'a, $recur_sc, PrevC>,
                RecursionEmulator<$recur_sc>,
            >
        where
            PrevC: ChipBehavior<
                Val<$recur_sc>,
                Program = RecursionProgram<Val<$recur_sc>>,
                Record = RecursionRecord<Val<$recur_sc>>,
            >,
            C: ChipBehavior<
                Val<$recur_sc>,
                Program = RecursionProgram<Val<$recur_sc>>,
                Record = RecursionRecord<Val<$recur_sc>>,
            >,
        {
            pub fn setup_combine(
                proving_witness: &'a ProvingWitness<
                    $recur_sc,
                    C,
                    RecursionStdin<'a, $recur_sc, PrevC>,
                >,
                machine: &'a BaseMachine<$recur_sc, C>,
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
                RecursionRecord<Val<$recur_sc>>,
                BaseProvingKey<$recur_sc>,
                BaseVerifyingKey<$recur_sc>,
                bool,
            ) {
                let (program, input, done) = self.stdin.get_program_and_input(self.pointer);
                let (pk, vk) = self.machine.unwrap().setup_keys(program);
                let mut emulator = RecursionEmulator::<$recur_sc> {
                    recursion_program: program.clone().into(),
                    config: self.machine.unwrap().config(),
                };
                let record = debug_span!("emulator run").in_scope(|| emulator.run_recursion(input));
                self.pointer += 1;
                (record, pk, vk, done)
            }

            #[allow(clippy::type_complexity)]
            pub fn next_record_keys_batch(
                &mut self,
            ) -> (
                Vec<RecursionRecord<Val<$recur_sc>>>,
                Vec<BaseProvingKey<$recur_sc>>,
                Vec<BaseVerifyingKey<$recur_sc>>,
                bool,
            ) {
                let mut batch_records = vec![];
                let mut batch_pks = vec![];
                let mut batch_vks = vec![];
                loop {
                    let (record, pk, vk, done) =
                        debug_span!("emulate record").in_scope(|| self.next_record_keys());
                    batch_records.push(record);
                    batch_pks.push(pk);
                    batch_vks.push(vk);
                    if done {
                        return (batch_records, batch_pks, batch_vks, true);
                    }
                    if batch_records.len() >= self.batch_size as usize {
                        break;
                    }
                }
                (batch_records, batch_pks, batch_vks, false)
            }
        }

        // MetaEmulator for recursion combine
        impl<'a, C, PrevC>
            $emul_name<
                'a,
                C,
                RecursionProgram<Val<$recur_sc>>,
                RecursionVkStdin<'a, $recur_sc, PrevC>,
                RecursionEmulator<$recur_sc>,
            >
        where
            PrevC: ChipBehavior<
                Val<$recur_sc>,
                Program = RecursionProgram<Val<$recur_sc>>,
                Record = RecursionRecord<Val<$recur_sc>>,
            >,
            C: ChipBehavior<
                Val<$recur_sc>,
                Program = RecursionProgram<Val<$recur_sc>>,
                Record = RecursionRecord<Val<$recur_sc>>,
            >,
        {
            pub fn setup_combine_vk(
                proving_witness: &'a ProvingWitness<
                    $recur_sc,
                    C,
                    RecursionVkStdin<'a, $recur_sc, PrevC>,
                >,
                machine: &'a BaseMachine<$recur_sc, C>,
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
                RecursionRecord<Val<$recur_sc>>,
                BaseProvingKey<$recur_sc>,
                BaseVerifyingKey<$recur_sc>,
                bool,
            ) {
                let (program, input, done) = self.stdin.get_program_and_input(self.pointer);
                let (pk, vk) = self.machine.unwrap().setup_keys(program);
                let mut emulator = RecursionEmulator::<$recur_sc> {
                    recursion_program: program.clone().into(),
                    config: self.machine.unwrap().config(),
                };
                let record =
                    debug_span!("emulator run").in_scope(|| emulator.run_recursion_vk(input));
                self.pointer += 1;
                (record, pk, vk, done)
            }
            #[allow(clippy::type_complexity)]
            pub fn next_record_keys_batch(
                &mut self,
            ) -> (
                Vec<RecursionRecord<Val<$recur_sc>>>,
                Vec<BaseProvingKey<$recur_sc>>,
                Vec<BaseVerifyingKey<$recur_sc>>,
                bool,
            ) {
                let mut batch_records = vec![];
                let mut batch_pks = vec![];
                let mut batch_vks = vec![];
                loop {
                    let (record, pk, vk, done) =
                        debug_span!("emulate record").in_scope(|| self.next_record_keys());
                    batch_records.push(record);
                    batch_pks.push(pk);
                    batch_vks.push(vk);
                    if done {
                        return (batch_records, batch_pks, batch_vks, true);
                    }
                    if batch_records.len() >= self.batch_size as usize {
                        break;
                    }
                }
                (batch_records, batch_pks, batch_vks, false)
            }
        }

        impl RecursionEmulator<$recur_sc> {
            pub fn run_riscv<RiscvC>(
                &mut self,
                stdin: &ConvertStdin<$riscv_sc, RiscvC>,
            ) -> RecursionRecord<Val<$recur_sc>>
            where
                RiscvC: ChipBehavior<Val<$riscv_sc>, Program = Program, Record = EmulationRecord>,
            {
                let mut witness_stream = Vec::new();
                Witnessable::<$recur_cc>::write(&stdin, &mut witness_stream);

                let mut runtime =
                    Runtime::<Val<$recur_sc>, Challenge<$recur_sc>, _, _, $s_box_degree>::new(
                        self.recursion_program.clone(),
                        self.config.perm.clone(),
                    );

                runtime.witness_stream = witness_stream.into();
                runtime.run().unwrap();
                runtime.record
            }

            pub fn run_recursion<RecursionC>(
                &mut self,
                stdin: &RecursionStdin<$recur_sc, RecursionC>,
            ) -> RecursionRecord<Val<$recur_sc>>
            where
                RecursionC: ChipBehavior<
                    Val<$recur_sc>,
                    Program = RecursionProgram<Val<$recur_sc>>,
                    Record = RecursionRecord<Val<$recur_sc>>,
                >,
            {
                let mut witness_stream = Vec::new();
                Witnessable::<$recur_cc>::write(&stdin, &mut witness_stream);

                let mut runtime =
                    Runtime::<Val<$recur_sc>, Challenge<$recur_sc>, _, _, $s_box_degree>::new(
                        self.recursion_program.clone(),
                        self.config.perm.clone(),
                    );
                runtime.witness_stream = witness_stream.into();
                runtime.run().unwrap();
                runtime.record
            }

            pub fn run_recursion_vk<RecursionC>(
                &mut self,
                stdin: &RecursionVkStdin<$recur_sc, RecursionC>,
            ) -> RecursionRecord<Val<$recur_sc>>
            where
                RecursionC: ChipBehavior<
                    Val<$recur_sc>,
                    Program = RecursionProgram<Val<$recur_sc>>,
                    Record = RecursionRecord<Val<$recur_sc>>,
                >,
            {
                let mut witness_stream = Vec::new();
                Witnessable::<$recur_cc>::write(&stdin, &mut witness_stream);
                let mut runtime =
                    Runtime::<Val<$recur_sc>, Challenge<$recur_sc>, _, _, $s_box_degree>::new(
                        self.recursion_program.clone(),
                        self.config.perm.clone(),
                    );
                runtime.witness_stream = witness_stream.into();
                runtime.run().unwrap();
                runtime.record
            }
        }
    };
}

impl_emulator!(
    BabyBearMetaEmulator,
    BabyBearPoseidon2,
    BabyBearSimple,
    BabyBearPoseidon2,
    BABYBEAR_S_BOX_DEGREE
);

impl_emulator!(
    KoalaBearMetaEmulator,
    KoalaBearPoseidon2,
    KoalaBearSimple,
    KoalaBearPoseidon2,
    KOALABEAR_S_BOX_DEGREE
);
