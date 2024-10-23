use crate::{
    compiler::{
        program::ProgramBehavior, recursion::program::RecursionProgram, riscv::program::Program,
    },
    configs::config::{StarkGenericConfig, Val},
    emulator::{
        context::EmulatorContext,
        opts::EmulatorOpts,
        riscv::{record::EmulationRecord, stdin::EmulatorStdin},
    },
    instances::{
        compiler::riscv_circuit::stdin::RiscvRecursionStdin,
        configs::{recur_config::StarkConfig as RecursionSC, riscv_config::StarkConfig as RiscvSC},
        machine::riscv_machine::RiscvMachine,
    },
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
    },
    recursion::runtime::{RecursionRecord, PERMUTATION_WIDTH, POSEIDON2_SBOX_DEGREE},
};
use p3_air::Air;
use p3_field::Field;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};

// Here SC, C refers to types in recurion, while I refers to type in native
pub struct ProvingWitness<'a, NSC, NC, SC, C, I>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    pub program: C::Program,

    pub stdin: Option<&'a EmulatorStdin<I>>,

    pub opts: Option<EmulatorOpts>,

    pub context: Option<EmulatorContext>,

    pub config: Option<&'a SC>,

    pub records: Vec<C::Record>,

    phantom: std::marker::PhantomData<(NSC, NC)>,
}

impl<'a, NSC, NC, SC, C, I> ProvingWitness<'a, NSC, NC, SC, C, I>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    pub fn setup_with_records(records: Vec<C::Record>) -> Self {
        Self {
            program: C::Program::default(),
            stdin: None,
            opts: None,
            context: None,
            config: None,
            records,
            phantom: std::marker::PhantomData,
        }
    }

    pub fn records(&self) -> &[C::Record] {
        &self.records
    }

    pub fn program(&self) -> &C::Program {
        &self.program
    }
}

// implement Witness for riscv machine
impl<'a, SC, C> ProvingWitness<'a, SC, C, SC, C, Vec<u8>>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    pub fn setup_for_riscv(
        program: C::Program,
        stdin: &'a EmulatorStdin<Vec<u8>>,
        opts: EmulatorOpts,
        context: EmulatorContext,
    ) -> Self {
        Self {
            program,
            stdin: Some(stdin),
            opts: Some(opts),
            context: Some(context),
            config: None,
            records: vec![],
            phantom: std::marker::PhantomData,
        }
    }
}

impl<'a, NC, C>
    ProvingWitness<'a, RiscvSC, NC, RecursionSC, C, RiscvRecursionStdin<'a, RiscvSC, NC>>
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
    pub fn setup_for_riscv_recursion(
        program: C::Program,
        stdin: &'a EmulatorStdin<RiscvRecursionStdin<'a, RiscvSC, NC>>,
        config: &'a RecursionSC,
    ) -> Self {
        Self {
            program,
            stdin: Some(stdin),
            opts: None,
            context: None,
            config: Some(config),
            records: vec![],
            phantom: std::marker::PhantomData,
        }
    }
}
