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
        compiler::{
            recursion_circuit::stdin::RecursionStdin, riscv_circuit::stdin::RiscvRecursionStdin,
        },
        configs::{recur_config::StarkConfig as RecursionSC, riscv_config::StarkConfig as RiscvSC},
    },
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseVerifyingKey,
    },
    recursion::runtime::RecursionRecord,
};
use p3_air::Air;

// Here SC, C refers to types in recursion (native), while I refers to type in original
pub struct ProvingWitness<'a, SC, C, I>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    pub program: C::Program,

    pub stdin: Option<&'a EmulatorStdin<I>>,

    pub opts: Option<EmulatorOpts>,

    pub context: Option<EmulatorContext>,

    pub config: Option<&'a SC>,

    pub vk: Option<&'a BaseVerifyingKey<SC>>, // for the machine to construct recursive stdin internally

    pub records: Vec<C::Record>,
}

#[allow(clippy::should_implement_trait)]
impl<'a, SC, C, I> ProvingWitness<'a, SC, C, I>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    pub fn default() -> Self {
        Self {
            program: C::Program::default(),
            stdin: None,
            opts: None,
            context: None,
            config: None,
            vk: None,
            records: vec![],
        }
    }
}

impl<'a, SC, C, I> ProvingWitness<'a, SC, C, I>
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
            vk: None,
            records,
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
impl<'a, SC, C> ProvingWitness<'a, SC, C, Vec<u8>>
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
            vk: None,
            records: vec![],
        }
    }
}

// implement Witness for riscv-recursion machine
impl<'a, C, RiscvC> ProvingWitness<'a, RecursionSC, C, RiscvRecursionStdin<'a, RiscvSC, RiscvC>>
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
    pub fn setup_for_riscv_recursion(
        program: C::Program,
        stdin: &'a EmulatorStdin<RiscvRecursionStdin<'a, RiscvSC, RiscvC>>,
        config: &'a RecursionSC,
        opts: EmulatorOpts,
    ) -> Self {
        Self {
            program,
            stdin: Some(stdin),
            opts: Some(opts),
            context: None,
            config: Some(config),
            vk: None,
            records: vec![],
        }
    }
}

// implement Witness for recursion-recursion machine
impl<'a, C, RecursionC>
    ProvingWitness<'a, RecursionSC, C, RecursionStdin<'a, RecursionSC, RecursionC>>
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
    pub fn setup_for_recursion(
        program: C::Program,
        stdin: &'a EmulatorStdin<RecursionStdin<'a, RecursionSC, RecursionC>>,
        config: &'a RecursionSC,
        vk: &'a BaseVerifyingKey<RecursionSC>,
        opts: EmulatorOpts,
    ) -> Self {
        Self {
            program,
            stdin: Some(stdin),
            opts: Some(opts),
            context: None,
            config: Some(config),
            vk: Some(vk),
            records: vec![],
        }
    }
}
