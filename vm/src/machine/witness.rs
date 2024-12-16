use crate::{
    compiler::{
        program::ProgramBehavior, recursion_v2::program::RecursionProgram, riscv::program::Program,
    },
    configs::config::{StarkGenericConfig, Val},
    emulator::{
        context::EmulatorContext,
        opts::EmulatorOpts,
        riscv::{record::EmulationRecord, stdin::EmulatorStdin},
    },
    instances::{
        compiler_v2::{
            recursion_circuit::stdin::RecursionStdin, riscv_circuit::stdin::RiscvRecursionStdin,
        },
        configs::{recur_config::StarkConfig as RecursionSC, riscv_config::StarkConfig as RiscvSC},
    },
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseVerifyingKey,
    },
    recursion_v2::runtime::RecursionRecord,
};
use alloc::sync::Arc;
use p3_air::Air;

// Here SC, C refers to types in recursion (native), while I refers to type in original
#[derive(Default)]
pub struct ProvingWitness<SC, C, I>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    pub program: Arc<C::Program>,

    pub stdin: Option<EmulatorStdin<I>>,

    pub opts: Option<EmulatorOpts>,

    pub context: Option<EmulatorContext>,

    pub config: Option<Arc<SC>>,

    pub vk: Option<BaseVerifyingKey<SC>>, // for the machine to construct recursive stdin internally

    pub records: Vec<C::Record>,
}

impl<SC, C, I> ProvingWitness<SC, C, I>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    pub fn setup_with_records(records: Vec<C::Record>) -> Self {
        Self {
            program: Default::default(),
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

    pub fn program(&self) -> Arc<C::Program> {
        self.program.clone()
    }
}

// implement Witness for riscv machine
impl<SC, C> ProvingWitness<SC, C, Vec<u8>>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    pub fn setup_for_riscv(
        program: Arc<C::Program>,
        stdin: &EmulatorStdin<Vec<u8>>,
        opts: EmulatorOpts,
        context: EmulatorContext,
    ) -> Self {
        Self {
            program,
            stdin: Some(stdin.clone()),
            opts: Some(opts),
            context: Some(context),
            config: None,
            vk: None,
            records: vec![],
        }
    }
}

// implement Witness for riscv-recursion machine
impl<'a, C, RiscvC> ProvingWitness<RecursionSC, C, RiscvRecursionStdin<'a, RiscvSC, RiscvC>>
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
        program: Arc<C::Program>,
        stdin: &'a EmulatorStdin<RiscvRecursionStdin<RiscvSC, RiscvC>>,
        config: Arc<RecursionSC>,
        opts: EmulatorOpts,
    ) -> Self {
        Self {
            program,
            stdin: Some(stdin.clone()),
            opts: Some(opts),
            context: None,
            config: Some(config),
            vk: None,
            records: vec![],
        }
    }
}

// implement Witness for recursion-recursion machine
impl<'a, C, RecursionC> ProvingWitness<RecursionSC, C, RecursionStdin<'a, RecursionSC, RecursionC>>
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
        program: Arc<C::Program>,
        stdin: &'a EmulatorStdin<RecursionStdin<RecursionSC, RecursionC>>,
        config: Arc<RecursionSC>,
        vk: &BaseVerifyingKey<RecursionSC>,
        opts: EmulatorOpts,
    ) -> Self {
        Self {
            program,
            stdin: Some(stdin.clone()),
            opts: Some(opts),
            context: None,
            config: Some(config),
            vk: Some(vk.clone()),
            records: vec![],
        }
    }
}
