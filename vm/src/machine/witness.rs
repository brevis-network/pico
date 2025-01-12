use crate::{
    compiler::{recursion_v2::program::RecursionProgram, riscv::program::Program},
    configs::config::{StarkGenericConfig, Val},
    emulator::{
        opts::EmulatorOpts,
        riscv::{record::EmulationRecord, stdin::EmulatorStdin},
    },
    instances::{
        compiler_v2::{
            recursion_circuit::stdin::RecursionStdin, riscv_circuit::stdin::ConvertStdin,
            vk_merkle::stdin::RecursionVkStdin,
        },
        configs::{recur_config::StarkConfig as RecursionSC, riscv_config::StarkConfig as RiscvSC},
    },
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, BaseVerifyingKey},
        proof::BaseProof,
    },
    primitives::consts::DIGEST_SIZE,
    recursion_v2::runtime::RecursionRecord,
};
use alloc::sync::Arc;
use p3_air::Air;

#[derive(Default)]
pub struct ProvingWitness<SC, C, I>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    pub program: Option<Arc<C::Program>>,

    pub pk: Option<BaseProvingKey<SC>>,

    pub vk: Option<BaseVerifyingKey<SC>>,

    pub proof: Option<BaseProof<SC>>,

    pub vk_root: Option<[Val<SC>; DIGEST_SIZE]>,

    pub stdin: Option<EmulatorStdin<C::Program, I>>,

    pub flag_empty_stdin: bool,

    pub config: Option<Arc<SC>>,

    pub opts: Option<EmulatorOpts>,

    pub records: Vec<C::Record>,
}

impl<SC, C, I> ProvingWitness<SC, C, I>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    pub fn setup_with_records(records: Vec<C::Record>) -> Self {
        Self {
            program: None,
            pk: None,
            vk: None,
            proof: None,
            vk_root: None,
            stdin: None,
            flag_empty_stdin: false,
            opts: None,
            config: None,
            records,
        }
    }

    pub fn setup_with_keys_and_records(
        pk: BaseProvingKey<SC>,
        vk: BaseVerifyingKey<SC>,
        records: Vec<C::Record>,
    ) -> Self {
        Self {
            program: None,
            pk: Some(pk),
            vk: Some(vk),
            proof: None,
            vk_root: None,
            stdin: None,
            flag_empty_stdin: false,
            opts: None,
            config: None,
            records,
        }
    }

    pub fn pk(&self) -> &BaseProvingKey<SC> {
        self.pk.as_ref().unwrap()
    }

    pub fn vk(&self) -> &BaseVerifyingKey<SC> {
        self.vk.as_ref().unwrap()
    }

    pub fn records(&self) -> &[C::Record] {
        &self.records
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
        stdin: EmulatorStdin<C::Program, Vec<u8>>,
        opts: EmulatorOpts,
        pk: BaseProvingKey<SC>,
        vk: BaseVerifyingKey<SC>,
    ) -> Self {
        Self {
            program: Some(program),
            pk: Some(pk),
            vk: Some(vk),
            proof: None,
            vk_root: None,
            stdin: Some(stdin),
            flag_empty_stdin: false,
            opts: Some(opts),
            config: None,
            records: vec![],
        }
    }
}

// implement Witness for riscv-recursion machine
impl<'a, C, PrevC> ProvingWitness<RecursionSC, C, ConvertStdin<'a, RiscvSC, PrevC>>
where
    PrevC: ChipBehavior<Val<RiscvSC>, Program = Program, Record = EmulationRecord>
        + for<'b> Air<ProverConstraintFolder<'b, RiscvSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RiscvSC>>,
    C: ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, RecursionSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RecursionSC>>,
{
    pub fn setup_for_convert(
        stdin: EmulatorStdin<C::Program, ConvertStdin<'a, RiscvSC, PrevC>>,
        config: Arc<RecursionSC>,
        opts: EmulatorOpts,
    ) -> Self {
        Self {
            program: None,
            pk: None,
            vk: None,
            proof: None,
            vk_root: None,
            stdin: Some(stdin),
            flag_empty_stdin: false,
            opts: Some(opts),
            config: Some(config),
            records: vec![],
        }
    }
}

// implement Witness for recursion-recursion machine
impl<'a, C, PrevC> ProvingWitness<RecursionSC, C, RecursionStdin<'a, RecursionSC, PrevC>>
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
    pub fn setup_for_recursion(
        vk_root: [Val<RecursionSC>; DIGEST_SIZE],
        stdin: EmulatorStdin<C::Program, RecursionStdin<'a, RecursionSC, PrevC>>,
        last_vk: Option<BaseVerifyingKey<RecursionSC>>,
        last_proof: Option<BaseProof<RecursionSC>>,
        config: Arc<RecursionSC>,
        opts: EmulatorOpts,
    ) -> Self {
        let flag_empty_stdin = stdin.flag_empty;
        Self {
            program: None,
            pk: None,
            vk: last_vk,
            proof: last_proof,
            vk_root: Some(vk_root),
            stdin: Some(stdin),
            flag_empty_stdin,
            opts: Some(opts),
            config: Some(config),
            records: vec![],
        }
    }
}

// implement Witness for recursion-recursion machine
impl<'a, C, PrevC> ProvingWitness<RecursionSC, C, RecursionVkStdin<'a, RecursionSC, PrevC>>
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
    pub fn setup_for_recursion_vk(
        vk_root: [Val<RecursionSC>; DIGEST_SIZE],
        stdin: EmulatorStdin<C::Program, RecursionVkStdin<'a, RecursionSC, PrevC>>,
        last_vk: Option<BaseVerifyingKey<RecursionSC>>,
        last_proof: Option<BaseProof<RecursionSC>>,
        config: Arc<RecursionSC>,
        opts: EmulatorOpts,
    ) -> Self {
        let flag_empty_stdin = stdin.flag_empty;
        Self {
            program: None,
            pk: None,
            vk: last_vk,
            proof: last_proof,
            vk_root: Some(vk_root),
            stdin: Some(stdin),
            flag_empty_stdin,
            opts: Some(opts),
            config: Some(config),
            records: vec![],
        }
    }
}
