use super::{InitialProverSetup, MachineProver};
use crate::{
    chips::{
        chips::riscv_poseidon2::FieldSpecificPoseidon2Chip,
        precompiles::poseidon2::FieldSpecificPrecompilePoseidon2Chip,
    },
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::config::{Com, Dom, PcsProverData, StarkGenericConfig, Val},
    emulator::{emulator::MetaEmulator, opts::EmulatorOpts, stdin::EmulatorStdin},
    instances::{
        chiptype::riscv_chiptype::RiscvChipType, compiler::shapes::riscv_shape::RiscvShapeConfig,
        machine::riscv::RiscvMachine,
    },
    machine::{
        field::FieldSpecificPoseidon2Config,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, BaseVerifyingKey, HashableKey},
        machine::{BaseMachine, MachineBehavior},
        proof::{BaseProof, MetaProof},
        witness::ProvingWitness,
    },
    primitives::{consts::RISCV_NUM_PVS, Poseidon2Init},
};
use alloc::sync::Arc;
use p3_air::Air;
use p3_field::PrimeField32;
use p3_symmetric::Permutation;

pub type RiscvChips<SC> = RiscvChipType<Val<SC>>;

pub struct RiscvProver<SC, P>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField32 + FieldSpecificPoseidon2Config,
{
    program: Arc<P>,
    machine: RiscvMachine<SC, RiscvChips<SC>>,
    opts: EmulatorOpts,
    shape_config: Option<RiscvShapeConfig<Val<SC>>>,
    pk: BaseProvingKey<SC>,
    vk: BaseVerifyingKey<SC>,
}

impl<SC> RiscvProver<SC, Program>
where
    SC: Send + StarkGenericConfig + 'static,
    Com<SC>: Send + Sync,
    Dom<SC>: Send + Sync,
    PcsProverData<SC>: Clone + Send + Sync,
    BaseProof<SC>: Send + Sync,
    BaseVerifyingKey<SC>: HashableKey<Val<SC>>,
    Val<SC>: PrimeField32 + FieldSpecificPoseidon2Config + Poseidon2Init,
    <Val<SC> as Poseidon2Init>::Poseidon2: Permutation<[Val<SC>; 16]>,
    FieldSpecificPoseidon2Chip<Val<SC>>: Air<ProverConstraintFolder<SC>>,
    FieldSpecificPrecompilePoseidon2Chip<Val<SC>>: Air<ProverConstraintFolder<SC>>,
{
    pub fn prove_cycles(&self, stdin: EmulatorStdin<Program, Vec<u8>>) -> (MetaProof<SC>, u64) {
        let witness = ProvingWitness::setup_for_riscv(
            self.program.clone(),
            stdin,
            self.opts,
            self.pk.clone(),
            self.vk.clone(),
        );
        if let Some(shape_config) = &self.shape_config {
            self.machine.prove_with_shape(&witness, Some(shape_config))
        } else {
            self.machine.prove_cycles(&witness)
        }
    }

    pub fn run_tracegen(&self, stdin: EmulatorStdin<Program, Vec<u8>>) -> u64 {
        let witness = ProvingWitness::<SC, RiscvChips<SC>, _>::setup_for_riscv(
            self.program.clone(),
            stdin,
            self.opts,
            self.pk.clone(),
            self.vk.clone(),
        );
        let mut emulator = MetaEmulator::setup_riscv(&witness);
        loop {
            let done = emulator.next_record_batch(&mut |_| {});
            if done {
                break;
            }
        }
        emulator.cycles()
    }

    pub fn get_program(&self) -> Arc<Program> {
        self.program.clone()
    }

    pub fn vk(&self) -> &BaseVerifyingKey<SC> {
        &self.vk
    }
}

impl<SC> InitialProverSetup for RiscvProver<SC, Program>
where
    SC: Send + StarkGenericConfig,
    Com<SC>: Send + Sync,
    Dom<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    BaseProof<SC>: Send + Sync,
    Val<SC>: PrimeField32 + FieldSpecificPoseidon2Config + Poseidon2Init,
    <Val<SC> as Poseidon2Init>::Poseidon2: Permutation<[Val<SC>; 16]>,
{
    type Input<'a> = (SC, &'a [u8]);
    type Opts = EmulatorOpts;

    type ShapeConfig = RiscvShapeConfig<Val<SC>>;

    fn new_initial_prover(
        input: Self::Input<'_>,
        opts: Self::Opts,
        shape_config: Option<Self::ShapeConfig>,
    ) -> Self {
        let (config, elf) = input;
        let mut program = Compiler::new(SourceType::RISCV, elf).compile();

        if let Some(shape_config) = shape_config.clone() {
            let p = Arc::get_mut(&mut program).expect("cannot get program");
            shape_config
                .padding_preprocessed_shape(p)
                .expect("cannot padding preprocessed shape");
        }

        let machine = RiscvMachine::new(config, RiscvChipType::all_chips(), RISCV_NUM_PVS);
        let (pk, vk) = machine.setup_keys(&program);
        Self {
            program,
            machine,
            opts,
            shape_config,
            pk,
            vk,
        }
    }
}

impl<SC> MachineProver<SC> for RiscvProver<SC, Program>
where
    SC: Send + StarkGenericConfig + 'static,
    Com<SC>: Send + Sync,
    Dom<SC>: Send + Sync,
    PcsProverData<SC>: Clone + Send + Sync,
    BaseProof<SC>: Send + Sync,
    BaseVerifyingKey<SC>: HashableKey<Val<SC>>,
    Val<SC>: PrimeField32 + FieldSpecificPoseidon2Config + Poseidon2Init,
    <Val<SC> as Poseidon2Init>::Poseidon2: Permutation<[Val<SC>; 16]>,
    FieldSpecificPoseidon2Chip<Val<SC>>:
        Air<ProverConstraintFolder<SC>> + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
    FieldSpecificPrecompilePoseidon2Chip<Val<SC>>:
        Air<ProverConstraintFolder<SC>> + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    type Witness = EmulatorStdin<Program, Vec<u8>>;
    type Chips = RiscvChips<SC>;

    fn machine(&self) -> &BaseMachine<SC, Self::Chips> {
        self.machine.base_machine()
    }

    fn prove(&self, stdin: Self::Witness) -> MetaProof<SC> {
        self.prove_cycles(stdin).0
    }

    fn verify(&self, proof: &MetaProof<SC>, riscv_vk: &dyn HashableKey<Val<SC>>) -> bool {
        self.machine.verify(proof, riscv_vk).is_ok()
    }
}
