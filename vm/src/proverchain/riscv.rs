use super::{InitialProverSetup, MachineProver};
use crate::{
    chips::precompiles::poseidon2::Poseidon2PermuteChip,
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::config::{Com, Dom, PcsProverData, StarkGenericConfig, Val},
    emulator::riscv::{record::EmulationRecord, stdin::EmulatorStdin},
    instances::{chiptype::riscv_chiptype::RiscvChipType, machine::riscv::RiscvMachine},
    machine::{
        chip::ChipBehavior,
        keys::{BaseProvingKey, BaseVerifyingKey},
        machine::{BaseMachine, MachineBehavior},
        proof::{BaseProof, MetaProof},
        witness::ProvingWitness,
    },
    primitives::consts::RISCV_NUM_PVS,
};
use alloc::sync::Arc;
use p3_field::PrimeField32;

pub type RiscvChips<SC, const HALF_EXTERNAL_ROUNDS: usize, const NUM_INTERNAL_ROUNDS: usize> =
    RiscvChipType<Val<SC>, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>;

pub struct RiscvProver<SC, P, const HALF_EXTERNAL_ROUNDS: usize, const NUM_INTERNAL_ROUNDS: usize>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField32,
    Poseidon2PermuteChip<Val<SC>, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>:
        ChipBehavior<Val<SC>, Record = EmulationRecord, Program = Program>,
{
    program: Arc<P>,
    machine: RiscvMachine<SC, RiscvChips<SC, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>>,
    pk: BaseProvingKey<SC>,
    vk: BaseVerifyingKey<SC>,
}

impl<SC, const HALF_EXTERNAL_ROUNDS: usize, const NUM_INTERNAL_ROUNDS: usize> InitialProverSetup
    for RiscvProver<SC, Program, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>
where
    SC: Send + StarkGenericConfig,
    Com<SC>: Send + Sync,
    Dom<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    BaseProof<SC>: Send + Sync,
    Val<SC>: PrimeField32,
    Poseidon2PermuteChip<Val<SC>, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>:
        ChipBehavior<Val<SC>, Record = EmulationRecord, Program = Program>,
{
    type Input<'a> = (SC, &'a [u8]);

    fn new_initial_prover(input: Self::Input<'_>) -> Self {
        let (config, elf) = input;
        let program = Compiler::new(SourceType::RiscV, elf).compile();
        let machine = RiscvMachine::new(config, RiscvChipType::all_chips(), RISCV_NUM_PVS);
        let (pk, vk) = machine.setup_keys(&program);
        Self {
            program,
            machine,
            pk,
            vk,
        }
    }
}

impl<SC, const HALF_EXTERNAL_ROUNDS: usize, const NUM_INTERNAL_ROUNDS: usize> MachineProver<SC>
    for RiscvProver<SC, Program, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>
where
    SC: Send + StarkGenericConfig,
    Com<SC>: Send + Sync,
    Dom<SC>: Send + Sync,
    PcsProverData<SC>: Clone + Send + Sync,
    BaseProof<SC>: Send + Sync,
    Val<SC>: PrimeField32,
    Poseidon2PermuteChip<Val<SC>, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>:
        ChipBehavior<Val<SC>, Record = EmulationRecord, Program = Program>,
{
    type Witness = EmulatorStdin<Program, Vec<u8>>;
    type Chips = RiscvChips<SC, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>;

    fn machine(&self) -> &BaseMachine<SC, Self::Chips> {
        self.machine.base_machine()
    }

    fn prove(&self, stdin: Self::Witness) -> MetaProof<SC> {
        let witness = ProvingWitness::setup_for_riscv(
            self.program.clone(),
            stdin,
            Default::default(),
            self.pk.clone(),
            self.vk.clone(),
        );
        self.machine.prove(&witness)
    }

    fn verify(&self, proof: &MetaProof<SC>) -> bool {
        self.machine.verify(proof).is_ok()
    }
}
