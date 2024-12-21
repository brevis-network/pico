use super::{InitialProverSetup, MachineProver};
use crate::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::config::{Com, Dom, PcsProverData, StarkGenericConfig, Val},
    emulator::riscv::stdin::EmulatorStdin,
    instances::{chiptype::riscv_chiptype::RiscvChipType, machine::riscv::RiscvMachine},
    machine::{
        keys::{BaseProvingKey, BaseVerifyingKey},
        machine::{BaseMachine, MachineBehavior},
        proof::{BaseProof, MetaProof},
        witness::ProvingWitness,
    },
    primitives::consts::RISCV_NUM_PVS,
};
use alloc::sync::Arc;
use p3_field::PrimeField32;

pub type RiscvChips<SC> = RiscvChipType<Val<SC>>;

pub struct RiscvProver<SC, P>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField32,
{
    program: Arc<P>,
    machine: RiscvMachine<SC, RiscvChips<SC>>,
    pk: BaseProvingKey<SC>,
    vk: BaseVerifyingKey<SC>,
}

impl<SC> InitialProverSetup for RiscvProver<SC, Program>
where
    SC: Send + StarkGenericConfig,
    Com<SC>: Send + Sync,
    Dom<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    BaseProof<SC>: Send + Sync,
    Val<SC>: PrimeField32,
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

impl<SC> MachineProver<SC> for RiscvProver<SC, Program>
where
    SC: Send + StarkGenericConfig,
    Com<SC>: Send + Sync,
    Dom<SC>: Send + Sync,
    PcsProverData<SC>: Clone + Send + Sync,
    BaseProof<SC>: Send + Sync,
    Val<SC>: PrimeField32,
{
    type Witness = EmulatorStdin<Program, Vec<u8>>;
    type Chips = RiscvChips<SC>;

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
