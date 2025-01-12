use super::{MachineProver, ProverChain};
use crate::{
    configs::config::{StarkGenericConfig, Val},
    emulator::riscv::stdin::EmulatorStdin,
    instances::{
        chiptype::recursion_chiptype_v2::RecursionChipType,
        configs::recur_config::StarkConfig as RecursionSC, machine::combine::CombineMachine,
    },
    machine::{
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    primitives::consts::{
        COMBINE_DEGREE, COMBINE_SIZE, CONVERT_DEGREE, DIGEST_SIZE, EXTENSION_DEGREE,
        RECURSION_NUM_PVS_V2,
    },
};
use p3_field::{extension::BinomiallyExtendable, FieldAlgebra, PrimeField32};

type ConvertChips<SC> = RecursionChipType<Val<SC>, CONVERT_DEGREE>;
pub type CombineChips<SC> = RecursionChipType<Val<SC>, COMBINE_DEGREE>;

pub struct CombineProver<PrevSC, SC>
where
    PrevSC: StarkGenericConfig,
    Val<PrevSC>: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>,
    SC: StarkGenericConfig,
    Val<SC>: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>,
{
    machine: CombineMachine<SC, CombineChips<SC>>,
    prev_machine: BaseMachine<PrevSC, ConvertChips<PrevSC>>,
}

// TODO: make RecursionCombineVerifierCircuit and Hintable traits generic over FC/SC
impl ProverChain<RecursionSC, ConvertChips<RecursionSC>, RecursionSC>
    for CombineProver<RecursionSC, RecursionSC>
{
    fn new_with_prev(
        prev_prover: &impl MachineProver<RecursionSC, Chips = ConvertChips<RecursionSC>>,
    ) -> Self {
        let machine = CombineMachine::new(
            RecursionSC::new(),
            CombineChips::<RecursionSC>::combine_chips(),
            RECURSION_NUM_PVS_V2,
        );
        Self {
            machine,
            prev_machine: prev_prover.machine().clone(),
        }
    }
}

impl MachineProver<RecursionSC> for CombineProver<RecursionSC, RecursionSC> {
    type Witness = MetaProof<RecursionSC>;
    type Chips = CombineChips<RecursionSC>;

    fn machine(&self) -> &BaseMachine<RecursionSC, Self::Chips> {
        self.machine.base_machine()
    }

    fn prove(&self, proofs: Self::Witness) -> MetaProof<RecursionSC> {
        let vk_root = [Val::<RecursionSC>::ZERO; DIGEST_SIZE];
        let (stdin, last_vk, last_proof) = EmulatorStdin::setup_for_combine(
            vk_root,
            proofs.vks(),
            &proofs.proofs(),
            &self.prev_machine,
            COMBINE_SIZE,
            false,
        );
        let witness = ProvingWitness::setup_for_recursion(
            vk_root,
            stdin,
            last_vk,
            last_proof,
            self.machine.config(),
            Default::default(),
        );
        self.machine.prove(&witness)
    }

    fn verify(&self, proof: &MetaProof<RecursionSC>) -> bool {
        self.machine.verify(proof).is_ok()
    }
}
