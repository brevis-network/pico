use super::{riscv::RiscvChips, MachineProver, ProverChain};
use crate::{
    configs::config::{StarkGenericConfig, Val},
    emulator::riscv::stdin::EmulatorStdin,
    instances::{
        chiptype::recursion_chiptype_v2::RecursionChipType,
        configs::{recur_config::StarkConfig as RecursionSC, riscv_config::StarkConfig as RiscvSC},
        machine::convert::ConvertMachine,
    },
    machine::{
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    primitives::consts::{CONVERT_DEGREE, DIGEST_SIZE, EXTENSION_DEGREE, RECURSION_NUM_PVS_V2},
};
use p3_field::{extension::BinomiallyExtendable, FieldAlgebra, PrimeField32};

type RecursionChips<SC> = RecursionChipType<Val<SC>, CONVERT_DEGREE>;

pub struct ConvertProver<RiscvSC, SC>
where
    RiscvSC: StarkGenericConfig,
    Val<RiscvSC>: PrimeField32,
    SC: StarkGenericConfig,
    Val<SC>: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>,
{
    machine: ConvertMachine<SC, RecursionChips<SC>>,
    prev_machine: BaseMachine<RiscvSC, RiscvChips<RiscvSC>>,
}

// TODO: make ConvertVerifierCircuit and Hintable traits generic over FC/SC
impl ProverChain<RiscvSC, RiscvChips<RiscvSC>, RecursionSC>
    for ConvertProver<RiscvSC, RecursionSC>
{
    fn new_with_prev(
        prev_prover: &impl MachineProver<RiscvSC, Chips = RiscvChips<RiscvSC>>,
    ) -> Self {
        let machine = ConvertMachine::new(
            RecursionSC::new(),
            RecursionChips::<RecursionSC>::convert_chips(),
            RECURSION_NUM_PVS_V2,
        );
        Self {
            machine,
            prev_machine: prev_prover.machine().clone(),
        }
    }
}

impl MachineProver<RecursionSC> for ConvertProver<RiscvSC, RecursionSC> {
    type Witness = MetaProof<RiscvSC>;
    type Chips = RecursionChips<RecursionSC>;

    fn machine(&self) -> &BaseMachine<RecursionSC, Self::Chips> {
        self.machine.base_machine()
    }

    fn prove(&self, proofs: Self::Witness) -> MetaProof<RecursionSC> {
        assert_eq!(proofs.vks.len(), 1);
        let stdin = EmulatorStdin::setup_for_convert(
            &proofs.vks[0],
            [Val::<RiscvSC>::ZERO; DIGEST_SIZE],
            &self.prev_machine,
            &proofs.proofs(),
            None,
        );
        let witness =
            ProvingWitness::setup_for_convert(stdin, self.machine.config(), Default::default());
        self.machine.prove(&witness)
    }

    fn verify(&self, proof: &MetaProof<RecursionSC>) -> bool {
        self.machine.verify(proof).is_ok()
    }
}
