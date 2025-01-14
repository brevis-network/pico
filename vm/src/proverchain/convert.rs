use super::{riscv::RiscvChips, MachineProver, ProverChain};
use crate::{
    chips::precompiles::poseidon2::Poseidon2PermuteChip,
    compiler::{recursion_v2::program::RecursionProgram, riscv::program::Program},
    configs::{
        config::{StarkGenericConfig, Val},
        field_config::{bb_simple::BabyBearSimple, kb_simple::KoalaBearSimple},
        stark_config::{bb_poseidon2::BabyBearPoseidon2, kb_poseidon2::KoalaBearPoseidon2},
    },
    emulator::riscv::{record::EmulationRecord, stdin::EmulatorStdin},
    instances::{
        chiptype::recursion_chiptype_v2::RecursionChipType, machine::convert::ConvertMachine,
    },
    machine::{
        chip::ChipBehavior,
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    primitives::consts::{
        BABYBEAR_NUM_EXTERNAL_ROUNDS, BABYBEAR_NUM_INTERNAL_ROUNDS, BABYBEAR_W, CONVERT_DEGREE,
        DIGEST_SIZE, EXTENSION_DEGREE, KOALABEAR_NUM_EXTERNAL_ROUNDS,
        KOALABEAR_NUM_INTERNAL_ROUNDS, KOALABEAR_W, RECURSION_NUM_PVS_V2,
    },
    recursion_v2::runtime::RecursionRecord,
};
use p3_field::{extension::BinomiallyExtendable, FieldAlgebra, PrimeField32};

type RecursionChips<
    SC,
    const W: u32,
    const NUM_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
> = RecursionChipType<
    Val<SC>,
    CONVERT_DEGREE,
    W,
    NUM_EXTERNAL_ROUNDS,
    NUM_INTERNAL_ROUNDS,
    NUM_INTERNAL_ROUNDS_MINUS_ONE,
>;

pub struct ConvertProver<
    RiscvSC,
    SC,
    const W: u32,
    const NUM_EXTERNAL_ROUNDS: usize,
    const HALF_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
> where
    RiscvSC: StarkGenericConfig,
    Val<RiscvSC>: PrimeField32,
    SC: StarkGenericConfig,
    Val<SC>: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>,
    Poseidon2PermuteChip<Val<RiscvSC>, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>:
        ChipBehavior<Val<RiscvSC>, Record = EmulationRecord, Program = Program>,

    RecursionChips<SC, W, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE>:
        ChipBehavior<
            Val<SC>,
            Program = RecursionProgram<Val<SC>>,
            Record = RecursionRecord<Val<SC>>,
        >,
{
    machine: ConvertMachine<
        SC,
        RecursionChips<
            SC,
            W,
            NUM_EXTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS_MINUS_ONE,
        >,
        HALF_EXTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS,
    >,
    prev_machine:
        BaseMachine<RiscvSC, RiscvChips<RiscvSC, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>>,
}

macro_rules! impl_convert_prover {
    ($riscv_sc:ident, $recur_cc:ident, $recur_sc:ident, $field_w:ident, $num_external_rounds:ident, $num_internal_rounds:ident) => {
        // TODO: make ConvertVerifierCircuit and Hintable traits generic over FC/SC
        impl
            ProverChain<
                $riscv_sc,
                RiscvChips<$riscv_sc, { $num_external_rounds / 2 }, $num_internal_rounds>,
                $recur_sc,
            >
            for ConvertProver<
                $riscv_sc,
                $recur_sc,
                $field_w,
                $num_external_rounds,
                { $num_external_rounds / 2 },
                $num_internal_rounds,
                { $num_internal_rounds - 1 },
            >
        {
            fn new_with_prev(
                prev_prover: &impl MachineProver<
                    $riscv_sc,
                    Chips = RiscvChips<
                        $riscv_sc,
                        { $num_external_rounds / 2 },
                        $num_internal_rounds,
                    >,
                >,
            ) -> Self {
                let machine = ConvertMachine::new(
                    $recur_sc::new(),
                    RecursionChips::<
                        $recur_sc,
                        $field_w,
                        $num_external_rounds,
                        $num_internal_rounds,
                        { $num_internal_rounds - 1 },
                    >::convert_chips(),
                    RECURSION_NUM_PVS_V2,
                );
                Self {
                    machine,
                    prev_machine: prev_prover.machine().clone(),
                }
            }
        }

        impl MachineProver<$recur_sc>
            for ConvertProver<
                $riscv_sc,
                $recur_sc,
                $field_w,
                $num_external_rounds,
                { $num_external_rounds / 2 },
                $num_internal_rounds,
                { $num_internal_rounds - 1 },
            >
        {
            type Witness = MetaProof<$riscv_sc>;
            type Chips = RecursionChips<
                $recur_sc,
                $field_w,
                $num_external_rounds,
                $num_internal_rounds,
                { $num_internal_rounds - 1 },
            >;

            fn machine(&self) -> &BaseMachine<$recur_sc, Self::Chips> {
                self.machine.base_machine()
            }

            fn prove(&self, proofs: Self::Witness) -> MetaProof<$recur_sc> {
                assert_eq!(proofs.vks.len(), 1);
                let stdin = EmulatorStdin::setup_for_convert::<
                    Val<$recur_sc>,
                    $recur_cc,
                    $field_w,
                    $num_external_rounds,
                    { $num_internal_rounds - 1 },
                >(
                    &proofs.vks[0],
                    [Val::<$riscv_sc>::ZERO; DIGEST_SIZE],
                    &self.prev_machine,
                    &proofs.proofs(),
                    None,
                );
                let witness = ProvingWitness::setup_for_convert(
                    stdin,
                    self.machine.config(),
                    Default::default(),
                );
                self.machine.prove(&witness)
            }

            fn verify(&self, proof: &MetaProof<$recur_sc>) -> bool {
                self.machine.verify(proof).is_ok()
            }
        }
    };
}

impl_convert_prover!(
    BabyBearPoseidon2,
    BabyBearSimple,
    BabyBearPoseidon2,
    BABYBEAR_W,
    BABYBEAR_NUM_EXTERNAL_ROUNDS,
    BABYBEAR_NUM_INTERNAL_ROUNDS
);
impl_convert_prover!(
    KoalaBearPoseidon2,
    KoalaBearSimple,
    KoalaBearPoseidon2,
    KOALABEAR_W,
    KOALABEAR_NUM_EXTERNAL_ROUNDS,
    KOALABEAR_NUM_INTERNAL_ROUNDS
);
