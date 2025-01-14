use super::{MachineProver, ProverChain};
use crate::{
    compiler::recursion_v2::program::RecursionProgram,
    configs::{
        config::{StarkGenericConfig, Val},
        field_config::{bb_simple::BabyBearSimple, kb_simple::KoalaBearSimple},
        stark_config::{bb_poseidon2::BabyBearPoseidon2, kb_poseidon2::KoalaBearPoseidon2},
    },
    emulator::riscv::stdin::EmulatorStdin,
    instances::{
        chiptype::recursion_chiptype_v2::RecursionChipType, machine::combine::CombineMachine,
    },
    machine::{
        chip::ChipBehavior,
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    primitives::consts::{
        BABYBEAR_NUM_EXTERNAL_ROUNDS, BABYBEAR_NUM_INTERNAL_ROUNDS, BABYBEAR_W, COMBINE_DEGREE,
        COMBINE_SIZE, CONVERT_DEGREE, DIGEST_SIZE, EXTENSION_DEGREE, KOALABEAR_NUM_EXTERNAL_ROUNDS,
        KOALABEAR_NUM_INTERNAL_ROUNDS, KOALABEAR_W, RECURSION_NUM_PVS,
    },
    recursion_v2::runtime::RecursionRecord,
};
use p3_field::{extension::BinomiallyExtendable, FieldAlgebra, PrimeField32};

type ConvertChips<
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
pub type CombineChips<
    SC,
    const W: u32,
    const NUM_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
> = RecursionChipType<
    Val<SC>,
    COMBINE_DEGREE,
    W,
    NUM_EXTERNAL_ROUNDS,
    NUM_INTERNAL_ROUNDS,
    NUM_INTERNAL_ROUNDS_MINUS_ONE,
>;

pub struct CombineProver<
    PrevSC,
    SC,
    const W: u32,
    const NUM_EXTERNAL_ROUNDS: usize,
    const HALF_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
> where
    PrevSC: StarkGenericConfig,
    Val<PrevSC>: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>,
    SC: StarkGenericConfig,
    Val<SC>: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>,
    CombineChips<SC, W, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE>:
        ChipBehavior<
            Val<SC>,
            Program = RecursionProgram<Val<SC>>,
            Record = RecursionRecord<Val<SC>>,
        >,
    ConvertChips<
        PrevSC,
        W,
        NUM_EXTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS_MINUS_ONE,
    >: ChipBehavior<Val<PrevSC>>,
{
    machine: CombineMachine<
        SC,
        CombineChips<
            SC,
            W,
            NUM_EXTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS_MINUS_ONE,
        >,
        HALF_EXTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS,
    >,
    prev_machine: BaseMachine<
        PrevSC,
        ConvertChips<
            PrevSC,
            W,
            NUM_EXTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS_MINUS_ONE,
        >,
    >,
}

macro_rules! impl_combine_prover {
    ($recur_cc:ident, $recur_sc:ident, $field_w:ident, $num_external_rounds:ident, $num_internal_rounds:ident) => {
        // TODO: make RecursionCombineVerifierCircuit and Hintable traits generic over FC/SC
        impl
            ProverChain<
                $recur_sc,
                ConvertChips<
                    $recur_sc,
                    $field_w,
                    $num_external_rounds,
                    $num_internal_rounds,
                    { $num_internal_rounds - 1 },
                >,
                $recur_sc,
            >
            for CombineProver<
                $recur_sc,
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
                    $recur_sc,
                    Chips = ConvertChips<
                        $recur_sc,
                        $field_w,
                        $num_external_rounds,
                        $num_internal_rounds,
                        { $num_internal_rounds - 1 },
                    >,
                >,
            ) -> Self {
                let machine = CombineMachine::new(
                    $recur_sc::new(),
                    CombineChips::<
                        $recur_sc,
                        $field_w,
                        $num_external_rounds,
                        $num_internal_rounds,
                        { $num_internal_rounds - 1 },
                    >::combine_chips(),
                    RECURSION_NUM_PVS,
                );
                Self {
                    machine,
                    prev_machine: prev_prover.machine().clone(),
                }
            }
        }

        impl MachineProver<$recur_sc>
            for CombineProver<
                $recur_sc,
                $recur_sc,
                $field_w,
                $num_external_rounds,
                { $num_external_rounds / 2 },
                $num_internal_rounds,
                { $num_internal_rounds - 1 },
            >
        {
            type Witness = MetaProof<$recur_sc>;
            type Chips = CombineChips<
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
                let vk_root = [Val::<$recur_sc>::ZERO; DIGEST_SIZE];
                let (stdin, last_vk, last_proof) =
                    EmulatorStdin::setup_for_combine::<Val<$recur_sc>, $recur_cc>(
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

            fn verify(&self, proof: &MetaProof<$recur_sc>) -> bool {
                self.machine.verify(proof).is_ok()
            }
        }
    };
}

impl_combine_prover!(
    BabyBearSimple,
    BabyBearPoseidon2,
    BABYBEAR_W,
    BABYBEAR_NUM_EXTERNAL_ROUNDS,
    BABYBEAR_NUM_INTERNAL_ROUNDS
);
impl_combine_prover!(
    KoalaBearSimple,
    KoalaBearPoseidon2,
    KOALABEAR_W,
    KOALABEAR_NUM_EXTERNAL_ROUNDS,
    KOALABEAR_NUM_INTERNAL_ROUNDS
);
