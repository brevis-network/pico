use super::{compress::CompressChips, MachineProver, ProverChain};
use crate::{
    compiler::recursion_v2::{circuit::witness::Witnessable, program::RecursionProgram},
    configs::{
        config::{Challenge, StarkGenericConfig, Val},
        stark_config::{
            bb_bn254_poseidon2::BabyBearBn254Poseidon2, kb_bn254_poseidon2::KoalaBearBn254Poseidon2,
        },
    },
    instances::{
        chiptype::recursion_chiptype_v2::RecursionChipType,
        compiler_v2::recursion_circuit::{
            embed::builder::EmbedVerifierCircuit, stdin::RecursionStdin,
        },
        configs::{recur_config, recur_kb_config},
        machine::embed::EmbedMachine,
    },
    machine::{
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    primitives::consts::{
        BABYBEAR_NUM_EXTERNAL_ROUNDS, BABYBEAR_NUM_INTERNAL_ROUNDS, BABYBEAR_W, DIGEST_SIZE,
        EMBED_DEGREE, EXTENSION_DEGREE, KOALABEAR_NUM_EXTERNAL_ROUNDS,
        KOALABEAR_NUM_INTERNAL_ROUNDS, KOALABEAR_W, RECURSION_NUM_PVS_V2,
    },
    proverchain::ChipBehavior,
    recursion_v2::runtime::{RecursionRecord, Runtime},
};
use alloc::sync::Arc;
use p3_air::Air;
use p3_field::{extension::BinomiallyExtendable, FieldAlgebra, PrimeField32};

pub type EmbedChips<
    SC,
    const W: u32,
    const NUM_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
> = RecursionChipType<
    Val<SC>,
    EMBED_DEGREE,
    W,
    NUM_EXTERNAL_ROUNDS,
    NUM_INTERNAL_ROUNDS,
    NUM_INTERNAL_ROUNDS_MINUS_ONE,
>;

pub struct EmbedProver<
    PrevSC,
    SC,
    I,
    const W: u32,
    const NUM_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
> where
    PrevSC: StarkGenericConfig,
    Val<PrevSC>: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>,
    SC: StarkGenericConfig,
    Val<SC>: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>,

    EmbedChips<SC, W, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE>:
        ChipBehavior<
                Val<SC>,
                Program = RecursionProgram<Val<SC>>,
                Record = RecursionRecord<Val<SC>>,
            > + for<'b> Air<ProverConstraintFolder<'b, SC>>
            + for<'b> Air<VerifierConstraintFolder<'b, SC>>,

    CompressChips<
        PrevSC,
        W,
        NUM_EXTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS_MINUS_ONE,
    >: ChipBehavior<Val<PrevSC>>
        + for<'a> Air<ProverConstraintFolder<'a, PrevSC>>
        + for<'a> Air<VerifierConstraintFolder<'a, PrevSC>>,
{
    machine: EmbedMachine<
        PrevSC,
        SC,
        EmbedChips<SC, W, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE>,
        I,
    >,
    prev_machine: BaseMachine<
        PrevSC,
        CompressChips<
            PrevSC,
            W,
            NUM_EXTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS_MINUS_ONE,
        >,
    >,
}

macro_rules! impl_embeded_prover {
    ($mod_name:ident, $embed_sc:ident, $field_w:ident, $num_external_rounds:ident, $num_internal_rounds:ident) => {
        // TODO: make RecursionCompressVerifierCircuit and Hintable traits generic over FC/SC
        impl<I>
            ProverChain<
                $mod_name::StarkConfig,
                CompressChips<
                    $mod_name::StarkConfig,
                    $field_w,
                    $num_external_rounds,
                    $num_internal_rounds,
                    { $num_internal_rounds - 1 },
                >,
                $embed_sc,
            >
            for EmbedProver<
                $mod_name::StarkConfig,
                $embed_sc,
                I,
                $field_w,
                $num_external_rounds,
                $num_internal_rounds,
                { $num_internal_rounds - 1 },
            >
        {
            fn new_with_prev(
                prev_prover: &impl MachineProver<
                    $mod_name::StarkConfig,
                    Chips = CompressChips<
                        $mod_name::StarkConfig,
                        $field_w,
                        $num_external_rounds,
                        $num_internal_rounds,
                        { $num_internal_rounds - 1 },
                    >,
                >,
            ) -> Self {
                let machine = EmbedMachine::<$mod_name::StarkConfig, _, _, I>::new(
                    $embed_sc::default(),
                    EmbedChips::<
                        $embed_sc,
                        $field_w,
                        $num_external_rounds,
                        $num_internal_rounds,
                        { $num_internal_rounds - 1 },
                    >::embed_chips(),
                    RECURSION_NUM_PVS_V2,
                );
                Self {
                    machine,
                    prev_machine: prev_prover.machine().clone(),
                }
            }
        }

        impl<I> MachineProver<$embed_sc>
            for EmbedProver<
                $mod_name::StarkConfig,
                $embed_sc,
                I,
                $field_w,
                $num_external_rounds,
                $num_internal_rounds,
                { $num_internal_rounds - 1 },
            >
        {
            type Witness = MetaProof<$mod_name::StarkConfig>;
            type Chips = EmbedChips<
                $embed_sc,
                $field_w,
                $num_external_rounds,
                $num_internal_rounds,
                { $num_internal_rounds - 1 },
            >;

            fn machine(&self) -> &BaseMachine<$embed_sc, Self::Chips> {
                self.machine.base_machine()
            }

            fn prove(&self, proofs: Self::Witness) -> MetaProof<$embed_sc> {
                let vk_root = [Val::<$mod_name::StarkConfig>::ZERO; DIGEST_SIZE];
                let stdin = RecursionStdin::new(
                    &self.prev_machine,
                    proofs.vks.clone(),
                    proofs.proofs.clone(),
                    true,
                    vk_root,
                );
                let program = EmbedVerifierCircuit::<
                    $mod_name::FieldConfig,
                    $mod_name::StarkConfig,
                    $field_w,
                    $num_external_rounds,
                    $num_internal_rounds,
                    { $num_internal_rounds - 1 },
                >::build(&self.prev_machine, &stdin);
                let (pk, vk) = self.machine.setup_keys(&program);

                let mut witness_stream = Vec::new();
                Witnessable::<$mod_name::FieldConfig>::write(&stdin, &mut witness_stream);

                let mut runtime = Runtime::<_, Challenge<$mod_name::StarkConfig>, _, _, _>::new(
                    Arc::new(program),
                    self.prev_machine.config().perm.clone(),
                );
                runtime.witness_stream = witness_stream.into();
                runtime.run().expect("error while running program");
                let witness =
                    ProvingWitness::setup_with_keys_and_records(pk, vk, vec![runtime.record]);
                self.machine.prove(&witness)
            }

            fn verify(&self, proof: &MetaProof<$embed_sc>) -> bool {
                self.machine.verify(proof).is_ok()
            }
        }
    };
}

impl_embeded_prover!(
    recur_config,
    BabyBearBn254Poseidon2,
    BABYBEAR_W,
    BABYBEAR_NUM_EXTERNAL_ROUNDS,
    BABYBEAR_NUM_INTERNAL_ROUNDS
);
impl_embeded_prover!(
    recur_kb_config,
    KoalaBearBn254Poseidon2,
    KOALABEAR_W,
    KOALABEAR_NUM_EXTERNAL_ROUNDS,
    KOALABEAR_NUM_INTERNAL_ROUNDS
);
