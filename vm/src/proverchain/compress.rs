use super::{combine::CombineChips, MachineProver, ProverChain};
use crate::{
    compiler::recursion_v2::{circuit::witness::Witnessable, program::RecursionProgram},
    configs::config::{Challenge, StarkGenericConfig, Val},
    instances::{
        chiptype::recursion_chiptype_v2::RecursionChipType,
        compiler_v2::recursion_circuit::{
            compress::builder::CompressVerifierCircuit, stdin::RecursionStdin,
        },
        configs::{recur_config, recur_kb_config},
        machine::compress::CompressMachine,
    },
    machine::{
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    primitives::consts::{
        BABYBEAR_NUM_EXTERNAL_ROUNDS, BABYBEAR_NUM_INTERNAL_ROUNDS, BABYBEAR_W, COMPRESS_DEGREE,
        DIGEST_SIZE, EXTENSION_DEGREE, KOALABEAR_NUM_EXTERNAL_ROUNDS,
        KOALABEAR_NUM_INTERNAL_ROUNDS, KOALABEAR_W, RECURSION_NUM_PVS_V2,
    },
    proverchain::ChipBehavior,
    recursion_v2::runtime::{RecursionRecord, Runtime},
};
use alloc::sync::Arc;
use p3_air::Air;
use p3_field::{extension::BinomiallyExtendable, FieldAlgebra, PrimeField32};

pub type CompressChips<
    SC,
    const W: u32,
    const NUM_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
> = RecursionChipType<
    Val<SC>,
    COMPRESS_DEGREE,
    W,
    NUM_EXTERNAL_ROUNDS,
    NUM_INTERNAL_ROUNDS,
    NUM_INTERNAL_ROUNDS_MINUS_ONE,
>;

pub struct CompressProver<
    PrevSC,
    SC,
    const W: u32,
    const NUM_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
> where
    PrevSC: StarkGenericConfig,
    Val<PrevSC>: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>,
    SC: StarkGenericConfig,
    Val<SC>: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>,

    CompressChips<SC, W, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE>:
        ChipBehavior<
                Val<SC>,
                Program = RecursionProgram<Val<SC>>,
                Record = RecursionRecord<Val<SC>>,
            > + for<'b> Air<ProverConstraintFolder<'b, SC>>
            + for<'b> Air<VerifierConstraintFolder<'b, SC>>,

    CombineChips<
        PrevSC,
        W,
        NUM_EXTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS_MINUS_ONE,
    >: ChipBehavior<Val<PrevSC>>
        + for<'a> Air<ProverConstraintFolder<'a, PrevSC>>
        + for<'a> Air<VerifierConstraintFolder<'a, PrevSC>>,
{
    machine: CompressMachine<
        SC,
        CompressChips<
            SC,
            W,
            NUM_EXTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS_MINUS_ONE,
        >,
    >,
    prev_machine: BaseMachine<
        PrevSC,
        CombineChips<
            PrevSC,
            W,
            NUM_EXTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS_MINUS_ONE,
        >,
    >,
}

macro_rules! impl_compress_prover {
    ($mod_name:ident, $field_w:ident, $num_external_rounds:ident, $num_internal_rounds:ident) => {
        // TODO: make RecursionCompressVerifierCircuit and Hintable traits generic over FC/SC
        impl
            ProverChain<
                $mod_name::StarkConfig,
                CombineChips<
                    $mod_name::StarkConfig,
                    $field_w,
                    $num_external_rounds,
                    $num_internal_rounds,
                    { $num_internal_rounds - 1 },
                >,
                $mod_name::StarkConfig,
            >
            for CompressProver<
                $mod_name::StarkConfig,
                $mod_name::StarkConfig,
                $field_w,
                $num_external_rounds,
                $num_internal_rounds,
                { $num_internal_rounds - 1 },
            >
        {
            fn new_with_prev(
                prev_prover: &impl MachineProver<
                    $mod_name::StarkConfig,
                    Chips = CombineChips<
                        $mod_name::StarkConfig,
                        $field_w,
                        $num_external_rounds,
                        $num_internal_rounds,
                        { $num_internal_rounds - 1 },
                    >,
                >,
            ) -> Self {
                let machine = CompressMachine::new(
                    $mod_name::StarkConfig::compress(),
                    CompressChips::<
                        $mod_name::StarkConfig,
                        $field_w,
                        $num_external_rounds,
                        $num_internal_rounds,
                        { $num_internal_rounds - 1 },
                    >::compress_chips(),
                    RECURSION_NUM_PVS_V2,
                );
                Self {
                    machine,
                    prev_machine: prev_prover.machine().clone(),
                }
            }
        }

        impl MachineProver<$mod_name::StarkConfig>
            for CompressProver<
                $mod_name::StarkConfig,
                $mod_name::StarkConfig,
                $field_w,
                $num_external_rounds,
                $num_internal_rounds,
                { $num_internal_rounds - 1 },
            >
        {
            type Witness = MetaProof<$mod_name::StarkConfig>;
            type Chips = CompressChips<
                $mod_name::StarkConfig,
                $field_w,
                $num_external_rounds,
                $num_internal_rounds,
                { $num_internal_rounds - 1 },
            >;

            fn machine(&self) -> &BaseMachine<$mod_name::StarkConfig, Self::Chips> {
                self.machine.base_machine()
            }

            fn prove(&self, proofs: Self::Witness) -> MetaProof<$mod_name::StarkConfig> {
                let vk_root = [Val::<$mod_name::StarkConfig>::ZERO; DIGEST_SIZE];
                let stdin = RecursionStdin::new(
                    self.machine.base_machine(),
                    proofs.vks.clone(),
                    proofs.proofs.clone(),
                    true,
                    vk_root,
                );
                let program = CompressVerifierCircuit::<
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

            fn verify(&self, proof: &MetaProof<$mod_name::StarkConfig>) -> bool {
                self.machine.verify(proof).is_ok()
            }
        }
    };
}

impl_compress_prover!(
    recur_config,
    BABYBEAR_W,
    BABYBEAR_NUM_EXTERNAL_ROUNDS,
    BABYBEAR_NUM_INTERNAL_ROUNDS
);
impl_compress_prover!(
    recur_kb_config,
    KOALABEAR_W,
    KOALABEAR_NUM_EXTERNAL_ROUNDS,
    KOALABEAR_NUM_INTERNAL_ROUNDS
);
