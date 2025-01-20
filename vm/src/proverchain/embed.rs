use super::{compress::CompressChips, MachineProver, ProverChain};
use crate::{
    compiler::recursion_v2::circuit::witness::Witnessable,
    configs::{
        config::{Challenge, StarkGenericConfig, Val},
        stark_config::{
            bb_bn254_poseidon2::BabyBearBn254Poseidon2, kb_bn254_poseidon2::KoalaBearBn254Poseidon2,
        },
    },
    emulator::recursion::emulator::Runtime,
    instances::{
        chiptype::recursion_chiptype_v2::RecursionChipType,
        compiler_v2::recursion_circuit::{
            embed::builder::EmbedVerifierCircuit, stdin::RecursionStdin,
        },
        configs::{recur_config, recur_kb_config},
        machine::embed::EmbedMachine,
    },
    machine::{
        field::FieldSpecificPoseidon2Config,
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    primitives::consts::{DIGEST_SIZE, EMBED_DEGREE, EXTENSION_DEGREE, RECURSION_NUM_PVS},
};
use alloc::sync::Arc;
use p3_field::{extension::BinomiallyExtendable, FieldAlgebra, PrimeField32};

pub type EmbedChips<SC> = RecursionChipType<Val<SC>, EMBED_DEGREE>;

pub struct EmbedProver<PrevSC, SC, I>
where
    PrevSC: StarkGenericConfig,
    Val<PrevSC>:
        PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + FieldSpecificPoseidon2Config,
    SC: StarkGenericConfig,
    Val<SC>: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + FieldSpecificPoseidon2Config,
{
    pub machine: EmbedMachine<PrevSC, SC, EmbedChips<SC>, I>,
    prev_machine: BaseMachine<PrevSC, CompressChips<PrevSC>>,
}

macro_rules! impl_embeded_prover {
    ($mod_name:ident, $embed_sc:ident) => {
        // TODO: make RecursionCompressVerifierCircuit and Hintable traits generic over FC/SC
        impl<I>
            ProverChain<$mod_name::StarkConfig, CompressChips<$mod_name::StarkConfig>, $embed_sc>
            for EmbedProver<$mod_name::StarkConfig, $embed_sc, I>
        {
            type Opts = ();

            fn new_with_prev(
                prev_prover: &impl MachineProver<
                    $mod_name::StarkConfig,
                    Chips = CompressChips<$mod_name::StarkConfig>,
                >,
                _opts: Self::Opts,
            ) -> Self {
                let machine = EmbedMachine::<$mod_name::StarkConfig, _, _, I>::new(
                    $embed_sc::default(),
                    EmbedChips::<$embed_sc>::embed_chips(),
                    RECURSION_NUM_PVS,
                );
                Self {
                    machine,
                    prev_machine: prev_prover.machine().clone(),
                }
            }
        }

        impl<I> MachineProver<$embed_sc> for EmbedProver<$mod_name::StarkConfig, $embed_sc, I> {
            type Witness = MetaProof<$mod_name::StarkConfig>;
            type Chips = EmbedChips<$embed_sc>;

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
                let program =
                    EmbedVerifierCircuit::<$mod_name::FieldConfig, $mod_name::StarkConfig>::build(
                        &self.prev_machine,
                        &stdin,
                    );
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

impl_embeded_prover!(recur_config, BabyBearBn254Poseidon2);
impl_embeded_prover!(recur_kb_config, KoalaBearBn254Poseidon2);
