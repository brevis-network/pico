use super::{combine::CombineChips, MachineProver, ProverChain};
use crate::{
    compiler::recursion_v2::circuit::witness::Witnessable,
    configs::config::{Challenge, StarkGenericConfig, Val},
    emulator::recursion::emulator::Runtime,
    instances::{
        chiptype::recursion_chiptype_v2::RecursionChipType,
        compiler_v2::recursion_circuit::{
            compress::builder::CompressVerifierCircuit, stdin::RecursionStdin,
        },
        configs::{recur_config, recur_kb_config},
        machine::compress::CompressMachine,
    },
    machine::{
        field::FieldSpecificPoseidon2Config,
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    primitives::consts::{COMPRESS_DEGREE, DIGEST_SIZE, EXTENSION_DEGREE, RECURSION_NUM_PVS},
};
use alloc::sync::Arc;
use p3_field::{extension::BinomiallyExtendable, FieldAlgebra, PrimeField32};

pub type CompressChips<SC> = RecursionChipType<Val<SC>, COMPRESS_DEGREE>;

pub struct CompressProver<PrevSC, SC>
where
    PrevSC: StarkGenericConfig,
    Val<PrevSC>:
        PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + FieldSpecificPoseidon2Config,
    SC: StarkGenericConfig,
    Val<SC>: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + FieldSpecificPoseidon2Config,
{
    machine: CompressMachine<SC, CompressChips<SC>>,
    prev_machine: BaseMachine<PrevSC, CombineChips<PrevSC>>,
}

macro_rules! impl_compress_prover {
    ($mod_name:ident) => {
        // TODO: make RecursionCompressVerifierCircuit and Hintable traits generic over FC/SC
        impl
            ProverChain<
                $mod_name::StarkConfig,
                CombineChips<$mod_name::StarkConfig>,
                $mod_name::StarkConfig,
            > for CompressProver<$mod_name::StarkConfig, $mod_name::StarkConfig>
        {
            type Opts = ();

            fn new_with_prev(
                prev_prover: &impl MachineProver<
                    $mod_name::StarkConfig,
                    Chips = CombineChips<$mod_name::StarkConfig>,
                >,
                _opts: Self::Opts,
            ) -> Self {
                let machine = CompressMachine::new(
                    $mod_name::StarkConfig::compress(),
                    CompressChips::<$mod_name::StarkConfig>::compress_chips(),
                    RECURSION_NUM_PVS,
                );
                Self {
                    machine,
                    prev_machine: prev_prover.machine().clone(),
                }
            }
        }

        impl MachineProver<$mod_name::StarkConfig>
            for CompressProver<$mod_name::StarkConfig, $mod_name::StarkConfig>
        {
            type Witness = MetaProof<$mod_name::StarkConfig>;
            type Chips = CompressChips<$mod_name::StarkConfig>;

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

impl_compress_prover!(recur_config);
impl_compress_prover!(recur_kb_config);
