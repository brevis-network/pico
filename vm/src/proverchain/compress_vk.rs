use super::{combine::CombineChips, MachineProver, ProverChain};
use crate::{
    compiler::recursion::circuit::witness::Witnessable,
    configs::config::{Challenge, StarkGenericConfig, Val},
    emulator::recursion::emulator::Runtime,
    instances::{
        chiptype::recursion_chiptype::RecursionChipType,
        compiler::{
            recursion_circuit::stdin::RecursionStdin,
            vk_merkle::{builder::CompressVkVerifierCircuit, HasStaticVkManager},
        },
        configs::{recur_config, recur_kb_config},
        machine::compress_vk::CompressVkMachine,
    },
    machine::{
        field::FieldSpecificPoseidon2Config,
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    primitives::consts::{COMPRESS_DEGREE, EXTENSION_DEGREE, RECURSION_NUM_PVS},
};
use alloc::sync::Arc;
use p3_field::{extension::BinomiallyExtendable, PrimeField32};

pub type CompressChips<SC> = RecursionChipType<Val<SC>, COMPRESS_DEGREE>;

pub struct CompressVkProver<PrevSC, SC>
where
    PrevSC: StarkGenericConfig,
    Val<PrevSC>:
        PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + FieldSpecificPoseidon2Config,
    SC: StarkGenericConfig,
    Val<SC>: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + FieldSpecificPoseidon2Config,
{
    machine: CompressVkMachine<SC, CompressChips<SC>>,
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
            > for CompressVkProver<$mod_name::StarkConfig, $mod_name::StarkConfig>
        {
            type Opts = ();
            type ShapeConfig = ();

            fn new_with_prev(
                prev_prover: &impl MachineProver<
                    $mod_name::StarkConfig,
                    Chips = CombineChips<$mod_name::StarkConfig>,
                >,
                _opts: Self::Opts,
                _shape_config: Option<Self::ShapeConfig>,
            ) -> Self {
                let machine = CompressVkMachine::new(
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
            for CompressVkProver<$mod_name::StarkConfig, $mod_name::StarkConfig>
        {
            type Witness = MetaProof<$mod_name::StarkConfig>;
            type Chips = CompressChips<$mod_name::StarkConfig>;

            fn machine(&self) -> &BaseMachine<$mod_name::StarkConfig, Self::Chips> {
                self.machine.base_machine()
            }

            fn prove(&self, proofs: Self::Witness) -> MetaProof<$mod_name::StarkConfig> {
                let vk_manager =
                    <$mod_name::StarkConfig as HasStaticVkManager>::static_vk_manager();
                let vk_root = vk_manager.merkle_root;

                let stdin = RecursionStdin::new(
                    self.machine.base_machine(),
                    proofs.vks.clone(),
                    proofs.proofs.clone(),
                    true,
                    vk_root,
                );

                let stdin = vk_manager.add_vk_merkle_proof(stdin);
                let mut program = CompressVkVerifierCircuit::<
                    $mod_name::FieldConfig,
                    $mod_name::StarkConfig,
                >::build(&self.prev_machine, &stdin);

                let compress_pad_shape =
                    RecursionChipType::<$mod_name::SC_Val, COMPRESS_DEGREE>::compress_shape();

                program.shape = Some(compress_pad_shape);

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
