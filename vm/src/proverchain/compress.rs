use super::{combine::CombineChips, MachineProver, ProverChain};
use crate::{
    compiler::recursion::circuit::witness::Witnessable,
    configs::config::{Challenge, StarkGenericConfig, Val},
    emulator::recursion::emulator::Runtime,
    instances::{
        chiptype::recursion_chiptype::RecursionChipType,
        compiler::{
            recursion_circuit::{
                compress::builder::CompressVerifierCircuit, stdin::RecursionStdin,
            },
            vk_merkle::{
                builder::CompressVkVerifierCircuit, stdin::RecursionStdinVariant,
                HasStaticVkManager,
            },
        },
        configs::{recur_config, recur_kb_config},
        machine::compress::CompressMachine,
    },
    machine::{
        field::FieldSpecificPoseidon2Config,
        keys::HashableKey,
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    primitives::consts::{DIGEST_SIZE, EXTENSION_DEGREE, RECURSION_NUM_PVS},
};
use alloc::sync::Arc;
use p3_field::{extension::BinomiallyExtendable, FieldAlgebra, PrimeField32};

pub type CompressChips<SC> = RecursionChipType<Val<SC>>;

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
        impl
            ProverChain<
                $mod_name::StarkConfig,
                CombineChips<$mod_name::StarkConfig>,
                $mod_name::StarkConfig,
            > for CompressProver<$mod_name::StarkConfig, $mod_name::StarkConfig>
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
                let vk_manager =
                    <$mod_name::StarkConfig as HasStaticVkManager>::static_vk_manager();

                let vk_root = if vk_manager.vk_verification_enabled() {
                    vk_manager.merkle_root
                } else {
                    [Val::<$mod_name::StarkConfig>::ZERO; DIGEST_SIZE]
                };

                let stdin = RecursionStdin::new(
                    self.machine.base_machine(),
                    proofs.vks.clone(),
                    proofs.proofs.clone(),
                    true,
                    vk_root,
                );

                let (program, stdin) = if vk_manager.vk_verification_enabled() {
                    let stdin = vk_manager.add_vk_merkle_proof(stdin);

                    let mut program = CompressVkVerifierCircuit::<
                        $mod_name::FieldConfig,
                        $mod_name::StarkConfig,
                    >::build(&self.prev_machine, &stdin);

                    let compress_pad_shape =
                        RecursionChipType::<$mod_name::SC_Val>::compress_shape();
                    program.shape = Some(compress_pad_shape);

                    (program, RecursionStdinVariant::WithVk(stdin))
                } else {
                    let program = CompressVerifierCircuit::<
                        $mod_name::FieldConfig,
                        $mod_name::StarkConfig,
                    >::build(&self.prev_machine, &stdin);

                    (program, RecursionStdinVariant::NoVk(stdin))
                };

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

            fn verify(
                &self,
                proof: &MetaProof<$mod_name::StarkConfig>,
                riscv_vk: &dyn HashableKey<Val<$mod_name::StarkConfig>>,
            ) -> bool {
                self.machine.verify(proof, riscv_vk).is_ok()
            }
        }
    };
}

impl_compress_prover!(recur_config);
impl_compress_prover!(recur_kb_config);
