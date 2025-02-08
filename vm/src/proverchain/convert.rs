use super::{riscv::RiscvChips, MachineProver, ProverChain};
use crate::{
    configs::{
        config::{StarkGenericConfig, Val},
        field_config::{bb_simple::BabyBearSimple, kb_simple::KoalaBearSimple},
        stark_config::{bb_poseidon2::BabyBearPoseidon2, kb_poseidon2::KoalaBearPoseidon2},
    },
    emulator::{opts::EmulatorOpts, riscv::stdin::EmulatorStdin},
    instances::{
        chiptype::recursion_chiptype::RecursionChipType,
        compiler::{shapes::compress_shape::RecursionShapeConfig, vk_merkle::HasStaticVkManager},
        machine::convert::ConvertMachine,
    },
    machine::{
        field::FieldSpecificPoseidon2Config,
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    primitives::consts::{DIGEST_SIZE, EXTENSION_DEGREE, RECURSION_NUM_PVS},
};
use p3_field::{extension::BinomiallyExtendable, FieldAlgebra, PrimeField32};

type RecursionChips<SC> = RecursionChipType<Val<SC>>;

pub struct ConvertProver<RiscvSC, SC>
where
    RiscvSC: StarkGenericConfig,
    Val<RiscvSC>: PrimeField32 + FieldSpecificPoseidon2Config,
    SC: StarkGenericConfig,
    Val<SC>: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + FieldSpecificPoseidon2Config,
{
    machine: ConvertMachine<SC, RecursionChips<SC>>,
    opts: EmulatorOpts,
    shape_config: Option<RecursionShapeConfig<Val<SC>, RecursionChips<SC>>>,
    prev_machine: BaseMachine<RiscvSC, RiscvChips<RiscvSC>>,
}

macro_rules! impl_convert_prover {
    ($riscv_sc:ident, $recur_cc:ident, $recur_sc:ident) => {
        // TODO: make ConvertVerifierCircuit and Hintable traits generic over FC/SC
        impl ProverChain<$riscv_sc, RiscvChips<$riscv_sc>, $recur_sc>
            for ConvertProver<$riscv_sc, $recur_sc>
        {
            type Opts = EmulatorOpts;
            type ShapeConfig = RecursionShapeConfig<Val<$recur_sc>, RecursionChips<$recur_sc>>;

            fn new_with_prev(
                prev_prover: &impl MachineProver<$riscv_sc, Chips = RiscvChips<$riscv_sc>>,
                opts: Self::Opts,
                shape_config: Option<Self::ShapeConfig>,
            ) -> Self {
                let machine = ConvertMachine::new(
                    $recur_sc::new(),
                    RecursionChips::<$recur_sc>::convert_chips(),
                    RECURSION_NUM_PVS,
                );
                Self {
                    machine,
                    opts,
                    shape_config,
                    prev_machine: prev_prover.machine().clone(),
                }
            }
        }

        impl MachineProver<$recur_sc> for ConvertProver<$riscv_sc, $recur_sc> {
            type Witness = MetaProof<$riscv_sc>;
            type Chips = RecursionChips<$recur_sc>;

            fn machine(&self) -> &BaseMachine<$recur_sc, Self::Chips> {
                self.machine.base_machine()
            }

            fn prove(&self, proofs: Self::Witness) -> MetaProof<$recur_sc> {
                assert_eq!(proofs.vks.len(), 1);

                let vk_root = if self.shape_config.is_some() {
                    let vk_manager = <$recur_sc as HasStaticVkManager>::static_vk_manager();
                    vk_manager.merkle_root
                } else {
                    [Val::<$riscv_sc>::ZERO; DIGEST_SIZE]
                };

                let stdin = EmulatorStdin::setup_for_convert::<Val<$recur_sc>, $recur_cc>(
                    &proofs.vks[0],
                    vk_root,
                    &self.prev_machine,
                    &proofs.proofs(),
                    &self.shape_config,
                );
                let witness =
                    ProvingWitness::setup_for_convert(stdin, self.machine.config(), self.opts);
                self.machine.prove(&witness)
            }

            fn verify(&self, proof: &MetaProof<$recur_sc>) -> bool {
                self.machine.verify(proof).is_ok()
            }
        }
    };
}

impl_convert_prover!(BabyBearPoseidon2, BabyBearSimple, BabyBearPoseidon2);
impl_convert_prover!(KoalaBearPoseidon2, KoalaBearSimple, KoalaBearPoseidon2);
