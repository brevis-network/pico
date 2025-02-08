use super::{MachineProver, ProverChain};
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
        machine::combine_vk::CombineVkMachine,
    },
    machine::{
        field::FieldSpecificPoseidon2Config,
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    primitives::consts::{COMBINE_SIZE, EXTENSION_DEGREE, RECURSION_NUM_PVS},
};
use p3_field::{extension::BinomiallyExtendable, PrimeField32};

type ConvertChips<SC> = RecursionChipType<Val<SC>>;
pub type CombineChips<SC> = RecursionChipType<Val<SC>>;

pub struct CombineVkProver<PrevSC, SC>
where
    PrevSC: StarkGenericConfig,
    Val<PrevSC>:
        PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + FieldSpecificPoseidon2Config,
    SC: StarkGenericConfig,
    Val<SC>: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + FieldSpecificPoseidon2Config,
{
    machine: CombineVkMachine<SC, CombineChips<SC>>,
    opts: EmulatorOpts,
    shape_config: Option<RecursionShapeConfig<Val<SC>, CombineChips<SC>>>,
    prev_machine: BaseMachine<PrevSC, ConvertChips<PrevSC>>,
}

macro_rules! impl_combine_vk_prover {
    ($recur_cc:ident, $recur_sc:ident) => {
        // TODO: make RecursionCombineVerifierCircuit and Hintable traits generic over FC/SC
        impl ProverChain<$recur_sc, ConvertChips<$recur_sc>, $recur_sc>
            for CombineVkProver<$recur_sc, $recur_sc>
        {
            type Opts = EmulatorOpts;
            type ShapeConfig = RecursionShapeConfig<Val<$recur_sc>, CombineChips<$recur_sc>>;

            fn new_with_prev(
                prev_prover: &impl MachineProver<$recur_sc, Chips = ConvertChips<$recur_sc>>,
                opts: Self::Opts,
                shape_config: Option<Self::ShapeConfig>,
            ) -> Self {
                let machine = CombineVkMachine::new(
                    $recur_sc::new(),
                    CombineChips::<$recur_sc>::combine_chips(),
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

        impl MachineProver<$recur_sc> for CombineVkProver<$recur_sc, $recur_sc> {
            type Witness = MetaProof<$recur_sc>;
            type Chips = CombineChips<$recur_sc>;

            fn machine(&self) -> &BaseMachine<$recur_sc, Self::Chips> {
                self.machine.base_machine()
            }

            fn prove(&self, proofs: Self::Witness) -> MetaProof<$recur_sc> {
                let vk_manager = <$recur_sc as HasStaticVkManager>::static_vk_manager();
                let vk_root = vk_manager.merkle_root;

                let shape_config = self.shape_config.as_ref().unwrap();

                let (stdin, last_vk, last_proof) =
                    EmulatorStdin::setup_for_combine_vk::<Val<$recur_sc>, $recur_cc>(
                        vk_root,
                        proofs.vks(),
                        &proofs.proofs(),
                        &self.prev_machine,
                        COMBINE_SIZE,
                        proofs.proofs.len() <= COMBINE_SIZE,
                        &vk_manager,
                        shape_config,
                    );
                let witness = ProvingWitness::setup_for_recursion_vk(
                    vk_root,
                    stdin,
                    last_vk,
                    last_proof,
                    self.machine.config(),
                    self.opts,
                );
                self.machine.prove(&witness)
            }

            fn verify(&self, proof: &MetaProof<$recur_sc>) -> bool {
                self.machine.verify(proof).is_ok()
            }
        }
    };
}

impl_combine_vk_prover!(BabyBearSimple, BabyBearPoseidon2);
impl_combine_vk_prover!(KoalaBearSimple, KoalaBearPoseidon2);
