use super::{MachineProver, ProverChain};
use crate::{
    configs::{
        config::{StarkGenericConfig, Val},
        field_config::{bb_simple::BabyBearSimple, kb_simple::KoalaBearSimple},
        stark_config::{bb_poseidon2::BabyBearPoseidon2, kb_poseidon2::KoalaBearPoseidon2},
    },
    emulator::{opts::EmulatorOpts, stdin::EmulatorStdin},
    instances::{
        chiptype::recursion_chiptype::RecursionChipType, machine::combine::CombineMachine,
    },
    machine::{
        field::FieldSpecificPoseidon2Config,
        keys::HashableKey,
        machine::{BaseMachine, MachineBehavior},
        proof::MetaProof,
        witness::ProvingWitness,
    },
    primitives::consts::{COMBINE_SIZE, DIGEST_SIZE, EXTENSION_DEGREE, RECURSION_NUM_PVS},
};
use p3_field::{extension::BinomiallyExtendable, FieldAlgebra, PrimeField32};

type ConvertChips<SC> = RecursionChipType<Val<SC>>;
pub type CombineChips<SC> = RecursionChipType<Val<SC>>;

pub struct CombineProver<PrevSC, SC>
where
    PrevSC: StarkGenericConfig,
    Val<PrevSC>:
        PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + FieldSpecificPoseidon2Config,
    SC: StarkGenericConfig,
    Val<SC>: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + FieldSpecificPoseidon2Config,
{
    machine: CombineMachine<SC, CombineChips<SC>>,
    opts: EmulatorOpts,
    prev_machine: BaseMachine<PrevSC, ConvertChips<PrevSC>>,
}

macro_rules! impl_combine_prover {
    ($recur_cc:ident, $recur_sc:ident) => {
        impl ProverChain<$recur_sc, ConvertChips<$recur_sc>, $recur_sc>
            for CombineProver<$recur_sc, $recur_sc>
        {
            type Opts = EmulatorOpts;
            type ShapeConfig = ();

            fn new_with_prev(
                prev_prover: &impl MachineProver<$recur_sc, Chips = ConvertChips<$recur_sc>>,
                opts: Self::Opts,
                _shape_config: Option<Self::ShapeConfig>,
            ) -> Self {
                let machine = CombineMachine::new(
                    $recur_sc::new(),
                    CombineChips::<$recur_sc>::combine_chips(),
                    RECURSION_NUM_PVS,
                );
                Self {
                    machine,
                    opts,
                    prev_machine: prev_prover.machine().clone(),
                }
            }
        }

        impl MachineProver<$recur_sc> for CombineProver<$recur_sc, $recur_sc> {
            type Witness = MetaProof<$recur_sc>;
            type Chips = CombineChips<$recur_sc>;

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
                        proofs.proofs.len() <= COMBINE_SIZE,
                    );
                let witness = ProvingWitness::setup_for_recursion(
                    vk_root,
                    stdin,
                    last_vk,
                    last_proof,
                    self.machine.config(),
                    self.opts,
                );
                self.machine.prove(&witness)
            }

            fn verify(
                &self,
                proof: &MetaProof<$recur_sc>,
                riscv_vk: &dyn HashableKey<Val<$recur_sc>>,
            ) -> bool {
                self.machine.verify(proof, riscv_vk).is_ok()
            }
        }
    };
}

impl_combine_prover!(BabyBearSimple, BabyBearPoseidon2);
impl_combine_prover!(KoalaBearSimple, KoalaBearPoseidon2);
