use crate::{
    configs::{
        config::{StarkGenericConfig, Val},
        field_config::{BabyBearSimple, KoalaBearSimple},
        stark_config::{BabyBearPoseidon2, KoalaBearPoseidon2},
    },
    emulator::{
        opts::EmulatorOpts,
        stdin::{EmulatorStdin, PicoProofPair},
    },
    instances::{
        chiptype::recursion_chiptype::RecursionChipType,
        compiler::{
            shapes::recursion_shape::RecursionShapeConfig,
            vk_merkle::{vk_verification_enabled, HasStaticVkManager},
        },
        machine::deferred::DeferredMachine,
    },
    machine::{
        field::FieldSpecificPoseidon2Config, keys::BaseVerifyingKey, machine::MachineBehavior,
        proof::MetaProof, witness::ProvingWitness,
    },
    primitives::consts::{DIGEST_SIZE, EXTENSION_DEGREE, RECURSION_NUM_PVS},
};
use p3_baby_bear::BabyBear;
use p3_field::{extension::BinomiallyExtendable, FieldAlgebra, PrimeField32};
use p3_koala_bear::KoalaBear;

pub type DeferredChips<SC> = RecursionChipType<Val<SC>>;

pub struct DeferredProver<SC>
where
    SC: StarkGenericConfig + 'static,
    Val<SC>: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + FieldSpecificPoseidon2Config,
{
    machine: DeferredMachine<SC, DeferredChips<SC>>,
    opts: EmulatorOpts,
    shape_config: Option<RecursionShapeConfig<Val<SC>, DeferredChips<SC>>>,
}

impl DeferredProver<KoalaBearPoseidon2> {
    pub fn new(
        opts: EmulatorOpts,
        shape_config: Option<RecursionShapeConfig<KoalaBear, DeferredChips<KoalaBearPoseidon2>>>,
    ) -> Self {
        let chips = RecursionChipType::combine_chips();
        let deferred = DeferredMachine::new(KoalaBearPoseidon2::new(), chips, RECURSION_NUM_PVS);
        Self {
            machine: deferred,
            opts,
            shape_config,
        }
    }
    pub fn prove_with_deferred(
        &self,
        riscv_vk: &BaseVerifyingKey<KoalaBearPoseidon2>,
        deferred_proofs: Vec<PicoProofPair<KoalaBearPoseidon2>>,
    ) -> (MetaProof<KoalaBearPoseidon2>, [KoalaBear; DIGEST_SIZE]) {
        let vk_root = if self.shape_config.is_some() && vk_verification_enabled() {
            let vk_manager = <KoalaBearPoseidon2 as HasStaticVkManager>::static_vk_manager();
            vk_manager.merkle_root
        } else {
            [KoalaBear::ZERO; DIGEST_SIZE]
        };

        let (meta_vec, vk_vec): (
            Vec<MetaProof<KoalaBearPoseidon2>>,
            Vec<BaseVerifyingKey<KoalaBearPoseidon2>>,
        ) = deferred_proofs.into_iter().unzip();

        let machine = self.machine.base_machine().clone();

        let (stdin, final_deferred_digest) =
            EmulatorStdin::setup_for_deferred::<KoalaBear, KoalaBearSimple>(
                riscv_vk,
                vk_root,
                &machine,
                &self.shape_config,
                &meta_vec,
                &vk_vec,
            );
        let witness = ProvingWitness::setup_for_deferred(stdin, self.machine.config(), self.opts);
        (
            self.machine.prove_with_deferred(&witness),
            final_deferred_digest,
        )
    }
}

impl DeferredProver<BabyBearPoseidon2> {
    pub fn new(
        opts: EmulatorOpts,
        shape_config: Option<RecursionShapeConfig<BabyBear, DeferredChips<BabyBearPoseidon2>>>,
    ) -> Self {
        let chips = RecursionChipType::combine_chips();
        let deferred = DeferredMachine::new(BabyBearPoseidon2::new(), chips, RECURSION_NUM_PVS);
        Self {
            machine: deferred,
            opts,
            shape_config,
        }
    }
    pub fn prove_with_deferred(
        &self,
        riscv_vk: &BaseVerifyingKey<BabyBearPoseidon2>,
        deferred_proofs: Vec<PicoProofPair<BabyBearPoseidon2>>,
    ) -> (MetaProof<BabyBearPoseidon2>, [BabyBear; DIGEST_SIZE]) {
        let vk_root = if self.shape_config.is_some() && vk_verification_enabled() {
            let vk_manager = <BabyBearPoseidon2 as HasStaticVkManager>::static_vk_manager();
            vk_manager.merkle_root
        } else {
            [BabyBear::ZERO; DIGEST_SIZE]
        };

        let (meta_vec, vk_vec): (
            Vec<MetaProof<BabyBearPoseidon2>>,
            Vec<BaseVerifyingKey<BabyBearPoseidon2>>,
        ) = deferred_proofs.into_iter().unzip();

        let machine = self.machine.base_machine().clone();

        let (stdin, final_deferred_digest) =
            EmulatorStdin::setup_for_deferred::<BabyBear, BabyBearSimple>(
                riscv_vk,
                vk_root,
                &machine,
                &self.shape_config,
                &meta_vec,
                &vk_vec,
            );
        let witness = ProvingWitness::setup_for_deferred(stdin, self.machine.config(), self.opts);
        (
            self.machine.prove_with_deferred(&witness),
            final_deferred_digest,
        )
    }
}
