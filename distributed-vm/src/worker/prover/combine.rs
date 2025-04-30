use crate::{
    gateway::handler::proof_tree::IndexedProof,
    messages::combine::{CombineRequest, CombineResponse},
};
use anyhow::Result;
use p3_baby_bear::BabyBear;
use p3_commit::Pcs;
use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use p3_koala_bear::KoalaBear;
use pico_perf::common::print_utils::log_section;
use pico_vm::{
    configs::{
        config::StarkGenericConfig,
        stark_config::{BabyBearPoseidon2, KoalaBearPoseidon2},
    },
    instances::{
        chiptype::recursion_chiptype::RecursionChipType, machine::combine::CombineMachine,
    },
    machine::{
        field::FieldSpecificPoseidon2Config, keys::HashableKey, machine::MachineBehavior,
        proof::MetaProof,
    },
    primitives::consts::{COMBINE_SIZE, EXTENSION_DEGREE, RECURSION_NUM_PVS},
};
use tracing::info;

pub struct CombineProver<SC>
where
    SC: StarkGenericConfig,
    SC::Val: PrimeField32 + FieldSpecificPoseidon2Config + BinomiallyExtendable<EXTENSION_DEGREE>,
{
    prover_id: String,
    machine: CombineMachine<SC, RecursionChipType<SC::Val>>,
}

impl<SC> CombineProver<SC>
where
    SC: Default + StarkGenericConfig,
    SC::Val: PrimeField32 + FieldSpecificPoseidon2Config + BinomiallyExtendable<EXTENSION_DEGREE>,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::ProverData: Send,
{
    pub fn new(prover_id: String) -> Self {
        let machine = CombineMachine::<_, _>::new(
            SC::default(),
            RecursionChipType::<SC::Val>::all_chips(),
            RECURSION_NUM_PVS,
        );

        Self { prover_id, machine }
    }
}

/// specialization for running prover on either babybear or koalabear
pub trait CombineHandler<SC: StarkGenericConfig> {
    fn process(&self, req: CombineRequest<SC>) -> CombineResponse<SC>;
    fn verify(&self, proof: &MetaProof<SC>, riscv_vk: &dyn HashableKey<SC::Val>) -> Result<()>;
}

impl<SC> CombineHandler<SC> for CombineProver<SC>
where
    SC: StarkGenericConfig,
    SC::Val: PrimeField32 + FieldSpecificPoseidon2Config + BinomiallyExtendable<EXTENSION_DEGREE>,
{
    /// default implementation
    default fn process(&self, _req: CombineRequest<SC>) -> CombineResponse<SC> {
        panic!("unsupported");
    }
    default fn verify(
        &self,
        _proof: &MetaProof<SC>,
        _riscv_vk: &dyn HashableKey<SC::Val>,
    ) -> Result<()> {
        panic!("unsupported");
    }
}

impl CombineHandler<BabyBearPoseidon2> for CombineProver<BabyBearPoseidon2> {
    fn process(
        &self,
        req: CombineRequest<BabyBearPoseidon2>,
    ) -> CombineResponse<BabyBearPoseidon2> {
        log_section("COMBINE PHASE");

        let CombineRequest {
            chunk_index,
            flag_complete,
            proofs,
        } = req;
        assert!(proofs.len() <= COMBINE_SIZE);

        info!(
            "[{}] receive combine request: chunk_index = {}",
            self.prover_id, chunk_index,
        );

        let start_a = proofs[0].start_chunk;
        let end_a = proofs[0].end_chunk;

        let start_b = proofs[1].start_chunk;
        let end_b = proofs[1].end_chunk;

        assert_eq!(
            end_a + 1,
            start_b,
            "proofs are not adjacent: cannot combine"
        );

        let meta_a = proofs[0].get_inner().clone();
        let meta_b = proofs[1].get_inner().clone();

        let proof = self.machine.prove_two(meta_a, meta_b, flag_complete);
        let proof = IndexedProof::new(proof, start_a, end_b);

        info!(
            "[{}] finish combine proving chunk-{chunk_index}",
            self.prover_id,
        );

        CombineResponse { chunk_index, proof }
    }

    default fn verify(
        &self,
        proof: &MetaProof<BabyBearPoseidon2>,
        riscv_vk: &dyn HashableKey<BabyBear>,
    ) -> Result<()> {
        self.machine.verify(proof, riscv_vk)
    }
}

impl CombineHandler<KoalaBearPoseidon2> for CombineProver<KoalaBearPoseidon2> {
    fn process(
        &self,
        req: CombineRequest<KoalaBearPoseidon2>,
    ) -> CombineResponse<KoalaBearPoseidon2> {
        log_section("COMBINE PHASE");

        let CombineRequest {
            chunk_index,
            flag_complete,
            proofs,
        } = req;
        assert!(proofs.len() <= COMBINE_SIZE);

        info!(
            "[{}] receive combine request: chunk_index = {}",
            self.prover_id, chunk_index,
        );

        let start_a = proofs[0].start_chunk;
        let end_a = proofs[0].end_chunk;

        let start_b = proofs[1].start_chunk;
        let end_b = proofs[1].end_chunk;

        assert_eq!(
            end_a + 1,
            start_b,
            "proofs are not adjacent: cannot combine"
        );

        let meta_a = proofs[0].get_inner().clone();
        let meta_b = proofs[1].get_inner().clone();

        let proof = self.machine.prove_two(meta_a, meta_b, flag_complete);
        let proof = IndexedProof::new(proof, start_a, end_b);

        CombineResponse { chunk_index, proof }
    }

    default fn verify(
        &self,
        proof: &MetaProof<KoalaBearPoseidon2>,
        riscv_vk: &dyn HashableKey<KoalaBear>,
    ) -> Result<()> {
        self.machine.verify(proof, riscv_vk)
    }
}
