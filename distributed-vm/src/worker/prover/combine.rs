use p3_commit::Pcs;
use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use pico_perf::common::print_utils::log_section;
use pico_vm::{
    configs::{
        config::StarkGenericConfig,
        stark_config::{BabyBearPoseidon2, KoalaBearPoseidon2},
    },
    instances::{
        chiptype::recursion_chiptype::RecursionChipType, machine::combine::CombineMachine,
    },
    machine::field::FieldSpecificPoseidon2Config,
    messages::combine::{CombineRequest, CombineResponse},
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

        let meta_a = proofs[0].clone();
        let meta_b = proofs[1].clone();

        let proof = self.machine.prove_two(meta_a, meta_b, flag_complete);

        CombineResponse { chunk_index, proof }
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

        let meta_a = proofs[0].clone();
        let meta_b = proofs[1].clone();

        let proof = self.machine.prove_two(meta_a, meta_b, flag_complete);

        CombineResponse { chunk_index, proof }
    }
}
