use getset::MutGetters;
use mle_core::{
    config::koala_bear_poseidon2::KoalaBearPoseidon2Config, prover::Coordinator, StarkEngine,
    SystemParams,
};

use crate::{
    gpu_backend::GenericGpuBackend,
    hash_scheme::{GpuHashScheme, KoalaBearPoseidon2HashScheme},
    sponge::KoalaBearDuplexSpongeGpu,
    GpuDevice,
};

/// Proving engine that runs on the GPU, with the hash scheme supplied as the type parameter `HS`.
///
/// Use the [`KoalaBearPoseidon2GpuEngine`] type alias for the production engine.
#[derive(MutGetters)]
pub struct GpuEngine<HS: GpuHashScheme> {
    #[getset(get_mut = "pub")]
    device: GpuDevice,
    #[getset(get_mut = "pub")]
    config: HS::SC,
}

impl<HS: GpuHashScheme> GpuEngine<HS> {
    pub fn new(params: SystemParams) -> Self {
        let config = HS::default_config(params.clone());
        Self {
            device: GpuDevice::new(params),
            config,
        }
    }
}

// ─── KoalaBear Poseidon2 GPU engine ──────────────────────────────────────────

/// Concrete GPU engine using the KoalaBear-Poseidon2 hash scheme — the production proving path.
///
/// The whole prover (`TraceCommitter`, `MultiRapProver`, `OpeningProver`) is generic over the hash
/// scheme; KoalaBear reaches its own kernels through
/// `FieldKernelsFor<KoalaBearPoseidon2HashScheme> → KoalaBearKernels` (see `gpu_backend.rs`).
pub type KoalaBearPoseidon2GpuEngine = GpuEngine<KoalaBearPoseidon2HashScheme>;

impl StarkEngine for GpuEngine<KoalaBearPoseidon2HashScheme> {
    type SC = KoalaBearPoseidon2Config;
    type PB = GenericGpuBackend<KoalaBearPoseidon2HashScheme>;
    type PD = GpuDevice;
    type TS = KoalaBearDuplexSpongeGpu;

    fn new(params: SystemParams) -> Self {
        GpuEngine::new(params)
    }

    fn config(&self) -> &Self::SC {
        &self.config
    }

    fn device(&self) -> &Self::PD {
        &self.device
    }

    fn initial_transcript(&self) -> Self::TS {
        KoalaBearDuplexSpongeGpu::default()
    }

    fn prover_from_transcript(
        &self,
        transcript: KoalaBearDuplexSpongeGpu,
    ) -> Coordinator<KoalaBearPoseidon2Config, Self::PB, Self::PD, Self::TS> {
        Coordinator::new(self.device.clone(), transcript)
    }
}
