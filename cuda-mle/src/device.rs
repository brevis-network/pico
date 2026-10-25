use crate::runtime::context::get_device;
use getset::{CopyGetters, Getters, MutGetters};
use mle_core::SystemParams;

use crate::cuda::{
    batch_ntt_small::{ensure_device_ntt_twiddles_initialized, validate_gpu_l_skip},
    device_info::get_sm_count,
};

/// One CUDA device as seen by the prover: protocol parameters plus GPU-specific knobs.
#[derive(Clone, Getters, CopyGetters, MutGetters)]
pub struct GpuDevice {
    /// Protocol parameters the device proves with.
    #[getset(get = "pub")]
    pub(crate) config: SystemParams,
    /// Memory/speed trade-offs, adjustable after construction.
    #[getset(get = "pub", get_mut = "pub")]
    pub(crate) prover_config: GpuProverConfig,
    /// CUDA ordinal of the device that was current at construction.
    pub id: u32,
    /// Streaming-multiprocessor count, used for launch sizing.
    #[getset(get_copy = "pub")]
    pub sm_count: u32,
}

/// What the prover keeps resident on the GPU versus recomputes.
#[derive(Clone, Copy)]
pub struct GpuProverConfig {
    /// Keep the stacked trace matrix after commit instead of re-stacking it later.
    pub cache_stacked_matrix: bool,
    /// Keep the RS codeword matrix in the Merkle tree instead of re-deriving it for openings.
    pub cache_rs_code_matrix: bool,
    /// Run the zerocheck/logup prover in its memory-saving mode.
    pub zerocheck_save_memory: bool,
}

impl GpuDevice {
    pub fn new(config: SystemParams) -> Self {
        validate_gpu_l_skip(config.l_skip)
            .expect("GPU backend requires l_skip <= 10 for current CUDA kernels");
        ensure_device_ntt_twiddles_initialized()
            .expect("failed to initialize small-NTT twiddles for current CUDA device");

        let prover_config = GpuProverConfig {
            zerocheck_save_memory: config.log_blowup == 1,
            ..Default::default()
        };
        let id = get_device().unwrap() as u32;
        let sm_count = get_sm_count(id).expect("failed to get SM count");
        Self {
            config,
            prover_config,
            id,
            sm_count,
        }
    }

    pub fn with_cache_rs_code_matrix(mut self, cache_rs_code_matrix: bool) -> Self {
        self.prover_config.cache_rs_code_matrix = cache_rs_code_matrix;
        self
    }

    pub fn set_cache_rs_code_matrix(&mut self, cache_rs_code_matrix: bool) {
        self.prover_config.cache_rs_code_matrix = cache_rs_code_matrix;
    }

    /// Cache the stacked matrix on device (default: off).
    ///
    /// Trades peak GPU memory for avoiding a re-stack during the WHIR-open recompute: with it set,
    /// `stacked_commit` keeps `StackedPcsDataGpu::matrix` and `rs_code_matrix` expands from it
    /// instead of re-stacking the traces. Off by default because the recompute is cheap relative to
    /// holding a second full-size matrix. Exposed for symmetry with
    /// [`Self::set_cache_rs_code_matrix`] — the knob was previously reachable only by writing
    /// through the `prover_config_mut()` getset escape hatch.
    pub fn with_cache_stacked_matrix(mut self, cache_stacked_matrix: bool) -> Self {
        self.prover_config.cache_stacked_matrix = cache_stacked_matrix;
        self
    }

    /// See [`Self::with_cache_stacked_matrix`].
    pub fn set_cache_stacked_matrix(&mut self, cache_stacked_matrix: bool) {
        self.prover_config.cache_stacked_matrix = cache_stacked_matrix;
    }
}

/// Default configuration is to reduce peak memory usage when there is not a significant performance
/// trade-off. The Reed-Solomon code computation does incur a performance penalty, so we cache it.
impl Default for GpuProverConfig {
    fn default() -> Self {
        Self {
            cache_stacked_matrix: false,
            cache_rs_code_matrix: true,
            zerocheck_save_memory: true,
        }
    }
}
