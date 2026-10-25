use std::marker::PhantomData;

use crate::runtime::memory_manager::MemTracker;
use itertools::Itertools;
use mle_core::{
    poly::Squarable,
    proof::*,
    prover::{
        DeviceMultiStarkProvingKey, MultiRapProver, OpeningProver, ProverBackend, ProverDevice,
        ProvingContext, TraceCommitter,
    },
};
use tracing::instrument;

use crate::{
    base::DeviceMatrix,
    cuda::field_kernels::FieldKernels,
    hash_scheme::GpuHashScheme,
    logup_zerocheck::prove_zerocheck_and_logup_gpu,
    merkle_tree::MerkleTreeConstructor,
    prelude::D_EF,
    sponge::GpuFiatShamirTranscript,
    stacked_pcs::{stacked_commit, StackedPcsDataGpu},
    stacked_reduction::prove_stacked_opening_reduction_gpu,
    whir::prove_whir_opening_gpu,
    AirDataGpu, GpuDevice, ProverError,
};

/// Associates a `GpuHashScheme` with the correct `FieldKernels` implementation
/// for the GPU proving pipeline (stacked reduction + WHIR).
///
/// Concrete impl: `KoalaBearPoseidon2HashScheme` → `KoalaBearKernels`.
pub trait FieldKernelsFor<HS: GpuHashScheme> {
    type FK: FieldKernels<Val = HS::BaseField, ValExt = HS::ExtField>;
}

impl FieldKernelsFor<crate::hash_scheme::KoalaBearPoseidon2HashScheme> for GpuDevice {
    type FK = crate::cuda::field_kernels::KoalaBearKernels;
}

/// The GPU prover backend; `HS` selects the hash scheme and, through it, the field kernels.
#[derive(Clone, Copy)]
pub struct GenericGpuBackend<HS: GpuHashScheme>(PhantomData<HS>);

impl<HS: GpuHashScheme> Default for GenericGpuBackend<HS> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<HS: GpuHashScheme> ProverBackend for GenericGpuBackend<HS> {
    const CHALLENGE_EXT_DEGREE: u8 = D_EF as u8; // 4

    type Val = HS::BaseField;
    type Challenge = HS::ExtField;
    type Commitment = HS::Digest;
    type Matrix = DeviceMatrix<HS::BaseField>;
    type PcsData = StackedPcsDataGpu<HS::BaseField, HS::Digest>;
    // `Arc` so the merged-preprocessed recursion path can serve one process-lifetime instance per
    // constraint system across layouts (`air_data_gpu_cached`). Every reader is a field access
    // through `Deref`, so only the two construction sites change.
    type OtherAirData = std::sync::Arc<AirDataGpu<HS::BaseField>>;
}

/// Eagerly nvrtc-compile every AIR's G1 (interaction-eval) + Z1 (round-0 zerocheck) JIT kernels on
/// the calling thread, before the prover spawns worker/pipeline/rayon threads. This is the fix for
/// the libnvrtc internal-threading deadlock that hit *lazy* compilation from a prove-worker thread
/// mid-proof (`nvrtcCompileProgram` stuck on an internal futex in the heavily-threaded prover).
/// No-op for AIRs without `jit_source` (i.e. when G1_JIT/Z1_JIT are off). Call right after
/// `transport_pk_to_device`. Recursion calls it from its keygen, which runs on several preparer
/// threads at once, so `compile_kernel` serialises nvrtc itself rather than relying on the caller
/// being alone. `num_cosets`
/// (`= max_constraint_degree - 1`) and `l_skip` are AIR-fixed, so the pre-populated OnceLocks match
/// what the lazy path would compute.
pub fn warmup_jit_kernels<HS: GpuHashScheme>(
    pk: &DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,
) {
    let l_skip = pk.params.l_skip as u32;
    for pk_air in &pk.per_air {
        tracing::info!(target: "bench", "[jit-warmup] air={}", pk_air.air_name);
        pk_air.other_data.interaction_rules.warm_jit();
        let deg = pk_air.vk.max_constraint_degree as u32;
        if deg >= 2 {
            pk_air.other_data.zerocheck_round0.warm_jit(deg - 1, l_skip);
        }
    }
}

impl<HS: GpuHashScheme> TraceCommitter<GenericGpuBackend<HS>> for GpuDevice
where
    HS::MerkleHash: MerkleTreeConstructor,
{
    type Error = ProverError;

    fn commit(
        &self,
        traces: &[&DeviceMatrix<HS::BaseField>],
    ) -> Result<(HS::Digest, StackedPcsDataGpu<HS::BaseField, HS::Digest>), Self::Error> {
        let _bt = crate::breakdown::start();
        let out = stacked_commit::<HS::BaseField, HS::MerkleHash>(
            self.config.l_skip,
            self.config.n_stack,
            self.config.log_blowup,
            self.config.k_whir(),
            traces,
            self.prover_config,
        );
        crate::breakdown::stop_commit(_bt);
        out
    }
}

impl<HS: GpuHashScheme, TS: GpuFiatShamirTranscript<HS::SC>> ProverDevice<GenericGpuBackend<HS>, TS>
    for GpuDevice
where
    GpuDevice: FieldKernelsFor<HS>,
    HS::MerkleHash: MerkleTreeConstructor,
{
    type Error = ProverError;
}

impl<HS: GpuHashScheme, TS: GpuFiatShamirTranscript<HS::SC>>
    MultiRapProver<GenericGpuBackend<HS>, TS> for GpuDevice
where
    GpuDevice: FieldKernelsFor<HS>,
{
    type PartialProof = (GkrProof<HS::SC>, BatchConstraintProof<HS::SC>);
    type Artifacts = Vec<HS::ExtField>;
    type Error = ProverError;

    #[allow(clippy::type_complexity)]
    #[instrument(name = "prover.rap_constraints", skip_all, fields(phase = "prover"))]
    fn prove_rap_constraints(
        &self,
        transcript: &mut TS,
        mpk: &DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,
        ctx: &ProvingContext<GenericGpuBackend<HS>>,
    ) -> Result<
        (
            (GkrProof<HS::SC>, BatchConstraintProof<HS::SC>),
            Vec<HS::ExtField>,
        ),
        Self::Error,
    > {
        // Opens this thread's small-upload arena for the phase; every block it takes is
        // freed when `_arena` drops. See `crate::scratch`.
        let _arena = crate::scratch::scope();
        // Opens this thread's small-upload arena for the phase; every block it takes is
        // freed when `_arena` drops. See `crate::scratch`.
        let _arena = crate::scratch::scope();
        let mem = MemTracker::start_and_reset_peak("prover.rap_constraints");
        let _bt = crate::breakdown::start();
        let save_memory = self.prover_config.zerocheck_save_memory;
        let monomial_num_y_threshold = if self.config.log_blowup == 1 { 512 } else { 64 };
        let (gkr_proof, batch_constraint_proof, r) =
            prove_zerocheck_and_logup_gpu::<<GpuDevice as FieldKernelsFor<HS>>::FK, HS, TS>(
                transcript,
                mpk,
                ctx,
                save_memory,
                monomial_num_y_threshold,
                self.sm_count,
            )?;
        crate::breakdown::stop_rap(_bt);
        mem.emit_metrics();
        Ok(((gkr_proof, batch_constraint_proof), r))
    }
}

impl<HS: GpuHashScheme, TS: GpuFiatShamirTranscript<HS::SC>>
    OpeningProver<GenericGpuBackend<HS>, TS> for GpuDevice
where
    GpuDevice: FieldKernelsFor<HS>,
    HS::MerkleHash: MerkleTreeConstructor,
{
    type OpeningProof = (StackingProof<HS::SC>, WhirProof<HS::SC>);
    type OpeningPoints = Vec<HS::ExtField>;
    type Error = ProverError;

    #[instrument(name = "prover.openings", skip_all, fields(phase = "prover"))]
    fn prove_openings(
        &self,
        transcript: &mut TS,
        mpk: &DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,
        ctx: ProvingContext<GenericGpuBackend<HS>>,
        common_main_pcs_data: StackedPcsDataGpu<HS::BaseField, HS::Digest>,
        r: Vec<HS::ExtField>,
    ) -> Result<Self::OpeningProof, Self::Error> {
        let _arena = crate::scratch::scope();
        let _arena = crate::scratch::scope();
        let mut mem = MemTracker::start_and_reset_peak("prover.openings");
        let _bt = crate::breakdown::start();
        let params = self.config();
        // Area/pricing probe (`MLE_AREA_DEBUG=1`, default silent): per-chunk stacked area
        // (width × 2^log_stacked_height) — the actual proof workload commit/WHIR process.
        // Used to split a throughput gap into "more cells/instr (AIR width)" vs "slower kernels".
        if std::env::var("MLE_AREA_DEBUG").is_ok() {
            let w = common_main_pcs_data.layout().width();
            tracing::info!(
                target: "bench",
                "[area-debug] main_stacked_width={} log_h={} area_cells={}",
                w,
                params.log_stacked_height(),
                (w as u64) << params.log_stacked_height()
            );
        }
        // Debug-only guard: the main, preprocessed and cached commits together may not exceed
        // the stacking width budget.
        #[cfg(debug_assertions)]
        {
            let total_stacked_width: usize = std::iter::once(common_main_pcs_data.layout().width())
                .chain(ctx.per_trace.iter().flat_map(|(ai, actx)| {
                    mpk.per_air[*ai]
                        .preprocessed_data
                        .iter()
                        .map(|cd| cd.data.layout().width())
                        .chain(actx.cached_mains.iter().map(|cd| cd.data.layout().width()))
                }))
                .sum();
            debug_assert!(
                total_stacked_width <= mpk.params.w_stack,
                "total stacked width across commits ({total_stacked_width}) exceeds w_stack ({})",
                mpk.params.w_stack
            );
        }
        // [stepprof] synced split of the opening step (stacked reduction vs WHIR open),
        // closing the engine-residual attribution gap. OFF by default.
        let step_prof = std::env::var("STEP_PROF").is_ok();
        let t_red = std::time::Instant::now();
        let (stacking_proof, u_prisma, stacked_per_commit) =
            prove_stacked_opening_reduction_gpu::<<GpuDevice as FieldKernelsFor<HS>>::FK, HS, TS>(
                self,
                transcript,
                mpk,
                ctx,
                common_main_pcs_data,
                &r,
            )?;
        if step_prof {
            let _ = crate::runtime::stream::current_stream_sync();
            tracing::info!(
                target: "bench",
                "[stepprof][{}] stacked_reduction={}us", crate::prove_phase(),
                t_red.elapsed().as_micros()
            );
        }

        let (&u0, u_rest) = u_prisma.split_first().unwrap();
        let u_cube = u0
            .exp_powers_of_2()
            .take(params.l_skip)
            .chain(u_rest.iter().copied())
            .collect_vec();

        let t_whir = std::time::Instant::now();
        let whir_proof = prove_whir_opening_gpu::<<GpuDevice as FieldKernelsFor<HS>>::FK, HS, TS>(
            params,
            transcript,
            stacked_per_commit,
            &u_cube,
        )?;
        if step_prof {
            let _ = crate::runtime::stream::current_stream_sync();
            tracing::info!(
                target: "bench",
                "[stepprof][{}] whir_open={}us", crate::prove_phase(),
                t_whir.elapsed().as_micros()
            );
        }
        crate::breakdown::stop_openings(_bt);
        mem.emit_metrics();
        mem.reset_peak();
        Ok((stacking_proof, whir_proof))
    }
}

// All KB impls (MultiRapProver, OpeningProver, ProverDevice) are handled by the generic
// impls using FieldKernelsFor<KoalaBearPoseidon2HashScheme> → KoalaBearKernels
