use std::{array::from_fn, cmp::max, ffi::c_void, iter::zip, marker::PhantomData, mem, sync::Arc};

use crate::runtime::{
    copy::{cuda_memcpy, MemCopyD2H, MemCopyH2D},
    d_buffer::DeviceBuffer,
    memory_manager::MemTracker,
};
use itertools::{zip_eq, Itertools};
use mle_core::{
    poly::{
        eq_uni_poly, eval_eq_mle, eval_eq_uni, eval_eq_uni_at_one, eval_in_uni,
        matrix::MatrixDimensions, Squarable, UnivariatePoly,
    },
    proof::StackingProof,
    protocol::stacking::StackedLayout,
    prover::{sumcheck::sumcheck_round0_deg, DeviceMultiStarkProvingKey, ProvingContext},
};
use p3_field::{
    BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField32, TwoAdicField,
};
use tracing::{debug, info_span, instrument};

use crate::{
    base::DeviceMatrix,
    cuda::{
        batch_ntt_small::ensure_device_ntt_twiddles_initialized, field_kernels::FieldKernels,
        stacked_reduction_kb::NUM_G,
    },
    gpu_backend::GenericGpuBackend,
    hash_scheme::GpuHashScheme,
    poly::EqEvalSegments,
    sponge::GpuFiatShamirTranscript,
    stacked_pcs::StackedPcsDataGpu,
    utils::compute_barycentric_inv_lagrange_denoms,
    GpuDevice, StackedReductionError,
};

/// Degree of each per-round sumcheck polynomial in the stacked opening reduction.
pub const STACKED_REDUCTION_S_DEG: usize = 2;

pub struct StackedReductionGpu<FK: FieldKernels, D> {
    sm_count: u32,

    l_skip: usize,
    n_stack: usize,

    omega_skip: FK::Val,
    skip_domain_powers: Vec<FK::Val>,
    d_skip_domain_powers: DeviceBuffer<FK::Val>,

    r_univariate: FK::ValExt,
    d_lambda_powers: DeviceBuffer<FK::ValExt>,
    eq_const: FK::ValExt,

    pub(crate) stacked_per_commit: Vec<StackedPcsData2<FK::Val, D>>,
    d_stacked_widths: DeviceBuffer<u32>,
    max_stacked_width: u32,
    d_stacked_eval_ptrs: DeviceBuffer<*const FK::ValExt>,

    /// Round-0 view of every trace: (device pointer, row count, column count).
    trace_views: Vec<(*const FK::Val, usize, usize)>,
    unstacked_cols: Vec<UnstackedSlice>,
    d_unstacked_cols: DeviceBuffer<UnstackedSlice>,
    // Column-index boundaries, one per trace plus a closing sentinel. Every column between two
    // consecutive boundaries has the same height; a run of equal heights may still be split into
    // several pieces when that keeps peak device memory down.
    trace_col_bounds: Vec<usize>,
    /// Coarser boundaries for the multilinear rounds: `trace_col_bounds` with neighbouring
    /// windows of equal `log_height` fused together.
    ///
    /// Round 0 walks `trace_views` in lockstep with `trace_col_bounds`, so that list must keep one
    /// boundary per trace. The two multilinear-round kernels only need every column of a window to
    /// have the same `log_height`: `batch_sumcheck_poly_eval` takes the hypercube size, the
    /// `settled_eq[log_height]` lookup and the degenerate/non-degenerate choice from the window's
    /// first column, and both kernels address `unstacked_cols`, `lambda_powers` and `eq_ub`
    /// relative to the window's first column. Inside a commit traces already come in descending
    /// height order, so equal heights sit next to each other and fusing costs nothing. Measured
    /// effect: 33.8 -> 16.8 windows per round, i.e. 45 839 of 90 867
    /// `stacked_reduction_sumcheck_mle_round*` launches per run disappear.
    mle_col_bounds: Vec<usize>,
    max_hypercube_dim: usize,

    // Starts as eq(r[1..=n], H_n) for every n in 0..=max_hypercube_dim; each sumcheck round then
    // folds it in place with a dedicated (triangular) fold.
    eq_segments: EqEvalSegments<FK::ValExt>,

    // -- populated once round 0 has run --
    // One folded matrix per commitment; its width is taken from `stacked_per_commit`.
    stacked_evals: Vec<DeviceBuffer<FK::ValExt>>,
    // eq values that are fully folded and will not change again. Right before round `round`
    // they cover log_height in 0..l_skip+round-1; each round appends one more entry.
    settled_eq: Vec<FK::ValExt>,
    settled_k_rot: Vec<FK::ValExt>,

    /// Folded evaluations of `\kappa_\rot(x, r) = eq_n(rot^{-1}(x), r)` for every `n`, refreshed
    /// after each round. Wrapped in [EqEvalSegments] so the segmented layout is enforced by type.
    k_rot_segments: EqEvalSegments<FK::ValExt>,
    /// Per column: eq(u[1+n_T..round-1], b_{T,j}[..round-n_T-1]).
    eq_ub_per_col: Vec<FK::ValExt>,
    d_eq_ub: DeviceBuffer<FK::ValExt>,

    d_block_sums: DeviceBuffer<FK::ValExt>,
    d_window_accums: DeviceBuffer<u64>,
    d_input_ptrs: DeviceBuffer<*const FK::ValExt>,
    d_output_ptrs: DeviceBuffer<*mut FK::ValExt>,

    mem: MemTracker,

    _field: PhantomData<FK>,
}

/// Commitment data paired with the traces it was built from. Only the Merkle tree inside
/// `StackedPcsDataGpu` is actually needed, but holding it behind an `Arc` lets the common main
/// commitment and the preprocessed / cached ones be handled the same way. `traces` keeps the
/// matrices before stacking, in prismalinear evaluation form.
///
/// `Val` is the base field and `D` the Merkle digest; the active `FieldKernels` /
/// `GpuHashScheme` choose both, there is no default tied to a particular field.
pub struct StackedPcsData2<Val, D> {
    pub(crate) inner: Arc<StackedPcsDataGpu<Val, D>>,
    /// Matrices, before stacking, that `inner` commits to.
    pub(crate) traces: Vec<DeviceMatrix<Val>>,
}

impl<Val, D> StackedPcsData2<Val, D> {
    pub fn layout(&self) -> &StackedLayout {
        &self.inner.layout
    }

    /// # Safety
    /// The caller guarantees that `commit_data` is the commitment to exactly `traces`.
    pub unsafe fn from_raw(
        commit_data: Arc<StackedPcsDataGpu<Val, D>>,
        traces: Vec<DeviceMatrix<Val>>,
    ) -> Self {
        Self {
            inner: commit_data,
            traces,
        }
    }
}

/// Locates one unstacked column inside the stacked matrix of commitment `commit_idx`, i.e. the
/// range `q[commit_idx].column(stacked_col_idx)[stacked_row_idx..stacked_row_idx + len]`.
/// Because columns shorter than the skip domain are padded up to it, `len` is
/// `max(2^log_height, 2^l_skip)` rather than just `2^log_height`.
///
/// # Safety
/// - Passed to CUDA kernels by pointer, hence the `repr(C)` layout.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct UnstackedSlice {
    commit_idx: u32,
    log_height: u32,
    stacked_row_idx: u32,
    stacked_col_idx: u32,
}

impl<FK: FieldKernels, D> StackedReductionGpu<FK, D> {
    /// Largest `n` that `eq_segments` still covers at the start of `round`.
    fn max_n_at_round(&self, round: usize) -> usize {
        self.max_hypercube_dim - (round - 1)
    }

    fn log_height_at_round(&self, round: usize) -> usize {
        self.n_stack - (round - 1)
    }

    fn height_at_round(&self, round: usize) -> usize {
        1 << self.log_height_at_round(round)
    }
}

/// Reduces all trace openings (rotated ones included) to a single opening of the stacked
/// matrices with one batched sumcheck.
///
/// Each stacked matrix and its layout must come from stacking `traces` with the configured
/// `l_skip` and `n_stack`.
#[allow(clippy::type_complexity)]
#[instrument(
    name = "prover.openings.stacked_reduction",
    level = "info",
    skip_all,
    fields(phase = "prover")
)]
pub fn prove_stacked_opening_reduction_gpu<FK, HS, TS>(
    device: &GpuDevice,
    transcript: &mut TS,
    mpk: &DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,
    ctx: ProvingContext<GenericGpuBackend<HS>>,
    common_main_pcs_data: StackedPcsDataGpu<FK::Val, HS::Digest>,
    r: &[FK::ValExt],
) -> Result<
    (
        StackingProof<HS::SC>,
        Vec<FK::ValExt>,
        Vec<StackedPcsData2<FK::Val, HS::Digest>>,
    ),
    StackedReductionError,
>
where
    FK: FieldKernels,
    HS: GpuHashScheme<BaseField = FK::Val, ExtField = FK::ValExt>,
    TS: GpuFiatShamirTranscript<HS::SC>,
    HS::Digest: Copy + Clone + Send + Sync + 'static,
    FK::ValExt: ExtensionField<FK::Val> + TwoAdicField,
{
    let n_stack = device.config.n_stack;
    // Random coefficient that batches all the opening claims together.
    let lambda = transcript.sample_ext();

    // [reduxprof] synced sub-step attribution of the 33 ms reduction (traffic floor
    // ~10 ms). OFF by default; REDUX_PROF=1 to enable.
    let redux_prof = std::env::var("REDUX_PROF").is_ok();
    let rsync = || {
        let _ = crate::runtime::stream::current_stream_sync();
    };

    let _round0_span =
        info_span!("prover.openings.stacked_reduction.round0", phase = "prover").entered();
    let t_new = std::time::Instant::now();
    let mut prover = StackedReductionGpu::<FK, _>::new::<HS>(
        mpk,
        ctx,
        common_main_pcs_data,
        r,
        lambda,
        device.sm_count(),
    )?;
    if redux_prof {
        rsync();
        tracing::info!(target: "bench", "[reduxprof] new={}us", t_new.elapsed().as_micros());
    }

    // Round 0 is the univariate (skip-domain) round.
    let t_r0 = std::time::Instant::now();
    let round0_poly = prover.batch_sumcheck_uni_round0_poly()?;
    if redux_prof {
        rsync();
        tracing::info!(target: "bench", "[reduxprof] r0_poly={}us", t_r0.elapsed().as_micros());
    }
    for &coeff in round0_poly.coeffs() {
        transcript.observe_ext(coeff);
    }

    let mut u_vec = Vec::with_capacity(n_stack + 1);
    let u_0 = transcript.sample_ext();
    u_vec.push(u_0);
    debug!(round = 0, u_round = %u_0);

    let t_r0f = std::time::Instant::now();
    prover.fold_ple_evals(u_0)?;
    if redux_prof {
        rsync();
        tracing::info!(target: "bench", "[reduxprof] r0_fold={}us", t_r0f.elapsed().as_micros());
    }
    drop(_round0_span);
    // Round 0 finished.

    let mut sumcheck_round_polys = Vec::with_capacity(n_stack);

    // Rounds 1..=n_stack are ordinary multilinear sumcheck rounds.
    let _mle_rounds_span = info_span!(
        "prover.openings.stacked_reduction.mle_rounds",
        phase = "prover"
    )
    .entered();
    let mut us_eval = 0u128;
    let mut us_fold = 0u128;
    let mut redux_rows: Vec<(usize, u128, u128)> = Vec::new();
    #[allow(clippy::needless_range_loop)]
    for round in 1..=n_stack {
        let t_ev = std::time::Instant::now();
        let batch_s_evals = prover.batch_sumcheck_poly_eval(round, u_vec[round - 1])?;
        let mut ev = 0u128;
        if redux_prof {
            rsync();
            ev = t_ev.elapsed().as_micros();
            us_eval += ev;
        }

        for &eval in &batch_s_evals {
            transcript.observe_ext(eval);
        }
        sumcheck_round_polys.push(batch_s_evals);

        let u_round = transcript.sample_ext();
        u_vec.push(u_round);
        debug!(%round, %u_round);

        let t_fo = std::time::Instant::now();
        prover.fold_mle_evals(round, u_round)?;
        if redux_prof {
            rsync();
            us_fold += t_fo.elapsed().as_micros();
            redux_rows.push((round, ev, t_fo.elapsed().as_micros()));
        }
    }
    if redux_prof {
        for (round, ev, fo) in &redux_rows {
            tracing::info!(target: "bench", "[reduxprof] round={round} eval={ev}us fold={fo}us");
        }
        tracing::info!(
            target: "bench",
            "[reduxprof] TOTAL eval={us_eval}us fold={us_fold}us rounds={n_stack}"
        );
    }
    let t_op = std::time::Instant::now();
    let stacking_openings = prover.get_stacked_openings()?;
    if redux_prof {
        rsync();
        tracing::info!(target: "bench", "[reduxprof] openings={}us", t_op.elapsed().as_micros());
    }
    for commit_openings in &stacking_openings {
        for &opening in commit_openings {
            transcript.observe_ext(opening);
        }
    }
    drop(_mle_rounds_span);
    let proof = StackingProof {
        univariate_round_coeffs: round0_poly.into_coeffs(),
        sumcheck_round_polys,
        stacking_openings,
    };
    Ok((proof, u_vec, prover.stacked_per_commit))
}

impl<FK: FieldKernels, D: Copy + Clone + Send + Sync + 'static> StackedReductionGpu<FK, D> {
    #[instrument("stacked_reduction_new", level = "debug", skip_all)]
    fn new<HS: GpuHashScheme<BaseField = FK::Val, ExtField = FK::ValExt, Digest = D>>(
        mpk: &DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,
        ctx: ProvingContext<GenericGpuBackend<HS>>,
        common_main_pcs_data: StackedPcsDataGpu<FK::Val, D>,
        r: &[FK::ValExt],
        lambda: FK::ValExt,
        sm_count: u32,
    ) -> Result<Self, StackedReductionError> {
        ensure_device_ntt_twiddles_initialized().map_err(StackedReductionError::InitNttTwiddles)?;
        let mem = MemTracker::start("prover.stacked_reduction_new");
        let l_skip = mpk.params.l_skip;
        let n_stack = mpk.params.n_stack;

        let omega_skip = FK::Val::two_adic_generator(l_skip);
        let skip_domain_powers = omega_skip.powers().take(1 << l_skip).collect_vec();
        let d_skip_domain_powers = skip_domain_powers.to_device()?;

        // Cloning a DeviceMatrix only bumps an Arc, so this is cheap at the moment.
        // PERF: every trace is stacked up front. Peak memory could be lowered by stacking and
        // releasing traces one at a time, or by keeping only the stacked matrix from commit time
        // on and freeing the traces much sooner.
        let common_main_traces = ctx
            .per_trace
            .iter()
            .map(|(_, air_ctx)| air_ctx.common_main.clone())
            .collect_vec();
        // SAFETY: common_main_pcs_data is the commitment to common_main_traces.
        let common_main_stacked = unsafe {
            StackedPcsData2::from_raw(Arc::new(common_main_pcs_data), common_main_traces)
        };
        let mut stacked_per_commit = vec![common_main_stacked];
        let merged_prep = mpk.merged_preprocessed.is_some();
        // In merged mode, ONE commitment holds every AIR's preprocessed matrix; both the trace
        // list and the need_rot vector below must follow the merged layout's matrix order
        // (descending hypercube_dim, ties by AIR index) — the order keygen committed in.
        let merged_mat_indices = merged_prep.then(|| {
            mle_core::keygen::types::merged_preprocessed_mat_indices(
                mpk.per_air
                    .iter()
                    .map(|pk| pk.vk.preprocessed_data.as_ref().map(|pd| pd.hypercube_dim)),
            )
        });
        if let (Some((_, merged_data)), Some(mat_indices)) =
            (&mpk.merged_preprocessed, &merged_mat_indices)
        {
            let num_mats = mat_indices.iter().flatten().count();
            let mut traces = vec![None; num_mats];
            for (air_idx, pk_air) in mpk.per_air.iter().enumerate() {
                if let (Some(mat_idx), Some(cd)) = (mat_indices[air_idx], &pk_air.preprocessed_data)
                {
                    traces[mat_idx] = Some(cd.trace.clone());
                }
            }
            let traces = traces
                .into_iter()
                .map(|t| t.expect("merged preprocessed matrix missing a device trace"))
                .collect_vec();
            // SAFETY: the traces are the matrices the merged commitment was built from.
            let commit_data = unsafe { StackedPcsData2::from_raw(merged_data.clone(), traces) };
            stacked_per_commit.push(commit_data);
        }
        for (air_idx, air_ctx) in ctx.per_trace.iter() {
            let per_air_prep = (!merged_prep)
                .then_some(&mpk.per_air[*air_idx].preprocessed_data)
                .and_then(|d| d.as_ref());
            for committed in per_air_prep.into_iter().chain(air_ctx.cached_mains.iter()) {
                // SAFETY: committed.data is the commitment to committed.trace.
                let commit_data = unsafe {
                    StackedPcsData2::from_raw(committed.data.clone(), vec![committed.trace.clone()])
                };
                stacked_per_commit.push(commit_data);
            }
        }

        debug_assert!(stacked_per_commit
            .iter()
            .all(|d| d.layout().height() == 1 << (l_skip + n_stack)));

        let need_rot_per_trace = ctx
            .per_trace
            .iter()
            .map(|(air_idx, _)| mpk.per_air[*air_idx].vk.params.need_rot)
            .collect_vec();
        let mut need_rot_per_commit = vec![need_rot_per_trace];
        if let Some(mat_indices) = &merged_mat_indices {
            // One need_rot per merged matrix, in the merged layout's matrix order (aligned with
            // the trace list built above).
            let num_mats = mat_indices.iter().flatten().count();
            let mut need_rot = vec![false; num_mats];
            for (air_idx, pk_air) in mpk.per_air.iter().enumerate() {
                if let Some(mat_idx) = mat_indices[air_idx] {
                    need_rot[mat_idx] = pk_air.vk.params.need_rot;
                }
            }
            need_rot_per_commit.push(need_rot);
        }
        for (air_idx, air_ctx) in ctx.per_trace.iter() {
            let need_rot = mpk.per_air[*air_idx].vk.params.need_rot;
            if !merged_prep && mpk.per_air[*air_idx].preprocessed_data.is_some() {
                need_rot_per_commit.push(vec![need_rot]);
            }
            for _ in &air_ctx.cached_mains {
                need_rot_per_commit.push(vec![need_rot]);
            }
        }
        let stacked_widths = stacked_per_commit
            .iter()
            .map(|d| d.layout().width() as u32)
            .collect_vec();
        let max_stacked_width = *stacked_widths.iter().max().unwrap();
        let d_stacked_widths = stacked_widths.to_device()?;

        let num_unstacked_cols: usize = stacked_per_commit
            .iter()
            .map(|d| d.layout().sorted_cols.len())
            .sum();
        let mut unstacked_cols = Vec::with_capacity(num_unstacked_cols);
        let mut need_rot_per_col = Vec::with_capacity(num_unstacked_cols);
        let mut trace_col_bounds = Vec::new();
        let mut trace_views: Vec<(*const FK::Val, usize, usize)> = Vec::new();
        for (commit_idx, commit_data) in stacked_per_commit.iter().enumerate() {
            let layout = commit_data.layout();
            let commit_need_rot = &need_rot_per_commit[commit_idx];
            debug_assert_eq!(commit_need_rot.len(), layout.mat_starts.len());
            for (mat_idx, (trace, &col_start)) in
                zip_eq(&commit_data.traces, &layout.mat_starts).enumerate()
            {
                debug_assert_ne!(trace.width(), 0);
                debug_assert_ne!(trace.height(), 0);
                trace_col_bounds.push(unstacked_cols.len());
                trace_views.push((trace.buffer().as_ptr(), trace.height(), trace.width()));
                let need_rot = commit_need_rot[mat_idx];
                for j in 0..trace.width() {
                    let sorted_col = layout.sorted_cols[col_start + j];
                    let (_src_col, col_slice) = (sorted_col.src_col_idx, sorted_col.slice);
                    debug_assert_eq!(_src_col, j);
                    debug_assert_eq!(1 << col_slice.log_height(), trace.height());
                    unstacked_cols.push(UnstackedSlice {
                        commit_idx: commit_idx as u32,
                        log_height: col_slice.log_height() as u32,
                        stacked_row_idx: col_slice.row_idx as u32,
                        stacked_col_idx: col_slice.col_idx as u32,
                    });
                    need_rot_per_col.push(need_rot);
                }
            }
        }
        debug_assert_eq!(unstacked_cols.len(), num_unstacked_cols);
        trace_col_bounds.push(unstacked_cols.len());

        // See `mle_col_bounds`. A boundary is dropped only when it does not start a new height;
        // the closing sentinel is always kept (it is not a column index).
        let mut mle_col_bounds: Vec<usize> = Vec::with_capacity(trace_col_bounds.len());
        for &boundary in &trace_col_bounds {
            let same_height_as_prev = mle_col_bounds.last().is_some_and(|&prev| {
                boundary < unstacked_cols.len()
                    && unstacked_cols[prev].log_height == unstacked_cols[boundary].log_height
            });
            if !same_height_as_prev {
                mle_col_bounds.push(boundary);
            }
        }

        let all_lambda_powers = lambda.powers().take(num_unstacked_cols * 2).collect_vec();
        let mut lambda_powers = vec![FK::ValExt::ZERO; num_unstacked_cols * 2];
        for (col_idx, need_rot) in need_rot_per_col.into_iter().enumerate() {
            let eq_power_idx = 2 * col_idx;
            let rot_power_idx = 2 * col_idx + 1;
            lambda_powers[eq_power_idx] = all_lambda_powers[eq_power_idx];
            if need_rot {
                lambda_powers[rot_power_idx] = all_lambda_powers[rot_power_idx];
            }
        }
        let d_lambda_powers = lambda_powers.to_device()?;

        let d_unstacked_cols = unstacked_cols.to_device()?;

        // Each commit's layout is sorted by height, so its first column is the tallest.
        let max_hypercube_dim = r.len() - 1;
        debug_assert_eq!(
            max_hypercube_dim,
            stacked_per_commit
                .iter()
                .map(|d| d.layout().sorted_cols[0].slice.log_height())
                .max()
                .unwrap_or(0)
                .saturating_sub(l_skip)
        );
        let eq_segments = EqEvalSegments::new_with_kernels::<FK>(&r[1..])
            .map_err(StackedReductionError::EqEvalSegments)?;

        let eq_const = eval_eq_uni_at_one(l_skip, r[0] * omega_skip);
        let eq_ub_per_col = vec![FK::ValExt::ONE; unstacked_cols.len()];
        let d_stacked_eval_ptrs = if stacked_per_commit.is_empty() {
            DeviceBuffer::new()
        } else {
            DeviceBuffer::with_capacity(stacked_per_commit.len())
        };
        let d_input_ptrs = if stacked_per_commit.is_empty() {
            DeviceBuffer::new()
        } else {
            DeviceBuffer::with_capacity(stacked_per_commit.len())
        };
        let d_output_ptrs = if stacked_per_commit.is_empty() {
            DeviceBuffer::new()
        } else {
            DeviceBuffer::with_capacity(stacked_per_commit.len())
        };
        // Each window gets its own slot of 4 u64 accumulators (one per extension coordinate) per
        // sumcheck evaluation point, so an entire multilinear round accumulates on the device
        // with no readback in between (see `batch_sumcheck_poly_eval`).
        let num_windows = mle_col_bounds.len().saturating_sub(1).max(1);
        let d_window_accums =
            DeviceBuffer::<u64>::with_capacity(num_windows * STACKED_REDUCTION_S_DEG * 4);
        // eq_ub for every column at once, uploaded a single time per multilinear round; a
        // degenerate window reads it starting at its first column.
        let d_eq_ub = if unstacked_cols.is_empty() {
            DeviceBuffer::new()
        } else {
            DeviceBuffer::with_capacity(unstacked_cols.len())
        };

        Ok(Self {
            sm_count,
            l_skip,
            n_stack,
            omega_skip,
            skip_domain_powers,
            d_skip_domain_powers,
            r_univariate: r[0],
            d_lambda_powers,
            eq_const,
            stacked_per_commit,
            d_stacked_widths,
            max_stacked_width,
            d_stacked_eval_ptrs,
            trace_views,
            unstacked_cols,
            d_unstacked_cols,
            trace_col_bounds,
            mle_col_bounds,
            max_hypercube_dim,
            eq_segments,
            stacked_evals: vec![],
            settled_eq: vec![],
            settled_k_rot: vec![],
            // SAFETY: round 0 never reads it; `fold_ple_evals` sets it up before round 1.
            k_rot_segments: unsafe { EqEvalSegments::from_raw_parts(DeviceBuffer::new(), 0) },
            eq_ub_per_col,
            d_eq_ub,
            d_block_sums: DeviceBuffer::new(),
            d_window_accums,
            d_input_ptrs,
            d_output_ptrs,
            mem,
            _field: PhantomData,
        })
    }

    /// Round 0 for the degree-1 kernel: the device accumulates G0, G1 and G2 over the identity
    /// coset only, and the host turns them into the univariate polynomial s₀.
    ///
    /// This avoids evaluating s₀(Z) on two cosets with an NTT inside the kernel: the three
    /// partial sums need just the identity coset, and the products with the known eq factors
    /// are formed afterwards on the host (see `assemble_round0_poly`).
    #[instrument(
        "stacked_reduction_sumcheck",
        level = "debug",
        skip_all,
        fields(round = 0)
    )]
    fn batch_sumcheck_uni_round0_poly(
        &mut self,
    ) -> Result<UnivariatePoly<FK::ValExt>, StackedReductionError>
    where
        FK::ValExt: ExtensionField<FK::Val> + TwoAdicField,
    {
        let l_skip = self.l_skip;
        let skip_domain = 1 << l_skip;
        let round0_degree = sumcheck_round0_deg(l_skip, STACKED_REDUCTION_S_DEG);

        // Device accumulators for G0, G1 and G2 over the identity coset.
        // Traces with n >= 0 all add into `d_g_nonneg`.
        let mut d_g_nonneg = DeviceBuffer::<FK::ValExt>::with_capacity(NUM_G * skip_domain);
        d_g_nonneg
            .fill_zero()
            .map_err(StackedReductionError::FillZero)?;

        // A trace with n < 0 adds into `d_g_neg_buckets[-n - 1]`, giving l_skip buckets in total.
        let mut d_g_neg_buckets: Vec<DeviceBuffer<FK::ValExt>> = (0..l_skip)
            .map(|_| {
                let bucket = DeviceBuffer::with_capacity(NUM_G * skip_domain);
                bucket
                    .fill_zero()
                    .map_err(StackedReductionError::FillZero)?;
                Ok(bucket)
            })
            .collect::<Result<Vec<_>, StackedReductionError>>()?;

        // [reduxprof] r0_poly broken down into the kernel loop and the host-side assembly of s0.
        let redux_prof = std::env::var("REDUX_PROF").is_ok();
        let t_kernels = std::time::Instant::now();

        // One kernel launch per trace, each adding into the bucket that matches its n.
        for ((trace_data, height, width), col_range) in zip(
            mem::take(&mut self.trace_views),
            self.trace_col_bounds.windows(2),
        ) {
            debug_assert_eq!(col_range[1] - col_range[0], width);
            let trace_log_height = height.ilog2();
            let n = trace_log_height as isize - l_skip as isize;

            // Pick the accumulator bucket for this n.
            let target_bucket = if n >= 0 {
                &mut d_g_nonneg
            } else {
                &mut d_g_neg_buckets[(-n - 1) as usize]
            };

            // Grow the scratch buffer for per-block partial sums when this trace needs more.
            let temp_len =
                unsafe { FK::stacked_r0_temp_buf_size(height as u32, width as u32, l_skip as u32) }
                    as usize;

            if temp_len > self.d_block_sums.len() {
                self.d_block_sums = DeviceBuffer::<FK::ValExt>::with_capacity(temp_len);
            }

            unsafe {
                // Every column owns two consecutive powers: coeff_eq, then coeff_rot.
                let lambda_powers_ptr = self.d_lambda_powers.as_ptr().add(2 * col_range[0]);

                FK::stacked_sumcheck_round0(
                    &self.eq_segments,
                    trace_data,
                    lambda_powers_ptr,
                    &mut self.d_block_sums,
                    target_bucket,
                    height,
                    width,
                    l_skip,
                )
                .map_err(StackedReductionError::SumcheckRound0)?;
            };
        }

        if redux_prof {
            let _ = crate::runtime::stream::current_stream_sync();
            tracing::info!(
                target: "bench",
                "[reduxprof] r0_kernels={}us",
                t_kernels.elapsed().as_micros()
            );
        }

        // Host side: s₀(Z) = E0(Z)*G0(Z) + E1(Z)*G1(Z) + E2(Z)*G2(Z).
        let t_reconstruct = std::time::Instant::now();
        let round0_poly = self.assemble_round0_poly(d_g_nonneg, d_g_neg_buckets, round0_degree)?;
        if redux_prof {
            tracing::info!(
                target: "bench",
                "[reduxprof] r0_reconstruct={}us",
                t_reconstruct.elapsed().as_micros()
            );
        }
        self.mem.tracing_info("stacked_reduction_sumcheck round 0");

        Ok(round0_poly)
    }

    /// Builds the round-0 polynomial s₀ out of the device partial sums G0, G1 and G2 by
    /// multiplying each with its known eq factor E0, E1 or E2.
    ///
    /// For the n >= 0 bucket, E0 and E1 are the univariate eq polynomials over the skip domain
    /// at r0 and at r0·ω_skip (`eq_uni_poly`), and E2 is `eq_const` times the eq-at-one
    /// polynomial (`eq_at_one_poly`).
    ///
    /// A bucket with n < 0 builds the same three factors on its smaller subgroup and then
    /// multiplies each by the indicator polynomial `indicator_poly(l_skip, n)`, which lifts it
    /// back onto the skip domain.
    fn assemble_round0_poly(
        &self,
        d_g_nonneg: DeviceBuffer<FK::ValExt>,
        d_g_neg_buckets: Vec<DeviceBuffer<FK::ValExt>>,
        round0_degree: usize,
    ) -> Result<UnivariatePoly<FK::ValExt>, StackedReductionError>
    where
        FK::ValExt: ExtensionField<FK::Val> + TwoAdicField,
    {
        let l_skip = self.l_skip;
        let skip_domain = 1 << l_skip;
        let padded_len = (round0_degree + 1).next_power_of_two(); // equals 2 * skip_domain

        // Coefficients of s₀, summed over every bucket.
        let mut round0_coeffs = vec![FK::ValExt::ZERO; padded_len];

        // Bucket for n >= 0.
        let host_g_nonneg = d_g_nonneg.to_host()?;
        if !host_g_nonneg.iter().all(|&x| x == FK::ValExt::ZERO) {
            // The three eq factors on the full skip domain.
            let eq_r_poly = eq_uni_poly::<FK::Val, FK::ValExt>(l_skip, self.r_univariate);
            let eq_rot_poly =
                eq_uni_poly::<FK::Val, FK::ValExt>(l_skip, self.r_univariate * self.omega_skip);
            let eq_one_poly = eq_at_one_poly::<FK::Val, FK::ValExt>(l_skip, self.eq_const);

            // s₀ += E0*G0 + E1*G1 + E2*G2
            self.add_products_into(
                [
                    eq_r_poly.coeffs(),
                    eq_rot_poly.coeffs(),
                    eq_one_poly.coeffs(),
                ],
                [
                    &host_g_nonneg[0..skip_domain],
                    &host_g_nonneg[skip_domain..2 * skip_domain],
                    &host_g_nonneg[2 * skip_domain..3 * skip_domain],
                ],
                &mut round0_coeffs,
            );
        }

        // Buckets for n < 0, one per |n|.
        for (neg_idx, neg_bucket) in d_g_neg_buckets.into_iter().enumerate() {
            let abs_n = neg_idx + 1;
            let host_g_neg = neg_bucket.to_host()?;
            if host_g_neg.iter().all(|&x| x == FK::ValExt::ZERO) {
                continue;
            }

            // A trace with n < 0 lives on the subgroup of size 2^(l_skip - |n|).
            let sub_log_size = l_skip - abs_n;
            let sub_generator = self.omega_skip.exp_power_of_2(abs_n);
            let r_power = self.r_univariate.exp_power_of_2(abs_n);

            // Eq factors on that subgroup, plus the indicator that lifts them to the skip domain.
            let indicator = indicator_poly::<FK::Val, FK::ValExt>(l_skip, -(abs_n as isize));
            let sub_eq_r = eq_uni_poly::<FK::Val, FK::ValExt>(sub_log_size, r_power);
            let sub_eq_rot =
                eq_uni_poly::<FK::Val, FK::ValExt>(sub_log_size, r_power * sub_generator);
            let sub_eq_one = eq_at_one_poly::<FK::Val, FK::ValExt>(sub_log_size, self.eq_const);

            // Multiply each factor by the indicator polynomial.
            let masked_eq_r = convolve_schoolbook(sub_eq_r.coeffs(), indicator.coeffs());
            let masked_eq_rot = convolve_schoolbook(sub_eq_rot.coeffs(), indicator.coeffs());
            let masked_eq_one = convolve_schoolbook(sub_eq_one.coeffs(), indicator.coeffs());

            self.add_products_into(
                [&masked_eq_r, &masked_eq_rot, &masked_eq_one],
                [
                    &host_g_neg[0..skip_domain],
                    &host_g_neg[skip_domain..2 * skip_domain],
                    &host_g_neg[2 * skip_domain..3 * skip_domain],
                ],
                &mut round0_coeffs,
            );
        }

        round0_coeffs.truncate(round0_degree + 1);
        Ok(UnivariatePoly::new(round0_coeffs))
    }

    /// Adds sum_i E[i] * G[i] onto `acc_coeffs`, where each E[i] is given by coefficients and
    /// each G[i] by its values on the skip-domain subgroup. Everything is plain schoolbook
    /// arithmetic.
    ///
    /// The NTT engine is avoided on purpose: with a 16-point skip domain a single
    /// `Radix2Bowers` transform spends ~1.4 ms on per-call setup for only a few hundred field
    /// multiplications, which added up to ~11 ms of host time per chunk, against ~0.1 ms for
    /// this direct version (measured). Product indices wrap modulo `acc_coeffs.len()` (a power
    /// of two), matching the cyclic convolution the NTT used to compute; for real shapes
    /// deg(E*G) < acc_coeffs.len(), so no index ever actually wraps.
    fn add_products_into(
        &self,
        eq_coeffs: [&[FK::ValExt]; 3],
        g_values: [&[FK::ValExt]; 3], // values of G on the identity coset
        acc_coeffs: &mut [FK::ValExt],
    ) where
        FK::ValExt: ExtensionField<FK::Val>,
    {
        let domain_size = 1usize << self.l_skip;
        debug_assert!(acc_coeffs.len().is_power_of_two());
        // omega_skip is Val::two_adic_generator(l_skip), the generator (and point order) that
        // `Radix2Bowers::idft` used when this went through the NTT, so the direct inverse DFT
        // below yields exactly the same values.
        let generator_powers = &self.skip_domain_powers;
        debug_assert_eq!(generator_powers.len(), domain_size);
        let inv_domain_size = FK::Val::ONE.halve().exp_u64(self.l_skip as u64);
        for i in 0..3 {
            debug_assert_eq!(g_values[i].len(), domain_size);
            if g_values[i].iter().all(|&x| x == FK::ValExt::ZERO) {
                continue;
            }
            // Direct inverse DFT: g_poly[j] = (1/size) * sum_k g_values[k] * omega^{-jk}
            let g_poly: Vec<FK::ValExt> = (0..domain_size)
                .map(|j| {
                    let mut sum = FK::ValExt::ZERO;
                    for (k, &g_at_k) in g_values[i].iter().enumerate() {
                        sum += g_at_k
                            * generator_powers[(domain_size - (j * k) % domain_size) % domain_size];
                    }
                    sum * inv_domain_size
                })
                .collect();
            for (e_idx, &e_coeff) in eq_coeffs[i].iter().enumerate() {
                if e_coeff == FK::ValExt::ZERO {
                    continue;
                }
                for (g_idx, &g_coeff) in g_poly.iter().enumerate() {
                    let slot = (e_idx + g_idx) & (acc_coeffs.len() - 1);
                    acc_coeffs[slot] += e_coeff * g_coeff;
                }
            }
        }
    }

    #[instrument("stacked_reduction_fold_ple", level = "debug", skip_all)]
    fn fold_ple_evals(&mut self, u_0: FK::ValExt) -> Result<(), StackedReductionError>
    where
        FK::ValExt: ExtensionField<FK::Val>,
    {
        let l_skip = self.l_skip;
        let n_stack = self.n_stack;
        let r_univariate = self.r_univariate;
        let omega_skip = self.omega_skip;
        let max_hypercube_dim = self.max_hypercube_dim;
        self.stacked_evals.clear();

        // The inverse Lagrange denominators depend only on u_0, so every trace shares them.
        let skip_domain = 1 << l_skip;
        let inv_lagrange_denoms =
            compute_barycentric_inv_lagrange_denoms(l_skip, &self.skip_domain_powers, u_0);
        let d_inv_lagrange_denoms = inv_lagrange_denoms.to_device()?;

        for commit_data in &self.stacked_per_commit {
            let layout = commit_data.layout();
            let num_hypercube_rows = 1 << n_stack;
            let commit_width = layout.width();
            debug_assert_eq!(layout.height(), 1 << (l_skip + n_stack));
            let commit_folded =
                DeviceBuffer::<FK::ValExt>::with_capacity(num_hypercube_rows * commit_width);
            // Zero-fill first: stacking leaves gaps that no trace writes to.
            commit_folded
                .fill_zero()
                .map_err(StackedReductionError::FillZero)?;
            let mut write_offset = 0;
            for trace in &commit_data.traces {
                if trace.width() == 0 || trace.height() == 0 {
                    continue;
                }
                let folded_height = max(trace.height(), skip_domain) / skip_domain;

                // One kernel launch folds this trace.
                // SAFETY:
                // - `trace.buffer()` points to `trace.height() * trace.width()` device elements.
                // - `commit_folded` has `num_hypercube_rows * commit_width` elements and the
                //   traces are written back to back, so `folded_height * trace.width()` elements
                //   starting at `write_offset` are in bounds.
                // - Both `d_skip_domain_powers` and `d_inv_lagrange_denoms` hold at least
                //   `skip_domain` entries.
                unsafe {
                    let dst_ptr = commit_folded.as_mut_ptr().add(write_offset);
                    FK::stacked_fold_ple(
                        trace.buffer().as_ptr(),
                        dst_ptr,
                        &self.d_skip_domain_powers,
                        &d_inv_lagrange_denoms,
                        trace.height(),
                        trace.width(),
                        l_skip,
                    )
                    .map_err(StackedReductionError::FoldPle)?;
                }

                write_offset += folded_height * trace.width();
            }
            self.stacked_evals.push(commit_folded);
        }

        // Collapse the univariate part of \eq and \kappa_\rot at u_0, leaving multilinear tables.
        let eq_u0_r0 = eval_eq_uni(l_skip, u_0, r_univariate);
        let eq_u0_r0_rot = eval_eq_uni(l_skip, u_0, r_univariate * omega_skip);
        let eq_u0_one = eval_eq_uni_at_one(l_skip, u_0);
        debug_assert_eq!(self.eq_segments.buffer.len(), 2 << max_hypercube_dim);
        self.k_rot_segments.buffer = DeviceBuffer::with_capacity(2 << max_hypercube_dim);
        [FK::ValExt::ZERO].copy_to(&mut self.k_rot_segments.buffer)?;
        unsafe {
            // SAFETY: `k_rot_segments` was just allocated with the same length as `eq_segments`.
            FK::init_k_rot_from_eq_segments(
                &self.eq_segments,
                &mut self.k_rot_segments.buffer,
                eq_u0_r0_rot,
                self.eq_const * eq_u0_one,
                max_hypercube_dim as u32,
            )
            .map_err(StackedReductionError::InitKRot)?;
        }
        FK::vector_scalar_multiply_ext(&mut self.eq_segments.buffer, eq_u0_r0)
            .map_err(StackedReductionError::VectorScalarMul)?;

        // Settled eq / k_rot values for the short traces, n = -l_skip..0. They are produced for
        // -n = 1..=l_skip and then reversed, so that index i matches log_height = i for
        // i in 0..l_skip.
        (self.settled_eq, self.settled_k_rot) =
            zip(r_univariate.exp_powers_of_2(), omega_skip.exp_powers_of_2())
                .enumerate()
                .skip(1)
                .take(l_skip)
                .map(|(abs_n, (r_power, sub_generator))| {
                    let sub_log_size = l_skip - abs_n;
                    let eq_value = eval_eq_uni(sub_log_size, u_0, r_power);
                    let eq_rot_value = eval_eq_uni(sub_log_size, u_0, r_power * sub_generator);
                    let indicator = eval_in_uni(l_skip, -(abs_n as isize), u_0);
                    (indicator * eq_value, indicator * eq_rot_value)
                })
                .unzip();
        self.settled_eq.reverse();
        self.settled_k_rot.reverse();
        Ok(())
    }

    #[instrument("stacked_reduction_sumcheck", level = "debug", skip_all, fields(round = round))]
    fn batch_sumcheck_poly_eval(
        &mut self,
        round: usize,
        _u_prev: FK::ValExt,
    ) -> Result<[FK::ValExt; STACKED_REDUCTION_S_DEG], StackedReductionError>
    where
        FK::ValExt: ExtensionField<FK::Val>,
    {
        let l_skip = self.l_skip;

        let stacked_eval_ptrs = self
            .stacked_evals
            .iter()
            .map(|matrix| matrix.as_ptr())
            .collect_vec();
        stacked_eval_ptrs.copy_to(&mut self.d_stacked_eval_ptrs)?;

        if self.max_hypercube_dim >= (round - 1) {
            // The entry at index 0 of each segmented table is now final; record it as settled.
            let mut scalar_host = [FK::ValExt::ZERO];
            debug_assert_eq!(self.settled_eq.len(), l_skip + round - 1);
            debug_assert_eq!(self.settled_k_rot.len(), l_skip + round - 1);
            debug_assert!(self.eq_segments.buffer.len() > 1);
            debug_assert!(self.k_rot_segments.buffer.len() > 1);
            // SAFETY: both segmented tables currently hold 2 * 2^{max_hypercube_dim - round + 1}
            // elements, so index 0 is valid.
            unsafe {
                // Read back one extension element.
                cuda_memcpy::<true, false>(
                    scalar_host.as_mut_ptr() as *mut c_void,
                    self.eq_segments.get_ptr(0) as *const c_void,
                    size_of::<FK::ValExt>(),
                )?;

                self.settled_eq.push(scalar_host[0]);

                // Same for k_rot.
                cuda_memcpy::<true, false>(
                    scalar_host.as_mut_ptr() as *mut c_void,
                    self.k_rot_segments.get_ptr(0) as *const c_void,
                    size_of::<FK::ValExt>(),
                )?;

                self.settled_k_rot.push(scalar_host[0]);
            }
        }
        // Every window owns 8 u64 accumulators. All of them are cleared by one memset, the
        // windows' kernels are queued back to back, and a single D2H copy (one stream sync)
        // brings everything back for the host-side reduction. Doing memset -> kernel -> D2H sync ->
        // host reduce separately for each window (~12 windows x ~19 rounds per chunk) left the GPU
        // waiting on every readback and the host waiting on every kernel.
        const ACCUM_LEN_PER_WINDOW: usize = STACKED_REDUCTION_S_DEG * 4;
        let num_windows = self.mle_col_bounds.len() - 1;
        debug_assert!(self.d_window_accums.len() >= num_windows * ACCUM_LEN_PER_WINDOW);
        self.d_window_accums
            .fill_zero()
            .map_err(StackedReductionError::FillZero)?;

        // Degenerate (settled) windows need the per-column eq_ub values, so the full vector goes
        // up once per round rather than one slice per window. An async H2D copy out of a pageable
        // Vec is safe for the source, since the driver stages the data before returning.
        // PERF: most of eq_ub could be folded into settled_eq / settled_k_rot, which would
        // shrink this upload.
        let has_settled_window = self
            .mle_col_bounds
            .windows(2)
            .any(|bounds| (self.unstacked_cols[bounds[0]].log_height as usize) < l_skip + round);
        if has_settled_window {
            self.eq_ub_per_col.copy_to(&mut self.d_eq_ub)?;
        }

        let rows_this_round = self.height_at_round(round);
        for (window_idx, col_range) in self.mle_col_bounds.windows(2).enumerate() {
            let window_width = col_range[1] - col_range[0];
            // SAFETY: mle_col_bounds only holds valid column indices (plus the end sentinel).
            let slices_ptr = unsafe { self.d_unstacked_cols.as_ptr().add(col_range[0]) };
            // Two powers per column, for eq and for k_rot.
            // SAFETY: lambda_powers has 2 entries for every column, so this offset is in range.
            let lambda_powers_ptr = unsafe { self.d_lambda_powers.as_ptr().add(2 * col_range[0]) };
            // SAFETY: `new` sizes d_window_accums with ACCUM_LEN_PER_WINDOW u64s for every window.
            let window_accum_ptr = unsafe {
                self.d_window_accums
                    .as_mut_ptr()
                    .add(window_idx * ACCUM_LEN_PER_WINDOW)
            };

            let window_log_height = self.unstacked_cols[col_range[0]].log_height as usize;

            if window_log_height < l_skip + round {
                // eq and k_rot no longer change for this window (every n < 0 trace ends up
                // here), so its contribution to the round polynomial is constant and no
                // interpolation is needed.
                let eq_value = self.settled_eq[window_log_height];
                let k_rot_value = self.settled_k_rot[window_log_height];
                unsafe {
                    FK::stacked_sumcheck_mle_round_degenerate(
                        &self.d_stacked_eval_ptrs,
                        self.d_eq_ub.as_ptr().add(col_range[0]),
                        eq_value,
                        k_rot_value,
                        slices_ptr,
                        lambda_powers_ptr,
                        window_accum_ptr,
                        rows_this_round,
                        window_width,
                        l_skip,
                        round,
                    )
                    .map_err(StackedReductionError::SumcheckMleRoundDegenerate)?;
                }
            } else {
                let remaining_vars = window_log_height - l_skip - round;
                let num_hypercube_points = 1 << remaining_vars;
                // grid.y (thread_window_stride) is left to the launcher, which tunes it from the
                // hypercube size, the window width and the number of SMs.
                unsafe {
                    FK::stacked_sumcheck_mle_round(
                        &self.d_stacked_eval_ptrs,
                        &self.eq_segments,
                        &self.k_rot_segments,
                        slices_ptr,
                        lambda_powers_ptr,
                        window_accum_ptr,
                        rows_this_round,
                        window_width,
                        num_hypercube_points,
                        self.sm_count,
                    )
                    .map_err(StackedReductionError::SumcheckMleRound)?;
                };
            }
        }

        // Read every window's accumulators back at once, then reduce them modulo P on the host.
        let host_accums = self.d_window_accums.to_host()?;
        let per_window_evals: Vec<Vec<FK::ValExt>> = (0..num_windows)
            .map(|window| {
                accums_to_ext_elems::<FK::Val, FK::ValExt>(
                    &host_accums
                        [window * ACCUM_LEN_PER_WINDOW..(window + 1) * ACCUM_LEN_PER_WINDOW],
                )
            })
            .collect();

        Ok(from_fn(|i| {
            per_window_evals
                .iter()
                .map(|window_evals| window_evals[i])
                .sum::<FK::ValExt>()
        }))
    }

    #[instrument("stacked_reduction_fold_mle", level = "debug", skip_all, fields(round = round))]
    fn fold_mle_evals(
        &mut self,
        round: usize,
        u_round: FK::ValExt,
    ) -> Result<(), StackedReductionError>
    where
        FK::ValExt: ExtensionField<FK::Val>,
    {
        debug_assert!(round <= self.n_stack);
        let l_skip = self.l_skip;
        let (next_stacked_evals, src_ptrs, dst_ptrs): (Vec<_>, Vec<_>, Vec<_>) = self
            .stacked_evals
            .iter()
            .map(|evals| {
                let halved = DeviceBuffer::with_capacity(evals.len() >> 1);
                let dst_ptr = halved.as_mut_ptr();
                (halved, evals.as_ptr(), dst_ptr)
            })
            .multiunzip();
        src_ptrs.copy_to(&mut self.d_input_ptrs)?;
        dst_ptrs.copy_to(&mut self.d_output_ptrs)?;

        // SAFETY:
        // - Each `d_input_ptrs` entry is a matrix whose width is listed in `d_stacked_widths` and
        //   whose height is `height_at_round(round)`, twice `height_at_round(round + 1)`.
        // - Each `d_output_ptrs` entry was allocated just above with the same width and height
        //   `height_at_round(round + 1)`.
        let folded_rows = self.height_at_round(round + 1) as u32;
        unsafe {
            FK::fold_mle(
                &self.d_input_ptrs,
                &self.d_output_ptrs,
                &self.d_stacked_widths,
                self.stacked_evals.len().try_into().unwrap(),
                self.height_at_round(round + 1) as u32,
                self.max_stacked_width * folded_rows,
                u_round,
            )
            .map_err(StackedReductionError::FoldMle)?;
        }
        self.stacked_evals = next_stacked_evals;

        if self.max_hypercube_dim >= (round - 1) {
            let prev_max_n = self.max_n_at_round(round);
            let next_max_n = prev_max_n.saturating_sub(1);
            let folded_len = 1 << prev_max_n;

            let mut segment_buf = DeviceBuffer::<FK::ValExt>::with_capacity(folded_len);
            [FK::ValExt::ZERO].copy_to(&mut segment_buf)?;
            // SAFETY: eq_segments currently covers n up to prev_max_n, and the new buffer is
            // half its size.
            unsafe {
                let mut folded_segments = EqEvalSegments::from_raw_parts(segment_buf, next_max_n);
                if prev_max_n != 0 {
                    FK::triangular_fold_mle(
                        &mut folded_segments,
                        &self.eq_segments,
                        u_round,
                        next_max_n,
                    )
                    .map_err(StackedReductionError::TriangularFoldMle)?;
                }
                self.eq_segments = folded_segments;
            }

            let mut segment_buf = DeviceBuffer::<FK::ValExt>::with_capacity(folded_len);
            [FK::ValExt::ZERO].copy_to(&mut segment_buf)?;
            // SAFETY: k_rot_segments currently covers n up to prev_max_n, and the new buffer is
            // half the size of eq_segments.
            unsafe {
                let mut folded_segments = EqEvalSegments::from_raw_parts(segment_buf, next_max_n);
                if prev_max_n != 0 {
                    FK::triangular_fold_mle(
                        &mut folded_segments,
                        &self.k_rot_segments,
                        u_round,
                        next_max_n,
                    )
                    .map_err(StackedReductionError::TriangularFoldMle)?;
                }
                self.k_rot_segments = folded_segments;
            }
        } else {
            assert_eq!(self.eq_segments.buffer.len(), 1);
            assert_eq!(self.k_rot_segments.buffer.len(), 1);
        }
        for (col, eq_ub_value) in zip(&self.unstacked_cols, &mut self.eq_ub_per_col) {
            if round + l_skip > col.log_height as usize {
                // This column is too short to be touched by the fold above; instead extend its
                // factor eq(u[1+n_T..=round], b_{T,j}[..=round-n_T-1]) by one more variable.
                debug_assert_eq!(col.stacked_row_idx % (1 << col.log_height), 0);
                let row_bit = (col.stacked_row_idx >> (l_skip + round - 1)) & 1;
                *eq_ub_value *= eval_eq_mle(&[u_round], &[FK::Val::from_bool(row_bit == 1)]);
            }
        }
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    fn get_stacked_openings(&self) -> Result<Vec<Vec<FK::ValExt>>, StackedReductionError> {
        self.stacked_evals
            .iter()
            .map(|matrix| matrix.to_host().map_err(StackedReductionError::MemCopy))
            .collect::<Result<Vec<_>, _>>()
    }
}

/// Turns raw u64 accumulators (which may exceed the modulus) into extension field elements.
///
/// Once taken modulo `p`, each u64 is the Montgomery representation of an `FVal` element.
/// `FExt` must be a degree-4 extension of `FVal`, i.e. four consecutive values per element.
#[inline]
fn accums_to_ext_elems<FVal, FExt>(raw_accums: &[u64]) -> Vec<FExt>
where
    FVal: PrimeField32,
    FExt: BasedVectorSpace<FVal>,
{
    // Base-field coordinates per extension element.
    const EXT_DEGREE: usize = 4;
    debug_assert_eq!(raw_accums.len() % EXT_DEGREE, 0);
    debug_assert_eq!(size_of::<FVal>(), size_of::<u32>());
    raw_accums
        .chunks_exact(EXT_DEGREE)
        .map(|limbs| {
            FExt::from_basis_coefficients_fn(|i| {
                let reduced = (limbs[i] % FVal::ORDER_U64) as u32;
                // SAFETY: a PrimeField32 element is a repr(transparent) wrapper around u32.
                // ptr::read acts like transmute here but skips the compile-time size check.
                unsafe { std::ptr::read(&reduced as *const u32 as *const FVal) }
            })
        })
        .collect()
}

/// Coefficients of the indicator ind(Z) = 2^{-|n|} * sum_{k=0}^{2^{|n|}-1} Z^{k * 2^l}, where
/// l = l_skip - |n| and `n` is negative.
fn indicator_poly<FVal, FExt>(l_skip: usize, n: isize) -> UnivariatePoly<FExt>
where
    FVal: p3_field::Field + Copy,
    FExt: p3_field::Field + From<FVal> + Copy,
{
    let abs_n = (-n) as usize;
    let log_step = l_skip - abs_n;
    let weight = FExt::ONE.halve().exp_u64(abs_n as u64);
    let mut poly_coeffs = vec![FExt::ZERO; 1 << l_skip];
    for k in 0..(1 << abs_n) {
        poly_coeffs[k * (1 << log_step)] = weight;
    }
    UnivariatePoly::new(poly_coeffs)
}

/// `factor * eq_D(Z, 1)` as a polynomial in Z, for a domain D of size 2^log_size.
///
/// Every coefficient equals `factor / 2^log_size`.
fn eq_at_one_poly<FVal, FExt>(log_size: usize, factor: FExt) -> UnivariatePoly<FExt>
where
    FVal: p3_field::Field + Copy,
    FExt: p3_field::Field + From<FVal> + Copy,
{
    let inv_size = FVal::ONE.halve().exp_u64(log_size as u64);
    UnivariatePoly::new(vec![FExt::from(inv_size) * factor; 1 << log_size])
}

/// Linear convolution of two coefficient vectors, computed term by term. Both inputs have at most
/// skip_domain coefficients, a size at which NTT setup costs far more than the arithmetic (see
/// `StackedReductionGpu::add_products_into`).
fn convolve_schoolbook<FExt: PrimeCharacteristicRing + Copy + PartialEq>(
    lhs: &[FExt],
    rhs: &[FExt],
) -> Vec<FExt> {
    let mut product = vec![FExt::ZERO; lhs.len() + rhs.len() - 1];
    for (i, &lhs_coeff) in lhs.iter().enumerate() {
        if lhs_coeff == FExt::ZERO {
            continue;
        }
        for (j, &rhs_coeff) in rhs.iter().enumerate() {
            product[i + j] += lhs_coeff * rhs_coeff;
        }
    }
    product
}
