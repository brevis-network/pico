//! `FieldKernels` — dispatch trait for field-specific GPU proving kernels.
//!
//! Separates "which CUDA library to call" from the proving business logic. KoalaBear
//! ([`KoalaBearKernels`], linking to `cuda_kb_all`) is the one implementation.
//!
//! # Zero-cost
//! The trait is monomorphised at compile time; no virtual dispatch.

use std::fmt;

use crate::runtime::{d_buffer::DeviceBuffer, error::CudaError};
use mle_core::{poly::Squarable, prover::fractional_sumcheck_gkr::Frac};
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeField32, TwoAdicField};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    cuda::logup_zerocheck::MainMatrixPtrs,
    ntt_field::GpuNttField,
    poly::{EqEvalLayers, EqEvalSegments, SqrtEqLayersFor},
    stacked_reduction::UnstackedSlice,
    whir::BatchingTracePacket,
};

/// Dispatch trait for all field-specific GPU proving kernels used by the
/// WHIR and stacked-reduction proving pipelines.
///
/// `Val` is the base field (KoalaBear) and `ValExt` is the degree-4 extension used
/// throughout the proof system.
pub trait FieldKernels: 'static + Copy + Send + Sync {
    /// If true, use the CPU path for the GKR fractional sumcheck instead of GPU.
    /// Default: false (use GPU). Override to true for fields where the GPU GKR
    /// has correctness issues (e.g. KoalaBear at round 7+).
    fn use_cpu_gkr() -> bool {
        false
    }
    /// If true, compute the GKR logup input layer (interaction frac leaves) on CPU instead
    /// of GPU. Needed for fields where the GPU `logup_gkr_input_eval` kernel is wrong for
    /// multi-partition AIRs (e.g. KoalaBear with ByteChip/ProgramChip cached+common mains).
    /// Independent of `use_cpu_gkr` so the GPU sumcheck can run on correct CPU-computed leaves.
    fn use_cpu_gkr_input_eval() -> bool {
        false
    }
    /// If true, use the CPU fallback for the per-round logup/zerocheck MLE evaluations, round0
    /// batch-MLE, and fold steps (sumcheck_polys_batch_eval, round0 constraints/interactions,
    /// mat_evals fold). Decoupled from `use_cpu_gkr_input_eval` so the GPU input-eval can be
    /// enabled independently of these (separately-suspect) GPU MLE/fold paths.
    /// Default: false (use GPU).
    fn use_cpu_zerocheck_mle() -> bool {
        false
    }

    // ── Monomial-basis batch MLE kernels ──
    /// Zerocheck monomial batched MLE (low num_y path).
    #[allow(clippy::too_many_arguments)]
    unsafe fn zerocheck_monomial_batched(
        tmp_sums: &mut DeviceBuffer<EF>,
        output: &mut DeviceBuffer<EF>,
        block_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::BlockCtx>,
        air_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::MonomialAirCtx>,
        air_block_offsets: &DeviceBuffer<u32>,
        num_blocks: u32,
        num_x: u32,
        num_airs: u32,
        threads_per_block: u32,
    ) -> Result<(), CudaError>;
    /// Zerocheck monomial par-Y batched MLE (high num_y path).
    #[allow(clippy::too_many_arguments)]
    unsafe fn zerocheck_monomial_par_y_batched(
        tmp_sums: &mut DeviceBuffer<EF>,
        output: &mut DeviceBuffer<EF>,
        block_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::BlockCtx>,
        air_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::MonomialAirCtx>,
        air_block_offsets: &DeviceBuffer<u32>,
        num_blocks: u32,
        num_x: u32,
        num_airs: u32,
        chunk_size: u32,
        threads_per_block: u32,
    ) -> Result<(), CudaError>;
    /// Logup monomial batched MLE.
    #[allow(clippy::too_many_arguments)]
    unsafe fn logup_monomial_batched(
        tmp_sums: &mut DeviceBuffer<Frac<EF>>,
        output: &mut DeviceBuffer<Frac<EF>>,
        block_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::BlockCtx>,
        common_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::LogupMonomialCommonCtx>,
        numer_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::LogupMonomialCtx>,
        denom_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::LogupMonomialCtx>,
        air_block_offsets: &DeviceBuffer<u32>,
        num_blocks: u32,
        num_x: u32,
        num_airs: u32,
        threads_per_block: u32,
    ) -> Result<(), CudaError>;
    /// Zerocheck batched DAG MLE (high monomial-to-rules ratio path).
    #[allow(clippy::too_many_arguments)]
    unsafe fn zerocheck_batch_eval_mle(
        tmp_sums_buffer: &mut DeviceBuffer<EF>,
        output: &mut DeviceBuffer<EF>,
        block_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::BlockCtx>,
        zc_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::ZerocheckCtx>,
        air_block_offsets: &DeviceBuffer<u32>,
        lambda_pows: &DeviceBuffer<EF>,
        lambda_len: usize,
        num_blocks: u32,
        num_x: u32,
        num_airs: u32,
        threads_per_block: u32,
    ) -> Result<(), CudaError>;
    /// Logup batched DAG MLE.
    #[allow(clippy::too_many_arguments)]
    unsafe fn logup_batch_eval_mle(
        tmp_sums_buffer: &mut DeviceBuffer<Frac<EF>>,
        output: &mut DeviceBuffer<Frac<EF>>,
        block_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::BlockCtx>,
        logup_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::LogupCtx>,
        air_block_offsets: &DeviceBuffer<u32>,
        num_blocks: u32,
        num_x: u32,
        num_airs: u32,
        threads_per_block: u32,
    ) -> Result<(), CudaError>;

    type Val: GpuNttField
        + PrimeField32
        + TwoAdicField
        + Field
        + Copy
        + Clone
        + Send
        + Sync
        + 'static;
    type ValExt: Field
        + TwoAdicField
        + ExtensionField<Self::Val>
        + BasedVectorSpace<Self::Val>
        + Squarable
        + Copy
        + Clone
        + Send
        + Sync
        + Serialize
        + DeserializeOwned
        + fmt::Debug
        + fmt::Display
        + 'static;

    // ─── stacked-reduction kernels ────────────────────────────────────────

    unsafe fn stacked_r0_temp_buf_size(trace_height: u32, trace_width: u32, l_skip: u32) -> u32;

    #[allow(clippy::too_many_arguments)]
    unsafe fn stacked_sumcheck_round0(
        eq_r_ns: &EqEvalSegments<Self::ValExt>,
        trace_ptr: *const Self::Val,
        lambda_pows: *const Self::ValExt,
        block_sums: &mut DeviceBuffer<Self::ValExt>,
        output: &mut DeviceBuffer<Self::ValExt>,
        height: usize,
        width: usize,
        l_skip: usize,
    ) -> Result<(), CudaError>;

    #[allow(clippy::too_many_arguments)]
    unsafe fn stacked_fold_ple(
        src: *const Self::Val,
        dst: *mut Self::ValExt,
        omega_skip_pows: &DeviceBuffer<Self::Val>,
        inv_lagrange_denoms: &DeviceBuffer<Self::ValExt>,
        trace_height: usize,
        trace_width: usize,
        l_skip: usize,
    ) -> Result<(), CudaError>;

    unsafe fn init_k_rot_from_eq_segments(
        eq_r_ns: &EqEvalSegments<Self::ValExt>,
        k_rot_ns: &mut DeviceBuffer<Self::ValExt>,
        k_rot_uni_0: Self::ValExt,
        k_rot_uni_1: Self::ValExt,
        max_n: u32,
    ) -> Result<(), CudaError>;

    #[allow(clippy::too_many_arguments)]
    unsafe fn stacked_sumcheck_mle_round(
        q_evals: &DeviceBuffer<*const Self::ValExt>,
        eq_r_ns: &EqEvalSegments<Self::ValExt>,
        k_rot_ns: &EqEvalSegments<Self::ValExt>,
        unstacked_cols: *const UnstackedSlice,
        lambda_pows: *const Self::ValExt,
        output: *mut u64,
        q_height: usize,
        window_len: usize,
        num_y: usize,
        sm_count: u32,
    ) -> Result<(), CudaError>;

    #[allow(clippy::too_many_arguments)]
    unsafe fn stacked_sumcheck_mle_round_degenerate(
        q_evals: &DeviceBuffer<*const Self::ValExt>,
        eq_ub: *const Self::ValExt,
        eq_r: Self::ValExt,
        k_rot_r: Self::ValExt,
        unstacked_cols: *const UnstackedSlice,
        lambda_pows: *const Self::ValExt,
        output: *mut u64,
        q_height: usize,
        window_len: usize,
        l_skip: usize,
        round: usize,
    ) -> Result<(), CudaError>;

    // ─── shared poly/sumcheck kernels ─────────────────────────────────────

    fn vector_scalar_multiply_ext(
        vec: &mut DeviceBuffer<Self::ValExt>,
        scalar: Self::ValExt,
    ) -> Result<(), CudaError>;

    #[allow(clippy::too_many_arguments)]
    unsafe fn fold_mle(
        input_matrices: &DeviceBuffer<*const Self::ValExt>,
        output_matrices: &DeviceBuffer<*mut Self::ValExt>,
        widths: &DeviceBuffer<u32>,
        num_matrices: u16,
        output_height: u32,
        max_output_cells: u32,
        r_val: Self::ValExt,
    ) -> Result<(), CudaError>;

    // ─── logup/zerocheck kernels ──────────────────────────────────────────

    /// Fold base-field selector columns (is_transition/is_first/is_last) after the
    /// univariate skip round, producing extension-field outputs.
    unsafe fn fold_selectors_round0(
        out: *mut Self::ValExt,
        input: *const Self::Val,
        is_first: Self::ValExt,
        is_last: Self::ValExt,
        num_x: usize,
    ) -> Result<(), CudaError>;

    /// Interpolate columns of a matrix to produce `s_deg` extra rows used in
    /// subsequent sumcheck rounds.
    unsafe fn interpolate_columns_gpu(
        interpolated: &DeviceBuffer<Self::ValExt>,
        columns: &DeviceBuffer<*const Self::ValExt>,
        s_deg: usize,
        num_y: usize,
    ) -> Result<(), CudaError>;

    /// Fold multiple MLE matrices simultaneously, each potentially at a different
    /// height (supplied via `log_output_heights`).
    #[allow(clippy::too_many_arguments)]
    unsafe fn batch_fold_mle(
        input_matrices: &DeviceBuffer<*const Self::ValExt>,
        output_matrices: &DeviceBuffer<*mut Self::ValExt>,
        widths: &DeviceBuffer<u32>,
        num_matrices: u16,
        log_output_heights: &DeviceBuffer<u8>,
        max_output_cells: u32,
        r_val: Self::ValExt,
    ) -> Result<(), CudaError>;

    unsafe fn triangular_fold_mle(
        output: &mut EqEvalSegments<Self::ValExt>,
        input: &EqEvalSegments<Self::ValExt>,
        r: Self::ValExt,
        output_max_n: usize,
    ) -> Result<(), CudaError>;

    // ─── WHIR kernels ─────────────────────────────────────────────────────

    /// Batch every unstacked trace into one column vector.
    ///
    /// The stacking geometry each trace needs -- lifted height and stride, as `log2` -- travels in
    /// its [`BatchingTracePacket`], so there is no `skip_domain` argument: the host derives and
    /// power-of-two-checks those shifts once, and the kernel indexes with them directly.
    unsafe fn whir_algebraic_batch_traces(
        output: &mut DeviceBuffer<Self::Val>,
        packets: &DeviceBuffer<BatchingTracePacket<Self::Val>>,
        mu_powers: &DeviceBuffer<Self::ValExt>,
    ) -> Result<(), CudaError>;

    fn whir_sumcheck_coeff_moments_required_temp_buffer_size(height: u32) -> u32;

    unsafe fn whir_sumcheck_coeff_moments_round(
        f_coeffs: &DeviceBuffer<Self::ValExt>,
        w_moments: &DeviceBuffer<Self::ValExt>,
        output: &mut DeviceBuffer<Self::ValExt>,
        tmp_block_sums: &mut DeviceBuffer<Self::ValExt>,
        height: u32,
    ) -> Result<(), CudaError>;

    unsafe fn whir_fold_coeffs_and_moments(
        f_coeffs: &DeviceBuffer<Self::ValExt>,
        w_moments: &DeviceBuffer<Self::ValExt>,
        f_folded: &mut DeviceBuffer<Self::ValExt>,
        w_folded: &mut DeviceBuffer<Self::ValExt>,
        alpha: Self::ValExt,
        height: u32,
    ) -> Result<(), CudaError>;

    unsafe fn w_moments_accumulate(
        w_moments: &mut DeviceBuffer<Self::ValExt>,
        z0_pows2: &DeviceBuffer<Self::ValExt>,
        z_pows2: &DeviceBuffer<Self::Val>,
        gamma: Self::ValExt,
        num_queries: u32,
        log_height: u32,
    ) -> Result<(), CudaError>;

    // ─── matrix/mle/poly kernels used by WHIR ─────────────────────────────

    unsafe fn batch_expand_pad(
        output: *mut Self::Val,
        input: *const Self::Val,
        poly_count: u32,
        out_size: u32,
        in_size: u32,
    ) -> Result<(), CudaError>;

    unsafe fn split_ext_to_base_col_major_matrix(
        d_matrix: &mut DeviceBuffer<Self::Val>,
        d_poly: &DeviceBuffer<Self::ValExt>,
        poly_len: u64,
        matrix_height: u32,
    ) -> Result<(), CudaError>;

    unsafe fn mle_interpolate_stage_ext(
        buffer: &mut DeviceBuffer<Self::ValExt>,
        step: u32,
        is_eval_to_coeff: bool,
    ) -> Result<(), CudaError>;

    unsafe fn eval_poly_ext_at_point_from_base(
        base_coeffs: &DeviceBuffer<Self::Val>,
        coeff_len: usize,
        x: Self::ValExt,
    ) -> Result<Self::ValExt, crate::KernelError>;

    unsafe fn transpose_fp_to_fpext_vec(
        output: &mut DeviceBuffer<Self::ValExt>,
        input: &DeviceBuffer<Self::Val>,
    ) -> Result<(), CudaError>;

    // ─── poly stage (used by WHIR evals_eq_hypercube) ─────────────────────

    unsafe fn eq_hypercube_stage_ext(
        out: *mut Self::ValExt,
        x_i: Self::ValExt,
        step: u32,
    ) -> Result<(), CudaError>;

    unsafe fn eq_hypercube_nonoverlapping_stage_ext(
        out: *mut Self::ValExt,
        input: *const Self::ValExt,
        x_i: Self::ValExt,
        step: u32,
    ) -> Result<(), CudaError>;

    unsafe fn eq_hypercube_interleaved_stage_ext(
        out: *mut Self::ValExt,
        input: *const Self::ValExt,
        x_i: Self::ValExt,
        step: u32,
    ) -> Result<(), CudaError>;

    // ─── logup / GKR fractional sumcheck kernels ──────────────────────────────

    unsafe fn frac_compute_round_temp_buffer_size(stride: u32) -> u32;

    unsafe fn frac_build_tree_layer(
        layer: &mut DeviceBuffer<Frac<Self::ValExt>>,
        layer_size: usize,
        revert: bool,
        alpha: Self::ValExt,
        apply_alpha: bool,
    ) -> Result<(), CudaError>;

    unsafe fn frac_build_tree_two_layers(
        layer: &mut DeviceBuffer<Frac<Self::ValExt>>,
        half_i1: usize,
    ) -> Result<(), CudaError>;

    #[allow(clippy::too_many_arguments)]
    unsafe fn frac_compute_round(
        eq_xi: &SqrtEqLayersFor<Self::ValExt>,
        pq_buffer: &DeviceBuffer<Frac<Self::ValExt>>,
        num_x: usize,
        lambda: Self::ValExt,
        out_device: &mut DeviceBuffer<Self::ValExt>,
        tmp_block_sums: &mut DeviceBuffer<Self::ValExt>,
    ) -> Result<(), CudaError>;

    #[allow(clippy::too_many_arguments)]
    unsafe fn frac_compute_round_and_revert(
        eq_xi: &mut SqrtEqLayersFor<Self::ValExt>,
        layer: &mut DeviceBuffer<Frac<Self::ValExt>>,
        num_x: usize,
        lambda: Self::ValExt,
        out_device: &mut DeviceBuffer<Self::ValExt>,
        tmp_block_sums: &mut DeviceBuffer<Self::ValExt>,
    ) -> Result<(), CudaError>;

    unsafe fn fold_ef_frac_columns(
        src: &DeviceBuffer<Frac<Self::ValExt>>,
        dst: *mut Frac<Self::ValExt>,
        size: usize,
        r: Self::ValExt,
    ) -> Result<(), CudaError>;

    unsafe fn fold_ef_frac_columns_inplace(
        pq_buffer: &mut DeviceBuffer<Frac<Self::ValExt>>,
        size: usize,
        r: Self::ValExt,
    ) -> Result<(), CudaError>;

    #[allow(clippy::too_many_arguments)]
    unsafe fn frac_compute_round_and_fold(
        eq_xi: &mut SqrtEqLayersFor<Self::ValExt>,
        src_pq_buffer: &DeviceBuffer<Frac<Self::ValExt>>,
        dst_pq_buffer: &mut DeviceBuffer<Frac<Self::ValExt>>,
        src_pq_size: usize,
        lambda: Self::ValExt,
        r_prev: Self::ValExt,
        out_device: &mut DeviceBuffer<Self::ValExt>,
        tmp_block_sums: &mut DeviceBuffer<Self::ValExt>,
    ) -> Result<(), CudaError>;

    #[allow(clippy::too_many_arguments)]
    unsafe fn frac_compute_round_and_fold_inplace(
        eq_xi: &mut SqrtEqLayersFor<Self::ValExt>,
        pq_buffer: &mut DeviceBuffer<Frac<Self::ValExt>>,
        src_pq_size: usize,
        lambda: Self::ValExt,
        r_prev: Self::ValExt,
        out_device: &mut DeviceBuffer<Self::ValExt>,
        tmp_block_sums: &mut DeviceBuffer<Self::ValExt>,
    ) -> Result<(), CudaError>;

    #[allow(clippy::too_many_arguments)]
    unsafe fn frac_precompute_m_build_raw(
        pq: *const Frac<Self::ValExt>,
        rem_n: usize,
        w: usize,
        lambda: Self::ValExt,
        r_prev: Self::ValExt,
        inline_fold: bool,
        eq_tail_low: *const Self::ValExt,
        eq_tail_high: *const Self::ValExt,
        eq_tail_low_cap: usize,
        tail_tile: usize,
        partial_out: *mut Self::ValExt,
        partial_len: usize,
        m_total: *mut Self::ValExt,
    ) -> Result<(), CudaError>;

    #[allow(clippy::too_many_arguments)]
    unsafe fn frac_precompute_m_eval_round_raw(
        m_total: *const Self::ValExt,
        w: usize,
        t: usize,
        eq_r_prefix: *const Self::ValExt,
        eq_suffix: *const Self::ValExt,
        out: *mut Self::ValExt,
    ) -> Result<(), CudaError>;

    #[allow(clippy::too_many_arguments)]
    unsafe fn frac_multifold_raw(
        src: *const Frac<Self::ValExt>,
        dst: *mut Frac<Self::ValExt>,
        rem_n: usize,
        w: usize,
        eq_r_window: *const Self::ValExt,
    ) -> Result<(), CudaError>;

    unsafe fn frac_add_alpha(
        data: &DeviceBuffer<Frac<Self::ValExt>>,
        alpha: Self::ValExt,
    ) -> Result<(), CudaError>;

    unsafe fn frac_vector_scalar_multiply_ext_fp(
        frac_vec: &mut DeviceBuffer<Frac<Self::ValExt>>,
        scalar: Self::Val,
    ) -> Result<(), CudaError>;

    unsafe fn frac_matrix_vertically_repeat(
        out: *mut Frac<Self::ValExt>,
        input: &DeviceBuffer<Frac<Self::ValExt>>,
        width: u32,
        lifted_height: u32,
        height: u32,
    ) -> Result<(), CudaError>;

    #[allow(clippy::too_many_arguments)]
    unsafe fn frac_matrix_vertically_repeat_ext(
        out_n: *mut Self::ValExt,
        out_d: *mut Self::ValExt,
        in_n: *const Self::ValExt,
        in_d: *const Self::ValExt,
        width: u32,
        lifted_height: u32,
        height: u32,
    ) -> Result<(), CudaError>;

    unsafe fn bit_rev_frac_ext(
        d_out: &DeviceBuffer<(Self::ValExt, Self::ValExt)>,
        d_inp: &DeviceBuffer<(Self::ValExt, Self::ValExt)>,
        lg_domain_size: u32,
        padded_poly_size: u32,
        poly_count: u32,
    ) -> Result<(), CudaError>;

    unsafe fn bit_rev_frac_ext_build_k2(
        inout: &DeviceBuffer<(Self::ValExt, Self::ValExt)>,
        lg_domain_size: u32,
        alpha: Self::ValExt,
    ) -> Result<(), CudaError>;

    // ─── logup / zerocheck eval kernels ───────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    unsafe fn fold_ple_from_evals(
        input: &DeviceBuffer<Self::Val>,
        output: *mut Self::ValExt,
        omega_skip_pows: &DeviceBuffer<Self::Val>,
        inv_lagrange_denoms: &DeviceBuffer<Self::ValExt>,
        height: u32,
        width: u32,
        l_skip: u32,
        new_height: u32,
        rotate: bool,
    ) -> Result<(), CudaError>;

    #[allow(clippy::too_many_arguments)]
    unsafe fn logup_gkr_input_eval(
        is_global: bool,
        fracs: *mut Frac<Self::ValExt>,
        preprocessed: &DeviceBuffer<Self::Val>,
        partitioned_main: &DeviceBuffer<u64>,
        public_values: &DeviceBuffer<Self::Val>,
        challenges: &DeviceBuffer<Self::ValExt>,
        intermediates: &DeviceBuffer<Self::ValExt>,
        rules: &DeviceBuffer<u128>,
        used_nodes: &DeviceBuffer<usize>,
        pair_idxs: &DeviceBuffer<u32>,
        height: u32,
        num_rows_per_tile: u32,
    ) -> Result<(), CudaError>;

    fn logup_r0_temp_sums_buffer_size(
        buffer_size: u32,
        skip_domain: u32,
        num_x: u32,
        num_cosets: u32,
        max_temp_bytes: usize,
    ) -> usize;

    fn logup_r0_intermediates_buffer_size(
        buffer_size: u32,
        skip_domain: u32,
        num_x: u32,
        num_cosets: u32,
        max_temp_bytes: usize,
    ) -> usize;

    fn zerocheck_r0_temp_sums_buffer_size(
        buffer_size: u32,
        skip_domain: u32,
        num_x: u32,
        num_cosets: u32,
        max_temp_bytes: usize,
    ) -> usize;

    fn zerocheck_r0_intermediates_buffer_size(
        buffer_size: u32,
        skip_domain: u32,
        num_x: u32,
        num_cosets: u32,
        max_temp_bytes: usize,
    ) -> usize;

    fn zerocheck_mle_temp_sums_buffer_size(num_x: u32, num_y: u32) -> usize;
    fn zerocheck_mle_intermediates_buffer_size(buffer_size: u32, num_x: u32, num_y: u32) -> usize;
    fn logup_mle_temp_sums_buffer_size(num_x: u32, num_y: u32) -> usize;
    fn logup_mle_intermediates_buffer_size(buffer_size: u32, num_x: u32, num_y: u32) -> usize;
    fn zerocheck_batch_mle_intermediates_buffer_size(
        buffer_size: u32,
        num_x: u32,
        num_y: u32,
    ) -> usize;
    fn logup_batch_mle_intermediates_buffer_size(buffer_size: u32, num_x: u32, num_y: u32)
        -> usize;

    #[allow(clippy::too_many_arguments)]
    unsafe fn zerocheck_ntt_eval_constraints(
        tmp_sums_buffer: &mut DeviceBuffer<Self::ValExt>,
        output: &mut DeviceBuffer<Self::ValExt>,
        selectors_cube: &DeviceBuffer<Self::Val>,
        preprocessed: *const Self::Val,
        main_parts: &DeviceBuffer<*const Self::Val>,
        eq_cube: *const Self::ValExt,
        lambda_pows: &DeviceBuffer<Self::ValExt>,
        public_values: &DeviceBuffer<Self::Val>,
        rules: &DeviceBuffer<u128>,
        used_nodes: &DeviceBuffer<usize>,
        buffer_size: u32,
        intermediates: &mut DeviceBuffer<Self::Val>,
        skip_domain: u32,
        num_x: u32,
        height: u32,
        num_cosets: u32,
        g_shift: Self::Val,
        max_temp_bytes: usize,
    ) -> Result<(), CudaError>;

    #[allow(clippy::too_many_arguments)]
    unsafe fn logup_bary_eval_interactions_round0(
        tmp_sums_buffer: &mut DeviceBuffer<Frac<Self::ValExt>>,
        output: &mut DeviceBuffer<Frac<Self::ValExt>>,
        selectors_cube: &DeviceBuffer<Self::Val>,
        preprocessed: *const Self::Val,
        main_ptrs: &DeviceBuffer<*const Self::Val>,
        eq_cube: *const Self::ValExt,
        public_values: &DeviceBuffer<Self::Val>,
        numer_weights: &DeviceBuffer<Self::ValExt>,
        denom_weights: &DeviceBuffer<Self::ValExt>,
        denom_sum_init: Self::ValExt,
        rules: &DeviceBuffer<u128>,
        buffer_size: u32,
        intermediates: &mut DeviceBuffer<Self::Val>,
        skip_domain: u32,
        num_x: u32,
        height: u32,
        num_cosets: u32,
        g_shift: Self::Val,
        max_temp_bytes: usize,
    ) -> Result<(), CudaError>;

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    unsafe fn zerocheck_eval_mle(
        tmp_sums_buffer: &mut DeviceBuffer<Self::ValExt>,
        output: &mut DeviceBuffer<Self::ValExt>,
        eq_xi: *const Self::ValExt,
        selectors: *const Self::ValExt,
        preprocessed: MainMatrixPtrs<Self::ValExt>,
        main: *const MainMatrixPtrs<Self::ValExt>,
        lambda_pows: *const Self::ValExt,
        lambda_len: usize,
        public_values: *const Self::Val,
        rules: *const std::ffi::c_void,
        rules_len: usize,
        used_nodes: *const usize,
        used_nodes_len: usize,
        buffer_size: u32,
        intermediates: &mut DeviceBuffer<Self::ValExt>,
        num_y: u32,
        num_x: u32,
    ) -> Result<(), CudaError>;

    #[allow(clippy::too_many_arguments)]
    unsafe fn logup_eval_mle(
        tmp_sums_buffer: &mut DeviceBuffer<Frac<Self::ValExt>>,
        output: &mut DeviceBuffer<Frac<Self::ValExt>>,
        eq_xi: *const Self::ValExt,
        selectors: *const Self::ValExt,
        preprocessed: MainMatrixPtrs<Self::ValExt>,
        main: *const MainMatrixPtrs<Self::ValExt>,
        challenges: *const Self::ValExt,
        eq_3bs: *const Self::ValExt,
        public_values: *const Self::Val,
        rules: *const std::ffi::c_void,
        used_nodes: *const usize,
        pair_idxs: *const u32,
        used_nodes_len: usize,
        buffer_size: u32,
        intermediates: &mut DeviceBuffer<Self::ValExt>,
        num_y: u32,
        num_x: u32,
    ) -> Result<(), CudaError>;

    // ─── monomial precompute kernels ─────────────────────────────────────────

    unsafe fn precompute_lambda_combinations(
        out: &mut DeviceBuffer<Self::ValExt>,
        headers: *const crate::monomial::MonomialHeader,
        lambda_terms: *const crate::monomial::LambdaTerm<Self::Val>,
        lambda_pows: &DeviceBuffer<Self::ValExt>,
        num_monomials: u32,
    ) -> Result<(), CudaError>;

    unsafe fn precompute_logup_numer_combinations(
        out: &mut DeviceBuffer<Self::ValExt>,
        headers: *const crate::monomial::MonomialHeader,
        terms: *const crate::monomial::InteractionMonomialTerm<Self::Val>,
        eq_3bs: &DeviceBuffer<Self::ValExt>,
        num_monomials: u32,
    ) -> Result<(), CudaError>;

    unsafe fn precompute_logup_denom_combinations(
        out: &mut DeviceBuffer<Self::ValExt>,
        headers: *const crate::monomial::MonomialHeader,
        terms: *const crate::monomial::InteractionMonomialTerm<Self::Val>,
        beta_pows: &DeviceBuffer<Self::ValExt>,
        eq_3bs: &DeviceBuffer<Self::ValExt>,
        num_monomials: u32,
    ) -> Result<(), CudaError>;

    /// Populates `out` with `eq(u, y)` for `y` in the boolean hypercube `{0,1}^n`,
    /// where `xs = u`.
    ///
    /// Default implementation uses `eq_hypercube_stage_ext`.
    unsafe fn evals_eq_hypercube(
        out: &mut DeviceBuffer<Self::ValExt>,
        xs: &[Self::ValExt],
    ) -> Result<(), crate::KernelError> {
        use crate::runtime::copy::MemCopyH2D;
        use p3_field::PrimeCharacteristicRing;
        let n = xs.len();
        assert!(out.len() >= 1 << n);
        [Self::ValExt::ONE]
            .copy_to(out)
            .map_err(crate::KernelError::MemCopy)?;
        for (i, &x_i) in xs.iter().enumerate() {
            let step = 1u32 << i;
            Self::eq_hypercube_stage_ext(out.as_mut_ptr(), x_i, step)
                .map_err(crate::KernelError::Kernel)?;
        }
        Ok(())
    }
}

use crate::prelude::{EF, F};

// ─────────────────────────────────────────────────────────────────────────────
// KoalaBear implementation
// ─────────────────────────────────────────────────────────────────────────────

pub use kb_kernels::KoalaBearKernels;

mod kb_kernels {
    use super::*;
    use crate::{
        cuda::{
            logup_zerocheck_kb, matrix_kb, mle_interpolate_kb, poly_kb, stacked_reduction_kb,
            sumcheck_kb, whir_kb,
        },
        prelude::{EF, F},
    };

    /// KoalaBear kernel implementation — delegates to `cuda_kb_all` static library.
    #[derive(Copy, Clone, Debug, Default)]
    pub struct KoalaBearKernels;

    impl FieldKernels for KoalaBearKernels {
        type Val = F;
        type ValExt = EF;

        fn use_cpu_gkr() -> bool {
            // GPU KB GKR sumcheck now works: the earlier failures were caused by a uint64
            // overflow in recip_b0() (KB extension-field inverse), fixed in
            // third_party/sppark/ff/koala_bear_ext.hpp. Verified by test_kb_gkr_gpu_vs_cpu_*.
            false
        }

        fn use_cpu_gkr_input_eval() -> bool {
            // GPU KB logup_gkr_input_eval is correct: verified byte-identical to CPU for all
            // 15 reth188 AIRs (incl. multi-partition, num_int up to 35, 146M fracs) via
            // MLE_VERIFY_INPUT_EVAL. The earlier "multi-partition bug" was a misdiagnosis;
            // the real root cause was the recip_b0 overflow (now fixed). GPU path removes the
            // ~17s/chunk CPU input-eval bottleneck.
            false
        }

        fn use_cpu_zerocheck_mle() -> bool {
            // GPU per-round logup/zerocheck MLE + round0 + fold now correct after fixing:
            // (1) recip_b0 uint64 overflow, (2) uninitialized KB DEVICE_NTT_TWIDDLES (round0
            // coset NTT), (3) monomial batch MLE kernels dispatching to BB instead of _kb.
            // Verified: test_kb_fib/interactions_roundtrip + full KB suite pass with this false.
            false
        }

        unsafe fn stacked_r0_temp_buf_size(height: u32, width: u32, l_skip: u32) -> u32 {
            stacked_reduction_kb::_kb_stacked_reduction_r0_required_temp_buffer_size(
                height, width, l_skip,
            )
        }

        unsafe fn stacked_sumcheck_round0(
            eq_segs: &EqEvalSegments<EF>,
            trace_cols: *const F,
            lambda_powers: *const EF,
            block_sums: &mut DeviceBuffer<EF>,
            output: &mut DeviceBuffer<EF>,
            height: usize,
            width: usize,
            l_skip: usize,
        ) -> Result<(), CudaError> {
            stacked_reduction_kb::stacked_reduction_sumcheck_round0(
                eq_segs,
                trace_cols,
                lambda_powers,
                block_sums,
                output,
                height,
                width,
                l_skip,
            )
        }

        unsafe fn stacked_fold_ple(
            src: *const F,
            dst: *mut EF,
            omega_skip_pows: &DeviceBuffer<F>,
            inv_lagrange_denoms: &DeviceBuffer<EF>,
            trace_height: usize,
            trace_width: usize,
            l_skip: usize,
        ) -> Result<(), CudaError> {
            stacked_reduction_kb::stacked_reduction_fold_ple(
                src,
                dst,
                omega_skip_pows,
                inv_lagrange_denoms,
                trace_height,
                trace_width,
                l_skip,
            )
        }

        unsafe fn init_k_rot_from_eq_segments(
            eq_r_ns: &EqEvalSegments<EF>,
            k_rot_ns: &mut DeviceBuffer<EF>,
            k_rot_uni_0: EF,
            k_rot_uni_1: EF,
            max_n: u32,
        ) -> Result<(), CudaError> {
            stacked_reduction_kb::initialize_k_rot_from_eq_segments(
                eq_r_ns,
                k_rot_ns,
                k_rot_uni_0,
                k_rot_uni_1,
                max_n,
            )
        }

        unsafe fn stacked_sumcheck_mle_round(
            q_cols: &DeviceBuffer<*const EF>,
            eq_segs: &EqEvalSegments<EF>,
            k_rot_segs: &EqEvalSegments<EF>,
            col_slices: *const UnstackedSlice,
            lambda_powers: *const EF,
            output: *mut u64,
            q_height: usize,
            window_len: usize,
            num_y: usize,
            sm_count: u32,
        ) -> Result<(), CudaError> {
            stacked_reduction_kb::stacked_reduction_sumcheck_mle_round(
                q_cols,
                eq_segs,
                k_rot_segs,
                col_slices,
                lambda_powers,
                output,
                q_height,
                window_len,
                num_y,
                sm_count,
            )
        }

        unsafe fn stacked_sumcheck_mle_round_degenerate(
            q_cols: &DeviceBuffer<*const EF>,
            eq_ub: *const EF,
            eq_r: EF,
            k_rot_r: EF,
            col_slices: *const UnstackedSlice,
            lambda_powers: *const EF,
            output: *mut u64,
            q_height: usize,
            window_len: usize,
            l_skip: usize,
            round: usize,
        ) -> Result<(), CudaError> {
            stacked_reduction_kb::stacked_reduction_sumcheck_mle_round_degenerate(
                q_cols,
                eq_ub,
                eq_r,
                k_rot_r,
                col_slices,
                lambda_powers,
                output,
                q_height,
                window_len,
                l_skip,
                round,
            )
        }

        fn vector_scalar_multiply_ext(
            vec: &mut DeviceBuffer<EF>,
            scalar: EF,
        ) -> Result<(), CudaError> {
            poly_kb::vector_scalar_multiply_ext(vec, scalar)
        }

        unsafe fn fold_mle(
            input_matrices: &DeviceBuffer<*const EF>,
            output_matrices: &DeviceBuffer<*mut EF>,
            widths: &DeviceBuffer<u32>,
            num_matrices: u16,
            output_height: u32,
            max_output_cells: u32,
            r_val: EF,
        ) -> Result<(), CudaError> {
            sumcheck_kb::fold_mle(
                input_matrices,
                output_matrices,
                widths,
                num_matrices,
                output_height,
                max_output_cells,
                r_val,
            )
        }

        unsafe fn triangular_fold_mle(
            output: &mut EqEvalSegments<EF>,
            input: &EqEvalSegments<EF>,
            r: EF,
            output_max_n: usize,
        ) -> Result<(), CudaError> {
            sumcheck_kb::triangular_fold_mle(output, input, r, output_max_n)
        }

        unsafe fn fold_selectors_round0(
            out: *mut EF,
            input: *const F,
            is_first: EF,
            is_last: EF,
            num_x: usize,
        ) -> Result<(), CudaError> {
            logup_zerocheck_kb::fold_selectors_round0_kb(out, input, is_first, is_last, num_x)
        }

        unsafe fn interpolate_columns_gpu(
            interpolated: &DeviceBuffer<EF>,
            columns: &DeviceBuffer<*const EF>,
            s_deg: usize,
            num_y: usize,
        ) -> Result<(), CudaError> {
            logup_zerocheck_kb::interpolate_columns_gpu_kb(interpolated, columns, s_deg, num_y)
        }

        unsafe fn batch_fold_mle(
            input_matrices: &DeviceBuffer<*const EF>,
            output_matrices: &DeviceBuffer<*mut EF>,
            widths: &DeviceBuffer<u32>,
            num_matrices: u16,
            log_output_heights: &DeviceBuffer<u8>,
            max_output_cells: u32,
            r_val: EF,
        ) -> Result<(), CudaError> {
            sumcheck_kb::batch_fold_mle(
                input_matrices,
                output_matrices,
                widths,
                num_matrices,
                log_output_heights,
                max_output_cells,
                r_val,
            )
        }

        unsafe fn whir_algebraic_batch_traces(
            output: &mut DeviceBuffer<F>,
            packets: &DeviceBuffer<BatchingTracePacket<F>>,
            mu_powers: &DeviceBuffer<EF>,
        ) -> Result<(), CudaError> {
            whir_kb::whir_algebraic_batch_traces(output, packets, mu_powers)
        }

        fn whir_sumcheck_coeff_moments_required_temp_buffer_size(height: u32) -> u32 {
            unsafe { whir_kb::_kb_whir_sumcheck_coeff_moments_required_temp_buffer_size(height) }
        }

        unsafe fn whir_sumcheck_coeff_moments_round(
            f_coeffs: &DeviceBuffer<EF>,
            w_moments: &DeviceBuffer<EF>,
            output: &mut DeviceBuffer<EF>,
            tmp_block_sums: &mut DeviceBuffer<EF>,
            height: u32,
        ) -> Result<(), CudaError> {
            whir_kb::whir_sumcheck_coeff_moments_round(
                f_coeffs,
                w_moments,
                output,
                tmp_block_sums,
                height,
            )
        }

        unsafe fn whir_fold_coeffs_and_moments(
            f_coeffs: &DeviceBuffer<EF>,
            w_moments: &DeviceBuffer<EF>,
            f_folded: &mut DeviceBuffer<EF>,
            w_folded: &mut DeviceBuffer<EF>,
            alpha: EF,
            height: u32,
        ) -> Result<(), CudaError> {
            whir_kb::whir_fold_coeffs_and_moments(
                f_coeffs, w_moments, f_folded, w_folded, alpha, height,
            )
        }

        unsafe fn w_moments_accumulate(
            w_moments: &mut DeviceBuffer<EF>,
            z0_pows2: &DeviceBuffer<EF>,
            z_pows2: &DeviceBuffer<F>,
            gamma: EF,
            num_queries: u32,
            log_height: u32,
        ) -> Result<(), CudaError> {
            whir_kb::w_moments_accumulate(
                w_moments,
                z0_pows2,
                z_pows2,
                gamma,
                num_queries,
                log_height,
            )
        }

        unsafe fn batch_expand_pad(
            output: *mut F,
            input: *const F,
            poly_count: u32,
            out_size: u32,
            in_size: u32,
        ) -> Result<(), CudaError> {
            matrix_kb::batch_expand_pad(output, input, poly_count, out_size, in_size)
        }

        unsafe fn split_ext_to_base_col_major_matrix(
            d_matrix: &mut DeviceBuffer<F>,
            d_poly: &DeviceBuffer<EF>,
            poly_len: u64,
            matrix_height: u32,
        ) -> Result<(), CudaError> {
            matrix_kb::split_ext_to_base_col_major_matrix(d_matrix, d_poly, poly_len, matrix_height)
        }

        unsafe fn mle_interpolate_stage_ext(
            buffer: &mut DeviceBuffer<EF>,
            step: u32,
            is_eval_to_coeff: bool,
        ) -> Result<(), CudaError> {
            mle_interpolate_kb::mle_interpolate_stage_ext(buffer, step, is_eval_to_coeff)
        }

        unsafe fn eval_poly_ext_at_point_from_base(
            base_coeffs: &DeviceBuffer<F>,
            coeff_len: usize,
            x: EF,
        ) -> Result<EF, crate::KernelError> {
            let result = poly_kb::eval_poly_ext_at_point_from_base(base_coeffs, coeff_len, x)?;
            Ok(result)
        }

        unsafe fn transpose_fp_to_fpext_vec(
            output: &mut DeviceBuffer<EF>,
            input: &DeviceBuffer<F>,
        ) -> Result<(), CudaError> {
            poly_kb::transpose_fp_to_fpext_vec(output, input)
        }

        unsafe fn eq_hypercube_stage_ext(
            out: *mut EF,
            x_i: EF,
            step: u32,
        ) -> Result<(), CudaError> {
            poly_kb::eq_hypercube_stage_ext(out, x_i, step)
        }

        unsafe fn eq_hypercube_nonoverlapping_stage_ext(
            out: *mut EF,
            input: *const EF,
            x_i: EF,
            step: u32,
        ) -> Result<(), CudaError> {
            poly_kb::eq_hypercube_nonoverlapping_stage_ext(out, input, x_i, step)
        }

        unsafe fn eq_hypercube_interleaved_stage_ext(
            out: *mut EF,
            input: *const EF,
            x_i: EF,
            step: u32,
        ) -> Result<(), CudaError> {
            poly_kb::eq_hypercube_interleaved_stage_ext(out, input, x_i, step)
        }

        // ─── GKR fractional sumcheck kernels (KoalaBear) ─────────────────────────

        unsafe fn frac_compute_round_temp_buffer_size(stride: u32) -> u32 {
            logup_zerocheck_kb::_kb_frac_compute_round_temp_buffer_size(stride)
        }

        unsafe fn frac_build_tree_layer(
            layer: &mut DeviceBuffer<Frac<EF>>,
            layer_size: usize,
            revert: bool,
            alpha: EF,
            apply_alpha: bool,
        ) -> Result<(), CudaError> {
            // SAFETY: Frac<EF> and Frac<EF> have identical memory layout ([u32;8]).
            logup_zerocheck_kb::frac_build_tree_layer_kb(
                layer,
                layer_size,
                revert,
                alpha,
                apply_alpha,
            )
        }

        unsafe fn frac_build_tree_two_layers(
            layer: &mut DeviceBuffer<Frac<EF>>,
            half_i1: usize,
        ) -> Result<(), CudaError> {
            logup_zerocheck_kb::frac_build_tree_two_layers_kb(layer, half_i1)
        }

        unsafe fn frac_compute_round(
            eq_xi: &SqrtEqLayersFor<EF>,
            pq_buffer: &DeviceBuffer<Frac<EF>>,
            num_x: usize,
            lambda: EF,
            out_device: &mut DeviceBuffer<EF>,
            tmp_block_sums: &mut DeviceBuffer<EF>,
        ) -> Result<(), CudaError> {
            logup_zerocheck_kb::frac_compute_round_kb(
                eq_xi,
                pq_buffer,
                num_x,
                lambda,
                out_device,
                tmp_block_sums,
            )
        }

        unsafe fn frac_compute_round_and_revert(
            eq_xi: &mut SqrtEqLayersFor<EF>,
            layer: &mut DeviceBuffer<Frac<EF>>,
            num_x: usize,
            lambda: EF,
            out_device: &mut DeviceBuffer<EF>,
            tmp_block_sums: &mut DeviceBuffer<EF>,
        ) -> Result<(), CudaError> {
            logup_zerocheck_kb::frac_compute_round_and_revert_kb(
                eq_xi,
                layer,
                num_x,
                lambda,
                out_device,
                tmp_block_sums,
            )
        }

        unsafe fn fold_ef_frac_columns(
            src: &DeviceBuffer<Frac<EF>>,
            dst: *mut Frac<EF>,
            size: usize,
            r: EF,
        ) -> Result<(), CudaError> {
            logup_zerocheck_kb::fold_ef_frac_columns_raw_kb(src, dst as *mut Frac<EF>, size, r)
        }

        unsafe fn fold_ef_frac_columns_inplace(
            pq_buffer: &mut DeviceBuffer<Frac<EF>>,
            size: usize,
            r: EF,
        ) -> Result<(), CudaError> {
            logup_zerocheck_kb::fold_ef_frac_columns_inplace_kb(pq_buffer, size, r)
        }

        unsafe fn frac_compute_round_and_fold(
            eq_xi: &mut SqrtEqLayersFor<EF>,
            src_pq_buffer: &DeviceBuffer<Frac<EF>>,
            dst_pq_buffer: &mut DeviceBuffer<Frac<EF>>,
            src_pq_size: usize,
            lambda: EF,
            r_prev: EF,
            out_device: &mut DeviceBuffer<EF>,
            tmp_block_sums: &mut DeviceBuffer<EF>,
        ) -> Result<(), CudaError> {
            logup_zerocheck_kb::frac_compute_round_and_fold_kb(
                eq_xi,
                src_pq_buffer,
                dst_pq_buffer,
                src_pq_size,
                lambda,
                r_prev,
                out_device,
                tmp_block_sums,
            )
        }

        unsafe fn frac_compute_round_and_fold_inplace(
            eq_xi: &mut SqrtEqLayersFor<EF>,
            pq_buffer: &mut DeviceBuffer<Frac<EF>>,
            src_pq_size: usize,
            lambda: EF,
            r_prev: EF,
            out_device: &mut DeviceBuffer<EF>,
            tmp_block_sums: &mut DeviceBuffer<EF>,
        ) -> Result<(), CudaError> {
            logup_zerocheck_kb::frac_compute_round_and_fold_inplace_kb(
                eq_xi,
                pq_buffer,
                src_pq_size,
                lambda,
                r_prev,
                out_device,
                tmp_block_sums,
            )
        }

        unsafe fn frac_precompute_m_build_raw(
            pq: *const Frac<EF>,
            rem_n: usize,
            w: usize,
            lambda: EF,
            r_prev: EF,
            inline_fold: bool,
            tail_eq_lo: *const EF,
            tail_eq_hi: *const EF,
            tail_lo_cap: usize,
            tail_tile: usize,
            partials_out: *mut EF,
            partial_len: usize,
            m_total: *mut EF,
        ) -> Result<(), CudaError> {
            logup_zerocheck_kb::frac_precompute_m_build_raw_kb(
                pq as *const Frac<EF>,
                rem_n,
                w,
                lambda,
                r_prev,
                inline_fold,
                tail_eq_lo,
                tail_eq_hi,
                tail_lo_cap,
                tail_tile,
                partials_out,
                partial_len,
                m_total,
            )
        }

        unsafe fn frac_precompute_m_eval_round_raw(
            m_total: *const EF,
            w: usize,
            t: usize,
            eq_r_prefix: *const EF,
            eq_suffix: *const EF,
            out: *mut EF,
        ) -> Result<(), CudaError> {
            logup_zerocheck_kb::frac_precompute_m_eval_round_raw_kb(
                m_total,
                w,
                t,
                eq_r_prefix,
                eq_suffix,
                out,
            )
        }

        unsafe fn frac_multifold_raw(
            src: *const Frac<EF>,
            dst: *mut Frac<EF>,
            rem_n: usize,
            w: usize,
            eq_r_window: *const EF,
        ) -> Result<(), CudaError> {
            logup_zerocheck_kb::frac_multifold_raw_kb(
                src as *const Frac<EF>,
                dst as *mut Frac<EF>,
                rem_n,
                w,
                eq_r_window,
            )
        }

        unsafe fn frac_add_alpha(
            data: &DeviceBuffer<Frac<EF>>,
            alpha: EF,
        ) -> Result<(), CudaError> {
            logup_zerocheck_kb::frac_add_alpha_kb(data, alpha)
        }

        unsafe fn bit_rev_frac_ext(
            d_out: &DeviceBuffer<(EF, EF)>,
            d_inp: &DeviceBuffer<(EF, EF)>,
            lg_domain_size: u32,
            padded_poly_size: u32,
            poly_count: u32,
        ) -> Result<(), CudaError> {
            crate::cuda::ntt_kb::kb_bit_rev_frac_ext(
                d_out,
                d_inp,
                lg_domain_size,
                padded_poly_size,
                poly_count,
            )
        }

        unsafe fn bit_rev_frac_ext_build_k2(
            inout: &DeviceBuffer<(EF, EF)>,
            lg_domain_size: u32,
            alpha: EF,
        ) -> Result<(), CudaError> {
            // The gkr.cu kernel, which applies alpha with KB field arithmetic.
            crate::cuda::logup_zerocheck_kb::gkr_bit_rev_frac_ext_build_k2_kb(
                inout,
                lg_domain_size,
                alpha,
            )
        }
        // ── logup: missing methods ──────────────────────────────────────────────
        unsafe fn frac_vector_scalar_multiply_ext_fp(
            frac_vec: &mut DeviceBuffer<Frac<EF>>,
            scalar: F,
        ) -> Result<(), CudaError> {
            crate::cuda::logup_zerocheck_kb::frac_vector_scalar_multiply_ext_fp_kb(
                frac_vec.as_mut_ptr(),
                scalar,
                frac_vec.len() as u32,
            )
        }
        unsafe fn frac_matrix_vertically_repeat(
            out: *mut Frac<EF>,
            input: &DeviceBuffer<Frac<EF>>,
            w: u32,
            lh: u32,
            h: u32,
        ) -> Result<(), CudaError> {
            crate::cuda::logup_zerocheck_kb::frac_matrix_vertically_repeat_kb(
                out as *mut Frac<EF>,
                input.as_ptr(),
                w,
                lh,
                h,
            )
        }
        unsafe fn frac_matrix_vertically_repeat_ext(
            on: *mut EF,
            od: *mut EF,
            in_n: *const EF,
            in_d: *const EF,
            w: u32,
            lh: u32,
            h: u32,
        ) -> Result<(), CudaError> {
            crate::cuda::logup_zerocheck_kb::frac_matrix_vertically_repeat_ext_kb(
                on, od, in_n, in_d, w, lh, h,
            )
        }
        // ── Monomial-basis batch MLE: dispatch to KB kernels (args already EF-typed) ──
        unsafe fn zerocheck_monomial_batched(
            tmp_sums: &mut DeviceBuffer<EF>,
            output: &mut DeviceBuffer<EF>,
            block_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::BlockCtx>,
            air_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::MonomialAirCtx>,
            air_block_offsets: &DeviceBuffer<u32>,
            num_blocks: u32,
            num_x: u32,
            num_airs: u32,
            threads_per_block: u32,
        ) -> Result<(), CudaError> {
            crate::cuda::logup_zerocheck_kb::zerocheck_monomial_batched_kb(
                tmp_sums,
                output,
                block_ctxs,
                air_ctxs,
                air_block_offsets,
                num_blocks,
                num_x,
                num_airs,
                threads_per_block,
            )
        }
        unsafe fn zerocheck_monomial_par_y_batched(
            tmp_sums: &mut DeviceBuffer<EF>,
            output: &mut DeviceBuffer<EF>,
            block_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::BlockCtx>,
            air_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::MonomialAirCtx>,
            air_block_offsets: &DeviceBuffer<u32>,
            num_blocks: u32,
            num_x: u32,
            num_airs: u32,
            chunk_size: u32,
            threads_per_block: u32,
        ) -> Result<(), CudaError> {
            crate::cuda::logup_zerocheck_kb::zerocheck_monomial_par_y_batched_kb(
                tmp_sums,
                output,
                block_ctxs,
                air_ctxs,
                air_block_offsets,
                num_blocks,
                num_x,
                num_airs,
                chunk_size,
                threads_per_block,
            )
        }
        unsafe fn logup_monomial_batched(
            tmp_sums: &mut DeviceBuffer<Frac<EF>>,
            output: &mut DeviceBuffer<Frac<EF>>,
            block_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::BlockCtx>,
            common_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::LogupMonomialCommonCtx>,
            numer_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::LogupMonomialCtx>,
            denom_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::LogupMonomialCtx>,
            air_block_offsets: &DeviceBuffer<u32>,
            num_blocks: u32,
            num_x: u32,
            num_airs: u32,
            threads_per_block: u32,
        ) -> Result<(), CudaError> {
            crate::cuda::logup_zerocheck_kb::logup_monomial_batched_kb(
                tmp_sums,
                output,
                block_ctxs,
                common_ctxs,
                numer_ctxs,
                denom_ctxs,
                air_block_offsets,
                num_blocks,
                num_x,
                num_airs,
                threads_per_block,
            )
        }
        unsafe fn zerocheck_batch_eval_mle(
            tmp_sums_buffer: &mut DeviceBuffer<EF>,
            output: &mut DeviceBuffer<EF>,
            block_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::BlockCtx>,
            zc_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::ZerocheckCtx>,
            air_block_offsets: &DeviceBuffer<u32>,
            lambda_pows: &DeviceBuffer<EF>,
            lambda_len: usize,
            num_blocks: u32,
            num_x: u32,
            num_airs: u32,
            threads_per_block: u32,
        ) -> Result<(), CudaError> {
            crate::cuda::logup_zerocheck_kb::zerocheck_batch_eval_mle_kb(
                tmp_sums_buffer,
                output,
                block_ctxs,
                zc_ctxs,
                air_block_offsets,
                lambda_pows,
                lambda_len,
                num_blocks,
                num_x,
                num_airs,
                threads_per_block,
            )
        }
        unsafe fn logup_batch_eval_mle(
            tmp_sums_buffer: &mut DeviceBuffer<Frac<EF>>,
            output: &mut DeviceBuffer<Frac<EF>>,
            block_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::BlockCtx>,
            logup_ctxs: &DeviceBuffer<crate::cuda::logup_zerocheck::LogupCtx>,
            air_block_offsets: &DeviceBuffer<u32>,
            num_blocks: u32,
            num_x: u32,
            num_airs: u32,
            threads_per_block: u32,
        ) -> Result<(), CudaError> {
            crate::cuda::logup_zerocheck_kb::logup_batch_eval_mle_kb(
                tmp_sums_buffer,
                output,
                block_ctxs,
                logup_ctxs,
                air_block_offsets,
                num_blocks,
                num_x,
                num_airs,
                threads_per_block,
            )
        }
        unsafe fn fold_ple_from_evals(
            input: &DeviceBuffer<F>,
            output: *mut EF,
            omega: &DeviceBuffer<F>,
            ild: &DeviceBuffer<EF>,
            h: u32,
            w: u32,
            ls: u32,
            nh: u32,
            rot: bool,
        ) -> Result<(), CudaError> {
            crate::cuda::logup_zerocheck_kb::fold_ple_from_evals_kb(
                input, output, omega, ild, h, w, ls, nh, rot,
            )
        }
        unsafe fn logup_gkr_input_eval(
            is_g: bool,
            fracs: *mut Frac<EF>,
            prep: &DeviceBuffer<F>,
            pm: &DeviceBuffer<u64>,
            pv: &DeviceBuffer<F>,
            ch: &DeviceBuffer<EF>,
            inter: &DeviceBuffer<EF>,
            rules: &DeviceBuffer<u128>,
            un: &DeviceBuffer<usize>,
            pi: &DeviceBuffer<u32>,
            h: u32,
            nrpt: u32,
        ) -> Result<(), CudaError> {
            crate::cuda::logup_zerocheck_kb::logup_gkr_input_eval_kb(
                is_g,
                fracs as *mut Frac<EF>,
                prep,
                pm,
                pv,
                ch,
                inter,
                rules,
                un,
                pi,
                h,
                nrpt,
            )
        }
        fn logup_r0_temp_sums_buffer_size(b: u32, s: u32, x: u32, c: u32, m: usize) -> usize {
            unsafe {
                crate::cuda::logup_zerocheck_kb::_kb_logup_r0_temp_sums_buffer_size(b, s, x, c, m)
            }
        }
        fn logup_r0_intermediates_buffer_size(b: u32, s: u32, x: u32, c: u32, m: usize) -> usize {
            unsafe {
                crate::cuda::logup_zerocheck_kb::_kb_logup_r0_intermediates_buffer_size(
                    b, s, x, c, m,
                )
            }
        }
        fn zerocheck_r0_temp_sums_buffer_size(b: u32, s: u32, x: u32, c: u32, m: usize) -> usize {
            unsafe {
                crate::cuda::logup_zerocheck_kb::_kb_zerocheck_r0_temp_sums_buffer_size(
                    b, s, x, c, m,
                )
            }
        }
        fn zerocheck_r0_intermediates_buffer_size(
            b: u32,
            s: u32,
            x: u32,
            c: u32,
            m: usize,
        ) -> usize {
            unsafe {
                crate::cuda::logup_zerocheck_kb::_kb_zerocheck_r0_intermediates_buffer_size(
                    b, s, x, c, m,
                )
            }
        }
        fn zerocheck_mle_temp_sums_buffer_size(x: u32, y: u32) -> usize {
            unsafe {
                crate::cuda::logup_zerocheck_kb::_kb_zerocheck_mle_temp_sums_buffer_size(x, y)
            }
        }
        fn zerocheck_mle_intermediates_buffer_size(b: u32, x: u32, y: u32) -> usize {
            unsafe {
                crate::cuda::logup_zerocheck_kb::_kb_zerocheck_mle_intermediates_buffer_size(
                    b, x, y,
                )
            }
        }
        fn logup_mle_temp_sums_buffer_size(x: u32, y: u32) -> usize {
            unsafe { crate::cuda::logup_zerocheck_kb::_kb_logup_mle_temp_sums_buffer_size(x, y) }
        }
        fn logup_mle_intermediates_buffer_size(b: u32, x: u32, y: u32) -> usize {
            unsafe {
                crate::cuda::logup_zerocheck_kb::_kb_logup_mle_intermediates_buffer_size(b, x, y)
            }
        }
        fn zerocheck_batch_mle_intermediates_buffer_size(b: u32, x: u32, y: u32) -> usize {
            unsafe {
                crate::cuda::logup_zerocheck_kb::_kb_zerocheck_batch_mle_intermediates_buffer_size(
                    b, x, y,
                )
            }
        }
        fn logup_batch_mle_intermediates_buffer_size(b: u32, x: u32, y: u32) -> usize {
            unsafe {
                crate::cuda::logup_zerocheck_kb::_kb_logup_batch_mle_intermediates_buffer_size(
                    b, x, y,
                )
            }
        }
        unsafe fn zerocheck_ntt_eval_constraints(
            ts: &mut DeviceBuffer<EF>,
            out: &mut DeviceBuffer<EF>,
            sel: &DeviceBuffer<F>,
            prep: *const F,
            main: &DeviceBuffer<*const F>,
            eq: *const EF,
            lp: &DeviceBuffer<EF>,
            pv: &DeviceBuffer<F>,
            rules: &DeviceBuffer<u128>,
            un: &DeviceBuffer<usize>,
            bs: u32,
            inter: &mut DeviceBuffer<F>,
            sd: u32,
            nx: u32,
            h: u32,
            nc: u32,
            gs: F,
            mt: usize,
        ) -> Result<(), CudaError> {
            crate::cuda::logup_zerocheck_kb::zerocheck_ntt_eval_constraints_kb(
                ts, out, sel, prep, main, eq, lp, pv, rules, un, bs, inter, sd, nx, h, nc, gs, mt,
            )
        }
        unsafe fn logup_bary_eval_interactions_round0(
            ts: &mut DeviceBuffer<Frac<EF>>,
            out: &mut DeviceBuffer<Frac<EF>>,
            sel: &DeviceBuffer<F>,
            prep: *const F,
            main: &DeviceBuffer<*const F>,
            eq: *const EF,
            pv: &DeviceBuffer<F>,
            nw: &DeviceBuffer<EF>,
            dw: &DeviceBuffer<EF>,
            dsi: EF,
            rules: &DeviceBuffer<u128>,
            bs: u32,
            inter: &mut DeviceBuffer<F>,
            sd: u32,
            nx: u32,
            h: u32,
            nc: u32,
            gs: F,
            mt: usize,
        ) -> Result<(), CudaError> {
            crate::cuda::logup_zerocheck_kb::logup_bary_eval_interactions_round0_kb(
                ts, out, sel, prep, main, eq, pv, nw, dw, dsi, rules, bs, inter, sd, nx, h, nc, gs,
                mt,
            )
        }
        unsafe fn zerocheck_eval_mle(
            ts: &mut DeviceBuffer<EF>,
            out: &mut DeviceBuffer<EF>,
            eq: *const EF,
            sel: *const EF,
            prep: MainMatrixPtrs<EF>,
            main: *const MainMatrixPtrs<EF>,
            lp: *const EF,
            ll: usize,
            pv: *const F,
            rules: *const std::ffi::c_void,
            rl: usize,
            un: *const usize,
            unl: usize,
            bs: u32,
            inter: &mut DeviceBuffer<EF>,
            ny: u32,
            nx: u32,
        ) -> Result<(), CudaError> {
            crate::cuda::logup_zerocheck_kb::zerocheck_eval_mle_kb(
                ts, out, eq, sel, prep, main, lp, ll, pv, rules, rl, un, unl, bs, inter, ny, nx,
            )
        }
        unsafe fn logup_eval_mle(
            ts: &mut DeviceBuffer<Frac<EF>>,
            out: &mut DeviceBuffer<Frac<EF>>,
            eq: *const EF,
            sel: *const EF,
            prep: MainMatrixPtrs<EF>,
            main: *const MainMatrixPtrs<EF>,
            ch: *const EF,
            e3b: *const EF,
            pv: *const F,
            rules: *const std::ffi::c_void,
            un: *const usize,
            pi: *const u32,
            unl: usize,
            bs: u32,
            inter: &mut DeviceBuffer<EF>,
            ny: u32,
            nx: u32,
        ) -> Result<(), CudaError> {
            crate::cuda::logup_zerocheck_kb::logup_eval_mle_kb(
                ts, out, eq, sel, prep, main, ch, e3b, pv, rules, un, pi, unl, bs, inter, ny, nx,
            )
        }

        unsafe fn precompute_lambda_combinations(
            out: &mut DeviceBuffer<EF>,
            headers: *const crate::monomial::MonomialHeader,
            lambda_terms: *const crate::monomial::LambdaTerm<F>,
            lambda_pows: &DeviceBuffer<EF>,
            num_monomials: u32,
        ) -> Result<(), CudaError> {
            crate::cuda::logup_zerocheck_kb::precompute_lambda_combinations_kb(
                out,
                headers,
                lambda_terms as *const crate::monomial::LambdaTerm<F>,
                lambda_pows,
                num_monomials,
            )
        }
        unsafe fn precompute_logup_numer_combinations(
            out: &mut DeviceBuffer<EF>,
            headers: *const crate::monomial::MonomialHeader,
            terms: *const crate::monomial::InteractionMonomialTerm<F>,
            eq_3bs: &DeviceBuffer<EF>,
            num_monomials: u32,
        ) -> Result<(), CudaError> {
            crate::cuda::logup_zerocheck_kb::precompute_logup_numer_combinations_kb(
                out,
                headers,
                terms as *const crate::monomial::InteractionMonomialTerm<F>,
                eq_3bs,
                num_monomials,
            )
        }
        unsafe fn precompute_logup_denom_combinations(
            out: &mut DeviceBuffer<EF>,
            headers: *const crate::monomial::MonomialHeader,
            terms: *const crate::monomial::InteractionMonomialTerm<F>,
            beta_pows: &DeviceBuffer<EF>,
            eq_3bs: &DeviceBuffer<EF>,
            num_monomials: u32,
        ) -> Result<(), CudaError> {
            crate::cuda::logup_zerocheck_kb::precompute_logup_denom_combinations_kb(
                out,
                headers,
                terms as *const crate::monomial::InteractionMonomialTerm<F>,
                beta_pows,
                eq_3bs,
                num_monomials,
            )
        }
    }
}
