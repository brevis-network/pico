use std::ffi::c_void;

use super::*;
use crate::{
    cuda::logup_zerocheck::{
        BlockCtx, EvalCoreCtx, LogupCtx, LogupMonomialCommonCtx, LogupMonomialCtx, MainMatrixPtrs,
        MonomialAirCtx, ZerocheckCtx,
    },
    monomial::{InteractionMonomialTerm, LambdaTerm, MonomialHeader, PackedVar},
    poly::SqrtEqLayers,
};

#[link(name = "cuda_kb_all", kind = "static")]
extern "C" {
    // ---- gkr.cu ----
    // Bit-reversal plus tree build, computed with KoalaBear arithmetic. The `_kb_gkr_` name keeps
    // it apart from the `_kb_bit_rev_frac_ext_build_k2` stub in ntt_bitrev_kb.cu.
    fn _kb_gkr_bit_rev_frac_ext_build_k2(inout: *mut c_void, log_n: u32, alpha: EF) -> i32;

    fn _kb_frac_build_tree_layer(
        layer: *mut Frac<EF>,
        layer_len: usize,
        revert: bool,
        alpha: EF,
        apply_alpha: bool,
    ) -> i32;

    /// Builds tree layers i and i+1 in a single launch. The right-half nodes produced in between
    /// are kept so a later revert can undo them. `half_next = N >> (i + 2)`, with i the lower of
    /// the two layer indices.
    fn _kb_frac_build_tree_two_layers(layer: *mut Frac<EF>, half_next: usize) -> i32;

    pub fn _kb_frac_compute_round_temp_buffer_size(stride: u32) -> u32;

    fn _kb_frac_compute_round(
        eq_lo: *const EF,
        eq_hi: *const EF,
        pq_buf: *const Frac<EF>,
        num_x: usize,
        eq_lo_cap: usize,
        lambda: EF,
        round_out: *mut EF,
        round_scratch: *mut EF,
    ) -> i32;

    /// Round computation of the first inner round merged with a reverting tree-layer pass (what
    /// frac_build_tree_layer with revert=true does). The revert rewrites `layer` in place.
    fn _kb_frac_compute_round_and_revert(
        eq_lo: *const EF,
        eq_hi: *const EF,
        layer: *mut Frac<EF>,
        num_x: usize,
        eq_lo_cap: usize,
        lambda: EF,
        round_out: *mut EF,
        round_scratch: *mut EF,
    ) -> i32;

    fn _kb_frac_fold_fpext_columns(
        src: *const Frac<EF>,
        dst: *mut Frac<EF>,
        size: usize,
        r: EF,
    ) -> i32;

    /// Folds and computes the round sums in one pass, out of place: reads the unfolded `pq_src`
    /// (`pre_fold_len` entries) and writes the folded values to `pq_dst` (`pre_fold_len / 2`
    /// entries). The two buffers must be disjoint.
    fn _kb_frac_compute_round_and_fold(
        eq_lo: *const EF,
        eq_hi: *const EF,
        pq_src: *const Frac<EF>,
        pq_dst: *mut Frac<EF>,
        pre_fold_len: usize,
        eq_lo_cap: usize,
        lambda: EF,
        r_prev: EF,
        round_out: *mut EF,
        round_scratch: *mut EF,
    ) -> i32;

    /// In-place counterpart of the above: `pq_buf` holds `pre_fold_len` unfolded entries and the
    /// folded values overwrite its first `pre_fold_len / 2` entries.
    fn _kb_frac_compute_round_and_fold_inplace(
        eq_lo: *const EF,
        eq_hi: *const EF,
        pq_buf: *mut Frac<EF>,
        pre_fold_len: usize,
        eq_lo_cap: usize,
        lambda: EF,
        r_prev: EF,
        round_out: *mut EF,
        round_scratch: *mut EF,
    ) -> i32;

    fn _kb_frac_precompute_m_build(
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
        partials_len: usize,
        m_acc: *mut EF,
    ) -> i32;

    fn _kb_frac_precompute_m_eval_round(
        m_acc: *const EF,
        w: usize,
        t: usize,
        prefix_eq: *const EF,
        suffix_eq: *const EF,
        dest: *mut EF,
    ) -> i32;

    fn _kb_frac_multifold(
        src: *const Frac<EF>,
        dst: *mut Frac<EF>,
        rem_n: usize,
        w: usize,
        window_eq: *const EF,
    ) -> i32;

    fn _kb_frac_add_alpha(data: *mut c_void, len: usize, alpha: EF) -> i32;

    fn _kb_frac_vector_scalar_multiply_ext_fp(
        frac_data: *mut Frac<EF>,
        scalar: F,
        length: u32,
    ) -> i32;

    // ---- utils.cu ----
    fn _kb_fold_ple_from_evals(
        src_mat: *const F,
        dst_mat: *mut EF,
        skip_omega_pows: *const F,
        lagrange_inv_denoms: *const EF,
        height: u32,
        width: u32,
        l_skip: u32,
        new_height: u32,
        rotate: bool,
    ) -> i32;

    fn _kb_interpolate_columns(
        interp_out: *mut EF,
        col_ptrs: *const *const EF,
        deg_s: usize,
        num_y: usize,
        num_columns: usize,
    ) -> i32;

    fn _kb_frac_matrix_vertically_repeat(
        dest: *mut Frac<EF>,
        source: *const Frac<EF>,
        width: u32,
        lifted_height: u32,
        height: u32,
    ) -> i32;

    fn _kb_frac_matrix_vertically_repeat_ext(
        dst_numer: *mut EF,
        dst_denom: *mut EF,
        src_numer: *const EF,
        src_denom: *const EF,
        width: u32,
        lifted_height: u32,
        height: u32,
    ) -> i32;

    // ---- gkr_input.cu ----
    fn _kb_logup_gkr_input_eval(
        is_global: bool,
        fracs: *mut Frac<EF>,
        prep_mat: *const F,
        main_part_ptrs: *const u64,
        pub_vals: *const F,
        chal_vals: *const EF,
        node_scratch: *const EF,
        rule_buf: *const c_void,
        live_nodes: *const usize,
        pair_indices: *const u32,
        live_nodes_len: usize,
        height: u32,
        rows_per_tile: u32,
    ) -> i32;

    // ---- logup_round0.cu ----
    pub fn _kb_logup_r0_temp_sums_buffer_size(
        row_buf_nodes: u32,
        skip_domain: u32,
        num_x: u32,
        num_cosets: u32,
        temp_byte_cap: usize,
    ) -> usize;

    pub fn _kb_logup_r0_intermediates_buffer_size(
        row_buf_nodes: u32,
        skip_domain: u32,
        num_x: u32,
        num_cosets: u32,
        temp_byte_cap: usize,
    ) -> usize;

    fn _kb_logup_bary_eval_interactions_round0(
        block_partials: *mut Frac<EF>,
        sums_out: *mut Frac<EF>,
        sel_cube: *const F,
        prep_mat: *const F,
        main_mats: *const *const F,
        eq_hc: *const EF,
        pub_vals: *const F,
        numer_wts: *const EF,
        denom_wts: *const EF,
        denom_sum_init: EF,
        rule_buf: *const c_void,
        rule_count: usize,
        row_buf_nodes: u32,
        node_scratch: *mut F,
        skip_domain: u32,
        num_x: u32,
        height: u32,
        num_cosets: u32,
        coset_shift: F,
        temp_byte_cap: usize,
    ) -> i32;

    // ---- zerocheck_round0.cu ----
    pub fn _kb_zerocheck_r0_temp_sums_buffer_size(
        row_buf_nodes: u32,
        skip_domain: u32,
        num_x: u32,
        num_cosets: u32,
        temp_byte_cap: usize,
    ) -> usize;

    pub fn _kb_zerocheck_r0_intermediates_buffer_size(
        row_buf_nodes: u32,
        skip_domain: u32,
        num_x: u32,
        num_cosets: u32,
        temp_byte_cap: usize,
    ) -> usize;

    fn _kb_zerocheck_ntt_eval_constraints(
        block_partials: *mut EF,
        sums_out: *mut EF,
        sel_cube: *const F,
        prep_mat: *const F,
        main_mats: *const *const F,
        eq_hc: *const EF,
        lambda_powers: *const EF,
        pub_vals: *const F,
        rule_buf: *const c_void,
        rule_count: usize,
        live_nodes: *const usize,
        live_nodes_len: usize,
        lambda_len: usize,
        row_buf_nodes: u32,
        node_scratch: *mut F,
        skip_domain: u32,
        num_x: u32,
        height: u32,
        num_cosets: u32,
        coset_shift: F,
        temp_byte_cap: usize,
    ) -> i32;

    fn _kb_fold_selectors_round0(
        dest: *mut EF,
        source: *const F,
        is_first: EF,
        is_last: EF,
        num_x: u32,
    ) -> i32;

    // ---- eval_mle.cu ----
    pub fn _kb_zerocheck_mle_temp_sums_buffer_size(num_x: u32, num_y: u32) -> usize;

    pub fn _kb_zerocheck_mle_intermediates_buffer_size(
        row_buf_nodes: u32,
        num_x: u32,
        num_y: u32,
    ) -> usize;

    fn _kb_zerocheck_eval_mle(
        block_partials: *mut EF,
        sums_out: *mut EF,
        eq_tab: *const EF,
        sel_cols: *const EF,
        prep_mat: MainMatrixPtrs<EF>,
        main_mats: *const MainMatrixPtrs<EF>,
        lambda_powers: *const EF,
        pub_vals: *const F,
        rule_buf: *const c_void,
        rule_count: usize,
        live_nodes: *const usize,
        live_nodes_len: usize,
        lambda_len: usize,
        row_buf_nodes: u32,
        node_scratch: *mut EF,
        num_y: u32,
        num_x: u32,
    ) -> i32;

    pub fn _kb_logup_mle_temp_sums_buffer_size(num_x: u32, num_y: u32) -> usize;

    pub fn _kb_logup_mle_intermediates_buffer_size(
        row_buf_nodes: u32,
        num_x: u32,
        num_y: u32,
    ) -> usize;

    fn _kb_logup_eval_mle(
        block_partials: *mut Frac<EF>,
        sums_out: *mut Frac<EF>,
        eq_tab: *const EF,
        sel_cols: *const EF,
        prep_mat: MainMatrixPtrs<EF>,
        main_mats: *const MainMatrixPtrs<EF>,
        chal_vals: *const EF,
        eq_3b: *const EF,
        pub_vals: *const F,
        rule_buf: *const c_void,
        live_nodes: *const usize,
        pair_indices: *const u32,
        live_nodes_len: usize,
        row_buf_nodes: u32,
        node_scratch: *mut EF,
        num_y: u32,
        num_x: u32,
    ) -> i32;

    // ---- batch_mle.cu ----
    // Whenever row_buf_nodes > 0 the batched kernels keep node values in global memory.
    pub fn _kb_zerocheck_batch_mle_intermediates_buffer_size(
        row_buf_nodes: u32,
        num_x: u32,
        num_y: u32,
    ) -> usize;

    pub fn _kb_logup_batch_mle_intermediates_buffer_size(
        row_buf_nodes: u32,
        num_x: u32,
        num_y: u32,
    ) -> usize;

    fn _kb_zerocheck_batch_eval_mle(
        block_partials: *mut EF,
        sums_out: *mut EF,
        blk_ctxs: *const BlockCtx,
        zc_ctxs: *const ZerocheckCtx,
        air_blk_starts: *const u32,
        lambda_powers: *const EF,
        lambda_len: usize,
        grid_blocks: u32,
        num_x: u32,
        num_airs: u32,
        block_dim: u32,
    ) -> i32;

    fn _kb_logup_batch_eval_mle(
        block_partials: *mut Frac<EF>,
        sums_out: *mut Frac<EF>,
        blk_ctxs: *const BlockCtx,
        logup_ctxs: *const LogupCtx,
        air_blk_starts: *const u32,
        grid_blocks: u32,
        num_x: u32,
        num_airs: u32,
        block_dim: u32,
    ) -> i32;

    fn _kb_zerocheck_monomial_batched(
        block_partials: *mut EF,
        sums_out: *mut EF,
        blk_ctxs: *const BlockCtx,
        air_mono_ctxs: *const MonomialAirCtx,
        air_blk_starts: *const u32,
        grid_blocks: u32,
        num_x: u32,
        num_airs: u32,
        block_dim: u32,
    ) -> i32;

    fn _kb_zerocheck_monomial_par_y_batched(
        block_partials: *mut EF,
        sums_out: *mut EF,
        blk_ctxs: *const BlockCtx,
        air_mono_ctxs: *const MonomialAirCtx,
        air_blk_starts: *const u32,
        grid_blocks: u32,
        num_x: u32,
        num_airs: u32,
        chunk_size: u32,
        block_dim: u32,
    ) -> i32;

    fn _kb_precompute_lambda_combinations(
        dest: *mut EF,
        mono_headers: *const MonomialHeader,
        lambda_terms: *const LambdaTerm<F>,
        lambda_powers: *const EF,
        mono_count: u32,
    ) -> i32;

    // Monomial-form logup kernels.
    fn _kb_precompute_logup_numer_combinations(
        dest: *mut EF,
        mono_headers: *const MonomialHeader,
        inter_terms: *const InteractionMonomialTerm<F>,
        eq_3b: *const EF,
        mono_count: u32,
    ) -> i32;

    fn _kb_precompute_logup_denom_combinations(
        dest: *mut EF,
        mono_headers: *const MonomialHeader,
        inter_terms: *const InteractionMonomialTerm<F>,
        beta_powers: *const EF,
        eq_3b: *const EF,
        mono_count: u32,
    ) -> i32;

    fn _kb_logup_monomial_batched(
        block_partials: *mut Frac<EF>,
        sums_out: *mut Frac<EF>,
        blk_ctxs: *const BlockCtx,
        common_ctxs: *const LogupMonomialCommonCtx,
        numer_ctxs: *const LogupMonomialCtx,
        denom_ctxs: *const LogupMonomialCtx,
        air_blk_starts: *const u32,
        grid_blocks: u32,
        num_x: u32,
        num_airs: u32,
        block_dim: u32,
    ) -> i32;
}

pub unsafe fn interpolate_columns_gpu_kb(
    interp_out: &DeviceBuffer<EF>,
    col_ptrs: &DeviceBuffer<*const EF>,
    deg_s: usize,
    num_y: usize,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_interpolate_columns(
        interp_out.as_mut_ptr(),
        col_ptrs.as_ptr(),
        deg_s,
        num_y,
        col_ptrs.len(),
    ))
}

/// Bit-reversal followed by the tree build, using the KoalaBear extension arithmetic
/// (`FracExtKb` over `kb31_4_t`).
pub unsafe fn gkr_bit_rev_frac_ext_build_k2_kb(
    inout: &DeviceBuffer<(EF, EF)>,
    log_n: u32,
    alpha: EF,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_gkr_bit_rev_frac_ext_build_k2(
        inout.as_mut_raw_ptr(),
        log_n,
        alpha,
    ))
}

pub unsafe fn frac_build_tree_layer_kb(
    layer: &mut DeviceBuffer<Frac<EF>>,
    layer_len: usize,
    revert: bool,
    alpha: EF,
    apply_alpha: bool,
) -> Result<(), CudaError> {
    debug_assert!(layer.len() >= layer_len);
    CudaError::from_result(_kb_frac_build_tree_layer(
        layer.as_mut_ptr(),
        layer_len,
        revert,
        alpha,
        apply_alpha,
    ))
}

/// Builds two adjacent tree layers in one launch; `half_next = N >> (i + 2)` where i is the
/// lower of the two layers.
pub unsafe fn frac_build_tree_two_layers_kb(
    layer: &mut DeviceBuffer<Frac<EF>>,
    half_next: usize,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_frac_build_tree_two_layers(
        layer.as_mut_ptr(),
        half_next,
    ))
}

// The first hypercube coordinate has no entries in `eq_tab`: the prover pulls that eq factor out
// separately.
#[allow(clippy::too_many_arguments)]
pub unsafe fn frac_compute_round_kb(
    eq_tab: &SqrtEqLayers,
    pq_buf: &DeviceBuffer<Frac<EF>>,
    num_x: usize,
    lambda: EF,
    round_out: &mut DeviceBuffer<EF>,
    round_scratch: &mut DeviceBuffer<EF>,
) -> Result<(), CudaError> {
    let low_n = eq_tab.low_n();
    let high_n = eq_tab.high_n();
    debug_assert_eq!(2 << (low_n + high_n), num_x);
    debug_assert!(pq_buf.len() >= 2 * num_x);
    #[cfg(debug_assertions)]
    {
        let have = round_scratch.len();
        let need = _kb_frac_compute_round_temp_buffer_size(num_x.try_into().unwrap());
        assert!(
            have >= need as usize,
            "round scratch too small: {have} elements, kernel needs {need}"
        );
    }
    CudaError::from_result(_kb_frac_compute_round(
        eq_tab.low.get_ptr(low_n),
        eq_tab.high.get_ptr(high_n),
        pq_buf.as_ptr(),
        num_x,
        1 << low_n,
        lambda,
        round_out.as_mut_ptr(),
        round_scratch.as_mut_ptr(),
    ))
}

/// First inner round's `compute_round` merged with the reverting pass of
/// `frac_build_tree_layer(revert=true)`, saving a launch per outer round.
///
/// The revert updates `layer` in place, setting `layer[i] = layer[i] - layer[i + half]` for every
/// `i < half`.
#[allow(clippy::too_many_arguments)]
pub unsafe fn frac_compute_round_and_revert_kb(
    eq_tab: &SqrtEqLayers,
    layer: &mut DeviceBuffer<Frac<EF>>,
    num_x: usize,
    lambda: EF,
    round_out: &mut DeviceBuffer<EF>,
    round_scratch: &mut DeviceBuffer<EF>,
) -> Result<(), CudaError> {
    let low_n = eq_tab.low_n();
    let high_n = eq_tab.high_n();
    debug_assert_eq!(2 << (low_n + high_n), num_x);
    #[cfg(debug_assertions)]
    {
        let have = round_scratch.len();
        let need = _kb_frac_compute_round_temp_buffer_size(num_x.try_into().unwrap());
        assert!(
            have >= need as usize,
            "round scratch too small: {have} elements, kernel needs {need}"
        );
        assert!(layer.len() >= 2 * num_x, "layer shorter than 2 * num_x");
    }
    CudaError::from_result(_kb_frac_compute_round_and_revert(
        eq_tab.low.get_ptr(low_n),
        eq_tab.high.get_ptr(high_n),
        layer.as_mut_ptr(),
        num_x,
        1 << low_n,
        lambda,
        round_out.as_mut_ptr(),
        round_scratch.as_mut_ptr(),
    ))
}

/// Same fold as [`fold_ef_frac_columns_kb`], but writing through a raw device pointer `dst`.
pub unsafe fn fold_ef_frac_columns_raw_kb(
    src: &DeviceBuffer<Frac<EF>>,
    dst: *mut Frac<EF>,
    size: usize,
    r: EF,
) -> Result<(), CudaError> {
    debug_assert!(src.len() >= size);
    CudaError::from_result(_kb_frac_fold_fpext_columns(src.as_ptr(), dst, size, r))
}

/// [`fold_ef_frac_columns_kb`] with the result written back into `buffer`.
pub unsafe fn fold_ef_frac_columns_inplace_kb(
    buffer: &mut DeviceBuffer<Frac<EF>>,
    size: usize,
    r: EF,
) -> Result<(), CudaError> {
    debug_assert!(buffer.len() >= size);
    let ptr = buffer.as_mut_ptr();
    CudaError::from_result(_kb_frac_fold_fpext_columns(ptr, ptr, size, r))
}

/// Folds the previous round's challenge into the data while computing the next round.
///
/// The unfolded `pq_src` (`pre_fold_len` entries) is folded with `r_prev` as it is read; the
/// degree-2 round polynomial s' is evaluated from the folded values, which are also stored in
/// `pq_dst` (`pre_fold_len / 2` entries). Doing both in one pass saves a launch and a round trip
/// through memory for every inner round.
///
/// `eq_tab` must be built for max_n = log2(pre_fold_len / 4), i.e. log2 of num_x after folding.
#[allow(clippy::too_many_arguments)]
pub unsafe fn frac_compute_round_and_fold_kb(
    eq_tab: &SqrtEqLayers,
    pq_src: &DeviceBuffer<Frac<EF>>,
    pq_dst: &mut DeviceBuffer<Frac<EF>>,
    pre_fold_len: usize,
    lambda: EF,
    r_prev: EF,
    round_out: &mut DeviceBuffer<EF>,
    round_scratch: &mut DeviceBuffer<EF>,
) -> Result<(), CudaError> {
    let low_n = eq_tab.low_n();
    let high_n = eq_tab.high_n();
    // Post-fold: num_x = pre_fold_len / 4
    let num_x = pre_fold_len >> 2;
    debug_assert_eq!(2 << (low_n + high_n), num_x);
    #[cfg(debug_assertions)]
    {
        assert!(pre_fold_len > 2, "pre_fold_len must be > 2");
        let pq_size = pre_fold_len >> 1;
        assert!(num_x > 0, "num_x must be > 0");
        assert!(
            pq_src.len() >= pre_fold_len,
            "pq_src too small: {} < {}",
            pq_src.len(),
            pre_fold_len
        );
        assert!(
            pq_dst.len() >= pq_size,
            "pq_dst too small: {} < {}",
            pq_dst.len(),
            pq_size
        );
        let have = round_scratch.len();
        let need = _kb_frac_compute_round_temp_buffer_size(num_x as u32);
        assert!(
            have >= need as usize,
            "round scratch too small: {have} elements, kernel needs {need}"
        );
    }
    CudaError::from_result(_kb_frac_compute_round_and_fold(
        eq_tab.low.get_ptr(low_n),
        eq_tab.high.get_ptr(high_n),
        pq_src.as_ptr(),
        pq_dst.as_mut_ptr(),
        pre_fold_len,
        1 << low_n,
        lambda,
        r_prev,
        round_out.as_mut_ptr(),
        round_scratch.as_mut_ptr(),
    ))
}

/// [`frac_compute_round_and_fold_kb`] with the folded values written back into `pq_buf`.
///
/// It launches a separate kernel whose pq pointer is not `__restrict__`, since passing one buffer
/// as two restrict pointers would be undefined behaviour.
///
/// **Why in place is sound:** a thread only writes first-half positions that it has itself read,
/// and nobody writes the second half, so threads never race with each other.
#[allow(clippy::too_many_arguments)]
pub unsafe fn frac_compute_round_and_fold_inplace_kb(
    eq_tab: &SqrtEqLayers,
    pq_buf: &mut DeviceBuffer<Frac<EF>>,
    pre_fold_len: usize,
    lambda: EF,
    r_prev: EF,
    round_out: &mut DeviceBuffer<EF>,
    round_scratch: &mut DeviceBuffer<EF>,
) -> Result<(), CudaError> {
    let low_n = eq_tab.low_n();
    let high_n = eq_tab.high_n();
    // Post-fold: num_x = pre_fold_len / 4
    let num_x = pre_fold_len >> 2;
    debug_assert_eq!(2 << (low_n + high_n), num_x);
    #[cfg(debug_assertions)]
    {
        assert!(pre_fold_len > 2, "pre_fold_len must be > 2");
        assert!(num_x > 0, "num_x must be > 0");
        assert!(
            pq_buf.len() >= pre_fold_len,
            "pq_buf too small: {} < {}",
            pq_buf.len(),
            pre_fold_len
        );
        let have = round_scratch.len();
        let need = _kb_frac_compute_round_temp_buffer_size(num_x as u32);
        assert!(
            have >= need as usize,
            "round scratch too small: {have} elements, kernel needs {need}"
        );
    }
    CudaError::from_result(_kb_frac_compute_round_and_fold_inplace(
        eq_tab.low.get_ptr(low_n),
        eq_tab.high.get_ptr(high_n),
        pq_buf.as_mut_ptr(),
        pre_fold_len,
        1 << low_n,
        lambda,
        r_prev,
        round_out.as_mut_ptr(),
        round_scratch.as_mut_ptr(),
    ))
}

#[allow(clippy::too_many_arguments)]
pub unsafe fn frac_precompute_m_build_raw_kb(
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
    partials_len: usize,
    m_acc: *mut EF,
) -> Result<(), CudaError> {
    debug_assert!(rem_n > 0);
    debug_assert!(w > 0 && w <= rem_n);
    debug_assert!(tail_lo_cap.is_power_of_two());
    debug_assert!(tail_tile > 0);
    CudaError::from_result(_kb_frac_precompute_m_build(
        pq,
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
        partials_len,
        m_acc,
    ))
}

#[allow(clippy::too_many_arguments)]
pub unsafe fn frac_precompute_m_eval_round_raw_kb(
    m_acc: *const EF,
    w: usize,
    t: usize,
    prefix_eq: *const EF,
    suffix_eq: *const EF,
    dest: *mut EF,
) -> Result<(), CudaError> {
    debug_assert!(w > 0);
    debug_assert!(t < w);
    CudaError::from_result(_kb_frac_precompute_m_eval_round(
        m_acc, w, t, prefix_eq, suffix_eq, dest,
    ))
}

pub unsafe fn frac_multifold_raw_kb(
    src: *const Frac<EF>,
    dst: *mut Frac<EF>,
    rem_n: usize,
    w: usize,
    window_eq: *const EF,
) -> Result<(), CudaError> {
    debug_assert!(rem_n > 0);
    debug_assert!(w > 0 && w <= rem_n);
    CudaError::from_result(_kb_frac_multifold(src, dst, rem_n, w, window_eq))
}

#[allow(clippy::too_many_arguments)]
pub unsafe fn fold_ple_from_evals_kb(
    src_mat: &DeviceBuffer<F>,
    dst_mat: *mut EF,
    skip_omega_pows: &DeviceBuffer<F>,
    lagrange_inv_denoms: &DeviceBuffer<EF>,
    height: u32,
    width: u32,
    l_skip: u32,
    new_height: u32,
    rotate: bool,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_fold_ple_from_evals(
        src_mat.as_ptr(),
        dst_mat,
        skip_omega_pows.as_ptr(),
        lagrange_inv_denoms.as_ptr(),
        height,
        width,
        l_skip,
        new_height,
        rotate,
    ))
}

/// # Safety
/// - `fracs` points to device memory with room for at least `num_interactions * height` entries.
#[allow(clippy::too_many_arguments)]
pub unsafe fn logup_gkr_input_eval_kb(
    is_global: bool,
    fracs: *mut Frac<EF>,
    prep_mat: &DeviceBuffer<F>,
    main_part_ptrs: &DeviceBuffer<u64>,
    pub_vals: &DeviceBuffer<F>,
    chal_vals: &DeviceBuffer<EF>,
    node_scratch: &DeviceBuffer<EF>,
    rule_buf: &DeviceBuffer<u128>,
    live_nodes: &DeviceBuffer<usize>,
    pair_indices: &DeviceBuffer<u32>,
    height: u32,
    rows_per_tile: u32,
) -> Result<(), CudaError> {
    debug_assert_eq!(live_nodes.len(), pair_indices.len());
    CudaError::from_result(_kb_logup_gkr_input_eval(
        is_global,
        fracs,
        prep_mat.as_ptr(),
        main_part_ptrs.as_ptr(),
        pub_vals.as_ptr(),
        chal_vals.as_ptr(),
        node_scratch.as_ptr(),
        rule_buf.as_raw_ptr(),
        live_nodes.as_ptr(),
        pair_indices.as_ptr(),
        live_nodes.len(),
        height,
        rows_per_tile,
    ))
}

pub unsafe fn frac_add_alpha_kb(data: &DeviceBuffer<Frac<EF>>, alpha: EF) -> Result<(), CudaError> {
    CudaError::from_result(_kb_frac_add_alpha(data.as_mut_raw_ptr(), data.len(), alpha))
}

/// # Safety
/// - `row_buf_nodes` is the number of DAG nodes that must be buffered per row, not the length of
///   `node_scratch`; that length is some runtime-derived multiple of it.
/// - `eq_hc` is a device pointer to at least `num_x` hypercube evaluations.
#[allow(clippy::too_many_arguments)]
pub unsafe fn zerocheck_ntt_eval_constraints_kb(
    block_partials: &mut DeviceBuffer<EF>,
    sums_out: &mut DeviceBuffer<EF>,
    sel_cube: &DeviceBuffer<F>,
    prep_mat: *const F,
    main_mats: &DeviceBuffer<*const F>,
    eq_hc: *const EF,
    lambda_powers: &DeviceBuffer<EF>,
    pub_vals: &DeviceBuffer<F>,
    rule_buf: &DeviceBuffer<u128>,
    live_nodes: &DeviceBuffer<usize>,
    row_buf_nodes: u32,
    node_scratch: &mut DeviceBuffer<F>,
    skip_domain: u32,
    num_x: u32,
    height: u32,
    num_cosets: u32,
    coset_shift: F,
    temp_byte_cap: usize,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_zerocheck_ntt_eval_constraints(
        block_partials.as_mut_ptr(),
        sums_out.as_mut_ptr(),
        sel_cube.as_ptr(),
        prep_mat,
        main_mats.as_ptr(),
        eq_hc,
        lambda_powers.as_ptr(),
        pub_vals.as_ptr(),
        rule_buf.as_raw_ptr(),
        rule_buf.len(),
        live_nodes.as_ptr(),
        live_nodes.len(),
        lambda_powers.len(),
        row_buf_nodes,
        node_scratch.as_mut_ptr(),
        skip_domain,
        num_x,
        height,
        num_cosets,
        coset_shift,
        temp_byte_cap,
    ))
}

/// # Safety
/// - `row_buf_nodes` is the number of DAG nodes that must be buffered per row, not the length of
///   `node_scratch`; that length is some runtime-derived multiple of it.
/// - `eq_hc` is a device pointer to at least `num_x` hypercube evaluations.
/// - Only `block_partials` is written here; `sums_out` is left untouched.
#[allow(clippy::too_many_arguments)]
pub unsafe fn logup_bary_eval_interactions_round0_kb(
    block_partials: &mut DeviceBuffer<Frac<EF>>,
    sums_out: &mut DeviceBuffer<Frac<EF>>,
    sel_cube: &DeviceBuffer<F>,
    prep_mat: *const F,
    main_mats: &DeviceBuffer<*const F>,
    eq_hc: *const EF,
    pub_vals: &DeviceBuffer<F>,
    numer_wts: &DeviceBuffer<EF>,
    denom_wts: &DeviceBuffer<EF>,
    denom_sum_init: EF,
    rule_buf: &DeviceBuffer<u128>,
    row_buf_nodes: u32,
    node_scratch: &mut DeviceBuffer<F>,
    skip_domain: u32,
    num_x: u32,
    height: u32,
    num_cosets: u32,
    coset_shift: F,
    temp_byte_cap: usize,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_logup_bary_eval_interactions_round0(
        block_partials.as_mut_ptr(),
        sums_out.as_mut_ptr(),
        sel_cube.as_ptr(),
        prep_mat,
        main_mats.as_ptr(),
        eq_hc,
        pub_vals.as_ptr(),
        numer_wts.as_ptr(),
        denom_wts.as_ptr(),
        denom_sum_init,
        rule_buf.as_raw_ptr(),
        rule_buf.len(),
        row_buf_nodes,
        node_scratch.as_mut_ptr(),
        skip_domain,
        num_x,
        height,
        num_cosets,
        coset_shift,
        temp_byte_cap,
    ))
}

/// GPU evaluation of the zerocheck constraints in MLE form, taking raw device pointers.
#[allow(clippy::too_many_arguments)]
pub unsafe fn zerocheck_eval_mle_kb(
    block_partials: &mut DeviceBuffer<EF>,
    sums_out: &mut DeviceBuffer<EF>,
    eq_tab: *const EF,
    sel_cols: *const EF,
    prep_mat: MainMatrixPtrs<EF>,
    main_mats: *const MainMatrixPtrs<EF>,
    lambda_powers: *const EF,
    lambda_len: usize,
    pub_vals: *const F,
    rule_buf: *const c_void,
    rule_count: usize,
    live_nodes: *const usize,
    live_nodes_len: usize,
    row_buf_nodes: u32,
    node_scratch: &mut DeviceBuffer<EF>,
    num_y: u32,
    num_x: u32,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_zerocheck_eval_mle(
        block_partials.as_mut_ptr(),
        sums_out.as_mut_ptr(),
        eq_tab,
        sel_cols,
        prep_mat,
        main_mats,
        lambda_powers,
        pub_vals,
        rule_buf,
        rule_count,
        live_nodes,
        live_nodes_len,
        lambda_len,
        row_buf_nodes,
        node_scratch.as_mut_ptr(),
        num_y,
        num_x,
    ))
}

#[allow(clippy::too_many_arguments)]
pub unsafe fn zerocheck_batch_eval_mle_kb(
    block_partials: &mut DeviceBuffer<EF>,
    sums_out: &mut DeviceBuffer<EF>,
    blk_ctxs: &DeviceBuffer<BlockCtx>,
    zc_ctxs: &DeviceBuffer<ZerocheckCtx>,
    air_blk_starts: &DeviceBuffer<u32>,
    lambda_powers: &DeviceBuffer<EF>,
    lambda_len: usize,
    grid_blocks: u32,
    num_x: u32,
    num_airs: u32,
    block_dim: u32,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_zerocheck_batch_eval_mle(
        block_partials.as_mut_ptr(),
        sums_out.as_mut_ptr(),
        blk_ctxs.as_ptr(),
        zc_ctxs.as_ptr(),
        air_blk_starts.as_ptr(),
        lambda_powers.as_ptr(),
        lambda_len,
        grid_blocks,
        num_x,
        num_airs,
        block_dim,
    ))
}

/// GPU evaluation of the logup interactions in MLE form, taking raw device pointers.
#[allow(clippy::too_many_arguments)]
pub unsafe fn logup_eval_mle_kb(
    block_partials: &mut DeviceBuffer<Frac<EF>>,
    sums_out: &mut DeviceBuffer<Frac<EF>>,
    eq_tab: *const EF,
    sel_cols: *const EF,
    prep_mat: MainMatrixPtrs<EF>,
    main_mats: *const MainMatrixPtrs<EF>,
    chal_vals: *const EF,
    eq_3b: *const EF,
    pub_vals: *const F,
    rule_buf: *const c_void,
    live_nodes: *const usize,
    pair_indices: *const u32,
    live_nodes_len: usize,
    row_buf_nodes: u32,
    node_scratch: &mut DeviceBuffer<EF>,
    num_y: u32,
    num_x: u32,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_logup_eval_mle(
        block_partials.as_mut_ptr(),
        sums_out.as_mut_ptr(),
        eq_tab,
        sel_cols,
        prep_mat,
        main_mats,
        chal_vals,
        eq_3b,
        pub_vals,
        rule_buf,
        live_nodes,
        pair_indices,
        live_nodes_len,
        row_buf_nodes,
        node_scratch.as_mut_ptr(),
        num_y,
        num_x,
    ))
}

#[allow(clippy::too_many_arguments)]
pub unsafe fn logup_batch_eval_mle_kb(
    block_partials: &mut DeviceBuffer<Frac<EF>>,
    sums_out: &mut DeviceBuffer<Frac<EF>>,
    blk_ctxs: &DeviceBuffer<BlockCtx>,
    logup_ctxs: &DeviceBuffer<LogupCtx>,
    air_blk_starts: &DeviceBuffer<u32>,
    grid_blocks: u32,
    num_x: u32,
    num_airs: u32,
    block_dim: u32,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_logup_batch_eval_mle(
        block_partials.as_mut_ptr(),
        sums_out.as_mut_ptr(),
        blk_ctxs.as_ptr(),
        logup_ctxs.as_ptr(),
        air_blk_starts.as_ptr(),
        grid_blocks,
        num_x,
        num_airs,
        block_dim,
    ))
}

#[allow(clippy::too_many_arguments)]
pub unsafe fn zerocheck_monomial_batched_kb(
    block_partials: &mut DeviceBuffer<EF>,
    sums_out: &mut DeviceBuffer<EF>,
    blk_ctxs: &DeviceBuffer<BlockCtx>,
    air_mono_ctxs: &DeviceBuffer<MonomialAirCtx>,
    air_blk_starts: &DeviceBuffer<u32>,
    grid_blocks: u32,
    num_x: u32,
    num_airs: u32,
    block_dim: u32,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_zerocheck_monomial_batched(
        block_partials.as_mut_ptr(),
        sums_out.as_mut_ptr(),
        blk_ctxs.as_ptr(),
        air_mono_ctxs.as_ptr(),
        air_blk_starts.as_ptr(),
        grid_blocks,
        num_x,
        num_airs,
        block_dim,
    ))
}

#[allow(clippy::too_many_arguments)]
pub unsafe fn zerocheck_monomial_par_y_batched_kb(
    block_partials: &mut DeviceBuffer<EF>,
    sums_out: &mut DeviceBuffer<EF>,
    blk_ctxs: &DeviceBuffer<BlockCtx>,
    air_mono_ctxs: &DeviceBuffer<MonomialAirCtx>,
    air_blk_starts: &DeviceBuffer<u32>,
    grid_blocks: u32,
    num_x: u32,
    num_airs: u32,
    chunk_size: u32,
    block_dim: u32,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_zerocheck_monomial_par_y_batched(
        block_partials.as_mut_ptr(),
        sums_out.as_mut_ptr(),
        blk_ctxs.as_ptr(),
        air_mono_ctxs.as_ptr(),
        air_blk_starts.as_ptr(),
        grid_blocks,
        num_x,
        num_airs,
        chunk_size,
        block_dim,
    ))
}

pub unsafe fn precompute_lambda_combinations_kb(
    dest: &mut DeviceBuffer<EF>,
    mono_headers: *const MonomialHeader,
    lambda_terms: *const LambdaTerm<F>,
    lambda_powers: &DeviceBuffer<EF>,
    mono_count: u32,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_precompute_lambda_combinations(
        dest.as_mut_ptr(),
        mono_headers,
        lambda_terms,
        lambda_powers.as_ptr(),
        mono_count,
    ))
}

pub unsafe fn precompute_logup_numer_combinations_kb(
    dest: &mut DeviceBuffer<EF>,
    mono_headers: *const MonomialHeader,
    inter_terms: *const InteractionMonomialTerm<F>,
    eq_3b: &DeviceBuffer<EF>,
    mono_count: u32,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_precompute_logup_numer_combinations(
        dest.as_mut_ptr(),
        mono_headers,
        inter_terms,
        eq_3b.as_ptr(),
        mono_count,
    ))
}

pub unsafe fn precompute_logup_denom_combinations_kb(
    dest: &mut DeviceBuffer<EF>,
    mono_headers: *const MonomialHeader,
    inter_terms: *const InteractionMonomialTerm<F>,
    beta_powers: &DeviceBuffer<EF>,
    eq_3b: &DeviceBuffer<EF>,
    mono_count: u32,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_precompute_logup_denom_combinations(
        dest.as_mut_ptr(),
        mono_headers,
        inter_terms,
        beta_powers.as_ptr(),
        eq_3b.as_ptr(),
        mono_count,
    ))
}

#[allow(clippy::too_many_arguments)]
pub unsafe fn logup_monomial_batched_kb(
    block_partials: &mut DeviceBuffer<Frac<EF>>,
    sums_out: &mut DeviceBuffer<Frac<EF>>,
    blk_ctxs: &DeviceBuffer<BlockCtx>,
    common_ctxs: &DeviceBuffer<LogupMonomialCommonCtx>,
    numer_ctxs: &DeviceBuffer<LogupMonomialCtx>,
    denom_ctxs: &DeviceBuffer<LogupMonomialCtx>,
    air_blk_starts: &DeviceBuffer<u32>,
    grid_blocks: u32,
    num_x: u32,
    num_airs: u32,
    block_dim: u32,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_logup_monomial_batched(
        block_partials.as_mut_ptr(),
        sums_out.as_mut_ptr(),
        blk_ctxs.as_ptr(),
        common_ctxs.as_ptr(),
        numer_ctxs.as_ptr(),
        denom_ctxs.as_ptr(),
        air_blk_starts.as_ptr(),
        grid_blocks,
        num_x,
        num_airs,
        block_dim,
    ))
}

pub unsafe fn frac_vector_scalar_multiply_ext_fp_kb(
    frac_data: *mut Frac<EF>,
    scalar: F,
    length: u32,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_frac_vector_scalar_multiply_ext_fp(
        frac_data, scalar, length,
    ))
}

/// Writes `source` into `dest` with its rows repeated vertically, from `height` up to
/// `lifted_height` rows. Both matrices are stored column-major.
///
/// # Safety
/// - `dest` points into a `DeviceBuffer<F>` holding at least `lifted_height * width` elements.
/// - `source` points into a `DeviceBuffer<F>` holding at least `height * width` elements.
/// - The two regions are disjoint.
pub unsafe fn frac_matrix_vertically_repeat_kb(
    dest: *mut Frac<EF>,
    source: *const Frac<EF>,
    width: u32,
    lifted_height: u32,
    height: u32,
) -> Result<(), CudaError> {
    debug_assert!(lifted_height > height);
    CudaError::from_result(_kb_frac_matrix_vertically_repeat(
        dest,
        source,
        width,
        lifted_height,
        height,
    ))
}

pub unsafe fn frac_matrix_vertically_repeat_ext_kb(
    dst_numer: *mut EF,
    dst_denom: *mut EF,
    src_numer: *const EF,
    src_denom: *const EF,
    width: u32,
    lifted_height: u32,
    height: u32,
) -> Result<(), CudaError> {
    debug_assert!(lifted_height > height);
    CudaError::from_result(_kb_frac_matrix_vertically_repeat_ext(
        dst_numer,
        dst_denom,
        src_numer,
        src_denom,
        width,
        lifted_height,
        height,
    ))
}

/// Builds the round-0 folded selector columns by combining the hypercube evaluations with the
/// univariate factors `is_first` / `is_last`.
///
/// `is_transition` does not split into a univariate times a hypercube factor, so it is not built
/// this way.
pub unsafe fn fold_selectors_round0_kb(
    dest: *mut EF,
    source: *const F,
    is_first: EF,
    is_last: EF,
    num_x: usize,
) -> Result<(), CudaError> {
    CudaError::from_result(_kb_fold_selectors_round0(
        dest,
        source,
        is_first,
        is_last,
        num_x as u32,
    ))
}
