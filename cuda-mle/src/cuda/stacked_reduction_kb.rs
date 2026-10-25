use crate::runtime::{
    d_buffer::DeviceBuffer,
    error::{check, CudaError},
};

use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::KoalaBear;

use crate::{
    poly::EqEvalSegments,
    stacked_reduction::{UnstackedSlice, STACKED_REDUCTION_S_DEG},
};

// `cuda_kb_all` is the KoalaBear link unit; this FFI is typed as KoalaBear.
type F = KoalaBear;
type EF = BinomialExtensionField<KoalaBear, 4>;
const D_EF: usize = 4;

/// How many partial-sum polynomials (G0, G1, G2) the round-0 kernel emits per point of the
/// univariate skip domain.
pub const NUM_G: usize = 3;

#[link(name = "cuda_kb_all", kind = "static")]
extern "C" {
    pub fn _kb_stacked_reduction_r0_required_temp_buffer_size(
        height: u32,
        width: u32,
        log_skip: u32,
    ) -> u32;

    fn _kb_initialize_k_rot_from_eq_segments(
        eq_segments: *const EF,
        k_rot_segments: *mut EF,
        k_rot_univariate_at_zero: EF,
        k_rot_univariate_at_one: EF,
        max_log_size: u32,
    ) -> i32;

    // Degree-1 variant: the kernel never packs z values; it ADDs `NUM_G * 2^log_skip` results.
    fn _kb_stacked_reduction_sumcheck_round0(
        eq_segments: *const EF,
        trace: *const F,
        lambda_powers: *const EF,
        partial_block_sums: *mut EF,
        accumulator: *mut EF,
        height: u32,
        width: u32,
        log_skip: u32,
        cube_size: u32,
    ) -> i32;

    fn _kb_stacked_reduction_fold_ple(
        source: *const F,
        destination: *mut EF,
        skip_domain_powers: *const F,
        lagrange_denom_inverses: *const EF,
        height: u32,
        width: u32,
        log_skip: u32,
    ) -> i32;

    fn _kb_stacked_reduction_sumcheck_mle_round_degenerate(
        column_evals: *const *const EF,
        eq_upper_bits: *const EF,
        eq_at_point: EF,
        k_rot_at_point: EF,
        column_slices: *const UnstackedSlice,
        lambda_powers: *const EF,
        accumulator: *mut u64, // u64 atomics, S_DEG * D_EF of them
        column_height: u32,
        num_columns: u32,
        log_skip: u32,
        round_idx: u32,
    ) -> i32;

    fn _kb_stacked_reduction_sumcheck_mle_round(
        column_evals: *const *const EF,
        eq_segments: *const EF,
        k_rot_segments: *const EF,
        column_slices: *const UnstackedSlice,
        lambda_powers: *const EF,
        accumulator: *mut u64, // u64 atomics, S_DEG * D_EF of them
        column_height: u32,
        num_columns: u32,
        num_hypercube_points: u32,
        num_sms: u32,
    ) -> i32;
}

/// First sumcheck round (degree 1): accumulates the three partial sums G0, G1 and G2 over the
/// identity coset of the skip domain, for every skip-domain point Z:
/// - G0(Z): sum over (col, x) of coeff_eq[col] · eq_cube(x) · q_{col,x}(Z)
/// - G1(Z): sum over (col, x) of coeff_rot[col] · eq_cube(x) · q_{col,x}(Z)
/// - G2(Z): same as G1 with eq_cube(x) replaced by eq_cube(rot_prev(x)) - eq_cube(x)
///
/// Combining them into s₀(Z) = E0(Z)*G0(Z) + E1(Z)*G1(Z) + E2(Z)*G2(Z) is left to the host.
///
/// Reduction happens in two launches: each block first writes its own sum into
/// `partial_block_sums` (reduced through shared memory), then a second kernel adds all block sums
/// onto whatever `accumulator` already holds, so several traces can share one bucket.
///
/// # Safety
/// - `trace` points to device memory holding at least `height * width` base-field elements.
/// - `lambda_powers` is a (possibly offset) pointer into a `DeviceBuffer<EF>` with at least
///   `2 * width` initialized entries, since rotated columns use a second power each.
/// - `partial_block_sums` holds at least
///   `_kb_stacked_reduction_r0_required_temp_buffer_size(...)` elements.
/// - `accumulator` holds at least `NUM_G * 2^log_skip` elements and is zeroed before the first
///   trace; later calls add on top of it.
#[allow(clippy::too_many_arguments)]
pub unsafe fn stacked_reduction_sumcheck_round0(
    eq_segments: &EqEvalSegments<EF>,
    trace: *const F,
    lambda_powers: *const EF,
    partial_block_sums: &mut DeviceBuffer<EF>,
    accumulator: &mut DeviceBuffer<EF>,
    height: usize,
    width: usize,
    log_skip: usize,
) -> Result<(), CudaError> {
    let required_len = NUM_G << log_skip;
    let cube_size = (height >> log_skip).max(1) as u32;
    debug_assert!(accumulator.len() >= required_len);

    check(_kb_stacked_reduction_sumcheck_round0(
        eq_segments.buffer().as_ptr(),
        trace,
        lambda_powers,
        partial_block_sums.as_mut_ptr(),
        accumulator.as_mut_ptr(),
        height as u32,
        width as u32,
        log_skip as u32,
        cube_size,
    ))
}

/// Folds one trace through the univariate skip by barycentric interpolation, using `2^log_skip`
/// threads for every output cell.
///
/// A launch covers a single trace, so callers iterate over their traces themselves.
///
/// # Safety
/// - `source` is a device pointer to `height * width` base-field elements.
/// - `destination` is a device pointer to `folded_height * width` extension-field elements,
///   with `folded_height = max(height, 2^log_skip) / 2^log_skip`.
/// - The `source` and `destination` ranges are disjoint.
/// - Both `skip_domain_powers` and `lagrange_denom_inverses` hold at least `2^log_skip` entries.
/// - `log_skip` lies in `0..=10`, i.e. the skip domain has between 1 and 1024 points.
#[allow(clippy::too_many_arguments)]
pub unsafe fn stacked_reduction_fold_ple(
    source: *const F,
    destination: *mut EF,
    skip_domain_powers: &DeviceBuffer<F>,
    lagrange_denom_inverses: &DeviceBuffer<EF>,
    height: usize,
    width: usize,
    log_skip: usize,
) -> Result<(), CudaError> {
    let domain_size = 1 << log_skip;
    debug_assert!(skip_domain_powers.len() >= domain_size);
    debug_assert!(lagrange_denom_inverses.len() >= domain_size);
    check(_kb_stacked_reduction_fold_ple(
        source,
        destination,
        skip_domain_powers.as_ptr(),
        lagrange_denom_inverses.as_ptr(),
        height as u32,
        width as u32,
        log_skip as u32,
    ))
}

/// Fills the segmented `k_rot` table for every `n` in `0..=max_log_size` once round 0 is done.
///
/// # Safety
/// - `eq_segments` and `k_rot_segments` each have `2 * 2^max_log_size` entries, segmented.
/// - Entry 0 of `k_rot_segments` is left untouched; nothing reads it, and a caller that wants it
///   defined has to write it itself.
pub unsafe fn initialize_k_rot_from_eq_segments(
    eq_segments: &EqEvalSegments<EF>,
    k_rot_segments: &mut DeviceBuffer<EF>,
    k_rot_univariate_at_zero: EF,
    k_rot_univariate_at_one: EF,
    max_log_size: u32,
) -> Result<(), CudaError> {
    debug_assert_eq!(eq_segments.buffer.len(), 2 << max_log_size);
    debug_assert_eq!(k_rot_segments.len(), eq_segments.buffer.len());

    check(_kb_initialize_k_rot_from_eq_segments(
        eq_segments.buffer.as_ptr(),
        k_rot_segments.as_mut_ptr(),
        k_rot_univariate_at_zero,
        k_rot_univariate_at_one,
        max_log_size,
    ))
}

/// Multilinear-round counterpart of [stacked_reduction_sumcheck_round0]. Unlike round 0, the
/// `k_rot` values come in their own buffer, laid out in the same segments as the eq values.
///
/// Each block sums its per-degree contributions and then atomically adds them into the u64
/// `accumulator`, which the caller zeroes beforehand and reduces modulo P afterwards.
///
/// # Safety
/// - `column_evals` holds pointers to `DeviceBuffer<EF>` matrices that all have height
///   `column_height`.
/// - `column_slices` is a (possibly offset) pointer into a `DeviceBuffer<UnstackedSlice>`:
///   - at least `num_columns` entries starting there are initialized;
///   - those entries share one `log_height`, and each `stacked_row_idx` is a multiple of
///     `2^l_skip`;
///   - every slice addresses memory inside `column_evals`.
/// - `lambda_powers` is a (possibly offset) pointer into a `DeviceBuffer<EF>` with at least
///   `2 * num_columns` initialized entries, since rotated columns use a second power each.
/// - `accumulator` has room for `S_DEG * D_EF = 8` values and starts zeroed.
#[allow(clippy::too_many_arguments)]
pub unsafe fn stacked_reduction_sumcheck_mle_round(
    column_evals: &DeviceBuffer<*const EF>,
    eq_segments: &EqEvalSegments<EF>,
    k_rot_segments: &EqEvalSegments<EF>,
    column_slices: *const UnstackedSlice,
    lambda_powers: *const EF,
    accumulator: *mut u64,
    column_height: usize,
    num_columns: usize,
    num_hypercube_points: usize,
    num_sms: u32,
) -> Result<(), CudaError> {
    check(_kb_stacked_reduction_sumcheck_mle_round(
        column_evals.as_ptr(),
        eq_segments.buffer.as_ptr(),
        k_rot_segments.buffer.as_ptr(),
        column_slices,
        lambda_powers,
        accumulator,
        column_height as u32,
        num_columns as u32,
        num_hypercube_points as u32,
        num_sms,
    ))
}

/// Multilinear sumcheck round for a degenerate window: its eq and `k_rot` values have already
/// stopped changing, so the single values `eq_at_point` / `k_rot_at_point` (scaled per column by
/// `eq_upper_bits`) stand in for the segmented tables.
///
/// Each block sums its per-degree contributions and then atomically adds them into the u64
/// `accumulator`, which the caller zeroes beforehand and reduces modulo P afterwards.
///
/// # Safety
/// - `accumulator` has room for `S_DEG * D_EF = 8` values and starts zeroed.
#[allow(clippy::too_many_arguments)]
pub unsafe fn stacked_reduction_sumcheck_mle_round_degenerate(
    column_evals: &DeviceBuffer<*const EF>,
    eq_upper_bits: *const EF,
    eq_at_point: EF,
    k_rot_at_point: EF,
    column_slices: *const UnstackedSlice,
    lambda_powers: *const EF,
    accumulator: *mut u64,
    column_height: usize,
    num_columns: usize,
    log_skip: usize,
    round_idx: usize,
) -> Result<(), CudaError> {
    check(_kb_stacked_reduction_sumcheck_mle_round_degenerate(
        column_evals.as_ptr(),
        eq_upper_bits,
        eq_at_point,
        k_rot_at_point,
        column_slices,
        lambda_powers,
        accumulator,
        column_height as u32,
        num_columns as u32,
        log_skip as u32,
        round_idx as u32,
    ))
}
