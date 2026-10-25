//! Base- and extension-field MLE-interpolate butterfly kernels and their dispatch.
//!
//! One in-place butterfly stage does, per `2*step`-aligned pair `(u, v)` that are `step` apart,
//! `v -= u` (eval→coeff) or `v += u` (coeff→eval). [`mle_interpolate_stages`] chains the stages
//! `[start, end]` over a `padded_height × width` column-major device buffer, picking the fastest
//! kernel per range: warp-shuffle fusion (log-steps `< LOG_WARP_SIZE`), a shared-memory tile
//! (log-steps `< MLE_SHARED_TILE_LOG_SIZE`), then a per-stage fallback. The launchers are reached
//! through the [`MleInterpolateField`] seam, implemented for KoalaBear (`_kb_mle_interpolate_*`) in
//! [`super::mle_interpolate_kb`].
//!
//! Live path: only the extension-field 1-D [`super::mle_interpolate_kb::mle_interpolate_stage_ext`]
//! runs in production (WHIR within-chunk zeta). The base-field 2-D family is the bit-exact
//! reference oracle for the fused iNTT+zeta kernel (`stacked_pcs::rs_code_matrix`), reached under
//! `C1_VERIFY` / `C1_FUSED_OFF` / the `cache_stacked_matrix` arm.
//!
//! Reachable arms at the legal `l_skip ≤ MAX_SMALL_NTT_LEVEL` (the call site passes
//! `[0, l_skip-1]`): `l_skip == 1` → shared-mem only; `2 ≤ l_skip ≤ 5` → fused only;
//! `6 ≤ l_skip ≤ 10` → fused then shared-mem. The per-stage fallback needs
//! `end ≥ MLE_SHARED_TILE_LOG_SIZE` (i.e. `l_skip ≥ 13`) and is unreachable under every legal config.
//!
//! CPU counterpart: `mle_core::poly::mle::Mle::{evals_to_coeffs_inplace, coeffs_to_evals_inplace}`
//! per `2^l_skip` chunk.

use crate::runtime::error::{check, CudaError};

use crate::cuda::LOG_WARP_SIZE;

/// Tile log size for the shared-memory kernel (must match the CUDA `MLE_SHARED_TILE_LOG_SIZE`).
pub const MLE_SHARED_TILE_LOG_SIZE: u32 = 12;

#[inline]
pub(crate) fn narrow_mle_width(width: usize) -> Result<u16, CudaError> {
    if width > u16::MAX as usize {
        return Err(CudaError::new(1));
    }
    Ok(width as u16)
}

/// Inclusive `[start, end]` log-step range for [`mle_interpolate_stages`]. The checked constructor
/// makes a transposed `(start, end)` pair an `Err`, not the silent no-op an untyped positional pair
/// used to produce.
#[derive(Copy, Clone, Debug)]
pub struct StageRange {
    start: u32,
    end: u32,
}

impl StageRange {
    /// `Err` if `start_log_step > end_log_step` (an inverted range — i.e. a transposed argument
    /// pair, which no live caller produces).
    pub fn new(start_log_step: u32, end_log_step: u32) -> Result<Self, CudaError> {
        if start_log_step > end_log_step {
            return Err(CudaError::new(1));
        }
        Ok(Self {
            start: start_log_step,
            end: end_log_step,
        })
    }
}

/// Launcher seam for the base-field 2-D interpolate kernels; KoalaBear (`_kb_mle_*`) is the one
/// impl. [`mle_interpolate_stages`] is the sole caller; the impl forwards its arguments verbatim to
/// its `extern "C"` launcher.
pub(crate) trait MleInterpolateField: Sized {
    /// # Safety
    /// `buffer` valid on device with length `>= padded_height * width`; `start_step` a power of two
    /// with `start_step << (num_stages - 1) <= 16` and `num_stages` in `1..=LOG_WARP_SIZE`.
    unsafe fn interpolate_fused_2d(
        buffer: *mut Self,
        width: u16,
        padded_height: u32,
        log_stride: u32,
        start_step: u32,
        num_stages: u32,
        is_eval_to_coeff: bool,
        right_pad: bool,
    ) -> i32;

    /// # Safety
    /// As [`Self::interpolate_fused_2d`]; additionally `end_log_step < MLE_SHARED_TILE_LOG_SIZE`.
    unsafe fn interpolate_shared_2d(
        buffer: *mut Self,
        width: u16,
        padded_height: u32,
        log_stride: u32,
        start_log_step: u32,
        end_log_step: u32,
        is_eval_to_coeff: bool,
        right_pad: bool,
    ) -> i32;

    /// # Safety
    /// As [`Self::interpolate_fused_2d`]; additionally `padded_height` a multiple of `step * 2`.
    unsafe fn interpolate_stage_2d(
        buffer: *mut Self,
        width: u16,
        height: u32,
        padded_height: u32,
        step: u32,
        is_eval_to_coeff: bool,
    ) -> i32;
}

/// Apply the MLE-interpolate butterfly stages in `range` to a `padded_height × width` column-major
/// device buffer, dispatching per range to the warp-shuffle / shared-memory / per-stage kernels.
/// Field-generic over the [`MleInterpolateField`] seam.
///
/// # Parameters
/// - `log_stride`: `meaningful_count = padded_height >> log_stride`. The RISC-V call site passes
///   `log_blowup`, so a padded codeword column reduces to its `height` real cells.
/// - `right_pad`: if `true`, physical index = `logical << log_stride` (strided); else contiguous.
///
/// # Safety
/// - `buffer` valid on device with length `>= padded_height * width`.
/// - if `right_pad`, `range.end < MLE_SHARED_TILE_LOG_SIZE` (the per-stage fallback has no strided
///   mode).
/// - a `uint32` cell index must not overflow: `width * padded_height < 2^32`.
pub(crate) unsafe fn mle_interpolate_stages<Fld: MleInterpolateField>(
    buffer: *mut Fld,
    width: usize,
    padded_height: u32,
    log_stride: u32,
    range: StageRange,
    is_eval_to_coeff: bool,
    right_pad: bool,
) -> Result<(), CudaError> {
    let StageRange { start, end } = range;
    let w = narrow_mle_width(width)?;
    let mut cur = start;

    // Phase 1: warp-shuffle fused kernel — fuses >= 2 stages with log_step < LOG_WARP_SIZE.
    let warp_end = end.min(LOG_WARP_SIZE as u32 - 1);
    let warp_stages = warp_end.saturating_sub(cur) + 1;
    if cur < LOG_WARP_SIZE as u32 && warp_stages >= 2 {
        let start_step = 1u32 << cur;
        debug_assert!((1..=LOG_WARP_SIZE as u32).contains(&warp_stages));
        debug_assert!((start_step << (warp_stages - 1)) <= 16);
        // Warp-shuffle partner lane is `tidx ^ step`, in-lane only while
        // `meaningful_count >= 2 * max_step`; holds by construction since
        // `meaningful_count = 2^(l_skip + n_stack) >= 2^l_skip > max_step`.
        debug_assert!((padded_height >> log_stride) >= 2 * (start_step << (warp_stages - 1)));
        check(Fld::interpolate_fused_2d(
            buffer,
            w,
            padded_height,
            log_stride,
            start_step,
            warp_stages,
            is_eval_to_coeff,
            right_pad,
        ))?;
        cur = warp_end + 1;
    }
    if cur > end {
        return Ok(());
    }

    // Phase 2: shared-memory tile kernel — log_step < MLE_SHARED_TILE_LOG_SIZE.
    if cur < MLE_SHARED_TILE_LOG_SIZE {
        let shared_end = end.min(MLE_SHARED_TILE_LOG_SIZE - 1);
        debug_assert!(shared_end < MLE_SHARED_TILE_LOG_SIZE);
        check(Fld::interpolate_shared_2d(
            buffer,
            w,
            padded_height,
            log_stride,
            cur,
            shared_end,
            is_eval_to_coeff,
            right_pad,
        ))?;
        cur = shared_end + 1;
    }

    // Phase 3: per-stage fallback for very large steps (no strided/`right_pad` mode).
    assert!(
        cur > end || !right_pad,
        "right_pad mode not supported for log_step >= MLE_SHARED_TILE_LOG_SIZE"
    );
    let height = padded_height >> log_stride;
    while cur <= end {
        let step = 1u32 << cur;
        debug_assert_eq!(padded_height % (step * 2), 0);
        check(Fld::interpolate_stage_2d(
            buffer,
            w,
            height,
            padded_height,
            step,
            is_eval_to_coeff,
        ))?;
        cur += 1;
    }

    Ok(())
}
