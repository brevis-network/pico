//! KoalaBear link-unit half of the MLE-interpolate family: the `_kb_mle_interpolate_*` externs, the
//! [`MleInterpolateField`] seam impl for `KoalaBear` that the shared
//! [`crate::cuda::mle_interpolate::mle_interpolate_stages`] driver dispatches through, and the
//! KoalaBear extension-field 1-D stage (the one production-live member — WHIR within-chunk zeta).
use crate::runtime::{
    d_buffer::DeviceBuffer,
    error::{check, CudaError},
};
use p3_koala_bear::KoalaBear as KbBase;

use crate::{cuda::mle_interpolate::MleInterpolateField, prelude::EF};

#[link(name = "cuda_kb_all", kind = "static")]
extern "C" {
    fn _kb_mle_interpolate_stage_ext(
        buffer: *mut EF,
        total_len: usize,
        step: u32,
        is_eval_to_coeff: bool,
    ) -> i32;

    fn _kb_mle_interpolate_stage_2d(
        buffer: *mut KbBase,
        width: u16,
        height: u32,
        padded_height: u32,
        step: u32,
        is_eval_to_coeff: bool,
    ) -> i32;

    fn _kb_mle_interpolate_fused_2d(
        buffer: *mut KbBase,
        width: u16,
        padded_height: u32,
        log_stride: u32,
        start_step: u32,
        num_stages: u32,
        is_eval_to_coeff: bool,
        right_pad: bool,
    ) -> i32;

    fn _kb_mle_interpolate_shared_2d(
        buffer: *mut KbBase,
        width: u16,
        padded_height: u32,
        log_stride: u32,
        start_log_step: u32,
        end_log_step: u32,
        is_eval_to_coeff: bool,
        right_pad: bool,
    ) -> i32;
}

impl MleInterpolateField for KbBase {
    unsafe fn interpolate_fused_2d(
        buffer: *mut Self,
        width: u16,
        padded_height: u32,
        log_stride: u32,
        start_step: u32,
        num_stages: u32,
        is_eval_to_coeff: bool,
        right_pad: bool,
    ) -> i32 {
        _kb_mle_interpolate_fused_2d(
            buffer,
            width,
            padded_height,
            log_stride,
            start_step,
            num_stages,
            is_eval_to_coeff,
            right_pad,
        )
    }

    unsafe fn interpolate_shared_2d(
        buffer: *mut Self,
        width: u16,
        padded_height: u32,
        log_stride: u32,
        start_log_step: u32,
        end_log_step: u32,
        is_eval_to_coeff: bool,
        right_pad: bool,
    ) -> i32 {
        _kb_mle_interpolate_shared_2d(
            buffer,
            width,
            padded_height,
            log_stride,
            start_log_step,
            end_log_step,
            is_eval_to_coeff,
            right_pad,
        )
    }

    unsafe fn interpolate_stage_2d(
        buffer: *mut Self,
        width: u16,
        height: u32,
        padded_height: u32,
        step: u32,
        is_eval_to_coeff: bool,
    ) -> i32 {
        _kb_mle_interpolate_stage_2d(buffer, width, height, padded_height, step, is_eval_to_coeff)
    }
}

/// Extension-field 1-D interpolate stage — the only production-live member of the family: one
/// in-place butterfly at `step` over the whole `buffer` (`v -= u` eval→coeff, `v += u` otherwise).
///
/// # Safety
/// - `buffer` allocated and initialized on device in the default stream.
/// - `step` a power of two and `<=` half `buffer.len()`.
pub unsafe fn mle_interpolate_stage_ext(
    buffer: &mut DeviceBuffer<EF>,
    step: u32,
    is_eval_to_coeff: bool,
) -> Result<(), CudaError> {
    check(_kb_mle_interpolate_stage_ext(
        buffer.as_mut_ptr(),
        buffer.len(),
        step,
        is_eval_to_coeff,
    ))
}
