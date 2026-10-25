use crate::runtime::{
    d_buffer::DeviceBuffer,
    error::{check, CudaError},
};

use crate::{
    prelude::{D_EF, EF, F},
    whir::BatchingTracePacket,
};

#[link(name = "cuda_kb_all", kind = "static")]
extern "C" {
    fn _kb_whir_algebraic_batch_traces(
        output: *mut F,
        packets: *const BatchingTracePacket<F>,
        mu_powers: *const EF,
        stacked_height: usize,
        num_packets: usize,
    ) -> i32;

    pub fn _kb_whir_sumcheck_coeff_moments_required_temp_buffer_size(height: u32) -> u32;

    fn _kb_whir_sumcheck_coeff_moments_round(
        f_coeffs: *const EF,
        w_moments: *const EF,
        output: *mut EF,
        tmp_block_sums: *mut EF,
        height: u32,
    ) -> i32;

    fn _kb_whir_fold_coeffs_and_moments(
        f_coeffs: *const EF,
        w_moments: *const EF,
        f_folded_coeffs: *mut EF,
        w_folded_moments: *mut EF,
        alpha: EF,
        height: u32,
    ) -> i32;

    fn _kb_w_moments_accumulate(
        w_moments: *const EF,
        z0_pows2: *const EF,
        z_pows2: *const F,
        gamma: EF,
        num_queries: u32,
        log_height: u32,
        height: u32,
    ) -> i32;
}

/// # Safety
/// - Each packet's `ptr` must point to a device trace readable for `height x width` elements,
///   and its `stacked_row_start` must be where that trace begins in the stacked matrix.
/// - `mu_powers` needs one entry per column summed over all stacked traces, at least.
pub unsafe fn whir_algebraic_batch_traces(
    output: &mut DeviceBuffer<F>,
    packets: &DeviceBuffer<BatchingTracePacket<F>>,
    mu_powers: &DeviceBuffer<EF>,
) -> Result<(), CudaError> {
    debug_assert_eq!(output.len() % D_EF, 0);
    check(_kb_whir_algebraic_batch_traces(
        output.as_mut_ptr(),
        packets.as_ptr(),
        mu_powers.as_ptr(),
        output.len() / D_EF,
        packets.len(),
    ))
}

/// One WHIR sumcheck round, where `f` is given by its coefficients and `w` by its moments.
///
/// # Safety
/// - `coeffs` and `moments` have equal power-of-two lengths.
/// - `round_out` holds at least 2 elements.
/// - `scratch` holds at least
///   `_kb_whir_sumcheck_coeff_moments_required_temp_buffer_size(height)` elements.
pub unsafe fn whir_sumcheck_coeff_moments_round(
    coeffs: &DeviceBuffer<EF>,
    moments: &DeviceBuffer<EF>,
    round_out: &mut DeviceBuffer<EF>,
    scratch: &mut DeviceBuffer<EF>,
    height: u32,
) -> Result<(), CudaError> {
    debug_assert!(coeffs.len() >= height as usize);
    debug_assert!(moments.len() >= height as usize);
    #[cfg(debug_assertions)]
    {
        let have = scratch.len();
        let need = _kb_whir_sumcheck_coeff_moments_required_temp_buffer_size(height);
        assert!(
            have >= need as usize,
            "block-sum scratch too small: {have} elements, kernel needs {need}"
        );
    }
    check(_kb_whir_sumcheck_coeff_moments_round(
        coeffs.as_ptr(),
        moments.as_ptr(),
        round_out.as_mut_ptr(),
        scratch.as_mut_ptr(),
        height,
    ))
}

/// Halves both `f` (coefficients) and `w` (moments) with the folding challenge `alpha`, as one
/// WHIR round requires.
///
/// # Safety
/// - `coeffs` and `moments` hold `height` elements, `height` a power of two.
/// - `coeffs_out` and `moments_out` hold `height / 2` elements.
pub unsafe fn whir_fold_coeffs_and_moments(
    coeffs: &DeviceBuffer<EF>,
    moments: &DeviceBuffer<EF>,
    coeffs_out: &mut DeviceBuffer<EF>,
    moments_out: &mut DeviceBuffer<EF>,
    alpha: EF,
    height: u32,
) -> Result<(), CudaError> {
    debug_assert!(coeffs.len() >= height as usize);
    debug_assert!(moments.len() >= height as usize);
    debug_assert!(coeffs_out.len() >= (height as usize / 2));
    debug_assert!(moments_out.len() >= (height as usize / 2));
    check(_kb_whir_fold_coeffs_and_moments(
        coeffs.as_ptr(),
        moments.as_ptr(),
        coeffs_out.as_mut_ptr(),
        moments_out.as_mut_ptr(),
        alpha,
        height,
    ))
}

/// Adds the `gamma`-weighted query contributions into the moment vector `w`, in place.
///
/// # Safety
/// - `moments` holds `height = 2^log_height` elements.
/// - `z0_sq_pows` holds `log_height` elements.
/// - `z_sq_pows` holds `num_queries * log_height` elements.
pub unsafe fn w_moments_accumulate(
    moments: &mut DeviceBuffer<EF>,
    z0_sq_pows: &DeviceBuffer<EF>,
    z_sq_pows: &DeviceBuffer<F>,
    gamma: EF,
    num_queries: u32,
    log_height: u32,
) -> Result<(), CudaError> {
    let height = moments.len();
    debug_assert_eq!(z0_sq_pows.len(), log_height as usize);
    debug_assert_eq!(z_sq_pows.len(), num_queries as usize * log_height as usize);
    check(_kb_w_moments_accumulate(
        moments.as_mut_ptr(),
        z0_sq_pows.as_ptr(),
        z_sq_pows.as_ptr(),
        gamma,
        num_queries,
        log_height,
        height as u32,
    ))
}
