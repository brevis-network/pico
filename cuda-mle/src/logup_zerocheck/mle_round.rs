use crate::runtime::{d_buffer::DeviceBuffer, error::CudaError};
use mle_core::prover::fractional_sumcheck_gkr::Frac;
use tracing::debug;

use crate::{
    cuda::{field_kernels::FieldKernels, logup_zerocheck::MainMatrixPtrs},
    error::KernelError,
    ConstraintOnlyRules, InteractionEvalRules,
};

// Columns are already interpolated, so reading a variable costs nothing; no var buffering.
const ZC_VARS_BUFFERED: bool = false;
const MAX_GRID_ROWS_Y: u32 = 65535;

fn check_num_x_fits_grid(x_count: u32) -> Result<(), KernelError> {
    if x_count == 0 || x_count > MAX_GRID_ROWS_Y {
        return Err(CudaError::new(1).into());
    }
    Ok(())
}

/// Runs the zerocheck constraint evaluation for one MLE round on the device.
///
/// Inputs are raw device pointers, so data already resident on the GPU is not copied again.
/// Async-free and peak-memory notes live in the [`crate::logup_zerocheck`] module docs.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_mle_constraints_gpu<FK: FieldKernels>(
    eq_xi_ptr: *const FK::ValExt,
    sels_ptr: *const FK::ValExt,
    prep_ptr: MainMatrixPtrs<FK::ValExt>,
    main_parts_dev: &DeviceBuffer<MainMatrixPtrs<FK::ValExt>>,
    public_ptr: *const FK::Val,
    lambda_pows: &DeviceBuffer<FK::ValExt>,
    rules: &ConstraintOnlyRules<ZC_VARS_BUFFERED>,
    num_y: u32,
    num_x: u32,
) -> Result<DeviceBuffer<FK::ValExt>, KernelError> {
    check_num_x_fits_grid(num_x)?;
    let buffer_size = rules.inner.buffer_size;
    let intermed_capacity =
        unsafe { FK::zerocheck_mle_intermediates_buffer_size(buffer_size, num_x, num_y) };
    let mut scratch = if intermed_capacity > 0 {
        debug!("zerocheck:intermediates_capacity={intermed_capacity}");
        DeviceBuffer::<FK::ValExt>::with_capacity(intermed_capacity)
    } else {
        DeviceBuffer::<FK::ValExt>::new()
    };
    let temp_sums_buffer_capacity =
        unsafe { FK::zerocheck_mle_temp_sums_buffer_size(num_x, num_y) };
    debug!("zerocheck:temp_sums_buffer_capacity={temp_sums_buffer_capacity}");
    let mut partial_sums = DeviceBuffer::<FK::ValExt>::with_capacity(temp_sums_buffer_capacity);
    let mut out_evals = DeviceBuffer::<FK::ValExt>::with_capacity(num_x as usize);

    unsafe {
        FK::zerocheck_eval_mle(
            &mut partial_sums,
            &mut out_evals,
            eq_xi_ptr,
            sels_ptr,
            prep_ptr,
            main_parts_dev.as_ptr(),
            lambda_pows.as_ptr(),
            lambda_pows.len(),
            public_ptr,
            rules.inner.d_rules.as_raw_ptr(),
            rules.inner.d_rules.len(),
            rules.inner.d_used_nodes.as_ptr(),
            rules.inner.d_used_nodes.len(),
            buffer_size,
            &mut scratch,
            num_y,
            num_x,
        )?;
    }
    Ok(out_evals)
}

/// Runs the logup interaction evaluation for one MLE round on the device.
///
/// Inputs are raw device pointers, so data already resident on the GPU is not copied again.
/// Async-free and peak-memory notes live in the [`crate::logup_zerocheck`] module docs.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_mle_interactions_gpu<FK: FieldKernels>(
    eq_xi_ptr: *const FK::ValExt,
    sels_ptr: *const FK::ValExt,
    prep_ptr: MainMatrixPtrs<FK::ValExt>,
    main_parts_dev: &DeviceBuffer<MainMatrixPtrs<FK::ValExt>>,
    public_ptr: *const FK::Val,
    challenges_ptr: *const FK::ValExt,
    eq_3bs_ptr: *const FK::ValExt,
    rules: &InteractionEvalRules,
    num_y: u32,
    num_x: u32,
) -> Result<DeviceBuffer<Frac<FK::ValExt>>, KernelError> {
    check_num_x_fits_grid(num_x)?;
    let buffer_size = rules.inner.buffer_size;
    let intermed_capacity =
        unsafe { FK::logup_mle_intermediates_buffer_size(buffer_size, num_x, num_y) };
    let mut scratch = if intermed_capacity > 0 {
        debug!("logup:intermediates_capacity={intermed_capacity}");
        DeviceBuffer::<FK::ValExt>::with_capacity(intermed_capacity)
    } else {
        DeviceBuffer::<FK::ValExt>::new()
    };
    let temp_sums_buffer_capacity = unsafe { FK::logup_mle_temp_sums_buffer_size(num_x, num_y) };
    debug!("logup:temp_sums_buffer_capacity={temp_sums_buffer_capacity}");
    let mut partial_sums =
        DeviceBuffer::<Frac<FK::ValExt>>::with_capacity(temp_sums_buffer_capacity);
    let mut out_evals = DeviceBuffer::<Frac<FK::ValExt>>::with_capacity(num_x as usize);

    unsafe {
        FK::logup_eval_mle(
            &mut partial_sums,
            &mut out_evals,
            eq_xi_ptr,
            sels_ptr,
            prep_ptr,
            main_parts_dev.as_ptr(),
            challenges_ptr,
            eq_3bs_ptr,
            public_ptr,
            rules.inner.d_rules.as_raw_ptr(),
            rules.inner.d_used_nodes.as_ptr(),
            rules.d_pair_idxs.as_ptr(),
            rules.inner.d_used_nodes.len(),
            buffer_size,
            &mut scratch,
            num_y,
            num_x,
        )?;
    }
    Ok(out_evals)
}
