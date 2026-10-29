use std::{cmp::max, sync::Arc};

use crate::runtime::d_buffer::DeviceBuffer;
use mle_core::poly::matrix::MatrixDimensions;

use super::errors::FoldPleError;
use crate::{
    base::DeviceMatrix,
    cuda::{batch_ntt_small::validate_gpu_l_skip, field_kernels::FieldKernels},
};

/// Folds a trace at r_0, optionally appending the folded rotated copy as extra columns.
/// - `mixed` would be the mixed-coefficient form of the _lifted_ trace.
/// - `base_evals` is the original, not yet lifted, trace.
pub fn fold_ple_evals_rotate<FK: FieldKernels>(
    l_skip: usize,
    omega_pows_dev: &DeviceBuffer<FK::Val>,
    base_evals: &DeviceMatrix<FK::Val>,
    inv_denoms_r0_dev: &DeviceBuffer<FK::ValExt>,
    need_rot: bool,
) -> Result<DeviceMatrix<FK::ValExt>, FoldPleError> {
    validate_gpu_l_skip(l_skip)?;
    let width = base_evals.width();
    let height = base_evals.height();
    let x_len = max(height >> l_skip, 1);
    let out_cols = width * if need_rot { 2 } else { 1 };
    let out_buf = DeviceBuffer::<FK::ValExt>::with_capacity(x_len * out_cols);
    // SAFETY:
    // - `out_buf` holds `x_len * width` elements, doubled when the rotation is folded too.
    // - `base_evals` is the unlifted `height x width` matrix.
    unsafe {
        fold_ple_evals_gpu::<FK>(
            l_skip,
            omega_pows_dev,
            base_evals,
            out_buf.as_mut_ptr(),
            inv_denoms_r0_dev,
            false,
        )?;

        if need_rot {
            // Second half of the output: the rotated trace, folded the same way.
            fold_ple_evals_gpu::<FK>(
                l_skip,
                omega_pows_dev,
                base_evals,
                out_buf.as_mut_ptr().add(x_len * width),
                inv_denoms_r0_dev,
                true,
            )?;
        }
    }
    let folded_mat = DeviceMatrix::new(Arc::new(out_buf), x_len, out_cols);
    Ok(folded_mat)
}

/// Interpolates each column's univariate restriction over the coset D and evaluates it at r_0,
/// writing one matrix with the same `width` as the input.
///
/// With `rotate` set, the lift of the rotated matrix is folded; otherwise the lift of `mat` itself.
///
/// # Safety
/// - `mat` holds the original (unlifted) trace evaluations.
/// - `dst` must point to device memory for at least `x_len * width` elements, with
///   `x_len = max(height / 2^l_skip, 1)`.
pub unsafe fn fold_ple_evals_gpu<FK: FieldKernels>(
    l_skip: usize,
    omega_pows_dev: &DeviceBuffer<FK::Val>,
    mat: &DeviceMatrix<FK::Val>,
    dst: *mut FK::ValExt,
    inv_denoms_r0_dev: &DeviceBuffer<FK::ValExt>,
    rotate: bool,
) -> Result<(), FoldPleError> {
    validate_gpu_l_skip(l_skip)?;
    let height = mat.height();
    let width = mat.width();

    if height == 0 || width == 0 {
        return Ok(());
    }

    let skip_size = omega_pows_dev.len();
    debug_assert_eq!(skip_size, 1 << l_skip);
    let padded_rows = max(skip_size, height);
    let x_len = padded_rows / skip_size;

    // Kernel launch.
    unsafe {
        FK::fold_ple_from_evals(
            mat.buffer(),
            dst,
            omega_pows_dev,
            inv_denoms_r0_dev,
            height as u32,
            width as u32,
            l_skip as u32,
            x_len as u32,
            rotate,
        )?;
    }
    Ok(())
}
