//! FFI wrappers over the `poly.cu` kernels (eq-hypercube stage kernels, extension-field point
//! evaluation, scalar multiply, and the base→extension transpose). Linked from the
//! **`cuda_kb_all`** static lib.

use crate::runtime::{
    copy::MemCopyD2H,
    d_buffer::DeviceBuffer,
    error::{check, CudaError},
};

use crate::{
    prelude::{D_EF, EF, F},
    KernelError,
};

#[link(name = "cuda_kb_all", kind = "static")]
extern "C" {
    fn _kb_vector_scalar_multiply_ext(vec: *mut EF, scalar: EF, length: u32) -> i32;

    fn _kb_eq_hypercube_stage_ext(out: *mut EF, x_i: EF, step: u32) -> i32;

    fn _kb_eq_hypercube_nonoverlapping_stage_ext(
        out: *mut EF,
        input: *const EF,
        x_i: EF,
        step: u32,
    ) -> i32;

    fn _kb_eq_hypercube_interleaved_stage_ext(
        out: *mut EF,
        input: *const EF,
        x_i: EF,
        step: u32,
    ) -> i32;

    fn _kb_eval_poly_ext_num_blocks(coeff_len: usize) -> u32;

    // `partials` and `out` must be device ptrs
    fn _kb_eval_poly_ext_at_point(
        base_coeffs: *const F,
        coeff_len: usize,
        x: EF,
        partials: *mut EF,
        num_blocks: u32,
        out: *mut EF,
    ) -> i32;

    fn _kb_transpose_fp_to_fpext_vec(output: *mut EF, input: *const F, height: u32) -> i32;
}

/// One in-place stage of building the eq table: for every `i` in `0..step`,
/// ```text
/// table[i + step] = table[i] * x_i
/// table[i]        = table[i] * (1 - x_i)
/// ```
///
/// # Safety
/// - `table` is a **device** pointer to at least `2 * step` elements.
pub unsafe fn eq_hypercube_stage_ext(table: *mut EF, x_i: EF, step: u32) -> Result<(), CudaError> {
    check(_kb_eq_hypercube_stage_ext(table, x_i, step))
}

/// Out-of-place variant of [eq_hypercube_stage_ext]: for every `i` in `0..step`,
/// ```text
/// dst[i + step] = src[i] * x_i
/// dst[i]        = src[i] * (1 - x_i)
/// ```
///
/// # Safety
/// - `dst` is a **device** pointer to at least `2 * step` elements.
/// - `src` is a **device** pointer to at least `step` elements.
/// - `dst` and `src` are meant to be disjoint. Passing the same pointer for both still gives the
///   right answer, but [eq_hypercube_stage_ext] is the function for that case.
pub unsafe fn eq_hypercube_nonoverlapping_stage_ext(
    dst: *mut EF,
    src: *const EF,
    x_i: EF,
    step: u32,
) -> Result<(), CudaError> {
    check(_kb_eq_hypercube_nonoverlapping_stage_ext(
        dst, src, x_i, step,
    ))
}

/// Like [eq_hypercube_nonoverlapping_stage_ext], but `x_i` is placed at the front, i.e. on the
/// lowest index bit: `dst[2 * i + 1] = src[i] * x_i` and `dst[2 * i] = src[i] * (1 - x_i)`.
///
/// # Safety
/// The requirements of [eq_hypercube_nonoverlapping_stage_ext]: `dst` is a **device** pointer to
/// at least `2 * step` elements, `src` a **device** pointer to at least `step` elements, and the
/// two do not overlap.
pub unsafe fn eq_hypercube_interleaved_stage_ext(
    dst: *mut EF,
    src: *const EF,
    x_i: EF,
    step: u32,
) -> Result<(), CudaError> {
    check(_kb_eq_hypercube_interleaved_stage_ext(dst, src, x_i, step))
}

/// Scalar multiplication of a vector in-place by `scalar`.
pub fn vector_scalar_multiply_ext(vec: &mut DeviceBuffer<EF>, scalar: EF) -> Result<(), CudaError> {
    // SAFETY: the kernel touches exactly `vec.len()` elements, all inside `vec`'s allocation.
    unsafe {
        check(_kb_vector_scalar_multiply_ext(
            vec.as_mut_ptr(),
            scalar,
            vec.len() as u32,
        ))
    }
}

/// Evaluates at `x` a polynomial with `EF` coefficients, given as a column-major `F` matrix.
///
/// # Safety
/// - `base_coeffs` holds **base**-field `F` values: `D_EF` columns of `coeff_len` each, one per
///   coordinate of the `EF` coefficient, so `base_coeffs.len() >= coeff_len * D_EF`.
/// - `partials` is sized by `_kb_eval_poly_ext_num_blocks` for the same `coeff_len`.
pub unsafe fn eval_poly_ext_at_point_from_base(
    base_coeffs: &DeviceBuffer<F>,
    coeff_len: usize,
    x: EF,
) -> Result<EF, KernelError> {
    debug_assert!(base_coeffs.len() >= coeff_len * D_EF);
    // Transient per-call scratch: one `EF` per block, capped at 256 blocks = 4 KiB. Allocated
    // through `DeviceBuffer` like every other device buffer, i.e. via the shared memory pool --
    // never a C-side `cudaMallocAsync`, which would bypass pico's registered external pool.
    let num_blocks = _kb_eval_poly_ext_num_blocks(coeff_len);
    let partials = DeviceBuffer::<EF>::with_capacity(num_blocks as usize);
    let d_out = DeviceBuffer::<EF>::with_capacity(1);
    check(_kb_eval_poly_ext_at_point(
        base_coeffs.as_ptr(),
        coeff_len,
        x,
        partials.as_mut_ptr(),
        num_blocks,
        d_out.as_mut_ptr(),
    ))
    .map_err(KernelError::Kernel)?;
    let out = d_out.to_host().map_err(KernelError::MemCopy)?;
    Ok(out[0])
}

/// Packs a column-major `height x D_EF` matrix of `F` values (one column per extension coordinate)
/// into `height` `EF` elements.
///
/// # Safety
/// - `input` holds exactly `D_EF` base elements per output element.
pub unsafe fn transpose_fp_to_fpext_vec(
    output: &mut DeviceBuffer<EF>,
    input: &DeviceBuffer<F>,
) -> Result<(), CudaError> {
    let height = output.len();
    debug_assert_eq!(height * D_EF, input.len());
    check(_kb_transpose_fp_to_fpext_vec(
        output.as_mut_ptr(),
        input.as_ptr(),
        height as u32,
    ))
}
