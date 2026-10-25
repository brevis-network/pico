//! Field-agnostic data movement: transpose, row gather, zero padding, strided collapse and the
//! stacked-trace gather. None of these kernels does field arithmetic -- they copy 32-bit words and
//! write zeros (Montgomery zero is bitwise zero) -- so every wrapper takes any 4-byte element type.
//!
//! They link to the `_kb_` launchers in `cuda_kb_all`, the only build of `matrix.cu` there is.

use crate::runtime::{d_buffer::DeviceBuffer, error::CudaError};

use crate::prelude::F;

const MAX_CUDA_GRID_Y: usize = u16::MAX as usize;

#[link(name = "cuda_kb_all", kind = "static")]
extern "C" {
    fn _kb_matrix_transpose_fp(
        output: *mut F,
        input: *const F,
        col_size: usize,
        row_size: usize,
    ) -> i32;

    fn _kb_matrix_get_rows_fp(
        output: *mut F,
        input: *const F,
        row_indices: *const u32,
        matrix_width: u64,
        matrix_height: u64,
        row_indices_len: u32,
    ) -> i32;

    fn _kb_collapse_strided_matrix(
        out: *mut F,
        input: *const F,
        width: u32,
        height: u32,
        stride: u32,
    ) -> i32;

    fn _kb_batch_expand_pad(
        output: *mut F,
        input: *const F,
        poly_count: u32,
        out_size: u32,
        in_size: u32,
    ) -> i32;

    fn _kb_batch_expand_pad_wide(
        out: *mut F,
        input: *const F,
        width: u32,
        padded_height: u32,
        height: u32,
    ) -> i32;

    fn _kb_stack_gather(
        out: *mut F,
        descs: *const std::ffi::c_void,
        n_descs: u32,
        total_cells: usize,
        vectorizable: bool,
    ) -> i32;
}

/// Transposes `input`, taken as a row-major matrix of `height` rows and `width` columns, into
/// `output`. Works for any 4-byte element type.
///
/// # Safety
/// - `T` must have same size as `F` (4 bytes, `#[repr(transparent)]` over u32)
/// - `input` and `output` must not overlap
/// - Both must have capacity at least `width * height`
pub unsafe fn matrix_transpose_fp_any<T>(
    output: &DeviceBuffer<T>,
    input: &DeviceBuffer<T>,
    width: usize,
    height: usize,
) -> Result<(), CudaError> {
    assert_eq!(std::mem::size_of::<T>(), std::mem::size_of::<F>());
    CudaError::from_result(_kb_matrix_transpose_fp(
        output.as_mut_ptr() as *mut F,
        input.as_ptr() as *const F,
        width,
        height,
    ))
}

pub unsafe fn matrix_get_rows_fp_kernel(
    output: &DeviceBuffer<F>,
    input: &DeviceBuffer<F>,
    row_indices: &DeviceBuffer<u32>,
    matrix_width: u64,
    matrix_height: u64,
    row_indices_len: usize,
) -> Result<(), CudaError> {
    if matrix_width == 0 || row_indices_len == 0 {
        return Ok(());
    }
    if row_indices_len > MAX_CUDA_GRID_Y || row_indices_len > u32::MAX as usize {
        return Err(CudaError::new(1));
    }
    CudaError::from_result(_kb_matrix_get_rows_fp(
        output.as_mut_ptr(),
        input.as_ptr(),
        row_indices.as_ptr(),
        matrix_width,
        matrix_height,
        row_indices_len as u32,
    ))
}

/// Keeps every `stride`-th row of a column-major matrix: the input has `lifted_height = height *
/// stride` rows, the output `height` rows, and both have `width` columns.
///
/// The CUDA kernel only copies bytes without any field-specific arithmetic, so it is
/// safe to use with any `T` that has the same size as `F` (4 bytes).
///
/// # Safety
/// - `output` must have length at least `height * width`.
/// - `input` must have length at least `lifted_height * width`.
pub unsafe fn collapse_strided_matrix_any<T>(
    output: *mut T,
    input: *const T,
    width: u32,
    height: u32,
    stride: u32,
) -> Result<(), CudaError> {
    // Safety: T has the same size as F (both are 4-byte field elements).
    // The kernel operates on raw bytes so the field semantics don't matter.
    assert_eq!(
        std::mem::size_of::<T>(),
        std::mem::size_of::<F>(),
        "collapse_strided_matrix_any: T must have same size as F"
    );
    CudaError::from_result(_kb_collapse_strided_matrix(
        output as *mut F,
        input as *const F,
        width,
        height,
        stride,
    ))
}

/// Zero-pads `poly_count` contiguous vectors of length `in_size` to length `out_size` each, for any
/// 4-byte element type.
pub unsafe fn batch_expand_pad_any<T>(
    output: *mut T,
    input: *const T,
    poly_count: u32,
    out_size: u32,
    in_size: u32,
) -> Result<(), CudaError> {
    assert_eq!(std::mem::size_of::<T>(), std::mem::size_of::<F>());
    CudaError::from_result(_kb_batch_expand_pad(
        output as *mut F,
        input as *const F,
        poly_count,
        out_size,
        in_size,
    ))
}

/// Zero-pads every column of a column-major `height × width` matrix to `padded_height` rows, for
/// any 4-byte element type. One block per column, so this variant suits very wide inputs (`width`
/// around 2^20).
///
/// # Safety
/// - `out` must have length at least `padded_height * width`.
/// - `input` must have length at least `height * width`.
pub unsafe fn batch_expand_pad_wide_any<T>(
    out: *mut T,
    input: *const T,
    width: u32,
    padded_height: u32,
    height: u32,
) -> Result<(), CudaError> {
    debug_assert!(padded_height > height);
    assert_eq!(std::mem::size_of::<T>(), std::mem::size_of::<F>());
    CudaError::from_result(_kb_batch_expand_pad_wide(
        out as *mut F,
        input as *const F,
        width,
        padded_height,
        height,
    ))
}

// ── Stacked-trace gather ───────────────────────────────────────────────────────

/// Descriptor for one unstacked column slice within the expanded stacked buffer.
/// Layout must match `StackGatherDesc` in `matrix.cu` (u64, u64, u32, u32 — 24 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StackGatherDesc {
    /// Device pointer to the column's source data.
    pub src: u64,
    /// Flat output index where this slice starts (table must be sorted ascending).
    pub dst_start: u64,
    /// Slice length in the output (`s_len = stride * src_len`).
    pub len: u32,
    /// 1 for plain copies; else `src[i]` lands at offset `i*stride`, rest zero.
    pub stride: u32,
}

/// One-pass stacked-trace gather: writes every cell of the expanded stacked buffer, gathering
/// from the descriptor table (binary search per cell) and writing the zero padding inline —
/// replaces the full-buffer memset + per-column memcpy/expand-pad launches of
/// `stack_traces_into_expanded`. Copy/zero only (Montgomery zero is bitwise zero), so it is
/// field-agnostic for any 4-byte element type, like [`batch_expand_pad_any`].
///
/// `vectorizable` selects a 4-wide kernel and asserts every `dst_start`, `len` and `total_cells` is
/// a multiple of 4. A wrong `true` corrupts silently, so the caller must **check**, not derive it.
pub unsafe fn stack_gather_any<T>(
    out: *mut T,
    d_descs: *const std::ffi::c_void,
    n_descs: u32,
    total_cells: usize,
    vectorizable: bool,
) -> Result<(), CudaError> {
    assert_eq!(std::mem::size_of::<T>(), std::mem::size_of::<F>());
    CudaError::from_result(_kb_stack_gather(
        out as *mut F,
        d_descs,
        n_descs,
        total_cells,
        vectorizable,
    ))
}
