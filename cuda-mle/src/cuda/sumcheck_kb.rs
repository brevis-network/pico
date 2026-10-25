//! FFI wrappers over the three fold launchers in pico-gpu's `src/prover/sumcheck.cu` — the
//! per-round multilinear folds that every sumcheck in the backend runs. [`fold_mle`] serves the
//! stacked opening reduction, [`batch_fold_mle`] the LogUp/zerocheck rounds, and
//! [`triangular_fold_mle`] the `eq` / `kappa_rot` segment trees.
//!
//! Linked from the **`cuda_kb_all`** static lib; like every launcher there, the exports are
//! named `_kb_*` in `sumcheck.cu` itself.
//!
//! **Buffer convention — column-major.** A `height x width` matrix is one contiguous buffer of
//! `height * width` cells in which column `c` occupies `[c * height, (c + 1) * height)`. A fold
//! keeps `width`, halves `height`, and pairs the *adjacent* rows `2y` / `2y + 1` inside each
//! column:
//!
//! ```text
//! out[y] = in[2y] + r * (in[2y + 1] - in[2y])
//! ```
//!
//! That column-major pairing is why `crate::tests::fold_parity` takes its oracles from
//! `mle_core::prover::sumcheck` (`fold_mle_evals` / `batch_fold_mle_evals`) and
//! `mle_core::poly::eq`, not from the row-major twins.
//!
//! **Ordering.** Every launcher issues on the per-thread default stream (`build.rs` compiles the
//! CUDA sources with `--default-stream=per-thread`, which is also what `DeviceBuffer`'s copies
//! use), so a launch is ordered against the calling thread's other work but asynchronous with
//! respect to the host: synchronize before reading an output, and keep every buffer the launch
//! names alive until it completes.

use crate::runtime::{d_buffer::DeviceBuffer, error::CudaError};

use crate::{poly::EqEvalSegments, prelude::EF};

#[link(name = "cuda_kb_all", kind = "static")]
extern "C" {
    fn _kb_fold_mle(
        input_matrices: *const *const EF,
        output_matrices: *const *mut EF,
        widths: *const u32,
        num_matrices: u16,
        output_height: u32,
        max_output_cells: u32,
        r_val: EF,
    ) -> i32;

    fn _kb_triangular_fold_mle(output: *mut EF, input: *const EF, r: EF, output_max_n: u32) -> i32;

    fn _kb_batch_fold_mle(
        input_matrices: *const *const EF,
        output_matrices: *const *mut EF,
        widths: *const u32,
        num_matrices: u16,
        log_output_heights: *const u8,
        max_output_cells: u32,
        r_val: EF,
    ) -> i32;
}

/// Folds one sumcheck round at `r_val` over `num_matrices` column-major matrices that all share
/// the height `2 * output_height`.
///
/// This and [`batch_fold_mle`] differ only in where the output height comes from, and that is why
/// both exist: the one shared `output_height` reaches every thread through the constant bank,
/// where the ragged entry point loads `log_output_heights[mat_idx]` from global memory in every
/// thread. Collapsing the pair would put that load on the stacked-reduction path, which folds once
/// per round over the widest buffers in the proof.
///
/// # Safety
/// - `input_matrices`, `output_matrices` and `widths` must each hold `num_matrices` entries
///   describing matrix `i` at index `i`; the first two are pointers into device memory.
/// - For each `i < num_matrices`, `input_matrices[i]` must be valid for
///   `2 * output_height * widths[i]` reads and `output_matrices[i]` valid for
///   `output_height * widths[i]` writes, both column-major, and the two must not alias.
/// - `max_output_cells` must be at least `max_i output_height * widths[i]` — the grid is sized
///   from it. This one is *not* checked: too small a value silently leaves part of the output
///   unwritten.
/// - `output_height` must be a non-zero power of two, and `num_matrices` and `max_output_cells`
///   must both be non-zero. The launcher checks these three and returns `cudaErrorInvalidValue`
///   without launching — defence in depth, unreachable from the production caller.
/// - Every buffer above, including the matrices the pointer arrays point *to*, must outlive the
///   launch; see the module docs on stream ordering.
pub unsafe fn fold_mle(
    input_matrices: &DeviceBuffer<*const EF>,
    output_matrices: &DeviceBuffer<*mut EF>,
    widths: &DeviceBuffer<u32>,
    num_matrices: u16,
    output_height: u32,
    max_output_cells: u32,
    r_val: EF,
) -> Result<(), CudaError> {
    debug_assert_eq!(input_matrices.len(), num_matrices as usize);
    debug_assert_eq!(output_matrices.len(), num_matrices as usize);
    debug_assert_eq!(widths.len(), num_matrices as usize);
    CudaError::from_result(_kb_fold_mle(
        input_matrices.as_ptr(),
        output_matrices.as_ptr(),
        widths.as_ptr(),
        num_matrices,
        output_height,
        max_output_cells,
        r_val,
    ))
}

/// Binds one variable of every segment of `input` to `r`, writing the halved segments to `output`.
///
/// One launch folds every layer: output layer `n` is built from input layer `n + 1`, for all `n`
/// in `0..=output_max_n`, so an [`EqEvalSegments`] over `max_n = output_max_n + 1` variables
/// becomes one over `output_max_n`. Index 0 of each buffer is the unread slot the type documents.
///
/// # Safety
/// - `output` holds layers up to `n = output_max_n`, so its buffer has `2 << output_max_n` entries.
/// - `input` holds one more layer, so its buffer has `4 << output_max_n` entries.
/// - `output_max_n` must be below 31; the launcher checks this and returns
///   `cudaErrorInvalidValue` without launching. `output_max_n == 0` is legitimate and reachable:
///   the last round folds a single-cell layer with one thread.
/// - Both buffers must be device memory, must not alias, and must outlive the launch; the kernel
///   writes all of `output` except index 0, so a partially initialized `input` yields a partially
///   garbage `output` rather than an error.
pub unsafe fn triangular_fold_mle(
    output: &mut EqEvalSegments<EF>,
    input: &EqEvalSegments<EF>,
    r: EF,
    output_max_n: usize,
) -> Result<(), CudaError> {
    debug_assert_eq!(output.buffer.len(), 2 << output_max_n);
    debug_assert_eq!(input.buffer.len(), 4 << output_max_n);
    CudaError::from_result(_kb_triangular_fold_mle(
        output.buffer.as_mut_ptr(),
        input.buffer.as_ptr(),
        r,
        output_max_n as u32,
    ))
}

/// Folds one sumcheck round at `r_val` over `num_matrices` column-major matrices of *independent*
/// heights, matrix `i` going from `2 << log_output_heights[i]` rows to
/// `1 << log_output_heights[i]`.
///
/// See [`fold_mle`] for why both entry points exist.
///
/// # Safety
/// - `input_matrices`, `output_matrices`, `widths` and `log_output_heights` must each hold
///   `num_matrices` entries describing matrix `i` at index `i`; the two pointer arrays point into
///   device memory.
/// - For each `i < num_matrices`, writing `h = 1 << log_output_heights[i]`, `input_matrices[i]`
///   must be valid for `2 * h * widths[i]` reads and `output_matrices[i]` valid for
///   `h * widths[i]` writes, both column-major, and the two must not alias.
/// - `max_output_cells` must be at least `max_i (1 << log_output_heights[i]) * widths[i]` — the
///   grid is sized from it. Not checked: too small a value silently leaves part of the output
///   unwritten.
/// - `num_matrices` and `max_output_cells` must both be non-zero. The launcher checks these and
///   returns `cudaErrorInvalidValue` without launching — defence in depth, unreachable from the
///   production caller. There is no height check, unlike [`fold_mle`]: this entry point is handed
///   the logs directly and runs no `clz`.
/// - Every buffer above, including the matrices the pointer arrays point *to*, must outlive the
///   launch; see the module docs on stream ordering.
pub unsafe fn batch_fold_mle(
    input_matrices: &DeviceBuffer<*const EF>,
    output_matrices: &DeviceBuffer<*mut EF>,
    widths: &DeviceBuffer<u32>,
    num_matrices: u16,
    log_output_heights: &DeviceBuffer<u8>,
    max_output_cells: u32,
    r_val: EF,
) -> Result<(), CudaError> {
    debug_assert_eq!(input_matrices.len(), num_matrices as usize);
    debug_assert_eq!(output_matrices.len(), num_matrices as usize);
    debug_assert_eq!(widths.len(), num_matrices as usize);
    debug_assert_eq!(log_output_heights.len(), num_matrices as usize);
    CudaError::from_result(_kb_batch_fold_mle(
        input_matrices.as_ptr(),
        output_matrices.as_ptr(),
        widths.as_ptr(),
        num_matrices,
        log_output_heights.as_ptr(),
        max_output_cells,
        r_val,
    ))
}
