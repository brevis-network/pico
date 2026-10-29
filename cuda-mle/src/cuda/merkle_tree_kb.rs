//! Rust bindings for the KoalaBear Poseidon2 Merkle tree CUDA kernels — **the production path**.
//!
//! Launch-shape limits and buffer preconditions are checked through [`super::merkle_limits`].
//!
//! # Why there is no `#[link(name = "cuda_kb_all")]` here
//!
//! Unlike `matrix_kb.rs` / `ntt_kb.rs`, these symbols are **not** in `cuda_kb_all`. pico-gpu's
//! `src/prover/merkle_tree.cu` declares `using Fp = kb31_t;` itself, and `build.rs` compiles it
//! into the **`mle-kernels`** library by name; it is absent from the explicit `cuda_kb_all` file
//! list.

use crate::runtime::{d_buffer::DeviceBuffer, error::CudaError};
use p3_koala_bear::KoalaBear;

use super::merkle_limits::{
    validate_merkle_log_rows_per_query, MERKLE_SPONGE_CELLS, MERKLE_SPONGE_RATE,
};
use crate::merkle_tree::BatchQueryMerkle;

pub(crate) type KbDigest = [KoalaBear; 8];

extern "C" {
    fn _kb_poseidon2_compressing_row_hashes(
        out: *mut KbDigest,
        matrix: *const KoalaBear,
        width: usize,
        query_stride: usize,
        log_rows_per_query: usize,
    ) -> i32;

    fn _kb_poseidon2_adjacent_compress_layer(
        output: *mut KbDigest,
        prev_layer: *const KbDigest,
        output_size: usize,
    ) -> i32;

    fn _kb_query_digest_layers(
        d_digest_matrix: *mut u32,
        d_layers_ptr: *const u64,
        d_indices: *const u64,
        num_query: u64,
        num_layer: u64,
    ) -> i32;

    fn _kb_poseidon2_absorb_columns(
        state: *mut KoalaBear,
        block: *const KoalaBear,
        width_block: usize,
        height: usize,
        is_first: i32,
        is_last: i32,
    ) -> i32;

    fn _kb_poseidon2_finalize_leaf_digests(
        out: *mut KbDigest,
        state: *const KoalaBear,
        query_stride: usize,
        log_rows_per_query: usize,
    ) -> i32;
}

/// Row-hash a column-major `width x (query_stride << log_rows_per_query)` matrix and collapse each
/// group of `2^log_rows_per_query` strided rows into one leaf digest, written in row order.
///
/// # Safety
/// - `out` must have length `>= query_stride` in `KbDigest` elements.
/// - `matrix` must hold `>= width * (query_stride << log_rows_per_query)` elements, column-major.
/// - `out` and `matrix` must not overlap.
pub unsafe fn kb_poseidon2_compressing_row_hashes(
    out: &mut DeviceBuffer<KbDigest>,
    matrix: &DeviceBuffer<KoalaBear>,
    width: usize,
    query_stride: usize,
    log_rows_per_query: usize,
) -> Result<(), CudaError> {
    validate_merkle_log_rows_per_query(log_rows_per_query)?;
    debug_assert!(matrix.len() >= width * (query_stride << log_rows_per_query));
    debug_assert!(out.len() >= query_stride);
    CudaError::from_result(_kb_poseidon2_compressing_row_hashes(
        out.as_mut_ptr(),
        matrix.as_ptr(),
        width,
        query_stride,
        log_rows_per_query,
    ))
}

/// Compress adjacent digest pairs of `prev_layer` into `output_size` digests.
///
/// # Safety
/// - `output` must have length `>= output_size` in `KbDigest` elements.
/// - `prev_layer` must have length `>= output_size * 2` in `KbDigest` elements.
/// - `output` and `prev_layer` must not overlap.
pub unsafe fn kb_poseidon2_adjacent_compress_layer(
    output: &mut DeviceBuffer<KbDigest>,
    prev_layer: &DeviceBuffer<KbDigest>,
    output_size: usize,
) -> Result<(), CudaError> {
    debug_assert!(output.len() >= output_size);
    debug_assert!(prev_layer.len() >= output_size * 2);
    CudaError::from_result(_kb_poseidon2_adjacent_compress_layer(
        output.as_mut_ptr(),
        prev_layer.as_ptr(),
        output_size,
    ))
}

/// Fold one column-block of an RS codeword into the per-row Poseidon2 sponge `state`.
///
/// # Safety
/// - `state` must hold `>= height * MERKLE_SPONGE_CELLS` elements; `block` must hold
///   `>= width_block * height` elements, column-major.
/// - **Rate alignment**: every block except the last (`is_last == false`) must have `width_block` a
///   multiple of [`MERKLE_SPONGE_RATE`]. The kernel does not persist the sponge's partial-lane
///   counter across blocks, so a misaligned non-final block silently resumes at lane 0, overwriting
///   the partial absorb — the leaf digests, and hence the commitment, then differ from the fused
///   row hash. Debug-asserted below; this is the one layer where the `unsafe` contract is declared,
///   so it is the layer that checks it.
pub unsafe fn kb_poseidon2_absorb_columns(
    state: &mut DeviceBuffer<KoalaBear>,
    block: &DeviceBuffer<KoalaBear>,
    width_block: usize,
    height: usize,
    is_first: bool,
    is_last: bool,
) -> Result<(), CudaError> {
    debug_assert!(
        is_last || width_block.is_multiple_of(MERKLE_SPONGE_RATE),
        "non-final streamed block must be rate-aligned: width_block={width_block} is not a \
         multiple of {MERKLE_SPONGE_RATE}; the sponge would resume at the wrong lane and the \
         commitment would silently differ from the fused row hash"
    );
    debug_assert!(state.len() >= height * MERKLE_SPONGE_CELLS);
    debug_assert!(block.len() >= width_block * height);
    CudaError::from_result(_kb_poseidon2_absorb_columns(
        state.as_mut_ptr(),
        block.as_ptr(),
        width_block,
        height,
        is_first as i32,
        is_last as i32,
    ))
}

/// Tree-reduce the finished per-row sponge digests in `state` down to `query_stride` leaf digests.
///
/// # Safety
/// - `out` must have length `>= query_stride` in `KbDigest` elements.
/// - `state` must hold `>= (query_stride << log_rows_per_query) * MERKLE_SPONGE_CELLS` elements,
///   laid out `state[lane * height + row]`, and must be the buffer a completed
///   [`kb_poseidon2_absorb_columns`] sequence wrote (i.e. the final call had `is_last == true`).
/// - `out` and `state` must not overlap.
pub unsafe fn kb_poseidon2_finalize_leaf_digests(
    out: &mut DeviceBuffer<KbDigest>,
    state: &DeviceBuffer<KoalaBear>,
    query_stride: usize,
    log_rows_per_query: usize,
) -> Result<(), CudaError> {
    validate_merkle_log_rows_per_query(log_rows_per_query)?;
    debug_assert!(out.len() >= query_stride);
    debug_assert!(
        state.len() >= (query_stride << log_rows_per_query) * MERKLE_SPONGE_CELLS,
        "state must hold codeword_height * {MERKLE_SPONGE_CELLS} elements"
    );
    CudaError::from_result(_kb_poseidon2_finalize_leaf_digests(
        out.as_mut_ptr(),
        state.as_ptr(),
        query_stride,
        log_rows_per_query,
    ))
}

/// Gather one sibling digest per `(layer, query)` out of the digest-layer pointer table into
/// `d_digest_matrix`, laid out `[query][layer]` with `DIGEST_SIZE` words per digest.
///
/// **Field-agnostic by construction**: the kernel performs no arithmetic, it copies 32 raw bytes per
/// digest. Typed on `u32` words rather than a field element so that the tree need not be
/// reinterpreted — every 32-bit field in this crate is `#[repr(transparent)]` over `u32`, and the
/// words stay in Montgomery form, so callers must *reinterpret* them (see
/// `BatchQueryMerkle::reconstruct_from_words`), never re-encode them.
///
/// # Safety
/// - `d_digest_matrix` must hold `>= num_layer * num_query * DIGEST_SIZE` words.
/// - `d_layers_ptr` must hold `num_layer` valid device pointers to digest layers.
/// - `d_indices` must hold `num_layer * num_query` in-bounds sibling indices.
pub unsafe fn query_digest_layers(
    d_digest_matrix: &mut DeviceBuffer<u32>,
    d_layers_ptr: &DeviceBuffer<u64>,
    d_indices: &DeviceBuffer<u64>,
    num_query: usize,
    num_layer: usize,
) -> Result<(), CudaError> {
    if num_query == 0 || num_layer == 0 {
        return Ok(());
    }
    if num_query > u16::MAX as usize {
        return Err(CudaError::new(1));
    }
    CudaError::from_result(_kb_query_digest_layers(
        d_digest_matrix.as_mut_ptr(),
        d_layers_ptr.as_ptr(),
        d_indices.as_ptr(),
        num_query as u64,
        num_layer as u64,
    ))
}
