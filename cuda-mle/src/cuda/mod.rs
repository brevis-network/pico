#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]

use crate::runtime::{d_buffer::DeviceBuffer, error::CudaError};
use mle_core::prover::fractional_sumcheck_gkr::Frac;

// Not dead: nothing in this file's own body names `Frac`, `EF` or `F`, but the `logup_zerocheck`
// types and the `logup_zerocheck_kb` bindings reach them by bare name through their
// `use super::*`, and `lib.rs`'s `allow(unused_imports)` means no lint guards them. The same is
// true of `DeviceBuffer` and `CudaError` imported above — `merkle_limits` re-imports `CudaError`
// locally, so the only remaining consumer of that line is `logup_zerocheck_kb`.
use crate::prelude::{EF, F};

pub mod batch_ntt_small;
pub mod device_info;
pub mod field_kernels;
pub mod jit;
pub mod logup_zerocheck;
pub mod logup_zerocheck_kb;
pub mod matrix;
pub mod matrix_kb;
pub mod merkle_tree_kb;
pub mod mle_interpolate;
pub mod mle_interpolate_kb;
pub mod ntt_kb;
pub mod poly_kb;
pub mod sponge_kb;
pub mod stacked_reduction_kb;
pub mod sumcheck_kb;
pub mod whir_kb;

/// Log of warp size (32)
pub const LOG_WARP_SIZE: usize = 5;

/// Launch-shape limits of the Merkle FFI bindings (`merkle_tree_kb`).
///
/// These are properties of the kernel launch geometry, not of a field: the leaf kernel puts one
/// strided row per `threadIdx.y`, so `2^log_rows_per_query` must fit a CUDA block's y-extent.
pub(crate) mod merkle_limits {
    use crate::runtime::error::CudaError;

    /// Max `log_rows_per_query`: `blockDim.y = 2^10 = 1024` is the CUDA per-block limit.
    ///
    /// Deliberately **1024 rows/query**, the full per-block limit. A lower cap such as 512 is a
    /// register/shared-memory budget for BN254 hashing; it does not apply to the Fp Merkle kernel
    /// this constant governs.
    pub(crate) const MAX_MERKLE_LOG_ROWS_PER_QUERY: usize = 10;

    /// Poseidon2 sponge state width and rate (`CELLS` / `CELLS_RATE` in
    /// `hash/poseidon2/poseidon2.cuh`).
    /// Mirrors p3's `PaddingFreeSponge<_, 16, 8, 8>`.
    pub(crate) const MERKLE_SPONGE_CELLS: usize = 16;
    pub(crate) const MERKLE_SPONGE_RATE: usize = 8;

    /// `cudaErrorInvalidValue`. Spelled out because `cuda-mle` has no `cudart_sys` dependency, and
    /// because a bare `1` at the call site reads as a sentinel rather than as a CUDA status.
    const CUDA_ERROR_INVALID_VALUE: i32 = 1;

    /// Reject a `log_rows_per_query` the launcher cannot express as a block y-extent.
    ///
    /// The typed, caller-facing form of this limit is `MerkleTreeError::UnsupportedRowsPerQuery`,
    /// raised in `merkle_tree::validate_merkle_rows_per_query` before any FFI call. This check is
    /// defence in depth at the boundary, so it can only speak the FFI's `CudaError`; the `.cu`
    /// launchers independently return `cudaErrorInvalidValue` for the same condition.
    pub(crate) fn validate_merkle_log_rows_per_query(
        log_rows_per_query: usize,
    ) -> Result<(), CudaError> {
        if log_rows_per_query > MAX_MERKLE_LOG_ROWS_PER_QUERY {
            return Err(CudaError::new(CUDA_ERROR_INVALID_VALUE));
        }
        Ok(())
    }
}
