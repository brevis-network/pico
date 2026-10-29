//! Hash-scheme dispatch: which CUDA kernels a Merkle commitment is built from.
//!
//! Three traits, in increasing scope:
//!
//! - [`GpuMerkleHash`] — the kernel triple a Merkle tree needs (`compress_rows`, `compress_layer`)
//!   plus the concrete `Digest` and `BaseField` they produce and consume.
//! - [`StreamingMerkleHash`] — the *optional* incremental leaf hash. A separate trait so that
//!   "only KoalaBear can stream" is checked by the compiler rather than asserted in a comment.
//! - [`GpuHashScheme`] — binds a `StarkProtocolConfig`, a Merkle hash and a transcript into one
//!   coherent proving configuration.
//!
//! **Leaf preimages are always base-field rows.** There is no extension-field commit path: the GPU
//! WHIR round tree transposes its `EF` codeword into `d_ef = 4` base-field columns before committing
//! (`whir.rs`), which is byte-for-byte the same leaf preimage `mle-cpu` hashes via
//! `g_rs[r].as_basis_coefficients_slice()`. A second, extension-typed spelling of that same commitment existed in
//! this module and was deleted as dead.

use crate::runtime::{d_buffer::DeviceBuffer, error::CudaError};
use mle_core::{
    config::koala_bear_poseidon2::KoalaBearPoseidon2Config, StarkProtocolConfig, SystemParams,
};
use p3_field::{PrimeField32, TwoAdicField};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    merkle_tree::BatchQueryMerkle, ntt_field::GpuNttField, sponge::GpuFiatShamirTranscript,
};

/// Selects the GPU kernels that implement one Merkle hash.
///
/// Each implementation routes the two kernel entry points (`compress_rows`, `compress_layer`) to
/// the appropriate CUDA FFI wrappers, and declares the concrete `Digest` type those kernels
/// produce. Leaf preimages are always **base-field** rows: an extension-field matrix is
/// transposed to `d_ef` base-field columns before it reaches this trait (see the module header).
pub trait GpuMerkleHash: Copy + Clone + Send + Sync + 'static {
    type Digest: Copy
        + Clone
        + PartialEq
        + Send
        + Sync
        + Serialize
        + DeserializeOwned
        + BatchQueryMerkle
        + 'static;

    /// The base field type this Merkle hash operates over.
    type BaseField: GpuNttField + PrimeField32 + TwoAdicField + Copy + Clone + Send + Sync + 'static;

    /// Hashes each group of `1 << log_rows_per_query` base-field rows into one leaf digest.
    ///
    /// # Safety
    ///
    /// `out` needs room for `query_stride` digests, and `matrix` must hold
    /// `width * query_stride * (1 << log_rows_per_query)` initialized elements.
    unsafe fn compress_rows(
        out: &mut DeviceBuffer<Self::Digest>,
        matrix: &DeviceBuffer<Self::BaseField>,
        width: usize,
        query_stride: usize,
        log_rows_per_query: usize,
    ) -> Result<(), CudaError>;

    /// Build the next Merkle layer up by hashing each sibling pair of `child_layer` into one
    /// parent digest.
    ///
    /// # Safety
    ///
    /// `parent_layer` needs room for `parent_count` digests, `child_layer` must hold at least
    /// twice that many initialized digests, and the two buffers may not alias.
    unsafe fn compress_layer(
        parent_layer: &mut DeviceBuffer<Self::Digest>,
        child_layer: &DeviceBuffer<Self::Digest>,
        parent_count: usize,
    ) -> Result<(), CudaError>;
}

/// Schemes that can hash leaves **incrementally, one column-block at a time**.
///
/// Splitting the fused row hash into `absorb_columns` + `finalize_leaf_digests` is what lets the
/// stacked commit hold only one RS column-block on the device instead of the whole codeword
/// matrix — the difference between fitting and not fitting a `CHUNK_SIZE = 2^23` chunk on a 32 GB
/// card.
///
/// This is a **separate trait, not two provided methods on [`GpuMerkleHash`]**, so that
/// "only KoalaBear can stream" is a bound the compiler checks rather than a comment on the caller.
/// Requiring it (see `stacked_pcs::rs_code_streamed_commit`) makes a non-streaming scheme a
/// compile error instead of a runtime `Err`.
pub trait StreamingMerkleHash: GpuMerkleHash {
    /// Fold one RS-codeword column-block into the per-row Poseidon2 sponge `state`.
    ///
    /// Call once per block in column order, with `is_first` on the first and `is_last` on the last;
    /// `finalize_leaf_digests` then reduces `state` to leaf digests.
    ///
    /// # Safety
    /// - `state` must hold `height * CELLS` (16) base-field elements, `block` must hold
    ///   `width_block * height` elements, column-major.
    /// - **Rate alignment**: every block except the last must have `width_block` a multiple of the
    ///   sponge rate (8). Otherwise the sponge resumes at the wrong lane on the next block and the
    ///   leaf digests — hence the commitment — silently differ from the fused row hash. Callers
    ///   round block widths up to a multiple of the rate; the FFI wrapper `debug_assert!`s it.
    unsafe fn absorb_columns(
        state: &mut DeviceBuffer<Self::BaseField>,
        block: &DeviceBuffer<Self::BaseField>,
        width_block: usize,
        height: usize,
        is_first: bool,
        is_last: bool,
    ) -> Result<(), CudaError>;

    /// Tree-reduce the finished per-row sponge digests in `state` into `query_stride` leaf digests.
    ///
    /// # Safety
    /// `out` must hold `query_stride` digests; `state` must hold
    /// `(query_stride << log_rows_per_query) * CELLS` (16) base-field elements.
    unsafe fn finalize_leaf_digests(
        out: &mut DeviceBuffer<Self::Digest>,
        state: &DeviceBuffer<Self::BaseField>,
        query_stride: usize,
        log_rows_per_query: usize,
    ) -> Result<(), CudaError>;
}

/// One GPU proving setup: the protocol config `SC` together with the Merkle hash and the
/// Fiat-Shamir transcript that go with it.
pub trait GpuHashScheme: Copy + Clone + Send + Sync + 'static {
    type SC: StarkProtocolConfig<F = Self::BaseField, EF = Self::ExtField, Digest = Self::Digest>;
    type Digest: Copy
        + Clone
        + PartialEq
        + Send
        + Sync
        + Serialize
        + DeserializeOwned
        + BatchQueryMerkle
        + 'static;

    /// The base prime field for this proving configuration.
    type BaseField: GpuNttField + PrimeField32 + TwoAdicField + Copy + Clone + Send + Sync + 'static;

    /// The extension field (typically degree-4 extension of `BaseField`).
    type ExtField: p3_field::Field
        + p3_field::TwoAdicField
        + p3_field::ExtensionField<Self::BaseField>
        + p3_field::BasedVectorSpace<Self::BaseField>
        + mle_core::poly::Squarable
        + Copy
        + Clone
        + Send
        + Sync
        + Serialize
        + DeserializeOwned
        + std::fmt::Debug
        + std::fmt::Display
        + 'static;

    type Transcript: GpuFiatShamirTranscript<Self::SC> + Default + Clone + Send + Sync + 'static;
    type MerkleHash: GpuMerkleHash<Digest = Self::Digest, BaseField = Self::BaseField>;

    fn default_config(params: SystemParams) -> Self::SC;

    fn default_transcript() -> Self::Transcript;
}

// ─── KoalaBear Poseidon2 hash scheme ────────────────────────────────────────

mod kb_hash_scheme {
    use mle_core::config::koala_bear_poseidon2::{Digest as KbDigest, EF as KbEF, F as KbF};

    use super::*;
    use crate::{
        cuda::merkle_tree_kb::{
            kb_poseidon2_absorb_columns, kb_poseidon2_adjacent_compress_layer,
            kb_poseidon2_compressing_row_hashes, kb_poseidon2_finalize_leaf_digests,
        },
        sponge::KoalaBearDuplexSpongeGpu,
    };

    /// KoalaBear Poseidon2 Merkle hash — uses kb31_t CUDA kernels.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct KoalaBearPoseidon2MerkleHash;

    impl GpuMerkleHash for KoalaBearPoseidon2MerkleHash {
        type Digest = KbDigest;
        type BaseField = KbF;

        unsafe fn compress_rows(
            out: &mut DeviceBuffer<Self::Digest>,
            matrix: &DeviceBuffer<KbF>,
            width: usize,
            query_stride: usize,
            log_rows_per_query: usize,
        ) -> Result<(), CudaError> {
            kb_poseidon2_compressing_row_hashes(
                out,
                matrix,
                width,
                query_stride,
                log_rows_per_query,
            )
        }

        unsafe fn compress_layer(
            output: &mut DeviceBuffer<Self::Digest>,
            prev_layer: &DeviceBuffer<Self::Digest>,
            output_size: usize,
        ) -> Result<(), CudaError> {
            kb_poseidon2_adjacent_compress_layer(output, prev_layer, output_size)
        }
    }

    /// KoalaBear is the **only** streaming-capable scheme; see [`StreamingMerkleHash`].
    impl StreamingMerkleHash for KoalaBearPoseidon2MerkleHash {
        unsafe fn absorb_columns(
            state: &mut DeviceBuffer<KbF>,
            block: &DeviceBuffer<KbF>,
            width_block: usize,
            height: usize,
            is_first: bool,
            is_last: bool,
        ) -> Result<(), CudaError> {
            kb_poseidon2_absorb_columns(state, block, width_block, height, is_first, is_last)
        }

        unsafe fn finalize_leaf_digests(
            out: &mut DeviceBuffer<Self::Digest>,
            state: &DeviceBuffer<KbF>,
            query_stride: usize,
            log_rows_per_query: usize,
        ) -> Result<(), CudaError> {
            kb_poseidon2_finalize_leaf_digests(out, state, query_stride, log_rows_per_query)
        }
    }

    /// KoalaBear Poseidon2 GPU hash scheme.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct KoalaBearPoseidon2HashScheme;

    impl GpuHashScheme for KoalaBearPoseidon2HashScheme {
        type SC = KoalaBearPoseidon2Config;
        type Digest = KbDigest;
        type BaseField = KbF;
        type ExtField = KbEF;
        type Transcript = KoalaBearDuplexSpongeGpu;
        type MerkleHash = KoalaBearPoseidon2MerkleHash;

        fn default_config(params: SystemParams) -> Self::SC {
            Self::SC::default_from_params(params)
        }

        fn default_transcript() -> Self::Transcript {
            Self::Transcript::default()
        }
    }
}

pub use kb_hash_scheme::{KoalaBearPoseidon2HashScheme, KoalaBearPoseidon2MerkleHash};
