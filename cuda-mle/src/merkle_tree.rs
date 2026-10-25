//! GPU Merkle commitment: leaf layer, inner layers, and the two query paths.
//!
//! # Layout, and its `mle-core` counterpart
//!
//! [`MerkleTreeGpu`] is the device twin of `mle_core::prover::stacked_pcs::ColMajorMerkleTree` and
//! stores digests in the same shape, which is why the two can be compared layer-for-layer (see the
//! parity tests at the bottom of this file).
//!
//! The leaf layer is built by **one fused kernel**: it row-hashes a column-major matrix and, in the
//! same launch, collapses each group of `rows_per_query` **strided** rows into a single stored leaf.
//! "Strided" is the load-bearing word — leaf `i` covers rows `{i + t * query_stride}` for
//! `t in 0..rows_per_query`, *not* a contiguous run — so a WHIR query that needs `rows_per_query`
//! rows reads one leaf and one authentication path. `query_stride = height / rows_per_query`, and
//! the `log2(rows_per_query)` collapse rounds are **not** materialized as layers. The CPU oracle
//! performs the same collapse in its constructor and likewise stores only the result.
//!
//! Inner layers then walk adjacent pairs to a single root, so
//! `digest_layers[0].len() == query_stride` and `proof_depth() == digest_layers.len() - 1`.
//!
//! # Preconditions, and where they differ from the CPU device
//!
//! Heights here must be **powers of two** — asserted, not padded. `mle-core`'s tree pads implicitly
//! (rows past the matrix read as zero), and `mle-cpu` hashes an explicit zero row. All three agree
//! numerically on a power-of-two height; the GPU simply has no padding concept, so callers pad
//! before committing and parity fixtures use power-of-two heights only.
//!
//! `rows_per_query` is validated in two places on purpose: it must be a power of two and fit within
//! the matrix height (**caller invariants**, so `assert!`), while exceeding
//! `MAX_MERKLE_ROWS_PER_QUERY` is a **backend limit**, so it returns
//! [`MerkleTreeError::UnsupportedRowsPerQuery`] and the caller can act on it. The 1024 value is
//! deliberate — see [`crate::cuda::merkle_limits`].
//!
//! # Field genericity
//!
//! The commit path is generic over the hash scheme ([`GpuMerkleHash`]), which fixes the field; the
//! two query paths are field-*agnostic* because they only move 32-byte digests and raw matrix words.
//! [`BatchQueryMerkle`] is where that reinterpretation is made explicit.

use std::array::from_fn;

use crate::runtime::{
    copy::{MemCopyD2H, MemCopyH2D},
    d_buffer::DeviceBuffer,
    memory_manager::MemTracker,
};
use itertools::Itertools;
use mle_core::poly::matrix::MatrixDimensions;
use p3_util::log2_strict_usize;
use tracing::{info_span, instrument};

use crate::{
    base::DeviceMatrix,
    cuda::{matrix::matrix_get_rows_fp_kernel, merkle_tree_kb::query_digest_layers},
    hash_scheme::GpuMerkleHash,
    prelude::{Digest, DIGEST_SIZE, F},
    MerkleTreeError,
};

/// Reconstruct a digest from the flat 32-bit words `query_digest_layers` gathers.
///
/// Every digest in this crate is `[Field; DIGEST_SIZE]` over a `#[repr(transparent)]`-over-`u32`
/// field, i.e. exactly `DIGEST_SIZE * 4` = 32 bytes. The gather kernel does no arithmetic, so the
/// words arrive **still in Montgomery form**: implementations must *reinterpret* each word as a
/// field element and must never re-encode it (`from_u32` would corrupt the digest).
pub trait BatchQueryMerkle: Copy + Sized + 'static {
    /// Reconstruct one digest from `DIGEST_SIZE` consecutive words of `out` starting at `base`.
    fn reconstruct_from_words(out: &[u32], base: usize) -> Self;
}

const MAX_MERKLE_ROWS_PER_QUERY: usize = 1024;

/// Returns `log2(rows_per_leaf)` once the leaf grouping is known to be buildable on the device.
fn checked_rows_per_query_log2(
    rows_per_leaf: usize,
    matrix_height: usize,
) -> Result<usize, MerkleTreeError> {
    // A non-power-of-two group size, or one taller than the matrix, is a caller bug and panics.
    // Exceeding the kernel's group-size cap is different: it is a property of this GPU backend,
    // not of the Merkle construction, so the caller gets an error it can handle.
    let log_rows_per_leaf = log2_strict_usize(rows_per_leaf);
    assert!(
        rows_per_leaf <= matrix_height,
        "rows_per_query ({rows_per_leaf}) must not exceed height ({matrix_height})"
    );
    if rows_per_leaf > MAX_MERKLE_ROWS_PER_QUERY {
        return Err(MerkleTreeError::UnsupportedRowsPerQuery {
            rows_per_query: rows_per_leaf,
            max_rows_per_query: MAX_MERKLE_ROWS_PER_QUERY,
        });
    }
    Ok(log_rows_per_leaf)
}

impl BatchQueryMerkle for mle_core::config::koala_bear_poseidon2::Digest {
    fn reconstruct_from_words(out: &[u32], base: usize) -> Self {
        use p3_koala_bear::KoalaBear;
        // SAFETY: `KoalaBear` is #[repr(transparent)] over u32 and the words are already
        // Montgomery-form limbs produced by the row-hash kernel, so this is a reinterpretation, not
        // a conversion.
        std::array::from_fn(|i| unsafe { std::mem::transmute::<u32, KoalaBear>(out[base + i]) })
    }
}

pub struct MerkleTreeGpu<FieldT, D> {
    /// Matrix whose rows are hashed into the leaf digests (the bottom digest layer).
    ///
    /// Kept only when the prover configuration asks for it. Keeping it costs peak GPU memory;
    /// dropping it means the MLE eval-to-coeffs, batch_expand and forward NTT have to be redone
    /// whenever rows are opened.
    pub(crate) backing_matrix: Option<DeviceMatrix<FieldT>>,
    pub(crate) digest_layers: Vec<DeviceBuffer<D>>,
    pub(crate) rows_per_query: usize,
    pub(crate) root: D,
}

pub trait MerkleTreeConstructor: GpuMerkleHash {
    fn new_merkle_tree(
        matrix: DeviceMatrix<Self::BaseField>, // Generic over BaseField from GpuMerkleHash
        rows_per_query: usize,
        cache_backing_matrix: bool,
    ) -> Result<MerkleTreeGpu<Self::BaseField, Self::Digest>, MerkleTreeError>;

    /// Commit by **streaming** the RS codeword one column-block at a time, or `None` if this scheme
    /// has no streaming kernels — in which case the caller falls back to the monolithic path.
    ///
    /// Why `Option` and why here: the streaming implementation
    /// ([`crate::stacked_pcs::rs_code_streamed_commit`]) is bounded on
    /// [`crate::hash_scheme::StreamingMerkleHash`], so it is **unreachable by type** for a scheme
    /// without the kernels. But its caller, `stacked_commit`, is generic over every scheme, so the
    /// capability cannot be a bound there. Per-scheme dispatch through this method is the
    /// resolution: the type system still guards the streaming code, and "this scheme cannot stream"
    /// is an honest `None` rather than the fabricated `cudaErrorInvalidValue` it used to return.
    #[allow(unused_variables)]
    fn new_merkle_tree_streamed(
        log_blowup: usize,
        layout: &mle_core::protocol::stacking::StackedLayout,
        traces: &[&DeviceMatrix<Self::BaseField>],
        rows_per_query: usize,
        n_blocks: usize,
    ) -> Option<Result<MerkleTreeGpu<Self::BaseField, Self::Digest>, crate::RsCodeMatrixError>>
    {
        None
    }
}

impl<FieldT, D> MerkleTreeGpu<FieldT, D> {
    /// Construct a MerkleTreeGpu from pre-uploaded digest layers (e.g., from CPU tree).
    /// The backing_matrix is not cached (None) to conserve GPU memory.
    pub fn from_digest_layers(
        digest_layers: Vec<DeviceBuffer<D>>,
        rows_per_query: usize,
        root: D,
    ) -> Self {
        Self {
            backing_matrix: None,
            digest_layers,
            rows_per_query,
            root,
        }
    }

    pub fn root(&self) -> D
    where
        D: Clone,
    {
        self.root.clone()
    }

    pub fn query_stride(&self) -> usize {
        self.digest_layers[0].len()
    }

    pub fn proof_depth(&self) -> usize {
        self.digest_layers.len() - 1
    }

    /// The leaf-preimage matrix, present only when the tree was built with
    /// `cache_backing_matrix = true` (and never for [`Self::from_digest_layers`]).
    pub fn backing_matrix(&self) -> Option<&DeviceMatrix<FieldT>> {
        self.backing_matrix.as_ref()
    }

    /// Number of strided rows collapsed into each stored leaf digest.
    pub fn rows_per_query(&self) -> usize {
        self.rows_per_query
    }
}

// Generic field Merkle tree constructor - works for any field FieldT
impl<FieldT: Copy + Send + Sync + 'static, D: Copy + Send + Sync + 'static>
    MerkleTreeGpu<FieldT, D>
{
    /// Builds the tree over `matrix`, hashing with `MH`.
    #[instrument(name = "merkle_tree", skip_all)]
    pub fn new_with_hash<MH: MerkleTreeConstructor<Digest = D, BaseField = FieldT>>(
        matrix: DeviceMatrix<FieldT>,
        rows_per_query: usize,
        cache_backing_matrix: bool,
    ) -> Result<Self, MerkleTreeError> {
        MH::new_merkle_tree(matrix, rows_per_query, cache_backing_matrix)
    }

    pub(crate) fn new_generic_with_hash<MH: GpuMerkleHash<Digest = D, BaseField = FieldT>>(
        matrix: DeviceMatrix<FieldT>,
        rows_per_query: usize,
        cache_backing_matrix: bool,
    ) -> Result<Self, MerkleTreeError> {
        let mem_tracker = MemTracker::start("prover.merkle_tree");
        let matrix_height = matrix.height();
        assert!(matrix_height.is_power_of_two());
        let log_rows_per_leaf = checked_rows_per_query_log2(rows_per_query, matrix_height)?;
        let leaf_count = matrix_height / rows_per_query;
        let mut leaf_layer = DeviceBuffer::<D>::with_capacity(leaf_count);
        // SAFETY: `leaf_layer` was just allocated with one slot per leaf.
        unsafe {
            MH::compress_rows(
                &mut leaf_layer,
                matrix.buffer(),
                matrix.width(),
                leaf_count,
                log_rows_per_leaf,
            )
            .map_err(MerkleTreeError::CompressingRowHashes)?;
        }
        // The leaves are done; keep the matrix only when the caller asked for it to be cached,
        // otherwise it is freed here, before the inner layers are allocated.
        let backing_matrix = cache_backing_matrix.then_some(matrix);

        let mut digest_layers = vec![leaf_layer];
        while digest_layers.last().unwrap().len() > 1 {
            let child_layer = digest_layers.last().unwrap();
            let mut parent_layer = DeviceBuffer::<D>::with_capacity(child_layer.len() / 2);
            let parent_len = parent_layer.len();
            let parent_level = digest_layers.len();
            // SAFETY: `parent_layer` is a fresh allocation of half the length of `child_layer`,
            // so the two buffers are disjoint and correctly sized for the pair-compress kernel.
            unsafe {
                MH::compress_layer(&mut parent_layer, child_layer, parent_len).map_err(
                    |error| MerkleTreeError::AdjacentCompressLayer {
                        error,
                        layer: parent_level,
                    },
                )?;
            }
            digest_layers.push(parent_layer);
        }
        let top_layer = digest_layers.last().unwrap();
        assert_eq!(top_layer.len(), 1, "Only one root is supported");
        let root = top_layer.to_host()?.pop().unwrap();

        mem_tracker.emit_metrics();
        Ok(Self {
            backing_matrix,
            digest_layers,
            rows_per_query,
            root,
        })
    }

    #[instrument(name = "batch_open_rows_f", skip_all)]
    pub(crate) fn batch_open_rows_f(
        backing_matrices: &[&DeviceMatrix<F>],
        query_indices: &[usize],
        query_stride: usize,
        rows_per_query: usize,
    ) -> Result<
        // Indexed [matrix][query]; each innermost Vec<F> is the `rows_per_query` strided rows of
        // that query's leaf, laid end to end.
        Vec<Vec<Vec<F>>>,
        MerkleTreeError,
    > {
        if query_indices.is_empty() {
            return Ok(vec![Vec::new(); backing_matrices.len()]);
        }
        let gather_row_idxs = query_indices
            .iter()
            .flat_map(|&leaf_idx| {
                debug_assert!(leaf_idx < query_stride);
                (0..rows_per_query)
                    .map(move |stride_step| (stride_step * query_stride + leaf_idx) as u32)
            })
            .collect_vec();
        let d_gather_row_idxs = gather_row_idxs.to_device()?;
        // One gather launch per matrix: the widths differ, so folding every matrix into a single
        // launch would need a dedicated kernel -- worth writing only if this shows up in profiles.
        // The loop stays sequential on purpose; spreading it over streams would cost extra
        // cross-stream synchronisation for little gain.
        backing_matrices
            .iter()
            .enumerate()
            .map(|(matrix_idx, source)| {
                let d_opened =
                    DeviceBuffer::<F>::with_capacity(gather_row_idxs.len() * source.width());
                // SAFETY: `d_opened` has one full row of `source.width()` elements for every
                // requested row index, and each index is below the matrix height (leaf index <
                // query_stride, stride step < rows_per_query).
                unsafe {
                    matrix_get_rows_fp_kernel(
                        &d_opened,
                        source.buffer(),
                        &d_gather_row_idxs,
                        source.width() as u64,
                        source.height() as u64,
                        d_gather_row_idxs.len(),
                    )
                    .map_err(|error| MerkleTreeError::MatrixGetRows { error, matrix_idx })?;
                }
                let row_width = source.width();
                let host_rows = info_span!("opened_rows_d2h").in_scope(|| d_opened.to_host())?;
                let rows_by_query = host_rows
                    .chunks_exact(rows_per_query * row_width)
                    .map(|leaf_rows| leaf_rows.to_vec())
                    .collect_vec();
                Ok(rows_by_query)
            })
            .collect::<Result<Vec<_>, MerkleTreeError>>()
    }
}

// KoalaBear Merkle tree constructor
impl MerkleTreeConstructor for crate::hash_scheme::KoalaBearPoseidon2MerkleHash {
    fn new_merkle_tree(
        matrix: DeviceMatrix<Self::BaseField>,
        rows_per_query: usize,
        cache_backing_matrix: bool,
    ) -> Result<MerkleTreeGpu<Self::BaseField, Self::Digest>, MerkleTreeError> {
        MerkleTreeGpu::<Self::BaseField, Self::Digest>::new_generic_with_hash::<Self>(
            matrix,
            rows_per_query,
            cache_backing_matrix,
        )
    }

    /// KoalaBear is the only scheme with the streaming kernels, so it is the only override.
    fn new_merkle_tree_streamed(
        log_blowup: usize,
        layout: &mle_core::protocol::stacking::StackedLayout,
        traces: &[&DeviceMatrix<Self::BaseField>],
        rows_per_query: usize,
        n_blocks: usize,
    ) -> Option<Result<MerkleTreeGpu<Self::BaseField, Self::Digest>, crate::RsCodeMatrixError>>
    {
        Some(crate::stacked_pcs::rs_code_streamed_commit::<
            Self::BaseField,
            Self,
        >(
            log_blowup, layout, traces, rows_per_query, n_blocks
        ))
    }
}

/// Generic (field-agnostic) Merkle query methods.
///
/// Neither method depends on the field-element type: `batch_query_merkle_proofs` touches only
/// digest layers, and `batch_open_rows` only moves raw 32-bit words. `batch_query_merkle_proofs`
/// is therefore implemented directly here — no type erasure is involved. `batch_open_rows` still
/// reaches a `F`-typed gather kernel and casts; see its own comment.
impl<FieldT, D: BatchQueryMerkle + Send + Sync + 'static> MerkleTreeGpu<FieldT, D> {
    #[instrument(name = "batch_open_rows_generic", skip_all)]
    pub fn batch_open_rows(
        backing_matrices: &[&DeviceMatrix<FieldT>],
        query_indices: &[usize],
        query_stride: usize,
        rows_per_query: usize,
    ) -> Result<Vec<Vec<Vec<FieldT>>>, MerkleTreeError> {
        // SAFETY: FieldT and F both are u32-based, same memory layout.
        let f_matrices: Vec<&DeviceMatrix<F>> = backing_matrices
            .iter()
            .map(|m| unsafe { &*(*m as *const DeviceMatrix<FieldT> as *const DeviceMatrix<F>) })
            .collect();
        let result = MerkleTreeGpu::<F, D>::batch_open_rows_f(
            &f_matrices,
            query_indices,
            query_stride,
            rows_per_query,
        )?;
        // SAFETY: Vec<F> and Vec<FieldT> have same element size and alignment.
        Ok(unsafe { std::mem::transmute(result) })
    }
}

impl<FieldT, D: BatchQueryMerkle + Send + Sync + 'static> MerkleTreeGpu<FieldT, D> {
    /// Gather one authentication path per (tree, query index) from the stored digest layers.
    ///
    /// Field-agnostic: only digest layers and their sibling indices are read, so this is generic
    /// over `FieldT` directly rather than delegating through a re-typed tree.
    pub fn batch_query_merkle_proofs(
        trees: &[&Self],
        query_indices: &[usize],
    ) -> Result<Vec<Vec<Vec<D>>>, MerkleTreeError> {
        if trees.is_empty() {
            return Ok(Vec::new());
        }
        // The gather kernel reads every digest layer through its own device pointer, so the
        // pointers of all trees are packed into one flat table, tree-major.
        let tree_count = trees.len();
        let query_count = query_indices.len();
        let path_len = trees[0].proof_depth();
        debug_assert!(
            trees
                .iter()
                .all(|merkle_tree| merkle_tree.proof_depth() == path_len),
            "Merkle trees don't have same depth"
        );
        if query_count == 0 {
            return Ok(vec![Vec::new(); tree_count]);
        }
        if path_len == 0 {
            return Ok(vec![vec![Vec::new(); query_count]; tree_count]);
        }
        let layer_ptrs = trees
            .iter()
            .flat_map(|merkle_tree| {
                // the last layer holds only the root, which is never part of a path
                merkle_tree
                    .digest_layers
                    .iter()
                    .take(path_len)
                    .map(|digest_layer| digest_layer.as_ptr() as u64)
            })
            .collect_vec();
        let d_layer_ptrs = layer_ptrs.to_device()?;
        debug_assert_eq!(d_layer_ptrs.len(), tree_count * path_len);

        // Sibling positions, ordered query-major, then tree, then layer: at layer `l` the
        // sibling of leaf `q` sits at `(q >> l) ^ 1`.
        let sibling_idxs = query_indices
            .iter()
            .flat_map(|&leaf_idx| {
                (0..tree_count).flat_map(move |tree_idx| {
                    (0..path_len).map(move |layer_idx| {
                        debug_assert!(leaf_idx < trees[tree_idx].query_stride());
                        ((leaf_idx >> layer_idx) ^ 1) as u64
                    })
                })
            })
            .collect_vec();
        let d_sibling_idxs = sibling_idxs.to_device()?;
        debug_assert_eq!(d_sibling_idxs.len(), d_layer_ptrs.len() * query_count);

        let mut d_proof_words =
            DeviceBuffer::<u32>::with_capacity(d_layer_ptrs.len() * query_count * DIGEST_SIZE);
        // SAFETY:
        // - `d_proof_words` holds tree_count * path_len * query_count digests of DIGEST_SIZE
        //   32-bit words each;
        // - `d_layer_ptrs` holds tree_count * path_len layer pointers, and `d_sibling_idxs` one
        //   sibling position per (query, tree, layer), i.e. that count times query_count;
        // - each digest is DIGEST_SIZE words (32 bytes) whatever field D is built on, so the
        //   word-based kernel copies exactly one digest per (query, tree, layer).
        unsafe {
            query_digest_layers(
                &mut d_proof_words,
                &d_layer_ptrs,
                &d_sibling_idxs,
                query_count,
                d_layer_ptrs.len(),
            )
            .map_err(MerkleTreeError::QueryDigestLayers)?;
        }
        let host_words = d_proof_words.to_host()?;
        // Chunk the flat word array back into digests, [query][tree][layer].
        let proofs = (0..tree_count)
            .map(|tree_idx| {
                (0..query_count)
                    .map(|query_idx| {
                        (0..path_len)
                            .map(|layer_idx| {
                                let word_offset = (query_idx * tree_count * path_len
                                    + tree_idx * path_len
                                    + layer_idx)
                                    * DIGEST_SIZE;
                                D::reconstruct_from_words(&host_words, word_offset)
                            })
                            .collect_vec()
                    })
                    .collect_vec()
            })
            .collect_vec();
        Ok(proofs)
    }
}

// ===========================================================================
// Tests — CPU<->GPU element-wise parity, plus the structural/edge cases.
//
// The oracle is `mle_core::prover::stacked_pcs::ColMajorMerkleTree`, the row-major CPU twin of
// `MerkleTreeGpu` (`cuda-mle` does not depend on `pico-mle-cpu`, so `mle-cpu`'s own merkle
// helpers are `pub(crate)` and unreachable from here).
//
// Note on prior coverage: this is not the module's first digest-value assertion — six KoalaBear
// digest tests already live in `kb_arithmetic_test.rs` (single-row, width 1 and width 8) and two
// commit-level digest-layer tests in `stacked_pcs.rs`. What was missing, and what these add, is a
// *swept* module-level comparison: layer count first (so a dropped layer cannot pass vacuously),
// then element-wise per layer, then the root, across `rows_per_query x width x height` — including
// widths that are not multiples of the sponge rate, which is where the partial-block branch lives.
// ===========================================================================
#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use itertools::Itertools;
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::runtime::copy::MemCopyH2D;

    /// Deterministic column-major test matrix. The kernels index `matrix[col * height + row]`, so
    /// the host buffer must be column-major; getting this backwards is the classic way to make a
    /// "parity" test compare two different matrices.
    fn host_col_major<T: PrimeCharacteristicRing>(
        width: usize,
        height: usize,
        salt: u32,
    ) -> Vec<T> {
        (0..width * height)
            .map(|i| {
                let x = (i as u32)
                    .wrapping_mul(2_654_435_761)
                    .wrapping_add(salt.wrapping_mul(97))
                    ^ ((i as u32) >> 3);
                // Stay well inside both primes so the value is unambiguous in either field.
                T::from_u32(x % 0x7000_0000)
            })
            .collect()
    }

    // ── KoalaBear parity: the production path ───────────────────────────────
    mod kb {
        use mle_core::{
            config::koala_bear_poseidon2::{default_koalabear_hasher, F as KbF},
            hasher::MerkleHasher,
            poly::matrix::ColMajorMatrix,
            prover::stacked_pcs::ColMajorMerkleTree,
        };

        use test_case::test_case;

        use super::*;
        use crate::hash_scheme::KoalaBearPoseidon2MerkleHash;

        type KbDigest = mle_core::config::koala_bear_poseidon2::Digest;
        type KbTree = MerkleTreeGpu<KbF, KbDigest>;

        /// `salt` must be varied when two trees of the *same shape* need distinct contents —
        /// deriving it from `(width, height)` alone silently produces identical trees.
        fn build_pair_salted(
            width: usize,
            height: usize,
            rows_per_query: usize,
            salt: u32,
        ) -> (KbTree, ColMajorMerkleTree<KbF, KbDigest>) {
            let host: Vec<KbF> = host_col_major(width, height, salt);
            let device =
                DeviceMatrix::new(Arc::new(host.clone().to_device().unwrap()), height, width);
            let gpu =
                KbTree::new_with_hash::<KoalaBearPoseidon2MerkleHash>(device, rows_per_query, true)
                    .expect("gpu merkle tree");
            let hasher = default_koalabear_hasher();
            let cpu =
                ColMajorMerkleTree::new(&hasher, ColMajorMatrix::new(host, width), rows_per_query)
                    .expect("cpu merkle tree");
            (gpu, cpu)
        }

        fn build_pair(
            width: usize,
            height: usize,
            rows_per_query: usize,
        ) -> (KbTree, ColMajorMerkleTree<KbF, KbDigest>) {
            build_pair_salted(width, height, rows_per_query, (width * 31 + height) as u32)
        }

        /// P-1 — digest layers, swept. `width in {1,7,9,16}` covers both sponge branches: 1/7/9 leave
        /// a partial rate block (the extra permutation fires), 16 is an exact multiple of the rate
        /// (it must not). Layer count is asserted before contents.
        #[test_case(1, 8; "rpq1_w1_h8")]
        #[test_case(7, 8; "rpq1_w7_h8")]
        #[test_case(9, 8; "rpq1_w9_h8")]
        #[test_case(16, 8; "rpq1_w16_h8")]
        #[test_case(4, 1024; "rpq1_w4_h1024")]
        fn kb_digest_layers_match_cpu_rpq1(width: usize, height: usize) {
            check_layers(width, height, 1);
        }

        #[test_case(4, 2, 16; "rpq2")]
        #[test_case(4, 4, 16; "rpq4")]
        #[test_case(7, 8, 64; "rpq8_w7")]
        #[test_case(9, 1024, 1024; "rpq1024_w9")]
        fn kb_digest_layers_match_cpu_strided(width: usize, rows_per_query: usize, height: usize) {
            check_layers(width, height, rows_per_query);
        }

        fn check_layers(width: usize, height: usize, rows_per_query: usize) {
            let (gpu, cpu) = build_pair(width, height, rows_per_query);
            let cpu_layers = cpu.digest_layers();
            assert_eq!(
                gpu.digest_layers.len(),
                cpu_layers.len(),
                "layer COUNT differs (w={width} h={height} rpq={rows_per_query}) — a missing layer \
                 must not pass by comparing only the layers that exist"
            );
            assert_eq!(gpu.query_stride(), cpu.query_stride(), "query_stride");
            assert_eq!(gpu.proof_depth(), cpu.proof_depth(), "proof_depth");
            for (i, (g, c)) in gpu.digest_layers.iter().zip_eq(cpu_layers).enumerate() {
                let got = g.to_host().unwrap();
                assert_eq!(&got, c, "digest layer {i} differs elementwise");
            }
            assert_eq!(gpu.root(), cpu.root().unwrap(), "root");
        }

        /// P-2 — authentication paths, including index 0, the last index, and a repeat.
        #[test]
        fn kb_batch_query_merkle_proofs_match_cpu() {
            let (width, height, rows_per_query) = (5usize, 64usize, 4usize);
            let (gpu, cpu) = build_pair(width, height, rows_per_query);
            let stride = cpu.query_stride();
            let queries = vec![0usize, 1, stride / 2, stride - 1, 0];

            let gpu_paths = KbTree::batch_query_merkle_proofs(&[&gpu], &queries).unwrap();
            assert_eq!(gpu_paths.len(), 1, "one tree in, one tree out");
            assert_eq!(gpu_paths[0].len(), queries.len());
            for (qi, &q) in queries.iter().enumerate() {
                let want = cpu.query_merkle_proof(q).unwrap();
                assert_eq!(
                    gpu_paths[0][qi].len(),
                    want.len(),
                    "path length for query {q}"
                );
                assert_eq!(gpu_paths[0][qi], want, "sibling digests for query {q}");
            }
        }

        /// P-2b — multiple trees in one call must not cross-contaminate.
        #[test]
        fn kb_batch_query_multi_tree_matches_per_tree_cpu() {
            let rows_per_query = 2usize;
            // Same shape (so the depths match, as `batch_query_proofs` requires) but distinct
            // contents, via distinct salts — otherwise the two trees would be identical and the
            // test could not detect a tree mix-up at all.
            let (g0, c0) = build_pair_salted(4, 32, rows_per_query, 11);
            let (g1, c1) = build_pair_salted(4, 32, rows_per_query, 12);
            assert_ne!(
                c0.root().unwrap(),
                c1.root().unwrap(),
                "fixtures must differ or this test is vacuous"
            );
            let queries = vec![0usize, 3, 7];
            let got = KbTree::batch_query_merkle_proofs(&[&g0, &g1], &queries).unwrap();
            assert_eq!(got.len(), 2);
            for (ti, cpu) in [&c0, &c1].into_iter().enumerate() {
                for (qi, &q) in queries.iter().enumerate() {
                    assert_eq!(
                        got[ti][qi],
                        cpu.query_merkle_proof(q).unwrap(),
                        "tree {ti} query {q}"
                    );
                }
            }
        }

        /// P-3 — opened rows vs the oracle's own accessor (`get_opened_rows` returns exactly the
        /// row set `{idx + t*query_stride}`, so no inline reconstruction is needed).
        #[test_case(1; "rpq1")]
        #[test_case(4; "rpq4")]
        fn kb_batch_open_rows_match_cpu(rows_per_query: usize) {
            let (width, height) = (6usize, 32usize);
            let host: Vec<KbF> = host_col_major(width, height, (width * 31 + height) as u32);
            let device =
                DeviceMatrix::new(Arc::new(host.clone().to_device().unwrap()), height, width);
            let hasher = default_koalabear_hasher();
            let cpu =
                ColMajorMerkleTree::new(&hasher, ColMajorMatrix::new(host, width), rows_per_query)
                    .unwrap();
            let query_stride = cpu.query_stride();
            let queries = vec![0usize, 1, query_stride - 1];

            let got = MerkleTreeGpu::<KbF, KbDigest>::batch_open_rows(
                &[&device],
                &queries,
                query_stride,
                rows_per_query,
            )
            .unwrap();
            assert_eq!(got.len(), 1);
            assert_eq!(got[0].len(), queries.len());
            for (qi, &q) in queries.iter().enumerate() {
                // GPU returns the rows concatenated; the oracle returns them per row.
                let want: Vec<KbF> = cpu.get_opened_rows(q).unwrap().concat();
                assert_eq!(got[0][qi], want, "opened rows for query {q}");
            }
        }

        /// P-4 — pin the compress order directly. A 2-row, rows_per_query=1 tree has root
        /// `compress(hash(row0), hash(row1))`; a transposed pair order would still produce a
        /// self-consistent tree, so the layer sweep alone would not catch it.
        #[test]
        fn kb_two_leaf_root_is_compress_of_row_hashes() {
            let (width, height) = (3usize, 2usize);
            let host: Vec<KbF> = host_col_major(width, height, 5);
            let device =
                DeviceMatrix::new(Arc::new(host.clone().to_device().unwrap()), height, width);
            let gpu =
                KbTree::new_with_hash::<KoalaBearPoseidon2MerkleHash>(device, 1, true).unwrap();

            let hasher = default_koalabear_hasher();
            let row = |r: usize| (0..width).map(|c| host[c * height + r]).collect_vec();
            let leaf0 = hasher.hash_slice(&row(0));
            let leaf1 = hasher.hash_slice(&row(1));
            assert_eq!(gpu.digest_layers[0].to_host().unwrap(), vec![leaf0, leaf1]);
            assert_eq!(
                gpu.root(),
                hasher.compress(leaf0, leaf1),
                "root = compress(l0, l1)"
            );
        }

        /// E-1 — a backend limit must surface as its typed error, not a panic or an opaque CUDA code.
        #[test]
        fn kb_rows_per_query_above_max_returns_typed_error() {
            let (width, height) = (2usize, 1usize << 11);
            let host: Vec<KbF> = host_col_major(width, height, 9);
            let device = DeviceMatrix::new(Arc::new(host.to_device().unwrap()), height, width);
            // Not `expect_err`: `MerkleTreeGpu` is deliberately not `Debug` (a `Debug` that read
            // device memory would hide I/O in a formatter).
            let err =
                match KbTree::new_with_hash::<KoalaBearPoseidon2MerkleHash>(device, 1 << 11, false)
                {
                    Ok(_) => panic!("rows_per_query = 2048 exceeds MAX_MERKLE_ROWS_PER_QUERY"),
                    Err(e) => e,
                };
            assert!(
                matches!(
                    err,
                    MerkleTreeError::UnsupportedRowsPerQuery {
                        rows_per_query: 2048,
                        max_rows_per_query: 1024
                    }
                ),
                "expected UnsupportedRowsPerQuery, got {err:?}"
            );
        }
    }
}
