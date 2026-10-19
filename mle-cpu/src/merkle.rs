//! [CpuMerkleTree] — a Merkle tree backed by a [RowMajorMatrix].
//!
//! This mirrors the interface of [`pico_mle_core::prover::stacked_pcs::ColMajorMerkleTree`]
//! but stores its codeword matrix in row-major layout for cache-friendly row hashing
//! and contiguous row access in query answering.

use p3_dft::TwoAdicSubgroupDft;
use p3_field::TwoAdicField;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use p3_util::log2_strict_usize;
use pico_mle_core::{
    hasher::MerkleHasher,
    poly::{
        eval_to_coeff_rs_message_with_twiddles,
        matrix::{ColMajorMatrix, MatrixDimensions},
        ntt::TwiddleDft,
    },
    protocol::stacking::StackedPcsError,
};
use tracing::instrument;

/// Merkle tree with row-major codeword backing.
///
/// Each leaf corresponds to a row of `backing_matrix` (or a batch of rows when
/// `rows_per_query > 1`).  The `digest_layers` are built exactly as in
/// [`ColMajorMerkleTree`](pico_mle_core::prover::stacked_pcs::ColMajorMerkleTree), so
/// proof construction and verification are identical.
#[derive(Clone, Debug)]
pub struct CpuMerkleTree<F, Digest> {
    pub(crate) backing_matrix: RowMajorMatrix<F>,
    pub(crate) digest_layers: Vec<Vec<Digest>>,
    pub(crate) rows_per_query: usize,
}

impl<F, Digest> CpuMerkleTree<F, Digest> {
    /// Construct a `CpuMerkleTree` from pre-computed parts without validation.
    ///
    /// # Correctness
    ///
    /// The caller must guarantee:
    /// - `digest_layers` form a valid Merkle tree over `backing_matrix`: the leaf layer contains
    ///   correct hashes of the matrix rows and each subsequent layer contains correct compressions
    ///   of consecutive pairs from the previous layer, terminating in a single root digest.
    /// - `rows_per_query` is a power of two and does not exceed the number of leaves (i.e.,
    ///   `backing_matrix.height().next_power_of_two()`).
    /// - The leaf layer length equals `backing_matrix.height().next_power_of_two() /
    ///   rows_per_query`.
    ///
    /// Violating these invariants yields incorrect Merkle proofs or panics in downstream
    /// query/verification code. This is a correctness contract, not a memory-safety one — every
    /// downstream access is bounds-checked — so the constructor is safe (not `unsafe`).
    pub fn from_raw_parts(
        backing_matrix: RowMajorMatrix<F>,
        digest_layers: Vec<Vec<Digest>>,
        rows_per_query: usize,
    ) -> Self {
        Self {
            backing_matrix,
            digest_layers,
            rows_per_query,
        }
    }

    /// Returns a reference to the row-major codeword matrix.
    pub fn backing_matrix(&self) -> &RowMajorMatrix<F> {
        &self.backing_matrix
    }

    /// Returns a reference to the digest layers.
    pub fn digest_layers(&self) -> &Vec<Vec<Digest>> {
        &self.digest_layers
    }

    /// Number of rows batched into each Merkle leaf.
    pub fn rows_per_query(&self) -> usize {
        self.rows_per_query
    }

    /// Number of distinct query indices (= number of entries in the bottom digest layer).
    pub fn query_stride(&self) -> usize {
        self.digest_layers[0].len()
    }

    /// Depth of a Merkle proof (number of sibling digests).
    pub fn proof_depth(&self) -> usize {
        self.digest_layers.len() - 1
    }
}

impl<F, Digest: Clone> CpuMerkleTree<F, Digest> {
    /// Returns the Merkle root (the single element of the topmost digest layer).
    pub fn root(&self) -> Result<Digest, StackedPcsError> {
        Ok(self
            .digest_layers
            .last()
            .ok_or(StackedPcsError::MerkleTreeNoRoot)?[0]
            .clone())
    }

    /// Returns the Merkle authentication path for the given `query_idx`.
    pub fn query_merkle_proof(&self, query_idx: usize) -> Result<Vec<Digest>, StackedPcsError> {
        let stride = self.query_stride();
        if query_idx >= stride {
            return Err(StackedPcsError::MerkleTreeQueryOutOfBounds {
                query_idx,
                query_stride: stride,
            });
        }

        let mut idx = query_idx;
        let mut proof = Vec::with_capacity(self.proof_depth());
        for layer in self.digest_layers.iter().take(self.proof_depth()) {
            let sibling = layer[idx ^ 1].clone();
            proof.push(sibling);
            idx >>= 1;
        }
        Ok(proof)
    }
}

impl<F: Copy, Digest> CpuMerkleTree<F, Digest> {
    /// Returns the opened rows for the given query index.
    ///
    /// The rows are `{ index + t * query_stride() }` for `t` in `0..rows_per_query`.
    ///
    /// Because the backing matrix is row-major, each row is a contiguous slice —
    /// no scatter-gather is needed (unlike the column-major variant).
    pub fn get_opened_rows(&self, index: usize) -> Result<Vec<Vec<F>>, StackedPcsError> {
        let query_stride = self.query_stride();
        if index >= query_stride {
            return Err(StackedPcsError::MerkleTreeOpenedRowsOutOfBounds {
                index,
                query_stride,
            });
        }

        let width = self.backing_matrix.width;
        let height = self.backing_matrix.values.len() / width;
        let mut rows = Vec::with_capacity(self.rows_per_query);
        for t in 0..self.rows_per_query {
            let row_idx = t * query_stride + index;
            if row_idx < height {
                let start = row_idx * width;
                rows.push(self.backing_matrix.values[start..start + width].to_vec());
            } else {
                // Padding row for matrices whose height is not a power of two.
                rows.push(vec![]);
            }
        }
        Ok(rows)
    }
}

pub(crate) fn hash_rows_with_padding<D, RowHashFn, PaddingHashFn>(
    num_leaves: usize,
    codeword_height: usize,
    row_hash_fn: RowHashFn,
    padding_hash_fn: PaddingHashFn,
) -> Vec<D>
where
    D: Send,
    RowHashFn: Fn(usize) -> D + Sync + Send,
    PaddingHashFn: Fn() -> D + Sync + Send,
{
    (0..num_leaves)
        .into_par_iter()
        .map(|r| {
            if r < codeword_height {
                row_hash_fn(r)
            } else {
                padding_hash_fn()
            }
        })
        .collect()
}

/// Fused RS encoding + Merkle tree construction with RowMajor backing.
///
/// Eliminates the Phase 6 transpose to col-major that the reference implementation requires,
/// since `CpuMerkleTree` stores the codeword matrix in row-major layout directly.
#[instrument(name = "rs_encode_and_merkle_cpu", skip_all)]
pub(crate) fn rs_encode_and_merkle_cpu<F, H>(
    hasher: &H,
    l_skip: usize,
    log_blowup: usize,
    eval_matrix: &ColMajorMatrix<F>,
    rows_per_query: usize,
) -> CpuMerkleTree<F, H::Digest>
where
    F: TwoAdicField + Ord + 'static,
    H: MerkleHasher<F = F>,
{
    use p3_dft::Radix2DitParallel;
    use p3_matrix::dense::RowMajorMatrix as P3RowMajorMatrix;

    let height = eval_matrix.height();
    let codeword_height = height.checked_shl(log_blowup as u32).unwrap();
    let width = eval_matrix.width();
    let twiddles = TwiddleDft::new(l_skip);

    // Phase 1: Convert PLE evaluations to coefficients (parallel per column).
    let coeff_vecs: Vec<Vec<F>> = tracing::info_span!("eval_to_coeff_phase").in_scope(|| {
        eval_matrix
            .values
            .par_chunks_exact(height)
            .map(|column_evals| {
                let mut coeffs = eval_to_coeff_rs_message_with_twiddles(column_evals, &twiddles);
                coeffs.resize(codeword_height, F::ZERO);
                coeffs
            })
            .collect()
    });

    // Phase 2: Transpose column vectors into a RowMajorMatrix for batch DFT.
    let rm_mat: P3RowMajorMatrix<F> = tracing::info_span!("transpose_to_rm").in_scope(|| {
        let mut rm_values = F::zero_vec(codeword_height * width);
        rm_values
            .par_chunks_exact_mut(width)
            .enumerate()
            .for_each(|(i, row)| {
                for (j, col) in coeff_vecs.iter().enumerate() {
                    row[j] = col[i];
                }
            });
        P3RowMajorMatrix::new(rm_values, width)
    });
    drop(coeff_vecs);

    // Phase 3: Batch DFT — single level of rayon parallelism + SIMD butterflies.
    let rm_result = tracing::info_span!("dft_batch").in_scope(|| {
        use p3_matrix::Matrix as _;
        Radix2DitParallel::default()
            .dft_batch(rm_mat)
            .to_row_major_matrix()
    });

    // Phase 4: Hash each codeword row into a leaf digest (padding short matrices with zero rows).
    let num_leaves = codeword_height.next_power_of_two();
    let rm_vals = &rm_result.values;
    let row_hashes: Vec<H::Digest> = tracing::info_span!("row_hash").in_scope(|| {
        let zero_row = vec![F::ZERO; width];
        hash_rows_with_padding(
            num_leaves,
            codeword_height,
            |r| hasher.hash_slice(&rm_vals[r * width..(r + 1) * width]),
            || hasher.hash_slice(&zero_row),
        )
    });

    // Phase 5: Build Merkle digest layers.
    let digest_layers = tracing::info_span!("digest_layers")
        .in_scope(|| build_digest_layers(row_hashes, rows_per_query, hasher));

    // No Phase 6: RowMajor DFT result is stored directly as the backing matrix.
    // This eliminates the O(n*m) transpose to col-major.

    // SAFETY: digest_layers were just computed as correct Merkle hashes over rm_result by
    // hash_rows_with_padding and build_digest_layers above.
    // rows_per_query is forwarded from the validated SystemParams.
    CpuMerkleTree::from_raw_parts(rm_result, digest_layers, rows_per_query)
}

/// Build Merkle digest layers from row hashes by repeated pairwise compression.
///
/// Shared by both `rs_encode_and_merkle_cpu` and `build_ef_merkle_tree_packed` in the WHIR module.
/// The first `log2(rows_per_query)` layers interleave by query stride (so a query index addresses a
/// contiguous batch of rows); the remaining layers are a standard adjacent-pair binary tree.
pub(crate) fn build_digest_layers<H: MerkleHasher>(
    row_hashes: Vec<H::Digest>,
    rows_per_query: usize,
    hasher: &H,
) -> Vec<Vec<H::Digest>> {
    let num_leaves = row_hashes.len();
    let query_stride = num_leaves / rows_per_query;
    let mut query_digest_layer = row_hashes;
    for _ in 0..log2_strict_usize(rows_per_query) {
        let prev_layer = query_digest_layer;
        query_digest_layer = (0..prev_layer.len() / 2)
            .into_par_iter()
            .map(|i| {
                let x = i / query_stride;
                let y = i % query_stride;
                let left = prev_layer[2 * x * query_stride + y];
                let right = prev_layer[(2 * x + 1) * query_stride + y];
                hasher.compress(left, right)
            })
            .collect();
    }
    let mut layers = vec![query_digest_layer];
    while layers.last().unwrap().len() > 1 {
        let prev = layers.last().unwrap();
        let layer: Vec<_> = prev
            .par_chunks_exact(2)
            .map(|pair| hasher.compress(pair[0], pair[1]))
            .collect();
        layers.push(layer);
    }
    layers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_raw_parts_and_accessors() {
        let mat = RowMajorMatrix::new(vec![1u32, 2, 3, 4, 5, 6], 3);
        let digest_layers = vec![vec![10u32, 20], vec![30]];

        let tree = CpuMerkleTree::from_raw_parts(mat, digest_layers, 1);

        assert_eq!(tree.rows_per_query(), 1);
        assert_eq!(tree.backing_matrix().width, 3);
        assert_eq!(tree.digest_layers().len(), 2);
        assert_eq!(tree.query_stride(), 2);
        assert_eq!(tree.proof_depth(), 1);
    }

    #[test]
    fn test_root() {
        let mat = RowMajorMatrix::new(vec![1u32, 2, 3, 4], 2);
        let digest_layers = vec![vec![10u32, 20], vec![42]];

        let tree = CpuMerkleTree::from_raw_parts(mat, digest_layers, 1);
        assert_eq!(tree.root().unwrap(), 42);
    }

    #[test]
    fn test_root_no_layers() {
        let mat = RowMajorMatrix::new(vec![1u32, 2], 2);
        let digest_layers: Vec<Vec<u32>> = vec![];

        let tree = CpuMerkleTree::from_raw_parts(mat, digest_layers, 1);
        assert!(tree.root().is_err());
    }

    #[test]
    fn test_query_merkle_proof() {
        // 4 leaves -> 2 layers: [a, b, c, d] -> [ab, cd] -> [abcd]
        let mat = RowMajorMatrix::new(vec![0u32; 8], 2);
        let layer0 = vec![10u32, 20, 30, 40]; // 4 entries
        let layer1 = vec![100u32, 200]; // 2 entries
        let layer2 = vec![999u32]; // root
        let digest_layers = vec![layer0, layer1, layer2];

        let tree = CpuMerkleTree::from_raw_parts(mat, digest_layers, 1);
        assert_eq!(tree.query_stride(), 4);
        assert_eq!(tree.proof_depth(), 2);

        // Query index 0: siblings are layer0[1], layer1[1]
        let proof = tree.query_merkle_proof(0).unwrap();
        assert_eq!(proof, vec![20, 200]);

        // Query index 1: siblings are layer0[0], layer1[1]
        let proof = tree.query_merkle_proof(1).unwrap();
        assert_eq!(proof, vec![10, 200]);

        // Query index 2: siblings are layer0[3], layer1[0]
        let proof = tree.query_merkle_proof(2).unwrap();
        assert_eq!(proof, vec![40, 100]);

        // Out of bounds
        assert!(tree.query_merkle_proof(4).is_err());
    }

    #[test]
    fn test_get_opened_rows_single() {
        // 4 rows x 3 cols, rows_per_query = 1
        let mat = RowMajorMatrix::new(vec![1u32, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], 3);
        let digest_layers = vec![vec![0u32; 4], vec![0u32; 2], vec![0u32; 1]];

        let tree = CpuMerkleTree::from_raw_parts(mat, digest_layers, 1);
        assert_eq!(tree.query_stride(), 4);

        let rows = tree.get_opened_rows(0).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0], vec![1, 2, 3]);

        let rows = tree.get_opened_rows(2).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0], vec![7, 8, 9]);
    }

    #[test]
    fn test_get_opened_rows_batched() {
        // 4 rows x 2 cols, rows_per_query = 2
        // query_stride = 4 / 2 = 2 (from digest_layers[0].len())
        let mat = RowMajorMatrix::new(vec![1u32, 2, 3, 4, 5, 6, 7, 8], 2);
        let digest_layers = vec![vec![0u32; 2], vec![0u32; 1]];

        let tree = CpuMerkleTree::from_raw_parts(mat, digest_layers, 2);
        assert_eq!(tree.query_stride(), 2);

        // index=0: rows at 0 and 0 + 2 = 2
        let rows = tree.get_opened_rows(0).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], vec![1, 2]);
        assert_eq!(rows[1], vec![5, 6]);

        // index=1: rows at 1 and 1 + 2 = 3
        let rows = tree.get_opened_rows(1).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], vec![3, 4]);
        assert_eq!(rows[1], vec![7, 8]);

        // Out of bounds
        assert!(tree.get_opened_rows(2).is_err());
    }

    // ---- Real KoalaBear Poseidon2 hashing: commit leaves and verify Merkle paths ----

    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
    use pico_mle_core::{
        config::koala_bear_poseidon2::default_koalabear_poseidon2_16,
        hasher::Hasher,
        p3_symmetric::{PaddingFreeSponge, TruncatedPermutation},
    };

    type Perm = Poseidon2KoalaBear<16>;
    type KbHasher = Hasher<
        KoalaBear,
        [KoalaBear; 8],
        PaddingFreeSponge<Perm, 16, 8, 8>,
        TruncatedPermutation<Perm, 2, 8, 16>,
    >;

    /// The production KoalaBear Poseidon2 Merkle hasher, built inline (mirrors
    /// `KoalaBearPoseidon2Config`'s hasher).
    fn kb_hasher() -> KbHasher {
        let perm = default_koalabear_poseidon2_16();
        Hasher::new(
            PaddingFreeSponge::new(perm.clone()),
            TruncatedPermutation::new(perm),
        )
    }

    fn kb(x: u32) -> KoalaBear {
        KoalaBear::from_u32(x)
    }

    /// Recompute the Merkle root from a leaf digest + authentication path (using the same
    /// even/odd compression order as `query_merkle_proof`) and compare to `root`.
    fn verify_path(
        hasher: &KbHasher,
        leaf: [KoalaBear; 8],
        mut idx: usize,
        proof: &[[KoalaBear; 8]],
        root: [KoalaBear; 8],
    ) -> bool {
        let mut node = leaf;
        for &sib in proof {
            node = if idx & 1 == 0 {
                hasher.compress(node, sib)
            } else {
                hasher.compress(sib, node)
            };
            idx >>= 1;
        }
        node == root
    }

    /// Build a `CpuMerkleTree` directly from a batch of leaf rows (one row per leaf).
    fn build_tree_from_leaves(
        hasher: &KbHasher,
        leaves: &[Vec<KoalaBear>],
    ) -> (
        Vec<[KoalaBear; 8]>,
        CpuMerkleTree<KoalaBear, [KoalaBear; 8]>,
    ) {
        let width = leaves.first().map(|r| r.len()).unwrap_or(1).max(1);
        let row_hashes: Vec<[KoalaBear; 8]> = leaves.iter().map(|r| hasher.hash_slice(r)).collect();
        let layers = build_digest_layers(row_hashes.clone(), 1, hasher);
        let backing = RowMajorMatrix::new(leaves.concat(), width);
        let tree = CpuMerkleTree::from_raw_parts(backing, layers, 1);
        (row_hashes, tree)
    }

    #[test]
    fn merkle_commit_and_verify_all_paths() {
        let hasher = kb_hasher();
        let leaves: Vec<Vec<KoalaBear>> = (0..8u32)
            .map(|i| (0..4u32).map(|j| kb(i * 4 + j + 1)).collect())
            .collect();
        let (row_hashes, tree) = build_tree_from_leaves(&hasher, &leaves);
        let root = tree.root().unwrap();
        assert_eq!(tree.query_stride(), 8);
        assert_eq!(tree.proof_depth(), 3);

        for (i, &leaf) in row_hashes.iter().enumerate() {
            let proof = tree.query_merkle_proof(i).unwrap();
            assert_eq!(proof.len(), 3);
            assert!(
                verify_path(&hasher, leaf, i, &proof, root),
                "path {i} failed to verify"
            );
        }

        // A wrong leaf (index 1's hash at position 0) must not verify against index 0's path.
        let proof0 = tree.query_merkle_proof(0).unwrap();
        assert!(!verify_path(&hasher, row_hashes[1], 0, &proof0, root));
    }

    #[test]
    fn merkle_single_leaf_tree() {
        let hasher = kb_hasher();
        let leaves = vec![vec![kb(1), kb(2), kb(3), kb(4)]];
        let (row_hashes, tree) = build_tree_from_leaves(&hasher, &leaves);
        let root = tree.root().unwrap();
        assert_eq!(tree.proof_depth(), 0);
        assert_eq!(root, row_hashes[0]);
        assert!(tree.query_merkle_proof(0).unwrap().is_empty());
        assert!(verify_path(&hasher, row_hashes[0], 0, &[], root));
    }

    #[test]
    fn merkle_two_leaf_tree() {
        let hasher = kb_hasher();
        let leaves = vec![vec![kb(1), kb(2)], vec![kb(3), kb(4)]];
        let (row_hashes, tree) = build_tree_from_leaves(&hasher, &leaves);
        let root = tree.root().unwrap();
        assert_eq!(tree.proof_depth(), 1);
        assert_eq!(root, hasher.compress(row_hashes[0], row_hashes[1]));
        for (i, &leaf) in row_hashes.iter().enumerate() {
            let proof = tree.query_merkle_proof(i).unwrap();
            assert!(verify_path(&hasher, leaf, i, &proof, root));
        }
    }

    #[test]
    fn rs_encode_and_merkle_commit_paths_verify() {
        // Drive the real commit path (eval→coeff, batch DFT, row hashing, Merkle layers) and
        // verify several authentication paths against the produced root.
        let hasher = kb_hasher();
        let l_skip = 2;
        let log_blowup = 1;
        let height = 8usize; // power of two and >= 2^l_skip
        let width = 2usize;
        let values: Vec<KoalaBear> = (0..(width * height) as u32).map(|v| kb(v + 1)).collect();
        let eval_matrix = ColMajorMatrix::new(values, width);

        let tree = rs_encode_and_merkle_cpu(&hasher, l_skip, log_blowup, &eval_matrix, 1);
        let root = tree.root().unwrap();

        let codeword_height = height << log_blowup; // 16, power of two => no padding leaves
        assert_eq!(tree.query_stride(), codeword_height);
        for i in [0usize, 1, 5, codeword_height - 1] {
            let rows = tree.get_opened_rows(i).unwrap();
            let leaf = hasher.hash_slice(&rows[0]);
            let proof = tree.query_merkle_proof(i).unwrap();
            assert!(
                verify_path(&hasher, leaf, i, &proof, root),
                "rs-encode path {i} failed to verify"
            );
        }
    }

    /// The col-major `ColMajorMerkleTree` and the row-major CPU twin produce identical digest
    /// layers (and therefore identical roots) for the same matrix and `rows_per_query`.
    ///
    /// `device.rs::stacked_pcs_data_to_cpu` relies on this when it reuses the digest layers while
    /// transposing the backing matrix.
    #[test]
    fn test_merkle_digest_layers_match_row_major_twin() {
        use pico_mle_core::{poly::matrix::MatrixView, prover::stacked_pcs::ColMajorMerkleTree};
        use rand::{rngs::StdRng, RngExt, SeedableRng};

        let hasher = kb_hasher();
        let mut rng = StdRng::seed_from_u64(11);
        let (width, height) = (3usize, 16usize);
        let values: Vec<KoalaBear> = (0..width * height)
            .map(|_| KoalaBear::from_u32(rng.random()))
            .collect();
        let mat = ColMajorMatrix::new(values, width);

        for rows_per_query in [1usize, 4] {
            let tree = ColMajorMerkleTree::new(&hasher, mat.clone(), rows_per_query).unwrap();

            let row_hashes: Vec<[KoalaBear; 8]> = (0..height)
                .map(|r| {
                    let row: Vec<KoalaBear> = (0..width).map(|c| *mat.get(r, c).unwrap()).collect();
                    hasher.hash_slice(&row)
                })
                .collect();
            let layers = build_digest_layers(row_hashes, rows_per_query, &hasher);

            assert_eq!(
                tree.digest_layers(),
                &layers,
                "rows_per_query={rows_per_query}"
            );
            assert_eq!(tree.root().unwrap(), layers.last().unwrap()[0]);
        }
    }
}
