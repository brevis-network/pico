//! Stacked polynomial commitment: pack every trace column into one tall
//! column-major matrix, Reed-Solomon-encode each stacked column, and Merkle-commit with
//! `2^k_whir`-row interleaved leaves.
//!
//! Where each step lives:
//! - [`StackedLayout`] — the injection ι: tallest-first greedy packing. A column
//!   shorter than `2^l_skip` is lifted to a `2^l_skip` slot and written with stride
//!   `2^{l_skip - log_h}`, landing on the order-`2^log_h` subgroup of the univariate-skip
//!   domain `D` (the univariate lifting).
//! - [`stacked_matrix`] — the stacked trace matrix `Q_T`: the extension-by-zero of ι(T). The
//!   zeros are written but never constrained — the stacked-reduction `in_{D,n_T}` indicator
//!   makes them invisible to openings.
//! - [`rs_code_matrix`] — RS encoding: per column, eval→coeff (iDFT per `D`-chunk +
//!   zeta transform), zero-pad by `2^log_blowup`, forward DFT over the 2-adic subgroup.
//! - [`ColMajorMerkleTree`] / [`stacked_commit`] — the matrix commitment `Com_{stack,k}`:
//!   each leaf is the mini-Merkle root of `2^k_whir` rows whose indices are strided
//!   by `query_stride = 2^{l_skip + n + log_blowup - k_whir}`, giving proof depth
//!   `l_skip + n + log_blowup - k_whir`. The interleaved-strided leaf layout is required by
//!   WHIR's folding step — do not "simplify" it into adjacent-row leaves.
//!
//! Layout invariants relied on downstream: slices never straddle stacked columns
//! (power-of-two lifted lengths packed in non-increasing height order), and each trace's
//! columns form one contiguous block of the column-major buffer, so [`StackedLayout::mat_view`]
//! can hand out a copy-free strided sub-view per trace.
//!
//! The optimized CPU backend keeps row-major twins of the types here: `CpuMerkleTree` (built by
//! the fused `rs_encode_and_merkle_cpu`) and `CpuStackedPcsData`. The digest layers are computed
//! identically on both sides, so roots and authentication paths are interchangeable. Consumers:
//! the stacked opening reduction and WHIR stages, plus keygen (preprocessed-trace
//! commits).

use getset::{CopyGetters, Getters};
use itertools::Itertools;
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_maybe_rayon::prelude::*;
use p3_util::log2_strict_usize;
use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::{
    hasher::MerkleHasher,
    poly::{
        eval_to_coeff_rs_message_with_twiddles,
        matrix::{
            col_maj_idx, ColMajorMatrix, MatrixDimensions, MatrixView, StridedColMajorMatrixView,
        },
        ntt::TwiddleDft,
    },
    protocol::stacking::{StackedLayout, StackedPcsError},
};

/// Merkle tree with column-major codeword backing (the reference flavor; the optimized CPU
/// backend uses the row-major `CpuMerkleTree` twin).
///
/// Each leaf batches `rows_per_query` rows whose indices are strided by
/// [`query_stride`](Self::query_stride); the digest layers are computed
/// identically on both flavors, so proofs verify interchangeably.
#[derive(Clone, Debug, Getters, CopyGetters, Serialize, Deserialize)]
pub struct ColMajorMerkleTree<F, Digest> {
    /// The matrix that is used to form the leaves of the Merkle tree, which are
    /// in turn hashed into the bottom digest layer.
    ///
    /// This is typically the codeword matrix in hash-based PCS.
    #[getset(get = "pub")]
    pub(crate) backing_matrix: ColMajorMatrix<F>,
    #[getset(get = "pub")]
    pub(crate) digest_layers: Vec<Vec<Digest>>,
    #[getset(get_copy = "pub")]
    pub(crate) rows_per_query: usize,
}

#[derive(Clone, Serialize, Deserialize, derive_new::new)]
pub struct StackedPcsData<F, Digest> {
    /// Layout of the unstacked collection of matrices within the stacked matrix.
    pub layout: StackedLayout,
    /// The stacked matrix of evaluations with height `2^{l_skip + n_stack}`.
    pub matrix: ColMajorMatrix<F>,
    /// Merkle tree of the Reed-Solomon codewords of the stacked matrix.
    /// Depends on `k_whir` parameter.
    pub tree: ColMajorMerkleTree<F, Digest>,
}

impl<F, Digest: Clone> StackedPcsData<F, Digest> {
    /// Returns the root of the Merkle tree.
    pub fn commit(&self) -> Result<Digest, StackedPcsError> {
        self.tree.root()
    }

    /// Copy-free strided view of one unstacked matrix inside the stacked matrix.
    pub fn mat_view(&self, unstacked_mat_idx: usize) -> StridedColMajorMatrixView<'_, F> {
        self.layout.mat_view(unstacked_mat_idx, &self.matrix)
    }
}

/// Commits to a height-sorted collection of traces: stack ([`stacked_matrix`]) → RS-encode
/// ([`rs_code_matrix`]) → Merkle ([`ColMajorMerkleTree::new`] with `2^k_whir` rows per leaf).
///
/// Returns the root (`Com_{stack,k}`) together with the prover-side data
/// needed to open it later.
#[instrument(level = "info", skip_all)]
#[allow(clippy::type_complexity)]
pub fn stacked_commit<H: MerkleHasher>(
    hasher: &H,
    l_skip: usize,
    n_stack: usize,
    log_blowup: usize,
    k_whir: usize,
    traces: &[&ColMajorMatrix<H::F>],
) -> Result<(H::Digest, StackedPcsData<H::F, H::Digest>), StackedPcsError>
where
    H::F: TwoAdicField + Ord,
    H::Digest: Copy,
{
    let (q_trace, layout) = stacked_matrix(l_skip, n_stack, traces)?;
    let rs_matrix = rs_code_matrix(l_skip, log_blowup, &q_trace)?;
    let tree = ColMajorMerkleTree::new(hasher, rs_matrix, 1 << k_whir)?;
    let root = tree.root()?;
    let data = StackedPcsData::new(layout, q_trace, tree);
    Ok((root, data))
}

// `mat_view` stays prover-side: it hands out a matrix view, which would drag a `poly` edge into
// `protocol::stacking`.
impl StackedLayout {
    /// Due to the definition of stacking, in a column major matrix the lifted columns of the
    /// unstacked matrix will always be contiguous in memory within the stacked matrix, so we
    /// can return the sub-view.
    pub fn mat_view<'a, F>(
        &self,
        unstacked_mat_idx: usize,
        stacked_matrix: &'a ColMajorMatrix<F>,
    ) -> StridedColMajorMatrixView<'a, F> {
        // The matrix's columns occupy the contiguous `sorted_cols` range given by `mat_starts`,
        // so no scan over the full column list is needed.
        let start_idx = self.mat_starts[unstacked_mat_idx];
        let end_idx = *self
            .mat_starts
            .get(unstacked_mat_idx + 1)
            .unwrap_or(&self.sorted_cols.len());
        let width = end_idx - start_idx;
        debug_assert!(self.sorted_cols[start_idx..end_idx]
            .iter()
            .all(|col| col.mat_idx == unstacked_mat_idx));
        let s = &self.sorted_cols[start_idx].slice;
        let lifted_height = s.len(self.l_skip());
        let stride = s.stride(self.l_skip());
        let start = col_maj_idx(s.row_idx, s.col_idx, stacked_matrix.height());
        StridedColMajorMatrixView::new(
            &stacked_matrix.values[start..start + lifted_height * width],
            width,
            stride,
        )
    }
}

/// Builds the stacked trace matrix `Q_T` (extension-by-zero of ι) and its
/// layout. The `traces` **must** already be in height-sorted (non-increasing) order — the
/// caller sorts (see `sort_for_stacking` in `prover/types.rs`), because prover and verifier
/// must agree on the order.
#[instrument(skip_all)]
pub fn stacked_matrix<F: Field>(
    l_skip: usize,
    n_stack: usize,
    traces: &[&ColMajorMatrix<F>],
) -> Result<(ColMajorMatrix<F>, StackedLayout), StackedPcsError> {
    let sorted_meta = traces
        .iter()
        .map(|trace| {
            // height cannot be zero:
            let log_height = log2_strict_usize(trace.height());
            (trace.width(), log_height)
        })
        .collect_vec();
    let layout = StackedLayout::new(l_skip, l_skip + n_stack, sorted_meta)?;
    let total_cells: usize = traces
        .iter()
        .map(|t| t.height().max(1 << l_skip) * t.width())
        .sum();
    let height = 1usize << (l_skip + n_stack);
    let width = total_cells.div_ceil(height);

    let mut q_mat = F::zero_vec(
        width
            .checked_mul(height)
            .ok_or(StackedPcsError::StackedMatrixOverflow)?,
    );
    for col in &layout.sorted_cols {
        let s = &col.slice;
        let start = s.col_idx * height + s.row_idx;
        let t_col = traces[col.mat_idx].column(col.src_col_idx);
        debug_assert_eq!(t_col.len(), 1 << s.log_height());
        if s.log_height() >= l_skip {
            q_mat[start..start + t_col.len()].copy_from_slice(t_col);
        } else {
            // t_col height is smaller than 2^l_skip, so we stride
            let stride = s.stride(l_skip);
            for (i, val) in t_col.iter().enumerate() {
                q_mat[start + i * stride] = *val;
            }
        }
    }
    Ok((ColMajorMatrix::new(q_mat, width), layout))
}

/// Computes the Reed-Solomon codeword of each column vector of `eval_matrix` where the rate is
/// `2^{-log_blowup}`. The column vectors are treated as evaluations of a prismalinear extension on
/// a hyperprism.
///
/// Mirrors the fused CPU commit path (`rs_encode_and_merkle_cpu`): one shared
/// twiddle table for the per-column eval-to-coeff step, then a single batch DFT over all columns
/// — instead of rebuilding DFT state per column.
#[instrument(skip_all)]
pub fn rs_code_matrix<F: TwoAdicField + Ord>(
    l_skip: usize,
    log_blowup: usize,
    eval_matrix: &ColMajorMatrix<F>,
) -> Result<ColMajorMatrix<F>, StackedPcsError> {
    use p3_matrix::Matrix as _;

    let height = eval_matrix.height();
    let width = eval_matrix.width();
    let rs_height = height
        .checked_shl(log_blowup as u32)
        .ok_or(StackedPcsError::RsCodeShiftOverflow { height, log_blowup })?;

    // Convert column evaluations on `D × {0,1}^n` directly into the eval-to-coeff RS
    // coefficient vector, avoiding redundant interpolation work.
    let twiddles = TwiddleDft::new(l_skip);
    let coeff_vecs: Vec<Vec<F>> = eval_matrix
        .values
        .par_chunks_exact(height)
        .map(|column_evals| {
            let mut coeffs = eval_to_coeff_rs_message_with_twiddles(column_evals, &twiddles);
            coeffs.resize(rs_height, F::ZERO);
            coeffs
        })
        .collect();

    // Transpose to row-major and batch-DFT every column at once (one twiddle table, internal
    // parallelism + SIMD butterflies), then transpose back to the column-major layout the
    // Merkle tree backing expects.
    let mut rm_values = F::zero_vec(rs_height * width);
    rm_values
        .par_chunks_exact_mut(width)
        .enumerate()
        .for_each(|(i, row)| {
            for (j, col) in coeff_vecs.iter().enumerate() {
                row[j] = col[i];
            }
        });
    drop(coeff_vecs);
    let rm_codewords = Radix2DitParallel::default()
        .dft_batch(p3_matrix::dense::RowMajorMatrix::new(rm_values, width))
        .to_row_major_matrix();

    Ok(ColMajorMatrix::from_row_major(&rm_codewords))
}

impl<F, Digest> ColMajorMerkleTree<F, Digest> {
    /// Reassemble a tree from parts computed elsewhere (e.g. a GPU device that produced the
    /// codeword matrix + digest layers on-device), without re-hashing. The row-major twin
    /// `CpuMerkleTree::from_raw_parts` (in `pico-mle-cpu`) is the analog; both let a device
    /// backend build the canonical host tree from transported raw parts.
    pub fn from_raw_parts(
        backing_matrix: ColMajorMatrix<F>,
        digest_layers: Vec<Vec<Digest>>,
        rows_per_query: usize,
    ) -> Self {
        Self {
            backing_matrix,
            digest_layers,
            rows_per_query,
        }
    }

    /// Number of distinct query indices (= number of entries in the bottom digest layer, which
    /// is also the row-index stride between the rows batched into one leaf).
    pub fn query_stride(&self) -> usize {
        self.digest_layers[0].len()
    }

    /// Depth of a Merkle proof (number of sibling digests).
    pub fn proof_depth(&self) -> usize {
        self.digest_layers.len() - 1
    }
}

impl<F, Digest: Clone> ColMajorMerkleTree<F, Digest> {
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

impl<EF: Field, Digest> ColMajorMerkleTree<EF, Digest>
where
    Digest: Copy + Send + Sync,
{
    /// Hashes every matrix row, folds each query's `rows_per_query` strided rows into a leaf
    /// digest (those first `log2(rows_per_query)` compress layers are not stored), then builds
    /// the standard adjacent-pair layers up to the root.
    #[instrument(name = "merkle_tree", skip_all)]
    pub fn new<H: MerkleHasher<Digest = Digest>>(
        hasher: &H,
        matrix: ColMajorMatrix<EF>,
        rows_per_query: usize,
    ) -> Result<Self, StackedPcsError>
    where
        EF: ExtensionField<H::F>,
    {
        let height = matrix.height();
        if height == 0 {
            return Err(StackedPcsError::MerkleTreeEmptyMatrix);
        }
        if !rows_per_query.is_power_of_two() {
            return Err(StackedPcsError::MerkleTreeRowsPerQueryNotPow2 { rows_per_query });
        }
        let num_leaves = height.next_power_of_two();
        if rows_per_query > num_leaves {
            return Err(StackedPcsError::MerkleTreeRowsPerQueryExceeded {
                rows_per_query,
                num_leaves,
            });
        }
        let base_elems_per_row = matrix.width() * EF::DIMENSION;
        let row_hashes: Vec<_> = (0..num_leaves)
            .into_par_iter()
            .map(|r| {
                // Flatten the row into base-field elements with one buffer per row (no
                // per-cell heap allocation).
                let mut hash_input: Vec<H::F> = Vec::with_capacity(base_elems_per_row);
                for ef in Self::row_iter(&matrix, r) {
                    hash_input.extend_from_slice(ef.as_basis_coefficients_slice());
                }
                hasher.hash_slice(&hash_input)
            })
            .collect();

        let query_stride = num_leaves / rows_per_query;
        let mut query_digest_layer = row_hashes;
        // For the first log2(rows_per_query) layers, we hash in `query_stride` pairs and don't
        // need to store the digest layers
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

        let mut digest_layers = vec![query_digest_layer];
        while digest_layers
            .last()
            .ok_or(StackedPcsError::MerkleTreeNoRoot)?
            .len()
            > 1
        {
            let prev_layer = digest_layers
                .last()
                .ok_or(StackedPcsError::MerkleTreeNoRoot)?;
            let layer: Vec<_> = prev_layer
                .par_chunks_exact(2)
                .map(|pair| hasher.compress(pair[0], pair[1]))
                .collect();
            digest_layers.push(layer);
        }

        Ok(Self {
            backing_matrix: matrix,
            digest_layers,
            rows_per_query,
        })
    }

    /// Returns the ordered set of opened rows for the given query index.
    /// The rows are { query_idx + t * query_stride() } for t in 0..rows_per_query.
    pub fn get_opened_rows(&self, index: usize) -> Result<Vec<Vec<EF>>, StackedPcsError> {
        let query_stride = self.query_stride();
        if index >= query_stride {
            return Err(StackedPcsError::MerkleTreeOpenedRowsOutOfBounds {
                index,
                query_stride,
            });
        }

        let rows_per_query = self.rows_per_query;
        let width = self.backing_matrix.width();
        let mut preimage = Vec::with_capacity(rows_per_query);
        for row_offset in 0..rows_per_query {
            let row_idx = row_offset * query_stride + index;
            let row = Self::row_iter(&self.backing_matrix, row_idx).collect_vec();
            debug_assert_eq!(
                row.len(),
                width,
                "row width mismatch: expected {width}, got {}",
                row.len()
            );
            preimage.push(row);
        }
        Ok(preimage)
    }

    fn row_iter(matrix: &ColMajorMatrix<EF>, index: usize) -> impl Iterator<Item = EF> + '_ {
        (0..matrix.width()).map(move |c| matrix.get(index, c).copied().unwrap_or(EF::ZERO))
    }
}

#[cfg(test)]
mod tests {
    use crate::config::koala_bear_poseidon2::*;
    use itertools::Itertools;
    use p3_field::{PrimeCharacteristicRing, TwoAdicField};
    use rand::{rngs::StdRng, RngExt, SeedableRng};

    use super::*;
    use crate::{
        poly::{matrix::ColMajorMatrix, Ple},
        protocol::stacking::{StackedColumn, StackedSlice},
    };

    /// Column-major matrix with values `start..start + width * height` (column by column).
    fn seq_matrix(start: u32, width: usize, height: usize) -> ColMajorMatrix<F> {
        let values = (start..start + (width * height) as u32)
            .map(F::from_u32)
            .collect();
        ColMajorMatrix::new(values, width)
    }

    fn random_matrix(rng: &mut StdRng, width: usize, height: usize) -> ColMajorMatrix<F> {
        let values = (0..width * height)
            .map(|_| F::from_u32(rng.random()))
            .collect();
        ColMajorMatrix::new(values, width)
    }

    #[test]
    fn test_stacked_matrix_manual_0() {
        let columns = [vec![1, 2, 3, 4], vec![5, 6], vec![7]]
            .map(|v| v.into_iter().map(F::from_u32).collect_vec());
        let mats = columns
            .into_iter()
            .map(|c| ColMajorMatrix::new(c, 1))
            .collect_vec();
        let mat_refs = mats.iter().collect_vec();
        let (stacked_mat, layout) = stacked_matrix(0, 2, &mat_refs).unwrap();
        assert_eq!(stacked_mat.height(), 4);
        assert_eq!(stacked_mat.width(), 2);
        assert_eq!(
            stacked_mat.values,
            [1, 2, 3, 4, 5, 6, 7, 0].map(F::from_u32).to_vec()
        );
        assert_eq!(layout.mat_starts, vec![0, 1, 2]);
    }

    #[test]
    fn test_stacked_matrix_manual_strided_0() {
        let columns = [vec![1, 2, 3, 4], vec![5, 6], vec![7]]
            .map(|v| v.into_iter().map(F::from_u32).collect_vec());
        let mats = columns
            .into_iter()
            .map(|c| ColMajorMatrix::new(c, 1))
            .collect_vec();
        let mat_refs = mats.iter().collect_vec();
        let (stacked_mat, _layout) = stacked_matrix(2, 0, &mat_refs).unwrap();
        assert_eq!(stacked_mat.height(), 4);
        assert_eq!(stacked_mat.width(), 3);
        assert_eq!(
            stacked_mat.values,
            [1, 2, 3, 4, 5, 0, 6, 0, 7, 0, 0, 0]
                .map(F::from_u32)
                .to_vec()
        );
    }

    #[test]
    fn test_stacked_matrix_manual_strided_1() {
        let columns = [vec![1, 2, 3, 4], vec![5, 6], vec![7]]
            .map(|v| v.into_iter().map(F::from_u32).collect_vec());
        let mats = columns
            .into_iter()
            .map(|c| ColMajorMatrix::new(c, 1))
            .collect_vec();
        let mat_refs = mats.iter().collect_vec();
        let (stacked_mat, _layout) = stacked_matrix(3, 0, &mat_refs).unwrap();
        assert_eq!(stacked_mat.height(), 8);
        assert_eq!(stacked_mat.width(), 3);
        assert_eq!(
            stacked_mat.values,
            [
                [1, 0, 2, 0, 3, 0, 4, 0],
                [5, 0, 0, 0, 6, 0, 0, 0],
                [7, 0, 0, 0, 0, 0, 0, 0]
            ]
            .into_iter()
            .flatten()
            .map(F::from_u32)
            .collect_vec()
        );
    }

    /// Multi-column traces at `l_skip = 0`: greedy tallest-first packing wraps trace columns
    /// across stacked columns without ever straddling one, and each trace occupies one
    /// contiguous block of the column-major buffer.
    #[test]
    fn test_stacked_layout_multi_column_wrapping() {
        // A: 8x2 (values 1..16), B: 4x3 (17..28), C: 2x2 (29..32); height-sorted.
        let mats = [
            seq_matrix(1, 2, 8),
            seq_matrix(17, 3, 4),
            seq_matrix(29, 2, 2),
        ];
        let mat_refs = mats.iter().collect_vec();
        let (stacked, layout) = stacked_matrix(0, 3, &mat_refs).unwrap();

        // total_cells = 16 + 12 + 4 = 32, height 8 => width 4.
        assert_eq!(stacked.height(), 8);
        assert_eq!(stacked.width(), 4);
        assert_eq!(layout.height(), 8);
        assert_eq!(layout.width(), 4);
        assert_eq!(layout.mat_starts, vec![0, 2, 5]);

        // Exact slice placements: (stacked col, stacked row, log_height) per source column.
        let expected_slices = [
            (0, (0, 0, 3)),
            (1, (1, 0, 3)), // A wraps to a fresh column per height-8 column
            (2, (2, 0, 2)),
            (3, (2, 4, 2)), // B0, B1 share stacked column 2
            (4, (3, 0, 2)), // B2 wraps into column 3
            (5, (3, 4, 1)), // C0 tucks under B2
            (6, (3, 6, 1)),
        ];
        for (flat_idx, (col_idx, row_idx, log_height)) in expected_slices {
            let s = &layout.sorted_cols[flat_idx].slice;
            assert_eq!(
                (s.col_idx, s.row_idx, s.log_height()),
                (col_idx, row_idx, log_height)
            );
        }

        // No slice straddles a stacked column boundary.
        for col in &layout.sorted_cols {
            let s = &col.slice;
            assert!(s.row_idx + s.len(layout.l_skip()) <= layout.height());
        }

        // Exact buffer: each trace is a contiguous block, and 32 cells fill the 4x8 stacked
        // matrix exactly (no zero padding).
        let expected: Vec<F> = (1..=32).map(F::from_u32).collect();
        assert_eq!(stacked.values, expected);
    }

    /// Short columns (`log_height < l_skip`) bill a full `2^l_skip` slot in the width formula and
    /// are written strided onto the order-`2^log_height` subgroup positions.
    #[test]
    fn test_stacked_layout_width_formula_with_striding() {
        let l_skip = 2;
        // A: 8x1 (1..8), B: 2x3 (9..14), C: 1x2 (15..16).
        let mats = [
            seq_matrix(1, 1, 8),
            seq_matrix(9, 3, 2),
            seq_matrix(15, 2, 1),
        ];
        let mat_refs = mats.iter().collect_vec();
        let (stacked, layout) = stacked_matrix(l_skip, 1, &mat_refs).unwrap();

        // total_cells = 8*1 + 3*max(2, 4) + 2*max(1, 4) = 28; height 8 => width ceil(28/8) = 4.
        assert_eq!(stacked.width(), 4);
        assert_eq!(layout.width(), 4);

        // Lifted lengths and strides.
        let b0 = layout.get(1, 0).unwrap();
        assert_eq!((b0.len(l_skip), b0.stride(l_skip)), (4, 2));
        let c0 = layout.get(2, 0).unwrap();
        assert_eq!((c0.len(l_skip), c0.stride(l_skip)), (4, 4));

        let expected: Vec<F> = [
            [1, 2, 3, 4, 5, 6, 7, 8],    // A contiguous
            [9, 0, 10, 0, 11, 0, 12, 0], // B0, B1 strided by 2
            [13, 0, 14, 0, 15, 0, 0, 0], // B2 strided by 2, C0 strided by 4
            [16, 0, 0, 0, 0, 0, 0, 0],   // C1 strided by 4 + zero padding
        ]
        .into_iter()
        .flatten()
        .map(F::from_u32)
        .collect();
        assert_eq!(stacked.values, expected);
    }

    /// `get` / `width_of` agree with `sorted_cols`, and `from_raw_parts` reconstructs the layout
    /// built by `new`. Constructor error cases return the dedicated `StackedPcsError` variants.
    #[test]
    fn test_stacked_layout_get_width_of_from_raw_parts() {
        let widths = [2usize, 3, 2];
        let log_heights = [3usize, 2, 1];
        let sorted = widths
            .iter()
            .zip(&log_heights)
            .map(|(&w, &lh)| (w, lh))
            .collect_vec();
        let layout = StackedLayout::new(0, 3, sorted).unwrap();

        for (mat_idx, &width) in widths.iter().enumerate() {
            assert_eq!(layout.width_of(mat_idx), width);
            for col_idx in 0..width {
                let s = layout.get(mat_idx, col_idx).unwrap();
                let col = &layout.sorted_cols[layout.mat_starts[mat_idx] + col_idx];
                assert_eq!((col.mat_idx, col.src_col_idx), (mat_idx, col_idx));
                assert_eq!(
                    (s.col_idx, s.row_idx, s.log_height()),
                    (col.slice.col_idx, col.slice.row_idx, col.slice.log_height())
                );
            }
        }
        // Reading past the final column of the final matrix yields None.
        assert!(layout.get(2, 2).is_none());

        let rebuilt = StackedLayout::from_raw_parts(0, 3, layout.sorted_cols.clone()).unwrap();
        assert_eq!(rebuilt.l_skip(), layout.l_skip());
        assert_eq!(rebuilt.height(), layout.height());
        assert_eq!(rebuilt.width(), layout.width());
        assert_eq!(rebuilt.mat_starts, layout.mat_starts);

        // A column taller than the stacked matrix cannot be stacked.
        assert!(matches!(
            StackedLayout::new(0, 2, vec![(1, 3)]),
            Err(StackedPcsError::LayoutHeightExceeded { .. })
        ));
        // `from_raw_parts` rejects a gap in matrix indices.
        let s = StackedSlice::new(0, 0, 1);
        assert!(matches!(
            StackedLayout::from_raw_parts(
                0,
                3,
                vec![StackedColumn::new(0, 0, s), StackedColumn::new(2, 0, s)]
            ),
            Err(StackedPcsError::LayoutRawPartsMatIdx { .. })
        ));
    }

    /// `mat_view` recovers each original trace from the stacked matrix, for both contiguous
    /// (`log_height >= l_skip`) and strided (`log_height < l_skip`) columns.
    #[test]
    fn test_mat_view_round_trip() {
        let l_skip = 2;
        let mats = [
            seq_matrix(1, 2, 8),
            seq_matrix(17, 3, 4),
            seq_matrix(29, 2, 2),
        ];
        let mat_refs = mats.iter().collect_vec();
        let (stacked, layout) = stacked_matrix(l_skip, 1, &mat_refs).unwrap();

        for (mat_idx, mat) in mats.iter().enumerate() {
            let view = layout.mat_view(mat_idx, &stacked);
            let recovered = view.to_matrix();
            assert_eq!(recovered.width(), mat.width());
            assert_eq!(recovered.height(), mat.height());
            assert_eq!(recovered.values, mat.values, "matrix {mat_idx}");
        }
    }

    /// Pins `rs_code_matrix` to the Reed-Solomon encoding: the codeword of column `q` is
    /// `RS(q)(x) = sum_i q_MLE(bin(i)) * x^i` over the 2-adic subgroup of order
    /// `height << log_blowup` in natural order.
    ///
    /// The reference value is computed through an independent path: `Ple::from_evaluations`
    /// (pinned separately in `poly::ple` tests) -> naive subset-sum zeta transform -> naive
    /// Horner evaluation, avoiding `eval_to_coeff_rs_message` and the DFT entirely.
    #[test]
    fn test_rs_code_matrix_matches_naive_eq_3_3() {
        fn naive_rs_column(l_skip: usize, log_blowup: usize, col: &[F]) -> Vec<F> {
            // PLE monomial coefficients; index bits = (Z-degree bits, X assignment bits).
            let coeffs = Ple::from_evaluations(l_skip, col).into_coeffs();
            let dim = coeffs.len();
            // Coefficient-to-coefficient identification in Z makes the vector multilinear in
            // all bits; its evaluation at the boolean point bin(i) is the subset sum over
            // monomials j with j & i == j.
            let msg: Vec<F> = (0..dim)
                .map(|i| {
                    (0..dim)
                        .filter(|&j| j & i == j)
                        .map(|j| coeffs[j])
                        .sum::<F>()
                })
                .collect();
            let rs_len = dim << log_blowup;
            let g = F::two_adic_generator(log2_strict_usize(rs_len));
            (0..rs_len)
                .map(|t| {
                    let x = g.exp_u64(t as u64);
                    msg.iter().rev().fold(F::ZERO, |acc, &c| acc * x + c)
                })
                .collect()
        }

        let mut rng = StdRng::seed_from_u64(7);
        let log_blowup = 1;
        for l_skip in [0usize, 2] {
            for n in 0..=2usize {
                let height = 1usize << (l_skip + n);
                let mat = random_matrix(&mut rng, 2, height);
                let rs = rs_code_matrix(l_skip, log_blowup, &mat).unwrap();
                assert_eq!(rs.height(), height << log_blowup);
                assert_eq!(rs.width(), mat.width());
                for c in 0..mat.width() {
                    assert_eq!(
                        rs.column(c),
                        naive_rs_column(l_skip, log_blowup, mat.column(c)),
                        "l_skip={l_skip}, n={n}, col={c}"
                    );
                }
            }
        }
    }

    /// Recompute the Merkle root from a leaf digest + authentication path (same even/odd
    /// compression order as `query_merkle_proof`) and compare to `root`.
    fn verify_path(
        hasher: &KoalaBearHasher,
        leaf: Digest,
        mut idx: usize,
        proof: &[Digest],
        root: Digest,
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

    /// Fold the `2^k_whir` opened rows of one query into its leaf digest: hash each row, then
    /// compress adjacent pairs (matching the unstored leaf-collapse layers of `ColMajorMerkleTree::new`).
    fn leaf_digest(hasher: &KoalaBearHasher, rows: &[Vec<F>]) -> Digest {
        let mut level: Vec<Digest> = rows.iter().map(|r| hasher.hash_slice(r)).collect();
        while level.len() > 1 {
            level = level
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| hasher.compress(pair[0], pair[1]))
                .collect();
        }
        level[0]
    }

    /// End-to-end `stacked_commit` over mixed-height traces: the opened rows agree with the RS
    /// codeword matrix, the row set is `{q + t * query_stride}`, the proof depth is
    /// `l_skip + n_stack + log_blowup - k_whir`, and every authentication path verifies.
    #[test]
    fn test_stacked_commit_query_round_trip() {
        let hasher = default_koalabear_hasher();
        let (l_skip, n_stack, log_blowup, k_whir) = (2usize, 2, 1, 2);
        // A: 16x1, B: 8x2, C: 2x1 (strided); total_cells = 16 + 16 + 4 = 36 => width 3.
        let mats = [
            seq_matrix(1, 1, 16),
            seq_matrix(17, 2, 8),
            seq_matrix(33, 1, 2),
        ];
        let mat_refs = mats.iter().collect_vec();
        let (root, data) =
            stacked_commit(&hasher, l_skip, n_stack, log_blowup, k_whir, &mat_refs).unwrap();

        assert_eq!(data.commit().unwrap(), root);
        assert_eq!(data.matrix.width(), 3);

        let tree = &data.tree;
        let rows_per_query = 1 << k_whir;
        let query_stride = tree.query_stride();
        // Codeword height 32, 4 rows per leaf => 8 query indices, depth 2+2+1-2 = 3.
        assert_eq!(query_stride, 8);
        assert_eq!(tree.rows_per_query(), rows_per_query);
        assert_eq!(tree.proof_depth(), l_skip + n_stack + log_blowup - k_whir);

        for q in [0usize, 3, 7] {
            let rows = tree.get_opened_rows(q).unwrap();
            assert_eq!(rows.len(), rows_per_query);
            // The opened rows are rows {q + t * query_stride} of the RS codeword matrix.
            for (t, row) in rows.iter().enumerate() {
                let row_idx = q + t * query_stride;
                let expected: Vec<F> = (0..tree.backing_matrix().width())
                    .map(|c| *tree.backing_matrix().get(row_idx, c).unwrap())
                    .collect();
                assert_eq!(row, &expected, "query {q}, row offset {t}");
            }

            let proof = tree.query_merkle_proof(q).unwrap();
            assert_eq!(proof.len(), tree.proof_depth());
            assert!(
                verify_path(&hasher, leaf_digest(&hasher, &rows), q, &proof, root),
                "query {q} authentication path failed"
            );
        }
    }

    /// Constructor and query error cases return the dedicated `StackedPcsError` variants.
    #[test]
    fn test_merkle_tree_error_cases() {
        let hasher = default_koalabear_hasher();
        let mat = seq_matrix(1, 1, 16);

        assert!(matches!(
            ColMajorMerkleTree::new(&hasher, mat.clone(), 3),
            Err(StackedPcsError::MerkleTreeRowsPerQueryNotPow2 { .. })
        ));
        assert!(matches!(
            ColMajorMerkleTree::new(&hasher, mat.clone(), 32),
            Err(StackedPcsError::MerkleTreeRowsPerQueryExceeded { .. })
        ));

        let tree = ColMajorMerkleTree::new(&hasher, mat, 4).unwrap();
        assert_eq!(tree.query_stride(), 4);
        assert!(matches!(
            tree.query_merkle_proof(4),
            Err(StackedPcsError::MerkleTreeQueryOutOfBounds { .. })
        ));
        assert!(matches!(
            tree.get_opened_rows(4),
            Err(StackedPcsError::MerkleTreeOpenedRowsOutOfBounds { .. })
        ));
    }

    /// Commit -> open one column: for every source column, the values recorded in the committed
    /// stacked matrix (located via `layout.get`, honoring the stride) equal the original trace
    /// column.
    #[test]
    fn test_stacked_commit_open_column_round_trip() {
        let hasher = default_koalabear_hasher();
        let (l_skip, n_stack, log_blowup, k_whir) = (2usize, 2, 1, 2);
        let mats = [
            seq_matrix(1, 1, 16),
            seq_matrix(17, 2, 8),
            seq_matrix(33, 1, 2),
        ];
        let mat_refs = mats.iter().collect_vec();
        let (_, data) =
            stacked_commit(&hasher, l_skip, n_stack, log_blowup, k_whir, &mat_refs).unwrap();

        let stacked_height = data.matrix.height();
        for (mat_idx, mat) in mats.iter().enumerate() {
            for j in 0..mat.width() {
                let s = data.layout.get(mat_idx, j).unwrap();
                let start = col_maj_idx(s.row_idx, s.col_idx, stacked_height);
                let stride = s.stride(l_skip);
                let opened: Vec<F> = (0..mat.height())
                    .map(|i| data.matrix.values[start + i * stride])
                    .collect();
                assert_eq!(opened, mat.column(j), "matrix {mat_idx}, column {j}");
            }
        }
    }
}
