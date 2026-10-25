//! Shape of the stacked layout: the placement types, their errors, and the helpers deriving
//! lifted heights and LogUp dimensions.
//!
//! Prover and verifier must agree bit-for-bit on the stacking injection ι, so both
//! derive it here. This module holds no data and depends on neither `poly` nor `prover`, which is
//! what lets the verifier use it without depending on the prover.
//!
//! The prover-side companions — stacked matrix, RS encoding, Merkle tree,
//! [`StackedLayout::mat_view`] — live in [`crate::prover::stacked_pcs`].

use std::cmp::Reverse;

use getset::CopyGetters;
use p3_util::log2_ceil_u64;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from the stacked PCS — Merkle tree, stacked layout, RS code.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum StackedPcsError {
    #[error("StackedLayout::new: column height {log_height} exceeds stacked height {log_stacked_height}")]
    LayoutHeightExceeded {
        log_height: usize,
        log_stacked_height: usize,
    },
    #[error("StackedLayout::new: row overflow at col_idx={col_idx}, expected row_idx to equal stacked height {stacked_height}")]
    LayoutRowOverflow {
        col_idx: usize,
        stacked_height: usize,
    },
    #[error("StackedLayout::from_raw_parts: mat_idx {mat_idx} does not equal mat_starts.len() {mat_starts_len}")]
    LayoutRawPartsMatIdx {
        mat_idx: usize,
        mat_starts_len: usize,
    },
    // Raised by every Merkle tree flavor, so the messages name none of them.
    #[error("Merkle tree: matrix height must be > 0")]
    MerkleTreeEmptyMatrix,
    #[error("Merkle tree: rows_per_query ({rows_per_query}) is not a power of two")]
    MerkleTreeRowsPerQueryNotPow2 { rows_per_query: usize },
    #[error("Merkle tree: rows_per_query ({rows_per_query}) exceeds number of Merkle leaves ({num_leaves})")]
    MerkleTreeRowsPerQueryExceeded {
        rows_per_query: usize,
        num_leaves: usize,
    },
    #[error("Merkle tree: empty digest layers (no root)")]
    MerkleTreeNoRoot,
    #[error("Merkle tree proof query: query_idx {query_idx} out of bounds for query_stride {query_stride}")]
    MerkleTreeQueryOutOfBounds {
        query_idx: usize,
        query_stride: usize,
    },
    #[error(
        "Merkle tree opened rows: index {index} out of bounds for query_stride {query_stride}"
    )]
    MerkleTreeOpenedRowsOutOfBounds { index: usize, query_stride: usize },
    #[error("stacked_matrix: width * height overflow")]
    StackedMatrixOverflow,
    #[error("rs_code_matrix: checked_shl overflow for height={height}, log_blowup={log_blowup}")]
    RsCodeShiftOverflow { height: usize, log_blowup: usize },
}

#[derive(Clone, Serialize, Deserialize, Debug, CopyGetters)]
pub struct StackedLayout {
    /// The univariate-skip parameter `ℓ` of the hyperprism this layout stacks into
    /// (`D_n = D × {0,1}^n` with `|D| = 2^l_skip` — see
    /// [`SystemParams::l_skip`](crate::SystemParams)). Within the layout it acts as the
    /// lift threshold: every slice occupies a slot of at least `2^l_skip` rows, and a column
    /// shorter than that is written with a stride so its values land on the
    /// order-`2^log_height` subgroup of `D`. Deliberately `0` for pure-hypercube
    /// stackings with no univariate skip (the GKR interactions layout in `logup_zerocheck`).
    #[getset(get_copy = "pub")]
    l_skip: usize,
    /// Height of the stacked matrix: `|D_n| = 2^{log_stacked_height}` rows (for the trace
    /// stacking, `2^{l_skip + n_stack}`).
    #[getset(get_copy = "pub")]
    height: usize,
    /// Number of stacked columns actually used:
    /// `⌈Σ lifted column lengths / height⌉` (`w_{T,stack}`).
    #[getset(get_copy = "pub")]
    width: usize,
    /// The columns of the unstacked matrices in sorted order: one placement record per source
    /// column.
    pub sorted_cols: Vec<StackedColumn>,
    /// `mat_starts[mat_idx]` is the index in `sorted_cols` where the matrix with index `mat_idx`
    /// starts.
    pub mat_starts: Vec<usize>,
}

/// Placement record for one unstacked column: `(mat_idx, src_col_idx)` identifies the source
/// column within the height-sorted unstacked collection, and `slice` is where its lifted image
/// lands in the stacked matrix.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, derive_new::new)]
pub struct StackedColumn {
    /// Index of the source matrix in the height-sorted unstacked collection.
    pub mat_idx: usize,
    /// Column index within the **source** matrix — distinct from [`StackedSlice::col_idx`], which
    /// is the destination column in the stacked matrix.
    pub src_col_idx: usize,
    /// Location of the (lifted) column within the stacked matrix.
    pub slice: StackedSlice,
}

/// Pointer to the location of a sub-column within the stacked matrix.
/// This struct contains length information, but information from [StackedLayout] (namely `l_skip`)
/// is needed to determine if this is a strided slice or not.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, CopyGetters, derive_new::new)]
pub struct StackedSlice {
    /// Index of the **stacked-matrix** column this slice lives in (not to be confused with
    /// [`StackedColumn::src_col_idx`], the source-matrix column index).
    pub col_idx: usize,
    /// Starting row of the slice's slot within that stacked column.
    pub row_idx: usize,
    /// The true (unlifted) log2 height of the source column; the per-trace hypercube
    /// dimension is `n_T = log_height - l_skip`, which may be negative. If `>= l_skip`, the
    /// column is written contiguously; otherwise strided by `2^{l_skip - log_height}`.
    #[getset(get_copy = "pub")]
    log_height: usize,
}

impl StackedSlice {
    /// Lifted slot length of this slice: `2^max(log_height, l_skip)` rows.
    #[inline(always)]
    pub fn len(&self, l_skip: usize) -> usize {
        Self::lifted_len(self.log_height, l_skip)
    }

    /// Row stride of the lifted writes: `2^{l_skip - log_height}` for a short column (placing
    /// its values on the order-`2^log_height` subgroup of `D`), `1` otherwise.
    #[inline(always)]
    pub fn stride(&self, l_skip: usize) -> usize {
        1 << l_skip.saturating_sub(self.log_height)
    }

    /// Length of the column once lifted into its stacked slot: `2^max(log_height, l_skip)`.
    #[inline(always)]
    fn lifted_len(log_height: usize, l_skip: usize) -> usize {
        if l_skip <= log_height {
            1 << log_height
        } else {
            1 << l_skip
        }
    }
}

impl StackedLayout {
    /// Computes the layout of greedily stacking columns with dimension metadata given by `sorted`
    /// into a stacked matrix.
    /// - `l_skip` — the univariate-skip parameter / lift threshold (see
    ///   [`StackedLayout::l_skip`]): a column shorter than `2^l_skip` occupies a `2^l_skip`-row
    ///   slot with stride `2^{l_skip - log_height}`.
    /// - `log_stacked_height` is the log2 height of the stacked matrix.
    /// - `sorted` is Vec of `(width, log_height)` that must already be **sorted** in descending
    ///   order of `log_height`.
    pub fn new(
        l_skip: usize,
        log_stacked_height: usize,
        sorted: Vec<(usize /* width */, usize /* log_height */)>,
    ) -> Result<Self, StackedPcsError> {
        debug_assert!(l_skip <= log_stacked_height);
        debug_assert!(sorted.is_sorted_by(|a, b| a.1 >= b.1));
        let mut sorted_cols = Vec::with_capacity(sorted.len());
        let mut mat_starts = Vec::new();
        let mut col_idx = 0;
        let mut row_idx = 0;
        for (mat_idx, (width, log_ht)) in sorted.into_iter().enumerate() {
            mat_starts.push(sorted_cols.len());
            if width == 0 {
                continue;
            }
            if log_ht > log_stacked_height {
                return Err(StackedPcsError::LayoutHeightExceeded {
                    log_height: log_ht,
                    log_stacked_height,
                });
            }
            for j in 0..width {
                let slice_len = StackedSlice::lifted_len(log_ht, l_skip);
                if row_idx + slice_len > (1 << log_stacked_height) {
                    if row_idx != 1 << log_stacked_height {
                        return Err(StackedPcsError::LayoutRowOverflow {
                            col_idx,
                            stacked_height: 1 << log_stacked_height,
                        });
                    }
                    col_idx += 1;
                    row_idx = 0;
                }
                let slice = StackedSlice {
                    col_idx,
                    row_idx,
                    log_height: log_ht,
                };
                sorted_cols.push(StackedColumn::new(mat_idx, j, slice));
                row_idx += slice_len;
            }
        }
        let stacked_width = col_idx + usize::from(row_idx != 0);
        debug_assert_eq!(
            stacked_width,
            sorted_cols
                .iter()
                .map(|col| col.slice.col_idx + 1)
                .max()
                .unwrap_or(0)
        );
        Ok(Self {
            l_skip,
            height: 1 << log_stacked_height,
            width: stacked_width,
            sorted_cols,
            mat_starts,
        })
    }

    /// Reconstructs a layout from existing placement records (device transport, tests).
    ///
    /// Only the matrix-index sequence is validated (`mat_idx` values must be `0..k` without
    /// gaps, non-decreasing); slice positions are taken as-is, so callers are responsible for
    /// records that actually came from [`StackedLayout::new`].
    pub fn from_raw_parts(
        l_skip: usize,
        log_stacked_height: usize,
        sorted_cols: Vec<StackedColumn>,
    ) -> Result<Self, StackedPcsError> {
        let height = 1 << log_stacked_height;
        let width = sorted_cols
            .iter()
            .map(|col| col.slice.col_idx + 1)
            .max()
            .unwrap_or(0);
        let mut mat_starts = Vec::new();
        for (idx, col) in sorted_cols.iter().enumerate() {
            if idx == 0 || col.mat_idx + 1 != mat_starts.len() {
                if col.mat_idx != mat_starts.len() {
                    return Err(StackedPcsError::LayoutRawPartsMatIdx {
                        mat_idx: col.mat_idx,
                        mat_starts_len: mat_starts.len(),
                    });
                }
                mat_starts.push(idx);
            }
        }
        Ok(Self {
            l_skip,
            height,
            width,
            sorted_cols,
            mat_starts,
        })
    }

    /// `(mat_idx, col_idx)` should be indexing into the unstacked collection of matrices.
    pub fn get(&self, mat_idx: usize, col_idx: usize) -> Option<&StackedSlice> {
        let idx = self.mat_starts[mat_idx];
        if idx + col_idx >= self.sorted_cols.len() {
            return None;
        }
        let col = &self.sorted_cols[idx + col_idx];
        debug_assert_eq!(col.mat_idx, mat_idx);
        debug_assert_eq!(col.src_col_idx, col_idx);
        Some(&col.slice)
    }

    pub fn width_of(&self, mat_idx: usize) -> usize {
        let start_idx = self.mat_starts[mat_idx];
        debug_assert_eq!(self.sorted_cols[start_idx].mat_idx, mat_idx);
        debug_assert_eq!(self.sorted_cols[start_idx].src_col_idx, 0);
        let next_idx = *self
            .mat_starts
            .get(mat_idx + 1)
            .unwrap_or(&self.sorted_cols.len());
        debug_assert_ne!(next_idx, usize::MAX);
        next_idx - start_idx
    }
}

/// Base-2 log of the *lifted* trace height in the stacked LogUp layout: a trace shorter than the
/// skip floor `2^l_skip` is lifted to it, giving `max(log_height, l_skip)`. Consensus-critical SSOT
/// — prover and verifier must compute this shift identically. See [`lifted_interaction_count`].
#[inline]
pub fn lifted_log_height(log_height: usize, l_skip: usize) -> usize {
    log_height.max(l_skip)
}

/// Stacked LogUp cells contributed by one trace: `count << lifted_log_height`. Summed over present
/// traces into `total_interactions` for [`calculate_n_logup`]; `u64` to avoid shift overflow.
#[inline]
pub fn lifted_interaction_count(count: usize, log_height: usize, l_skip: usize) -> u64 {
    (count as u64) << lifted_log_height(log_height, l_skip)
}

/// Sort key for the stacked column layout: tallest first, ties broken by ascending AIR index.
/// Consensus-critical SSOT — the prover commits to this order and the verifier reconstructs it
/// (`ProvingContext::sort_for_stacking`, `verifier/mod.rs`, `verifier/proof_shape.rs`). Keyed on
/// `log_height` since that is all the verifier has.
#[inline]
pub fn stacking_sort_key(log_height: usize, air_idx: usize) -> (Reverse<usize>, usize) {
    (Reverse(log_height), air_idx)
}

/// λ-batching slot assignment for one stacked column in the stacked-opening reduction.
/// Each source column reserves **two** consecutive powers of the batching randomness λ:
/// `eq_exp` batches the column's plain opening claim, and `rot_exp` — present iff the column's
/// source matrix needs a rotation opening — batches its rotational-convolution claim. Both slots
/// are reserved unconditionally (see [`lambda_slots`]), so a column that does not use its rotation
/// slot never shifts a later column's exponents.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ColLambda {
    /// Exponent `i` such that this column's plain claim is batched by `λ^i`.
    pub eq_exp: usize,
    /// Exponent `i` such that this column's rotation claim is batched by `λ^i`, or `None` when the
    /// column's source matrix carries no rotation opening.
    pub rot_exp: Option<usize>,
}

/// Consensus-critical SSOT for the stacked-opening reduction's λ-batching exponents. Walks every
/// commitment's `sorted_cols` — consulting `need_rot_per_commit[commit][col.mat_idx]` — and assigns
/// each column two consecutive λ exponents (`eq_exp = 2i`, `rot_exp = 2i+1`) where `i` is the
/// column's flat index across all commitments in `(commit, sorted-column)` order.
///
/// Both prover and verifier index `lambda.powers()` with this assignment, so they cannot drift: the
/// prover's per-column `(eq, rot)` slots (`prover/stacked_reduction.rs`) and the verifier's batching
/// of the column-opening claims and the final `q` coefficients (`verifier/stacked_reduction.rs`)
/// are the same walk. Reserving the rotation slot even when unused keeps `λ^{2i}` / `λ^{2i+1}`
/// aligned with the verifier's `(λ²)^i` / `(λ²)^i·λ` spelling.
pub fn lambda_slots<'a>(
    layouts: impl IntoIterator<Item = &'a StackedLayout>,
    need_rot_per_commit: &[Vec<bool>],
) -> Vec<Vec<ColLambda>> {
    let layouts: Vec<_> = layouts.into_iter().collect();
    assert_eq!(
        layouts.len(),
        need_rot_per_commit.len(),
        "lambda_slots requires one rotation vector per commitment"
    );
    let mut exp = 0usize;
    layouts
        .into_iter()
        .zip(need_rot_per_commit)
        .map(|(layout, need_rot)| {
            assert_eq!(
                need_rot.len(),
                layout.mat_starts.len(),
                "lambda_slots requires one rotation flag per source matrix"
            );
            layout
                .sorted_cols
                .iter()
                .map(|col| {
                    let eq_exp = exp;
                    let rot_exp = need_rot[col.mat_idx].then_some(exp + 1);
                    exp += 2;
                    ColLambda { eq_exp, rot_exp }
                })
                .collect()
        })
        .collect()
}

/// Common utility function for computing `n_logup` parameter in terms of `total_interactions`,
/// which is the sum of interaction message counts across all traces, using the lifted trace
/// heights.
///
/// This calculation must be consistent between the prover and verifier and is enforced by
/// the verifier.
pub fn calculate_n_logup(l_skip: usize, total_interactions: u64) -> usize {
    if total_interactions != 0 {
        let n_logup = (u64::BITS - total_interactions.leading_zeros()) as usize - l_skip;
        debug_assert_eq!(
            n_logup + l_skip,
            log2_ceil_u64(total_interactions + 1) as usize
        );
        n_logup
    } else {
        0
    }
}

/// Canonical present-only GKR-shape arithmetic, shared by the verifier's transcript extractor and
/// the recursion VK-layout extractor so their round counts cannot drift.
///
/// `present` yields `(num_interactions, log_height)` for every PRESENT trace. Absent AIRs must be
/// excluded: their `ni << l_skip` terms can tip `total_interactions` across a power-of-2 boundary
/// and yield an `n_logup` off-by-one on small programs.
pub fn present_gkr_shape(
    l_skip: usize,
    present: impl Iterator<Item = (usize, usize)>,
) -> (usize, usize, usize) {
    let mut total_interactions = 0u64;
    let mut max_log_height = 0usize;
    for (num_interactions, log_height) in present {
        total_interactions += lifted_interaction_count(num_interactions, log_height, l_skip);
        max_log_height = max_log_height.max(log_height);
    }
    let n_logup = calculate_n_logup(l_skip, total_interactions);
    let num_gkr_rounds = if total_interactions == 0 {
        0
    } else {
        l_skip + n_logup
    };
    let n_max = max_log_height.saturating_sub(l_skip);
    (n_logup, num_gkr_rounds, n_max)
}

#[cfg(test)]
mod tests {
    use super::{
        lambda_slots, lifted_interaction_count, lifted_log_height, present_gkr_shape, StackedLayout,
    };

    /// A layout whose `sorted_cols` are one column per matrix of the given `log_height`s (all
    /// full-height, stride 1), so `lambda_slots` walks one column per commit entry per matrix.
    fn layout(log_heights: &[usize]) -> StackedLayout {
        let l_skip = 0;
        let log_stacked_height = log_heights.iter().copied().max().unwrap_or(0);
        // One width-1 matrix per entry; already descending is not required for this construction,
        // but `StackedLayout::new` expects descending log_height, so sort.
        let mut sorted: Vec<(usize, usize)> = log_heights.iter().map(|&h| (1usize, h)).collect();
        sorted.sort_by_key(|&(_, log_height)| std::cmp::Reverse(log_height));
        StackedLayout::new(l_skip, log_stacked_height, sorted).unwrap()
    }

    /// `lambda_slots` reserves two consecutive exponents per column: `eq_exp = 2i`, and
    /// `rot_exp = Some(2i+1)` exactly when the column's matrix needs a rotation — regardless of
    /// whether earlier columns used their rotation slot. `i` is the flat column index across
    /// commitments.
    #[test]
    fn lambda_slots_reserves_two_exponents_per_column() {
        // Two commitments: 2 columns then 1 column. need_rot: [true, false] and [true].
        let layouts = [layout(&[3, 3]), layout(&[2])];
        let need_rot = vec![vec![true, false], vec![true]];
        let slots = lambda_slots(layouts.iter(), &need_rot);

        assert_eq!(slots.len(), 2);
        assert_eq!(slots[0].len(), 2);
        assert_eq!(slots[1].len(), 1);

        // Flat column 0: matrix 0 needs rot.
        assert_eq!(slots[0][0].eq_exp, 0);
        assert_eq!(slots[0][0].rot_exp, Some(1));
        // Flat column 1: matrix 1 does not need rot, but its eq slot is still 2 (slot 3 reserved).
        assert_eq!(slots[0][1].eq_exp, 2);
        assert_eq!(slots[0][1].rot_exp, None);
        // Flat column 2 (next commit): matrix 0 of commit 1 needs rot.
        assert_eq!(slots[1][0].eq_exp, 4);
        assert_eq!(slots[1][0].rot_exp, Some(5));
    }

    #[test]
    #[should_panic(expected = "one rotation vector per commitment")]
    fn lambda_slots_rejects_missing_commitment_shape() {
        let layouts = [layout(&[2]), layout(&[1])];
        let _ = lambda_slots(layouts.iter(), &[vec![false]]);
    }

    #[test]
    #[should_panic(expected = "one rotation flag per source matrix")]
    fn lambda_slots_rejects_missing_matrix_shape() {
        let layouts = [layout(&[2, 2])];
        let _ = lambda_slots(layouts.iter(), &[vec![false]]);
    }

    /// The prover indexes `λ.powers()` with these exponents; the verifier historically indexed
    /// `(λ²).powers()` (one index per column) times an extra `λ` for the rot term. The two spellings
    /// must agree: `λ^{2i} == (λ²)^i` and `λ^{2i+1} == (λ²)^i · λ`.
    #[test]
    fn lambda_slots_match_lambda_squared_spelling() {
        use p3_field::PrimeCharacteristicRing;
        use p3_koala_bear::KoalaBear;

        let layouts = [layout(&[4, 4, 3]), layout(&[2, 2])];
        let need_rot = vec![vec![true, false, true], vec![false, true]];
        let slots = lambda_slots(layouts.iter(), &need_rot);

        let lambda = KoalaBear::from_u32(7);
        let lambda_pows: Vec<KoalaBear> = lambda.powers().take(64).collect();
        let lambda_sqr_pows: Vec<KoalaBear> = (lambda * lambda).powers().take(64).collect();

        for (flat_idx, slot) in slots.iter().flatten().enumerate() {
            assert_eq!(slot.eq_exp, 2 * flat_idx);
            assert_eq!(lambda_pows[slot.eq_exp], lambda_sqr_pows[flat_idx]);
            if let Some(rot_exp) = slot.rot_exp {
                assert_eq!(rot_exp, 2 * flat_idx + 1);
                assert_eq!(lambda_pows[rot_exp], lambda_sqr_pows[flat_idx] * lambda);
            }
        }
    }

    #[test]
    fn lifted_log_height_lifts_below_floor() {
        // log_height < l_skip: lifted up to the l_skip floor.
        assert_eq!(lifted_log_height(0, 5), 5);
        assert_eq!(lifted_log_height(3, 5), 5);
    }

    #[test]
    fn lifted_log_height_at_and_above_floor() {
        // log_height == l_skip: unchanged.
        assert_eq!(lifted_log_height(5, 5), 5);
        // log_height > l_skip: unchanged (already above the floor).
        assert_eq!(lifted_log_height(7, 5), 7);
        // l_skip == 0: identity in log_height.
        assert_eq!(lifted_log_height(9, 0), 9);
    }

    #[test]
    fn lifted_interaction_count_scales_by_lifted_height() {
        // Above the floor: count << log_height.
        assert_eq!(lifted_interaction_count(3, 7, 5), 3u64 << 7);
        // Below the floor: count << l_skip (lifted).
        assert_eq!(lifted_interaction_count(3, 2, 5), 3u64 << 5);
        // Zero count contributes nothing.
        assert_eq!(lifted_interaction_count(0, 7, 5), 0);
    }

    /// The three spellings the helper replaced must all agree with it over every reachable
    /// `(log_height, l_skip)`, so adopting it at the production sites can't shift the lifted height.
    #[test]
    fn all_three_spellings_agree_with_helper() {
        for l_skip in 0..12usize {
            for log_height in 0..20usize {
                let expected = lifted_log_height(log_height, l_skip);

                // Spelling 1: `max(...)` — the prover / proof-shape form.
                assert_eq!(log_height.max(l_skip), expected);

                // Spelling 2: `l_skip + n_lift`, `n_lift = n.max(0)` — the old batch_constraints form.
                let n = log_height as isize - l_skip as isize;
                let n_lift = n.max(0) as usize;
                assert_eq!(l_skip + n_lift, expected);

                // Spelling 3: n-space reconstruction — the new batch_constraints form. The
                // reconstruction must never underflow (`n >= -l_skip` since `log_height >= 0`).
                assert!(l_skip as isize + n >= 0);
                let reconstructed = (l_skip as isize + n) as usize;
                assert_eq!(lifted_log_height(reconstructed, l_skip), expected);

                // The count helper equals `count << expected` for a representative nonzero count.
                let count = 5usize;
                assert_eq!(
                    lifted_interaction_count(count, log_height, l_skip),
                    (count as u64) << expected,
                );
            }
        }
    }

    /// No present trace, or none carrying interactions: GKR is skipped entirely.
    #[test]
    fn present_gkr_shape_empty_runs_no_rounds() {
        assert_eq!(present_gkr_shape(5, [].into_iter()), (0, 0, 0));
        assert_eq!(
            present_gkr_shape(5, [(0, 7), (0, 9)].into_iter()),
            (0, 0, 4)
        );
    }

    /// `n_max` is `max ñT` over *all* present traces, including those with
    /// no interactions — they still carry zerocheck constraints. It is not gated on `num_interactions`.
    #[test]
    fn present_gkr_shape_n_max_counts_non_interacting_traces() {
        let (_, _, n_max) = present_gkr_shape(5, [(0, 15), (1, 5)].into_iter());
        assert_eq!(n_max, 10);
    }

    /// Absent AIRs must not be fed to the helper. Their `ni << l_skip` terms can tip
    /// `total_interactions` over a power-of-2 boundary and shift `n_logup` by one, which then
    /// mismatches the GKR round count the prover committed to.
    #[test]
    fn present_gkr_shape_excludes_absent_airs() {
        let l_skip = 5;
        let present = [(1usize, 5usize)];
        let absent_included = [(1usize, 5usize), (1usize, 0usize)];

        let (n_logup_present, rounds_present, _) = present_gkr_shape(l_skip, present.into_iter());
        let (n_logup_both, rounds_both, _) = present_gkr_shape(l_skip, absent_included.into_iter());

        // total = 2^5 vs 2^6: one extra lifted term crosses the boundary.
        assert_eq!((n_logup_present, rounds_present), (1, 6));
        assert_eq!((n_logup_both, rounds_both), (2, 7));
    }

    /// The LogUp injection ȷ maps `⊔_T D_ñT × I` into `H_{ℓ+nLogUp}`. Injectivity
    /// requires the target to be large enough, and `nLogUp ≥ ñT` for every trace that actually
    /// contributes points (`|I| > 0`; a zero-interaction trace injects an empty set). Both must
    /// hold for the round count the verifier reconstructs, or the GKR circuit is mis-shaped.
    #[test]
    fn present_gkr_shape_satisfies_logup_injection_bounds() {
        for l_skip in 0..8usize {
            for traces in [
                vec![(1usize, l_skip)], // total is an exact power of two
                vec![(12, l_skip), (7, l_skip + 3), (3, l_skip + 1)],
                vec![(0, l_skip + 10), (1, l_skip)], // tall trace, no interactions
                vec![(1, 0), (1, l_skip + 4)],       // a trace below the skip floor
            ] {
                let (n_logup, rounds, n_max) = present_gkr_shape(l_skip, traces.iter().copied());

                let total: u64 = traces
                    .iter()
                    .map(|&(ni, lh)| lifted_interaction_count(ni, lh, l_skip))
                    .sum();
                if total == 0 {
                    assert_eq!((n_logup, rounds), (0, 0));
                    continue;
                }

                // Injectivity: the hypercube `H_{ℓ+nLogUp}` must hold every injected point.
                assert_eq!(rounds, l_skip + n_logup);
                assert!((1u64 << rounds) >= total, "capacity: 2^{rounds} < {total}");

                // Injectivity: `nLogUp ≥ ñT` for each interacting trace.
                for &(_, lh) in traces.iter().filter(|&&(ni, _)| ni > 0) {
                    assert!(n_logup >= lifted_log_height(lh, l_skip) - l_skip);
                }

                // `n_max = max ñT` over all present traces.
                let expected_n_max = traces
                    .iter()
                    .map(|&(_, lh)| lifted_log_height(lh, l_skip) - l_skip)
                    .max()
                    .unwrap();
                assert_eq!(n_max, expected_n_max);
            }
        }
    }
}
