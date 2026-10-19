//! Row-major native fold and sumcheck utilities.
//!
//! These are RowMajor-native counterparts of the ColMajor functions in
//! [`crate::prover::sumcheck`].

use std::array::from_fn;

use itertools::Itertools;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;

/// Halves the height of a [RowMajorMatrix] by folding adjacent row pairs via
/// multilinear interpolation at challenge `r`.
///
/// For each pair of rows `(row_{2y}, row_{2y+1})`, the folded row is
/// `row_{2y} * (1 - r) + row_{2y+1} * r`.
///
/// Returns the input unchanged when its height is 0 or 1.
pub fn fold_mle_evals_rm<EF: Field>(mat: RowMajorMatrix<EF>, r: EF) -> RowMajorMatrix<EF> {
    let width = mat.width;
    let height = mat.values.len() / width;
    if height <= 1 {
        return mat;
    }
    let new_height = height / 2;
    let one_minus_r = EF::ONE - r;

    let mut values = EF::zero_vec(new_height * width);
    values
        .par_chunks_exact_mut(width)
        .enumerate()
        .for_each(|(y, row)| {
            let row0_start = (2 * y) * width;
            let row1_start = (2 * y + 1) * width;
            for (j, value) in row.iter_mut().enumerate() {
                *value = mat.values[row0_start + j] * one_minus_r + mat.values[row1_start + j] * r;
            }
        });
    RowMajorMatrix::new(values, width)
}

/// Batch version of [`fold_mle_evals_rm`]: folds each matrix independently.
pub fn batch_fold_mle_evals_rm<EF: Field>(
    mats: Vec<RowMajorMatrix<EF>>,
    r: EF,
) -> Vec<RowMajorMatrix<EF>> {
    mats.into_iter().map(|m| fold_mle_evals_rm(m, r)).collect()
}

/// RowMajor-native version of
/// [`sumcheck_round_poly_evals`](crate::prover::sumcheck::sumcheck_round_poly_evals).
///
/// Evaluates the degree-`d` sumcheck round polynomial `s(X) = sum_{y in H_{n-1}} hat{f}(X, y)`
/// at `X = 1, ..., d`, where `hat{f}` is defined by the weight function `w` applied to multilinear
/// polynomials whose evaluations on `H_n` are stored in the RowMajor matrices `parts`.
///
/// The key advantage over the ColMajor version is that for each hypercube point `y`, the two
/// rows `(2y, 2y+1)` needed for linear interpolation are **contiguous** in memory.
///
/// Returns `WD` vectors, each of length `d`, containing the evaluations at `{1, ..., d}`.
pub fn sumcheck_round_poly_evals_rm<EF, FN, const WD: usize>(
    n: usize,
    d: usize,
    parts: &[&RowMajorMatrix<EF>],
    w: FN,
) -> [Vec<EF>; WD]
where
    EF: Field,
    FN: Fn(EF, usize, &[Vec<EF>]) -> [EF; WD] + Sync,
{
    debug_assert!(parts.iter().all(|mat| {
        let h = mat.values.len() / mat.width;
        h == 1 << n
    }));

    if n == 0 {
        // Trivial sum: s(X) is constant. Each matrix is a single row.
        let row_vecs: Vec<Vec<EF>> = parts.iter().map(|mat| mat.values.to_vec()).collect();
        return w(EF::ONE, 0, &row_vecs).map(|x| vec![x; d]);
    }

    let hypercube_dim = n - 1;

    // For each y in H_{n-1}, evaluate hat{f}(x, y) for x in {1, ..., d} by MLE interpolation.
    // The row buffers are reused across all x values for the same y.
    let evals = (0..1usize << hypercube_dim).into_par_iter().map(|y| {
        let mut interp_rows: Vec<Vec<EF>> =
            parts.iter().map(|mat| EF::zero_vec(mat.width)).collect();
        let mut local = vec![[EF::ZERO; WD]; d];
        for (x_idx, x) in (1..=d).enumerate() {
            let x_ef = EF::from_usize(x);
            // For each matrix, read row 2y and row 2y+1, interpolate column-wise.
            for (part_idx, mat) in parts.iter().enumerate() {
                let width = mat.width;
                let r0 = (y << 1) * width;
                let r1 = ((y << 1) | 1) * width;
                for (j, value) in interp_rows[part_idx].iter_mut().enumerate() {
                    let t_0 = mat.values[r0 + j];
                    let t_1 = mat.values[r1 + j];
                    *value = t_0 + (t_1 - t_0) * x_ef;
                }
            }
            local[x_idx] = w(x_ef, y, &interp_rows);
        }
        local
    });

    // Reduce: sum over H_{n-1}
    let hypercube_sum = |mut acc: Vec<[EF; WD]>, x: Vec<[EF; WD]>| {
        for (a, b) in acc.iter_mut().zip(x.iter()) {
            for (ai, bi) in a.iter_mut().zip(b.iter()) {
                *ai += *bi;
            }
        }
        acc
    };
    cfg_if::cfg_if! {
        if #[cfg(feature = "parallel")] {
            let evals = evals.reduce(
                || vec![[EF::ZERO; WD]; d],
                hypercube_sum,
            );
        } else {
            let evals = evals.collect_vec();
            let evals = evals.into_iter().fold(
                vec![[EF::ZERO; WD]; d],
                hypercube_sum,
            );
        }
    }
    from_fn(|i| evals.iter().map(|eval| eval[i]).collect_vec())
}

#[cfg(test)]
mod tests {
    use crate::config::koala_bear_poseidon2::F;
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    #[test]
    fn test_fold_mle_evals_rm_identity_at_zero() {
        // Folding at r=0 should keep even-indexed rows.
        let mat = RowMajorMatrix::new(
            vec![
                F::from_u32(1),
                F::from_u32(2),
                F::from_u32(3),
                F::from_u32(4),
                F::from_u32(5),
                F::from_u32(6),
                F::from_u32(7),
                F::from_u32(8),
            ],
            2,
        );
        let folded = fold_mle_evals_rm(mat, F::ZERO);
        assert_eq!(folded.width, 2);
        let h = folded.values.len() / folded.width;
        assert_eq!(h, 2);
        // row 0 = original row 0
        assert_eq!(folded.values[0], F::from_u32(1));
        assert_eq!(folded.values[1], F::from_u32(2));
        // row 1 = original row 2
        assert_eq!(folded.values[2], F::from_u32(5));
        assert_eq!(folded.values[3], F::from_u32(6));
    }

    #[test]
    fn test_fold_mle_evals_rm_identity_at_one() {
        // Folding at r=1 should keep odd-indexed rows.
        let mat = RowMajorMatrix::new(
            vec![
                F::from_u32(1),
                F::from_u32(2),
                F::from_u32(3),
                F::from_u32(4),
                F::from_u32(5),
                F::from_u32(6),
                F::from_u32(7),
                F::from_u32(8),
            ],
            2,
        );
        let folded = fold_mle_evals_rm(mat, F::ONE);
        assert_eq!(folded.values[0], F::from_u32(3));
        assert_eq!(folded.values[1], F::from_u32(4));
        assert_eq!(folded.values[2], F::from_u32(7));
        assert_eq!(folded.values[3], F::from_u32(8));
    }

    #[test]
    fn test_fold_mle_evals_rm_height_one() {
        let mat = RowMajorMatrix::new(vec![F::from_u32(42), F::from_u32(7)], 2);
        let folded = fold_mle_evals_rm(mat.clone(), F::from_u32(123));
        assert_eq!(folded.values, mat.values);
    }

    #[test]
    fn test_fold_mle_evals_rm_interpolation() {
        // 2 rows x 1 col: [a, b] folded at r -> a*(1-r) + b*r
        let a = F::from_u32(10);
        let b = F::from_u32(30);
        let r = F::from_u32(3);
        let mat = RowMajorMatrix::new(vec![a, b], 1);
        let folded = fold_mle_evals_rm(mat, r);
        assert_eq!(folded.values.len(), 1);
        let expected = a * (F::ONE - r) + b * r;
        assert_eq!(folded.values[0], expected);
    }

    #[test]
    fn test_batch_fold_mle_evals_rm() {
        let mat1 = RowMajorMatrix::new(
            vec![
                F::from_u32(1),
                F::from_u32(2),
                F::from_u32(3),
                F::from_u32(4),
            ],
            2,
        );
        let mat2 = RowMajorMatrix::new(
            vec![
                F::from_u32(10),
                F::from_u32(20),
                F::from_u32(30),
                F::from_u32(40),
            ],
            2,
        );
        let r = F::ZERO;
        let folded = batch_fold_mle_evals_rm(vec![mat1, mat2], r);
        assert_eq!(folded.len(), 2);
        // At r=0, we keep even rows
        assert_eq!(folded[0].values, vec![F::from_u32(1), F::from_u32(2)]);
        assert_eq!(folded[1].values, vec![F::from_u32(10), F::from_u32(20)]);
    }

    #[test]
    fn test_sumcheck_round_poly_evals_rm_identity() {
        // Single matrix, W = identity, n=1, d=1
        // mat = [[a], [b]] (2 rows, 1 col)
        // s(X) = sum_{y in H_0} f(X, y) = f(X, 0) = a*(1-X) + b*X
        // s(1) = b
        let a = F::from_u32(5);
        let b = F::from_u32(11);
        let mat = RowMajorMatrix::new(vec![a, b], 1);
        let [result] =
            sumcheck_round_poly_evals_rm::<_, _, 1>(1, 1, &[&mat], |_x, _y, parts| [parts[0][0]]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], b); // s(1) = b
    }

    #[test]
    fn test_sumcheck_round_poly_evals_rm_n2() {
        // n=2, d=1, single matrix with 4 rows x 1 col: [a, b, c, d]
        // MLE on H_2: f(x0, x1) where row index = x1*2 + x0
        // s(X) = sum_{y in H_1} f(X, y) = f(X, 0) + f(X, 1)
        //   f(X, 0) = row[0]*(1-X) + row[1]*X = a*(1-X) + b*X
        //   f(X, 1) = row[2]*(1-X) + row[3]*X = c*(1-X) + d*X
        //   s(X) = (a+c)*(1-X) + (b+d)*X
        //   s(1) = b + d
        let a = F::from_u32(1);
        let b = F::from_u32(2);
        let c = F::from_u32(3);
        let d = F::from_u32(4);
        let mat = RowMajorMatrix::new(vec![a, b, c, d], 1);
        let [result] =
            sumcheck_round_poly_evals_rm::<_, _, 1>(2, 1, &[&mat], |_x, _y, parts| [parts[0][0]]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], b + d);
    }

    #[test]
    fn test_sumcheck_round_poly_evals_rm_n0() {
        // n=0, d=1: trivial case, single row
        let mat = RowMajorMatrix::new(vec![F::from_u32(42)], 1);
        let [result] =
            sumcheck_round_poly_evals_rm::<_, _, 1>(0, 1, &[&mat], |_x, _y, parts| [parts[0][0]]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], F::from_u32(42));
    }

    #[test]
    fn test_sumcheck_round_poly_evals_rm_multi_part() {
        // 2 parts (matrices), W sums them: W(a, b) = a + b
        // n=1, d=1
        let mat1 = RowMajorMatrix::new(vec![F::from_u32(10), F::from_u32(20)], 1);
        let mat2 = RowMajorMatrix::new(vec![F::from_u32(3), F::from_u32(7)], 1);
        let [result] =
            sumcheck_round_poly_evals_rm::<_, _, 1>(1, 1, &[&mat1, &mat2], |_x, _y, parts| {
                [parts[0][0] + parts[1][0]]
            });
        // s(1) = (mat1 row1) + (mat2 row1) = 20 + 7 = 27
        assert_eq!(result[0], F::from_u32(27));
    }

    #[test]
    fn test_sumcheck_round_poly_evals_rm_degree2() {
        // n=1, d=2, single matrix [[a], [b]]
        // s(X) = a*(1-X) + b*X
        // s(1) = b, s(2) = a*(1-2) + b*2 = -a + 2b
        let a = F::from_u32(5);
        let b = F::from_u32(11);
        let mat = RowMajorMatrix::new(vec![a, b], 1);
        let [result] =
            sumcheck_round_poly_evals_rm::<_, _, 1>(1, 2, &[&mat], |_x, _y, parts| [parts[0][0]]);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], b); // s(1)
        let expected_s2 = a * (F::ONE - F::from_u32(2)) + b * F::from_u32(2);
        assert_eq!(result[1], expected_s2); // s(2)
    }
}
