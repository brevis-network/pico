//! Dense matrix primitives for the MLE backend: column-major storage + virtual views.
//!
//! [`MatrixDimensions`] lives here (the base layer) rather than in `prover::hal`, so the `poly`
//! tree has no upward dependency on `prover`; `prover` re-exports it for back-compat.

use std::borrow::Borrow;

use getset::CopyGetters;
use p3_field::Field;
use p3_matrix::dense::{DenseMatrix, RowMajorMatrix};
use p3_maybe_rayon::prelude::*;
use serde::{Deserialize, Serialize};

/// Width/height accessors shared by every (real or virtual) matrix in the backend.
pub trait MatrixDimensions {
    fn height(&self) -> usize;
    fn width(&self) -> usize;
}

impl<T, V: Borrow<[T]>> MatrixDimensions for DenseMatrix<T, V> {
    fn height(&self) -> usize {
        self.values.borrow().len() / self.width
    }
    fn width(&self) -> usize {
        self.width
    }
}

/// Trait to consolidate different virtual matrices that may not be backed by an in-memory matrix
/// with a standard column-major or row-major layout.
///
/// Note: for performance, users should still be aware of the underlying memory layout. This trait
/// is just an organizational convenience.
pub trait MatrixView<F>: MatrixDimensions {
    fn get(&self, row_idx: usize, col_idx: usize) -> Option<&F> {
        if col_idx >= self.width() || row_idx >= self.height() {
            None
        } else {
            // SAFETY: bounds checked above
            Some(unsafe { self.get_unchecked(row_idx, col_idx) })
        }
    }
    /// Get a reference to an element without bounds checking.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `col_idx` and `row_idx` are within the bounds of the matrix.
    unsafe fn get_unchecked(&self, row_idx: usize, col_idx: usize) -> &F;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ColMajorMatrix<F> {
    pub values: Vec<F>,
    width: usize,
    height: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct ColMajorMatrixView<'a, F> {
    pub values: &'a [F],
    width: usize,
    height: usize,
}

/// Vertically strided column-major matrix view.
#[derive(Clone, Copy, Debug, CopyGetters)]
pub struct StridedColMajorMatrixView<'a, F> {
    #[getset(get_copy = "pub")]
    values: &'a [F],
    width: usize,
    height: usize,
    /// Row stride
    #[getset(get_copy = "pub")]
    stride: usize,
}

impl<F> ColMajorMatrix<F> {
    pub fn new(values: Vec<F>, width: usize) -> Self {
        assert_eq!(values.len() % width, 0);
        let height = values.len() / width;
        assert!(height.is_power_of_two());
        Self {
            values,
            width,
            height,
        }
    }

    pub fn column(&self, col_idx: usize) -> &[F] {
        let start = col_idx * self.height;
        let end = start + self.height;
        &self.values[start..end]
    }

    pub fn columns(&self) -> impl Iterator<Item = &[F]> {
        self.values.chunks_exact(self.height)
    }

    pub fn as_view(&self) -> ColMajorMatrixView<'_, F> {
        ColMajorMatrixView {
            values: &self.values,
            width: self.width,
            height: self.height,
        }
    }

    pub fn from_row_major(mat: &RowMajorMatrix<F>) -> Self
    where
        F: Field,
    {
        let mut values = F::zero_vec(mat.values.len());
        let width = mat.width;
        let height = mat.values.len() / mat.width;
        values.par_iter_mut().enumerate().for_each(|(idx, value)| {
            let r = idx % height;
            let c = idx / height;
            // SAFETY: index is in bounds for row-major matrix
            *value = unsafe { *mat.values.get_unchecked(r * width + c) };
        });
        Self {
            values,
            width,
            height,
        }
    }
}

impl<F: Sync> ColMajorMatrix<F> {
    pub fn par_columns(&self) -> impl ParallelIterator<Item = &[F]> {
        self.values.par_chunks_exact(self.height)
    }
}

impl<F> MatrixDimensions for ColMajorMatrix<F> {
    fn width(&self) -> usize {
        self.width
    }
    fn height(&self) -> usize {
        self.height
    }
}

impl<F> MatrixView<F> for ColMajorMatrix<F> {
    unsafe fn get_unchecked(&self, row_idx: usize, col_idx: usize) -> &F {
        debug_assert!(col_idx < self.width);
        debug_assert!(row_idx < self.height);
        self.values.get_unchecked(col_idx * self.height + row_idx)
    }
}

impl<'a, F> ColMajorMatrixView<'a, F> {
    pub fn new(values: &'a [F], width: usize) -> Self {
        assert_eq!(values.len() % width, 0);
        let height = values.len() / width;
        debug_assert!(height == 0 || height.is_power_of_two());
        Self {
            values,
            width,
            height,
        }
    }

    pub fn column(&self, col_idx: usize) -> &[F] {
        let start = col_idx * self.height;
        let end = start + self.height;
        &self.values[start..end]
    }

    pub fn columns(&self) -> impl Iterator<Item = &[F]> {
        self.values.chunks_exact(self.height)
    }
}

impl<F> MatrixDimensions for ColMajorMatrixView<'_, F> {
    fn width(&self) -> usize {
        self.width
    }
    fn height(&self) -> usize {
        self.height
    }
}

impl<F> MatrixView<F> for ColMajorMatrixView<'_, F> {
    unsafe fn get_unchecked(&self, row_idx: usize, col_idx: usize) -> &F {
        debug_assert!(col_idx < self.width);
        debug_assert!(row_idx < self.height);
        self.values
            .get_unchecked(col_maj_idx(row_idx, col_idx, self.height))
    }
}

impl<'a, F> StridedColMajorMatrixView<'a, F> {
    pub fn new(values: &'a [F], width: usize, stride: usize) -> Self {
        assert_eq!(values.len() % (width * stride), 0);
        let height = values.len() / (width * stride);
        debug_assert!(height == 0 || height.is_power_of_two());
        Self {
            values,
            width,
            height,
            stride,
        }
    }

    pub fn to_matrix(&self) -> ColMajorMatrix<F>
    where
        F: Field,
    {
        let values: Vec<_> = (0..self.width * self.height)
            .into_par_iter()
            .map(|i| {
                let r = i % self.height;
                let c = i / self.height;
                unsafe { *self.get_unchecked(r, c) }
            })
            .collect();
        ColMajorMatrix::new(values, self.width)
    }

    pub fn to_row_major_matrix(&self) -> RowMajorMatrix<F>
    where
        F: Field,
    {
        let values: Vec<_> = (0..self.width * self.height)
            .into_par_iter()
            .map(|i| {
                let r = i / self.width;
                let c = i % self.width;
                unsafe { *self.get_unchecked(r, c) }
            })
            .collect();
        RowMajorMatrix::new(values, self.width)
    }
}

impl<F> MatrixDimensions for StridedColMajorMatrixView<'_, F> {
    fn width(&self) -> usize {
        self.width
    }
    fn height(&self) -> usize {
        self.height
    }
}

impl<F> MatrixView<F> for StridedColMajorMatrixView<'_, F> {
    unsafe fn get_unchecked(&self, row_idx: usize, col_idx: usize) -> &F {
        debug_assert!(col_idx < self.width);
        debug_assert!(row_idx < self.height);
        self.values.get_unchecked(col_maj_idx(
            row_idx * self.stride,
            col_idx,
            self.height * self.stride,
        ))
    }
}

impl<'a, F> From<ColMajorMatrixView<'a, F>> for StridedColMajorMatrixView<'a, F> {
    fn from(mat: ColMajorMatrixView<'a, F>) -> Self {
        Self::new(mat.values, mat.width, 1)
    }
}

#[inline(always)]
pub(crate) fn col_maj_idx(row_idx: usize, col_idx: usize, height: usize) -> usize {
    col_idx * height + row_idx
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    use super::{ColMajorMatrix, StridedColMajorMatrixView};

    type F = KoalaBear;

    /// Pins the col-major → row-major transpose (`rm[r*w+c] = cm[c*h+r]`) that
    /// `stacked_pcs_data_to_cpu` uses to move a Merkle backing onto the CPU device.
    #[test]
    fn strided_view_transposes_col_major_to_row_major() {
        let width = 3;
        let height = 4; // power of two, required by `ColMajorMatrix::new`
                        // Encode each cell as `r*10 + c`, stored column-major.
        let mut cm_values = vec![F::ZERO; width * height];
        for c in 0..width {
            for r in 0..height {
                cm_values[c * height + r] = F::from_u32((r * 10 + c) as u32);
            }
        }
        let cm = ColMajorMatrix::new(cm_values.clone(), width);

        let view: StridedColMajorMatrixView<'_, F> = cm.as_view().into();
        let rm = view.to_row_major_matrix();

        assert_eq!(rm.width, width);
        assert_eq!(rm.values.len(), width * height);
        for r in 0..height {
            for c in 0..width {
                assert_eq!(rm.values[r * width + c], cm_values[c * height + r]);
                assert_eq!(rm.values[r * width + c], F::from_u32((r * 10 + c) as u32));
            }
        }
    }
}
