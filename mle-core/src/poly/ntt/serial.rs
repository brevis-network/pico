//! Serial radix-2 DFT over a two-adic subgroup (Bowers G network, no rayon).
//!
//! [`SerialRadix2Dft`] is the workspace's vendored, single-threaded implementation of
//! `p3_dft::TwoAdicSubgroupDft`, used for batch LDE / coset-LDE and the univariate-poly
//! interpolation helpers. It is one of three DFT paths in this crate (see [`super`]).

use std::borrow::BorrowMut;

// Originally copied from p3-dft [src/radix_2_bowers.rs] to turn off rayon
use p3_dft::{Butterfly, DifButterfly, DitButterfly, TwiddleFreeButterfly, TwoAdicSubgroupDft};
use p3_field::{Field, PackedValue, Powers, TwoAdicField};
use p3_matrix::{
    dense::{DenseMatrix, DenseStorage, RowMajorMatrix, RowMajorMatrixViewMut},
    Matrix,
};
use p3_util::{log2_strict_usize, reverse_bits, reverse_bits_len, reverse_slice_index_bits};
use tracing::instrument;

/// The Bowers G FFT algorithm, serial (no rayon).
/// See: "Improved Twiddle Access for Fast Fourier Transforms"
#[derive(Default, Clone)]
pub struct SerialRadix2Dft;

impl<F: TwoAdicField> TwoAdicSubgroupDft<F> for SerialRadix2Dft {
    type Evaluations = RowMajorMatrix<F>;

    fn dft(&self, vec: Vec<F>) -> Vec<F> {
        self.dft_batch(RowMajorMatrix::new_col(vec)).values
    }

    fn dft_batch(&self, mut mat: RowMajorMatrix<F>) -> RowMajorMatrix<F> {
        reverse_matrix_index_bits(&mut mat);
        bowers_g(&mut mat.as_view_mut());
        mat
    }

    /// Compute the inverse DFT of `vec`.
    fn idft(&self, vec: Vec<F>) -> Vec<F> {
        self.idft_batch(RowMajorMatrix::new(vec, 1)).values
    }

    /// Compute the inverse DFT of each column in `mat`.
    fn idft_batch(&self, mut mat: RowMajorMatrix<F>) -> RowMajorMatrix<F> {
        bowers_g_t(&mut mat.as_view_mut());
        divide_by_height(&mut mat);
        reverse_matrix_index_bits(&mut mat);
        mat
    }

    fn lde_batch(&self, mut mat: RowMajorMatrix<F>, added_bits: usize) -> RowMajorMatrix<F> {
        bowers_g_t(&mut mat.as_view_mut());
        divide_by_height(&mut mat);
        mat = mat.bit_reversed_zero_pad(added_bits);
        bowers_g(&mut mat.as_view_mut());
        mat
    }

    #[instrument(skip_all, fields(dims = %mat.dimensions(), added_bits))]
    fn coset_lde_batch(
        &self,
        mut mat: RowMajorMatrix<F>,
        added_bits: usize,
        shift: F,
    ) -> RowMajorMatrix<F> {
        let h = mat.height();
        let log_h = log2_strict_usize(h);
        // It's cheaper to use div_2exp_u64 as this usually avoids an inversion.
        // It's also cheaper to work in the PrimeSubfield whenever possible.
        let h_inv = F::ONE.div_2exp_u64(log_h as u64);

        bowers_g_t(&mut mat.as_view_mut());

        // Rescale coefficients in two ways:
        // - divide by height (since we're doing an inverse DFT)
        // - multiply by powers of the coset shift (see default coset LDE impl for an explanation)
        let weights = Powers {
            base: shift,
            current: h_inv,
        }
        .take(h);
        for (row, weight) in weights.enumerate() {
            // reverse_bits because mat is encoded in bit-reversed order
            mat.scale_row(reverse_bits(row, h), weight);
        }

        mat = mat.bit_reversed_zero_pad(added_bits);

        bowers_g(&mut mat.as_view_mut());

        mat
    }
}

/// Executes the Bowers G network. This is like a DFT, except it assumes the input is in
/// bit-reversed order.
fn bowers_g<F: TwoAdicField>(mat: &mut RowMajorMatrixViewMut<F>) {
    let h = mat.height();
    let log_h = log2_strict_usize(h);

    let root = F::two_adic_generator(log_h);
    let mut twiddles: Vec<_> = root.powers().take(h / 2).map(DifButterfly).collect();
    reverse_slice_index_bits(&mut twiddles);

    let log_h = log2_strict_usize(mat.height());
    for log_half_block_size in 0..log_h {
        butterfly_layer(mat, 1 << log_half_block_size, &twiddles)
    }
}

/// Executes the Bowers G^T network. This is like an inverse DFT, except we skip rescaling by
/// 1/height, and the output is bit-reversed.
fn bowers_g_t<F: TwoAdicField>(mat: &mut RowMajorMatrixViewMut<F>) {
    let h = mat.height();
    let log_h = log2_strict_usize(h);

    let root_inv = F::two_adic_generator(log_h).inverse();
    let mut twiddles: Vec<_> = root_inv.powers().take(h / 2).map(DitButterfly).collect();
    reverse_slice_index_bits(&mut twiddles);

    let log_h = log2_strict_usize(mat.height());
    for log_half_block_size in (0..log_h).rev() {
        butterfly_layer(mat, 1 << log_half_block_size, &twiddles)
    }
}

fn butterfly_layer<F: Field, B: Butterfly<F>>(
    mat: &mut RowMajorMatrixViewMut<F>,
    half_block_size: usize,
    twiddles: &[B],
) {
    mat.row_chunks_exact_mut(2 * half_block_size)
        .enumerate()
        .for_each(|(block, mut chunks)| {
            let (mut hi_chunks, mut lo_chunks) = chunks.split_rows_mut(half_block_size);
            hi_chunks
                .rows_mut()
                .zip(lo_chunks.rows_mut())
                .for_each(|(hi_chunk, lo_chunk)| {
                    if block == 0 {
                        TwiddleFreeButterfly.apply_to_rows(hi_chunk, lo_chunk)
                    } else {
                        twiddles[block].apply_to_rows(hi_chunk, lo_chunk);
                    }
                });
        });
}

pub fn divide_by_height<F: Field, S: DenseStorage<F> + BorrowMut<[F]>>(
    mat: &mut DenseMatrix<F, S>,
) {
    let h = mat.height();
    let log_h = log2_strict_usize(h);
    // It's cheaper to use div_2exp_u64 as this usually avoids an inversion.
    // It's also cheaper to work in the PrimeSubfield whenever possible.
    let h_inv = F::ONE.div_2exp_u64(log_h as u64);
    scale_slice_in_place(h_inv, mat.values.borrow_mut());
}

pub fn scale_slice_in_place<F: Field>(s: F, slice: &mut [F]) {
    let (packed, sfx) = F::Packing::pack_slice_with_suffix_mut(slice);
    let packed_s: F::Packing = s.into();
    packed.iter_mut().for_each(|x| *x *= packed_s);
    sfx.iter_mut().for_each(|x| *x *= s);
}

#[instrument(level = "debug", skip_all)]
pub fn reverse_matrix_index_bits<'a, F, S>(mat: &mut DenseMatrix<F, S>)
where
    F: Clone + Send + Sync + 'a,
    S: DenseStorage<F> + BorrowMut<[F]>,
{
    let w = mat.width();
    let h = mat.height();
    let log_h = log2_strict_usize(h);
    let values = mat.values.borrow_mut().as_mut_ptr() as usize;

    (0..h).for_each(|i| {
        let values = values as *mut F;
        let j = reverse_bits_len(i, log_h);
        if i < j {
            unsafe { swap_rows_raw(values, w, i, j) };
        }
    });
}

/// Assumes `i < j`.
///
/// SAFETY: The caller must ensure `i < j < h`, where `h` is the height of the matrix.
pub(crate) unsafe fn swap_rows_raw<F>(mat: *mut F, w: usize, i: usize, j: usize) {
    let row_i = core::slice::from_raw_parts_mut(mat.add(i * w), w);
    let row_j = core::slice::from_raw_parts_mut(mat.add(j * w), w);
    row_i.swap_with_slice(row_j);
}
