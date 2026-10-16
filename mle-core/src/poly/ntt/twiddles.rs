//! Cached radix-2 twiddle-table DFT (in-place DIF/DIT).
//!
//! [`TwiddleDft`] precomputes per-layer twiddle factors once and reuses them across many in-place
//! transforms of the same size. Used by the CPU Merkle / WHIR / stacked-reduction paths. It is one
//! of three DFT paths in this crate (see [`super`]).

use p3_field::TwoAdicField;
use p3_util::reverse_slice_index_bits;

/// Precomputed radix-2 twiddle factors for size `2^log_n`.
pub struct TwiddleDft<F> {
    /// iDFT twiddle factors (DIF: omega_inv powers), per layer.
    idft_tw: Vec<Vec<F>>,
    /// DFT twiddle factors (DIT: omega powers), per layer.
    dft_tw: Vec<Vec<F>>,
    /// 1/N scaling factor for iDFT.
    n_inv: F,
    log_n: usize,
}

impl<F: TwoAdicField> TwiddleDft<F> {
    pub fn new(log_n: usize) -> Self {
        let n = 1usize << log_n;
        let omega = F::two_adic_generator(log_n);
        let omega_inv = omega.inverse();
        let mut n_field = F::ONE;
        for _ in 0..log_n {
            n_field += n_field;
        }
        let n_inv = n_field.inverse();

        let idft_tw = (0..log_n)
            .map(|layer| {
                let half = n >> (layer + 1);
                let w = omega_inv.exp_power_of_2(layer);
                w.powers().take(half).collect()
            })
            .collect();

        let dft_tw = (0..log_n)
            .map(|layer| {
                let half = 1usize << layer;
                let w = omega.exp_power_of_2(log_n - 1 - layer);
                w.powers().take(half).collect()
            })
            .collect();

        Self {
            idft_tw,
            dft_tw,
            n_inv,
            log_n,
        }
    }

    pub fn size(&self) -> usize {
        1usize << self.log_n
    }

    /// In-place iDFT (DIF + bit-reverse + scale by 1/N).
    pub fn idft_inplace(&self, buf: &mut [F]) {
        let n = self.size();
        debug_assert_eq!(buf.len(), n);

        let mut block_size = n;
        for tw in &self.idft_tw {
            let half = block_size >> 1;
            let mut k = 0;
            while k < n {
                for j in 0..half {
                    let u = buf[k + j];
                    let v = buf[k + j + half];
                    buf[k + j] = u + v;
                    buf[k + j + half] = (u - v) * tw[j];
                }
                k += block_size;
            }
            block_size = half;
        }

        self.bit_reverse(buf);
        for val in buf.iter_mut() {
            *val *= self.n_inv;
        }
    }

    /// In-place DFT (DIT: bit-reverse input, then butterflies).
    pub fn dft_inplace(&self, buf: &mut [F]) {
        let n = self.size();
        debug_assert_eq!(buf.len(), n);

        self.bit_reverse(buf);

        let mut block_size = 2;
        for tw in &self.dft_tw {
            let half = block_size >> 1;
            let mut k = 0;
            while k < n {
                for j in 0..half {
                    let u = buf[k + j];
                    let v = buf[k + j + half] * tw[j];
                    buf[k + j] = u + v;
                    buf[k + j + half] = u - v;
                }
                k += block_size;
            }
            block_size <<= 1;
        }
    }

    /// Coset DFT: evaluate polynomial at `shift * omega^k` for `k = 0..N-1`.
    pub fn coset_dft_inplace(&self, buf: &mut [F], shift: F) {
        debug_assert_eq!(buf.len(), self.size());

        let mut s = F::ONE;
        for val in buf.iter_mut() {
            *val *= s;
            s *= shift;
        }
        self.dft_inplace(buf);
    }

    fn bit_reverse(&self, buf: &mut [F]) {
        reverse_slice_index_bits(buf);
    }
}
