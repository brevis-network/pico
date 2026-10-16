//! Radix-2 NTT/DFT primitives.
//!
//! This crate carries **three** radix-2 DFT paths, kept distinct on purpose:
//! - [`serial::SerialRadix2Dft`] — vendored single-threaded `p3_dft::TwoAdicSubgroupDft` impl
//!   (Bowers G), for batch LDE / coset-LDE and univariate-poly interpolation.
//! - [`twiddles::TwiddleDft`] — cached twiddle-table in-place DIF/DIT, reused across many
//!   transforms of the same size (CPU Merkle / WHIR / stacked-reduction).
//! - upstream `p3_dft::Radix2Bowers` — the parallel (rayon) reference, used directly by the
//!   prismalinear eval-to-coeff paths in [`super::ple`]. Imported from `p3_dft`, not re-exported
//!   here, and intentionally left as-is.

pub mod serial;
pub mod twiddles;

pub use serial::*;
// `TwiddleDft` is semi-internal: public for out-of-crate device backends, not a stable API.
pub use twiddles::*;

#[cfg(test)]
mod tests {
    use super::{serial::SerialRadix2Dft, twiddles::TwiddleDft};
    use crate::config::koala_bear_poseidon2::F;
    use p3_dft::TwoAdicSubgroupDft;
    use p3_field::{PrimeCharacteristicRing, TwoAdicField};
    use p3_util::log2_strict_usize;
    use rand::{rngs::StdRng, RngExt, SeedableRng};

    /// Reference DFT: evaluate the polynomial `coeffs` at `omega^k`, `k = 0..n`.
    fn naive_dft(coeffs: &[F]) -> Vec<F> {
        let n = coeffs.len();
        let omega = F::two_adic_generator(log2_strict_usize(n));
        (0..n)
            .map(|k| {
                let point = omega.exp_u64(k as u64);
                let mut acc = F::ZERO;
                let mut p = F::ONE;
                for &c in coeffs {
                    acc += c * p;
                    p *= point;
                }
                acc
            })
            .collect()
    }

    #[test]
    fn serial_dft_matches_naive_and_round_trips() {
        let mut rng = StdRng::seed_from_u64(0);
        let dft = SerialRadix2Dft;
        for log_n in 0..=8 {
            let n = 1usize << log_n;
            let coeffs: Vec<F> = (0..n).map(|_| F::from_u32(rng.random())).collect();
            assert_eq!(dft.dft(coeffs.clone()), naive_dft(&coeffs), "log_n={log_n}");
            let round_trip = dft.idft(dft.dft(coeffs.clone()));
            assert_eq!(round_trip, coeffs, "idft(dft(x)) != x, log_n={log_n}");
        }
    }

    #[test]
    fn twiddle_dft_matches_serial_and_round_trips() {
        let mut rng = StdRng::seed_from_u64(1);
        let serial = SerialRadix2Dft;
        for log_n in 0..=8 {
            let n = 1usize << log_n;
            let coeffs: Vec<F> = (0..n).map(|_| F::from_u32(rng.random())).collect();
            let tw = TwiddleDft::new(log_n);

            // The cached-twiddle DFT must agree with the serial Bowers DFT (cross-check).
            let mut buf = coeffs.clone();
            tw.dft_inplace(&mut buf);
            assert_eq!(
                buf,
                serial.dft(coeffs.clone()),
                "twiddle vs serial, log_n={log_n}"
            );

            // idft_inplace(dft_inplace(x)) == x
            let mut rt = coeffs.clone();
            tw.dft_inplace(&mut rt);
            tw.idft_inplace(&mut rt);
            assert_eq!(
                rt, coeffs,
                "idft_inplace(dft_inplace(x)) != x, log_n={log_n}"
            );
        }
    }
}
