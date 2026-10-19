//! Serial (non-rayon) batch multiplicative inverse via Montgomery's trick.
//!
//! Adapted from `p3-field`'s `batch_inverse` to drop the rayon dependency.

use p3_field::{Field, FieldArray, PackedValue, PrimeCharacteristicRing};
use tracing::instrument;

/// Batch multiplicative inverses with Montgomery's trick
/// This is Montgomery's trick. At a high level, we invert the product of the given field
/// elements, then derive the individual inverses from that via multiplication.
///
/// The usual Montgomery trick involves calculating an array of cumulative products,
/// resulting in a long dependency chain. To increase instruction-level parallelism, we
/// compute WIDTH separate cumulative product arrays that only meet at the end.
///
/// # Panics
/// This will panic if any of the inputs is zero.
#[instrument(level = "debug", skip_all)]
pub fn batch_multiplicative_inverse_serial<F: Field>(x: &[F]) -> Vec<F> {
    let n = x.len();
    let mut result = F::zero_vec(n);

    batch_multiplicative_inverse_helper(x, &mut result);

    result
}

/// Like `batch_multiplicative_inverse`, but writes the result to the given output buffer.
fn batch_multiplicative_inverse_helper<F: Field>(x: &[F], result: &mut [F]) {
    // Higher WIDTH increases instruction-level parallelism, but too high a value will cause us
    // to run out of registers.
    const WIDTH: usize = 4;

    let n = x.len();
    assert_eq!(result.len(), n);
    if !n.is_multiple_of(WIDTH) {
        // There isn't a very clean way to do this with FieldArray; for now just do it in serial.
        // Another simple (though suboptimal) workaround would be to make two separate calls, one
        // for the packed part and one for the remainder.
        return batch_multiplicative_inverse_general(x, result, |x| x.inverse());
    }

    let x_packed = FieldArray::<F, 4>::pack_slice(x);
    let result_packed = FieldArray::<F, 4>::pack_slice_mut(result);

    let inv = |x_packed: FieldArray<F, 4>| {
        let mut result = FieldArray::<F, 4>::default();
        batch_multiplicative_inverse_general(&x_packed.0, &mut result.0, |x| x.inverse());
        result
    };
    batch_multiplicative_inverse_general(x_packed, result_packed, inv);
}

/// A simple single-threaded implementation of Montgomery's trick. Since not all
/// `PrimeCharacteristicRing`s support inversion, this takes a custom inversion function.
pub(crate) fn batch_multiplicative_inverse_general<F, Inv>(x: &[F], result: &mut [F], inv: Inv)
where
    F: PrimeCharacteristicRing + Copy,
    Inv: Fn(F) -> F,
{
    let n = x.len();
    assert_eq!(result.len(), n);
    if n == 0 {
        return;
    }

    result[0] = F::ONE;
    for i in 1..n {
        result[i] = result[i - 1] * x[i - 1];
    }

    let product = result[n - 1] * x[n - 1];
    let mut inv = inv(product);

    for i in (0..n).rev() {
        result[i] *= inv;
        inv *= x[i];
    }
}

#[cfg(test)]
mod tests {
    use p3_field::{Field, PrimeCharacteristicRing};
    use p3_koala_bear::KoalaBear;

    use super::batch_multiplicative_inverse_serial;

    type F = KoalaBear;

    /// The batch inverse agrees with element-wise `Field::inverse` on both code paths — the packed
    /// `WIDTH`-multiple path (`len % 4 == 0`) and the general/remainder path (`len % 4 != 0`),
    /// including the empty slice.
    #[test]
    fn batch_inverse_matches_elementwise_inverse() {
        // Lengths hitting the packed path (8, 4), the remainder path (5, 3, 1) and the empty case.
        for len in [0usize, 1, 3, 4, 5, 8] {
            let xs: Vec<F> = (0..len).map(|i| F::from_usize(i + 1)).collect();
            let got = batch_multiplicative_inverse_serial(&xs);
            assert_eq!(got.len(), len);
            for (x, inv) in xs.iter().zip(&got) {
                assert_eq!(*inv, x.inverse(), "1/{x:?} mismatch at len {len}");
                assert_eq!(*x * *inv, F::ONE);
            }
        }
    }
}
