use p3_field::{
    extension::QuinticTrinomialExtensionField, BasedVectorSpace, Field, PrimeCharacteristicRing,
    PrimeField32,
};
use p3_koala_bear::KoalaBear;

/// KoalaBear's challenge field, `F_p[X]/(X^5 + X^2 - 1)`: mle-core's `EF`, and the extension the
/// gnark circuit computes in.
type Quintic = QuinticTrinomialExtensionField<KoalaBear>;

/// The number of coefficients of a `Quintic`, as the Go side's `ExtDegree`.
const DEGREE: usize = 5;

/// Writes the inverse of the element whose `DEGREE` coefficients, lowest first, are at `input` to
/// the `DEGREE` words at `output`. Zero has no inverse and gives zero, which the circuit's check
/// that the product is one rejects, rather than a panic that would abort the Go process.
///
/// # Safety
///
/// `input` and `output` each point to `DEGREE` `u32`s.
#[no_mangle]
pub unsafe extern "C" fn koalabearquinticinv(input: *const u32, output: *mut u32) {
    let (input, output) = unsafe {
        (
            std::slice::from_raw_parts(input, DEGREE),
            std::slice::from_raw_parts_mut(output, DEGREE),
        )
    };
    let coefficients: Vec<KoalaBear> = input.iter().map(|&c| KoalaBear::from_u32(c)).collect();
    let inverse = Quintic::from_basis_coefficients_slice(&coefficients)
        .expect("DEGREE coefficients")
        .try_inverse()
        .unwrap_or(Quintic::ZERO);
    let inverse: &[KoalaBear] = inverse.as_basis_coefficients_slice();
    for (out, c) in output.iter_mut().zip(inverse) {
        *out = c.as_canonical_u32();
    }
}

#[no_mangle]
pub extern "C" fn koalabearinv(a: u32) -> u32 {
    let a = KoalaBear::from_u32(a);
    a.inverse().as_canonical_u32()
}

#[cfg(test)]
pub mod test {
    use super::{koalabearquinticinv, Quintic, DEGREE};
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
    use p3_koala_bear::KoalaBear;

    fn element(coefficients: [u32; DEGREE]) -> Quintic {
        Quintic::from_basis_coefficients_slice(&coefficients.map(KoalaBear::from_u32))
            .expect("DEGREE coefficients")
    }

    fn inverse(coefficients: [u32; DEGREE]) -> [u32; DEGREE] {
        let mut out = [u32::MAX; DEGREE];
        unsafe { koalabearquinticinv(coefficients.as_ptr(), out.as_mut_ptr()) };
        out
    }

    #[test]
    fn an_element_times_its_inverse_is_one() {
        for coefficients in [
            [1, 0, 0, 0, 0],
            [1, 2, 3, 4, 5],
            [0, 0, 0, 0, 1],
            [2130706432, 0, 7, 0, 2130706432],
            [123456789, 987654321, 55555, 2130706400, 31],
        ] {
            assert_eq!(
                element(coefficients) * element(inverse(coefficients)),
                Quintic::ONE,
                "{coefficients:?}"
            );
        }
    }

    #[test]
    fn zero_gives_zero() {
        assert_eq!(inverse([0; DEGREE]), [0; DEGREE]);
    }
}
