mod dummy;
pub mod koalabear;

use super::{SepticCurve, SepticExtension};
use crate::machine::field::{same_field, same_type};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use std::any::Any;

/// Field trait for adapting Septic Curve to the base field
pub trait FieldSepticCurve: Sized {
    /// Field top bits
    const TOP_BITS: usize;

    /// Exntesion coefficients
    const EXT_COEFFS: [u32; 7];

    /// [`EXT_COEFFS`](Self::EXT_COEFFS) in balanced form: the representative of each coefficient
    /// in `(-p/2, p/2]`, so `z^7 = sum_k EXT_COEFFS_SIGNED[k] z^k` still holds in the field.
    /// Requires `|EXT_COEFFS_SIGNED[k]| <= 127` for every registered field; a coefficient outside
    /// `i8` makes `ext_coeffs_signed` fail const evaluation when that field instantiates it.
    const EXT_COEFFS_SIGNED: [i8; 7];

    /// z^p
    const Z_POW_P: [[u32; 7]; 7];

    /// z^p^2
    const Z_POW_P2: [[u32; 7]; 7];

    /// X-coordinate for a curve point used as a witness for padding interactions
    const CURVE_WITNESS_DUMMY_POINT_X: [u32; 7];

    /// Y-coordinate for a curve point used as a witness for padding interactions
    const CURVE_WITNESS_DUMMY_POINT_Y: [u32; 7];

    /// X-coordinate for a curve point used as a starting cumulative sum for global permutation trace generation
    const CURVE_CUMULATIVE_SUM_START_X: [u32; 7];

    /// Y-coordinate for a curve point used as a starting cumulative sum for global permutation trace generation
    const CURVE_CUMULATIVE_SUM_START_Y: [u32; 7];

    /// X-coordinate for a curve point used as a starting random point for digest accumulation
    const DIGEST_SUM_START_X: [u32; 7];

    /// Y-coordinate for a curve point used as a starting random point for digest accumulation
    const DIGEST_SUM_START_Y: [u32; 7];

    fn n_power(n: SepticExtension<Self>) -> SepticExtension<Self>
    where
        Self: Field;

    fn curve_slope(point: &SepticCurve<Self>) -> SepticExtension<Self>
    where
        Self: Field;
}

impl<F: Any + PrimeCharacteristicRing> FieldSepticCurve for F {
    const TOP_BITS: usize = top_bits::<F>();
    const EXT_COEFFS: [u32; 7] = ext_coeffs::<F>();
    const EXT_COEFFS_SIGNED: [i8; 7] = ext_coeffs_signed::<F>();
    const Z_POW_P: [[u32; 7]; 7] = z_pow_p::<F>();
    const Z_POW_P2: [[u32; 7]; 7] = z_pow_p2::<F>();
    const CURVE_WITNESS_DUMMY_POINT_X: [u32; 7] = curve_witness_dummy_point_x::<F>();
    const CURVE_WITNESS_DUMMY_POINT_Y: [u32; 7] = curve_witness_dummy_point_y::<F>();
    const CURVE_CUMULATIVE_SUM_START_X: [u32; 7] = curve_cumulative_sum_start_x::<F>();
    const CURVE_CUMULATIVE_SUM_START_Y: [u32; 7] = curve_cumulative_sum_start_y::<F>();
    const DIGEST_SUM_START_X: [u32; 7] = digest_sum_start_x::<F>();
    const DIGEST_SUM_START_Y: [u32; 7] = digest_sum_start_y::<F>();

    fn n_power(n: SepticExtension<F>) -> SepticExtension<F>
    where
        F: Field,
    {
        if same_field::<F, KoalaBear, 4>() {
            let mut n_iter = n;
            let mut n_power = n;
            for i in 1..30 {
                n_iter *= n_iter;
                if i >= 30 - F::TOP_BITS {
                    n_power *= n_iter;
                }
            }

            n_power
        } else {
            panic!("Unsupported field type");
        }
    }

    fn curve_slope(point: &SepticCurve<F>) -> SepticExtension<F>
    where
        F: Field,
    {
        if same_field::<F, KoalaBear, 4>() {
            (point.x * point.x * F::from_u8(3) + F::TWO) / (point.y * F::TWO)
        } else {
            panic!("Unsupported field type");
        }
    }
}

/// Generator of the septic extension's multiplicative group, as `Field::GENERATOR` for
/// `SepticExtension<F>`. Only instantiated for the concrete base fields (the `Field` bound keeps
/// the symbolic / packed aliases that `same_field` also accepts out).
pub(super) const fn ext_generator<F: Field + 'static>() -> [F; 7] {
    if same_field::<F, KoalaBear, 4>() {
        // KoalaBear exntesion generator
        [
            koalabear_five::<F>(),
            F::ONE,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ]
    } else {
        // Dummy extension generator
        [
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ]
    }
}

/// `5 ∈ F` for the KoalaBear branch of [`ext_generator`]. Plonky3 0.5 dropped the `FIVE`
/// constant and `from_u32` is not `const`, so the value is built as a `KoalaBear` and re-typed.
/// The exact-type check makes any other instantiation (the packed / binomial / symbolic aliases
/// `same_field` accepts, or a stray field) a compile-time error instead of a silent misread.
const fn koalabear_five<F: 'static>() -> F {
    assert!(
        same_type::<F, KoalaBear>(),
        "KoalaBear septic generator requested for a non-KoalaBear coefficient type"
    );
    // SAFETY: `F` is exactly `KoalaBear` (checked above), so the bit pattern of a KoalaBear
    // element is a valid `F`.
    unsafe { std::mem::transmute_copy::<KoalaBear, F>(&KoalaBear::new(5)) }
}

const fn top_bits<F: PrimeCharacteristicRing + 'static>() -> usize {
    if same_field::<F, KoalaBear, 4>() {
        koalabear::TOP_BITS
    } else {
        dummy::TOP_BITS
    }
}

const fn ext_coeffs<F: PrimeCharacteristicRing + 'static>() -> [u32; 7] {
    if same_field::<F, KoalaBear, 4>() {
        koalabear::EXT_COEFFS
    } else {
        dummy::EXT_COEFFS
    }
}

/// Balanced form of [`ext_coeffs`], derived from the same dispatch and the branch's modulus so
/// the two tables cannot drift: a field is registered once, in both functions' `if` chains, and
/// the signed table follows from its unsigned one.
const fn ext_coeffs_signed<F: PrimeCharacteristicRing + 'static>() -> [i8; 7] {
    if same_field::<F, KoalaBear, 4>() {
        to_signed(koalabear::EXT_COEFFS, KoalaBear::ORDER_U32)
    } else {
        // The dummy fallback has no field and no modulus; its coefficients are all zero, which is
        // its own balanced representative under any modulus.
        to_signed(dummy::EXT_COEFFS, 0)
    }
}

/// `c - p` for `c > p / 2`, `c` otherwise. Panics at compile time when a balanced representative
/// does not fit in an `i8`.
const fn to_signed(coeffs: [u32; 7], p: u32) -> [i8; 7] {
    let mut signed = [0i8; 7];
    let mut k = 0;
    while k < 7 {
        let balanced = if coeffs[k] > p / 2 {
            coeffs[k] as i64 - p as i64
        } else {
            coeffs[k] as i64
        };
        assert!(
            balanced >= i8::MIN as i64 && balanced <= i8::MAX as i64,
            "septic reduction coefficient does not fit in an i8"
        );
        signed[k] = balanced as i8;
        k += 1;
    }
    signed
}

const fn z_pow_p<F: PrimeCharacteristicRing + 'static>() -> [[u32; 7]; 7] {
    if same_field::<F, KoalaBear, 4>() {
        koalabear::Z_POW_P
    } else {
        dummy::Z_POW_P
    }
}

const fn z_pow_p2<F: PrimeCharacteristicRing + 'static>() -> [[u32; 7]; 7] {
    if same_field::<F, KoalaBear, 4>() {
        koalabear::Z_POW_P2
    } else {
        dummy::Z_POW_P2
    }
}

const fn curve_witness_dummy_point_x<F: PrimeCharacteristicRing + 'static>() -> [u32; 7] {
    if same_field::<F, KoalaBear, 4>() {
        koalabear::CURVE_WITNESS_DUMMY_POINT_X
    } else {
        dummy::CURVE_WITNESS_DUMMY_POINT_X
    }
}

const fn curve_witness_dummy_point_y<F: PrimeCharacteristicRing + 'static>() -> [u32; 7] {
    if same_field::<F, KoalaBear, 4>() {
        koalabear::CURVE_WITNESS_DUMMY_POINT_Y
    } else {
        dummy::CURVE_WITNESS_DUMMY_POINT_Y
    }
}

const fn curve_cumulative_sum_start_x<F: PrimeCharacteristicRing + 'static>() -> [u32; 7] {
    if same_field::<F, KoalaBear, 4>() {
        koalabear::CURVE_CUMULATIVE_SUM_START_X
    } else {
        dummy::CURVE_CUMULATIVE_SUM_START_X
    }
}

const fn curve_cumulative_sum_start_y<F: PrimeCharacteristicRing + 'static>() -> [u32; 7] {
    if same_field::<F, KoalaBear, 4>() {
        koalabear::CURVE_CUMULATIVE_SUM_START_Y
    } else {
        dummy::CURVE_CUMULATIVE_SUM_START_Y
    }
}

const fn digest_sum_start_x<F: PrimeCharacteristicRing + 'static>() -> [u32; 7] {
    if same_field::<F, KoalaBear, 4>() {
        koalabear::DIGEST_SUM_START_X
    } else {
        dummy::DIGEST_SUM_START_X
    }
}

const fn digest_sum_start_y<F: PrimeCharacteristicRing + 'static>() -> [u32; 7] {
    if same_field::<F, KoalaBear, 4>() {
        koalabear::DIGEST_SUM_START_Y
    } else {
        dummy::DIGEST_SUM_START_Y
    }
}
