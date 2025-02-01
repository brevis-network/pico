pub mod babybear;
mod dummy;
pub mod koalabear;
pub mod mersenne31;

use super::{SepticCurve, SepticExtension};
use crate::machine::field::same_field;
use p3_baby_bear::BabyBear;
use p3_field::{Field, FieldAlgebra};
use p3_koala_bear::KoalaBear;
use p3_mersenne_31::Mersenne31;
use std::any::Any;

/// Field trait for adapting Septic Curve with multiple fields
pub trait FieldSepticCurve: Sized {
    /// Extension generator
    const EXT_GENERATOR: [Self; 7];

    /// Field top bits
    const TOP_BITS: usize;

    /// Exntesion coefficients
    const EXT_COEFFS: [u32; 7];

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

impl<F: Any + FieldAlgebra> FieldSepticCurve for F {
    const EXT_GENERATOR: [Self; 7] = ext_generator::<F>();
    const TOP_BITS: usize = top_bits::<F>();
    const EXT_COEFFS: [u32; 7] = ext_coeffs::<F>();
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
        if same_field::<F, BabyBear, 4>() || same_field::<F, KoalaBear, 4>() {
            let mut n_iter = n;
            let mut n_power = n;
            for i in 1..30 {
                n_iter *= n_iter;
                if i >= 30 - F::TOP_BITS {
                    n_power *= n_iter;
                }
            }

            n_power
        } else if same_field::<F, Mersenne31, 3>() {
            let mut n_power = n;
            for _ in 1..31 {
                n_power *= n_power;
            }
            n_power
        } else {
            panic!("Unsupport field type");
        }
    }

    fn curve_slope(point: &SepticCurve<F>) -> SepticExtension<F>
    where
        F: Field,
    {
        if same_field::<F, BabyBear, 4>() || same_field::<F, KoalaBear, 4>() {
            (point.x * point.x * F::from_canonical_u8(3) + F::TWO) / (point.y * F::TWO)
        } else if same_field::<F, Mersenne31, 3>() {
            (point.x * point.x * F::from_canonical_u8(3) - F::from_canonical_u32(3))
                / (point.y * F::TWO)
        } else {
            panic!("Unsupported field type");
        }
    }
}

const fn ext_generator<F: FieldAlgebra + 'static>() -> [F; 7] {
    if same_field::<F, BabyBear, 4>() {
        // BabyBear extension generator
        [F::TWO, F::ONE, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO]
    } else if same_field::<F, KoalaBear, 4>() {
        // KoalaBear exntesion generator
        [F::FIVE, F::ONE, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO]
    } else if same_field::<F, Mersenne31, 3>() {
        // Mersenne31 extension generator
        [F::TWO, F::ONE, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO]
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

const fn top_bits<F: FieldAlgebra + 'static>() -> usize {
    if same_field::<F, BabyBear, 4>() {
        babybear::TOP_BITS
    } else if same_field::<F, KoalaBear, 4>() {
        koalabear::TOP_BITS
    } else if same_field::<F, Mersenne31, 3>() {
        mersenne31::TOP_BITS
    } else {
        dummy::TOP_BITS
    }
}

const fn ext_coeffs<F: FieldAlgebra + 'static>() -> [u32; 7] {
    if same_field::<F, BabyBear, 4>() {
        babybear::EXT_COEFFS
    } else if same_field::<F, KoalaBear, 4>() {
        koalabear::EXT_COEFFS
    } else if same_field::<F, Mersenne31, 3>() {
        mersenne31::EXT_COEFFS
    } else {
        dummy::EXT_COEFFS
    }
}

const fn z_pow_p<F: FieldAlgebra + 'static>() -> [[u32; 7]; 7] {
    if same_field::<F, BabyBear, 4>() {
        babybear::Z_POW_P
    } else if same_field::<F, KoalaBear, 4>() {
        koalabear::Z_POW_P
    } else if same_field::<F, Mersenne31, 3>() {
        mersenne31::Z_POW_P
    } else {
        dummy::Z_POW_P
    }
}

const fn z_pow_p2<F: FieldAlgebra + 'static>() -> [[u32; 7]; 7] {
    if same_field::<F, BabyBear, 4>() {
        babybear::Z_POW_P2
    } else if same_field::<F, KoalaBear, 4>() {
        koalabear::Z_POW_P2
    } else if same_field::<F, Mersenne31, 3>() {
        mersenne31::Z_POW_P2
    } else {
        dummy::Z_POW_P2
    }
}

const fn curve_witness_dummy_point_x<F: FieldAlgebra + 'static>() -> [u32; 7] {
    if same_field::<F, BabyBear, 4>() {
        babybear::CURVE_WITNESS_DUMMY_POINT_X
    } else if same_field::<F, KoalaBear, 4>() {
        koalabear::CURVE_WITNESS_DUMMY_POINT_X
    } else if same_field::<F, Mersenne31, 3>() {
        mersenne31::CURVE_WITNESS_DUMMY_POINT_X
    } else {
        dummy::CURVE_WITNESS_DUMMY_POINT_X
    }
}

const fn curve_witness_dummy_point_y<F: FieldAlgebra + 'static>() -> [u32; 7] {
    if same_field::<F, BabyBear, 4>() {
        babybear::CURVE_WITNESS_DUMMY_POINT_Y
    } else if same_field::<F, KoalaBear, 4>() {
        koalabear::CURVE_WITNESS_DUMMY_POINT_Y
    } else if same_field::<F, Mersenne31, 3>() {
        mersenne31::CURVE_WITNESS_DUMMY_POINT_Y
    } else {
        dummy::CURVE_WITNESS_DUMMY_POINT_Y
    }
}

const fn curve_cumulative_sum_start_x<F: FieldAlgebra + 'static>() -> [u32; 7] {
    if same_field::<F, BabyBear, 4>() {
        babybear::CURVE_CUMULATIVE_SUM_START_X
    } else if same_field::<F, KoalaBear, 4>() {
        koalabear::CURVE_CUMULATIVE_SUM_START_X
    } else if same_field::<F, Mersenne31, 3>() {
        mersenne31::CURVE_CUMULATIVE_SUM_START_X
    } else {
        dummy::CURVE_CUMULATIVE_SUM_START_X
    }
}

const fn curve_cumulative_sum_start_y<F: FieldAlgebra + 'static>() -> [u32; 7] {
    if same_field::<F, BabyBear, 4>() {
        babybear::CURVE_CUMULATIVE_SUM_START_Y
    } else if same_field::<F, KoalaBear, 4>() {
        koalabear::CURVE_CUMULATIVE_SUM_START_Y
    } else if same_field::<F, Mersenne31, 3>() {
        mersenne31::CURVE_CUMULATIVE_SUM_START_Y
    } else {
        dummy::CURVE_CUMULATIVE_SUM_START_Y
    }
}

const fn digest_sum_start_x<F: FieldAlgebra + 'static>() -> [u32; 7] {
    if same_field::<F, BabyBear, 4>() {
        babybear::DIGEST_SUM_START_X
    } else if same_field::<F, KoalaBear, 4>() {
        koalabear::DIGEST_SUM_START_X
    } else if same_field::<F, Mersenne31, 3>() {
        mersenne31::DIGEST_SUM_START_X
    } else {
        dummy::DIGEST_SUM_START_X
    }
}

const fn digest_sum_start_y<F: FieldAlgebra + 'static>() -> [u32; 7] {
    if same_field::<F, BabyBear, 4>() {
        babybear::DIGEST_SUM_START_Y
    } else if same_field::<F, KoalaBear, 4>() {
        koalabear::DIGEST_SUM_START_Y
    } else if same_field::<F, Mersenne31, 3>() {
        mersenne31::DIGEST_SUM_START_Y
    } else {
        dummy::DIGEST_SUM_START_Y
    }
}
