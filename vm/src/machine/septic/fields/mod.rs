mod babybear;
mod dummy;
mod koalabear;

use crate::machine::field::same_field;
use p3_baby_bear::BabyBear;
use p3_field::FieldAlgebra;
use p3_koala_bear::KoalaBear;
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
}

const fn ext_generator<F: FieldAlgebra + 'static>() -> [F; 7] {
    if same_field::<F, BabyBear>() {
        // BabyBear extension generator
        [F::TWO, F::ONE, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO]
    } else if same_field::<F, KoalaBear>() {
        // KoalaBear exntesion generator
        [F::FOUR, F::ONE, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO]
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
    if same_field::<F, BabyBear>() {
        babybear::TOP_BITS
    } else if same_field::<F, KoalaBear>() {
        koalabear::TOP_BITS
    } else {
        dummy::TOP_BITS
    }
}

const fn ext_coeffs<F: FieldAlgebra + 'static>() -> [u32; 7] {
    if same_field::<F, BabyBear>() {
        babybear::EXT_COEFFS
    } else if same_field::<F, KoalaBear>() {
        koalabear::EXT_COEFFS
    } else {
        dummy::EXT_COEFFS
    }
}

const fn z_pow_p<F: FieldAlgebra + 'static>() -> [[u32; 7]; 7] {
    if same_field::<F, BabyBear>() {
        babybear::Z_POW_P
    } else if same_field::<F, KoalaBear>() {
        koalabear::Z_POW_P
    } else {
        dummy::Z_POW_P
    }
}

const fn z_pow_p2<F: FieldAlgebra + 'static>() -> [[u32; 7]; 7] {
    if same_field::<F, BabyBear>() {
        babybear::Z_POW_P2
    } else if same_field::<F, KoalaBear>() {
        koalabear::Z_POW_P2
    } else {
        dummy::Z_POW_P2
    }
}

const fn curve_witness_dummy_point_x<F: FieldAlgebra + 'static>() -> [u32; 7] {
    if same_field::<F, BabyBear>() {
        babybear::CURVE_WITNESS_DUMMY_POINT_X
    } else if same_field::<F, KoalaBear>() {
        koalabear::CURVE_WITNESS_DUMMY_POINT_X
    } else {
        dummy::CURVE_WITNESS_DUMMY_POINT_X
    }
}

const fn curve_witness_dummy_point_y<F: FieldAlgebra + 'static>() -> [u32; 7] {
    if same_field::<F, BabyBear>() {
        babybear::CURVE_WITNESS_DUMMY_POINT_Y
    } else if same_field::<F, KoalaBear>() {
        koalabear::CURVE_WITNESS_DUMMY_POINT_Y
    } else {
        dummy::CURVE_WITNESS_DUMMY_POINT_Y
    }
}

const fn curve_cumulative_sum_start_x<F: FieldAlgebra + 'static>() -> [u32; 7] {
    if same_field::<F, BabyBear>() {
        babybear::CURVE_CUMULATIVE_SUM_START_X
    } else if same_field::<F, KoalaBear>() {
        koalabear::CURVE_CUMULATIVE_SUM_START_X
    } else {
        dummy::CURVE_CUMULATIVE_SUM_START_X
    }
}

const fn curve_cumulative_sum_start_y<F: FieldAlgebra + 'static>() -> [u32; 7] {
    if same_field::<F, BabyBear>() {
        babybear::CURVE_CUMULATIVE_SUM_START_Y
    } else if same_field::<F, KoalaBear>() {
        koalabear::CURVE_CUMULATIVE_SUM_START_Y
    } else {
        dummy::CURVE_CUMULATIVE_SUM_START_Y
    }
}

const fn digest_sum_start_x<F: FieldAlgebra + 'static>() -> [u32; 7] {
    if same_field::<F, BabyBear>() {
        babybear::DIGEST_SUM_START_X
    } else if same_field::<F, KoalaBear>() {
        koalabear::DIGEST_SUM_START_X
    } else {
        dummy::DIGEST_SUM_START_X
    }
}

const fn digest_sum_start_y<F: FieldAlgebra + 'static>() -> [u32; 7] {
    if same_field::<F, BabyBear>() {
        babybear::DIGEST_SUM_START_Y
    } else if same_field::<F, KoalaBear>() {
        koalabear::DIGEST_SUM_START_Y
    } else {
        dummy::DIGEST_SUM_START_Y
    }
}
