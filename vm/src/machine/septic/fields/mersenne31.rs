use super::super::extension::SepticExtension;
use p3_field::{FieldAlgebra, FieldExtensionAlgebra};
use std::any::Any;

pub const TOP_BITS: usize = 30;

// x^7 - 3 = 0
// x^7 = 3
pub const EXT_COEFFS: [u32; 7] = [3, 0, 0, 0, 0, 0, 0];

pub const Z_POW_P: [[u32; 7]; 7] = [
    [1, 1, 1, 1, 1, 1, 1],
    [0, 1752599774, 0, 0, 0, 0, 0],
    [0, 0, 1600955193, 0, 0, 0, 0],
    [0, 0, 0, 1537170743, 0, 0, 0],
    [0, 0, 0, 0, 894255406, 0, 0],
    [0, 0, 0, 0, 0, 1599590586, 0],
    [0, 0, 0, 0, 0, 0, 1205362885],
];

pub const Z_POW_P2: [[u32; 7]; 7] = [
    [1, 1, 1, 1, 1, 1, 1],
    [0, 1600955193, 0, 0, 0, 0, 0],
    [0, 0, 894255406, 0, 0, 0, 0],
    [0, 0, 0, 1205362885, 0, 0, 0],
    [0, 0, 0, 0, 1752599774, 0, 0],
    [0, 0, 0, 0, 0, 1537170743, 0],
    [0, 0, 0, 0, 0, 0, 1599590586],
];

pub const CURVE_WITNESS_DUMMY_POINT_X: [u32; 7] = [
    1887983713, 232764464, 2044093728, 2072363284, 1917093950, 1756290126, 915837828,
];

pub const CURVE_WITNESS_DUMMY_POINT_Y: [u32; 7] = [
    2024725728, 1538238608, 1683006154, 191691368, 175558761, 1303059383, 85695614,
];

pub const CURVE_CUMULATIVE_SUM_START_X: [u32; 7] = [
    386388864, 338751050, 795063093, 2043791572, 872442338, 1653665459, 1125176854,
];

pub const CURVE_CUMULATIVE_SUM_START_Y: [u32; 7] = [
    761023576, 1763771681, 1927675268, 503929669, 2086476997, 506598583, 845355171,
];

pub const DIGEST_SUM_START_X: [u32; 7] = [
    1443485196, 1194429389, 1901403950, 483995622, 2015246587, 349369981, 844650080,
];

pub const DIGEST_SUM_START_Y: [u32; 7] = [
    916190192, 901932536, 501889474, 1142803471, 1398101008, 1630702259, 658142343,
];

// y^2 = x^3 - 3x + 1134*z^5
pub fn curve_formula<F: Any + FieldAlgebra>(x: SepticExtension<F>) -> SepticExtension<F> {
    x.cube() - x * F::from_canonical_u32(3)
        + SepticExtension::from_base_slice(&[
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::from_canonical_u32(1134),
            F::ZERO,
        ])
}
