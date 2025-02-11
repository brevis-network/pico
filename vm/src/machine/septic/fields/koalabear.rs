use super::super::extension::SepticExtension;
use p3_field::{FieldAlgebra, FieldExtensionAlgebra};
use std::any::Any;

pub const TOP_BITS: usize = 7;

// z^7 + 2*z^6 + 2130706431 = 0
// x^7 = -2*x^6 - 2130706431
pub const EXT_COEFFS: [u32; 7] = [2, 0, 0, 0, 0, 0, 2130706431];

pub const Z_POW_P: [[u32; 7]; 7] = [
    [1, 1, 1, 1, 1, 1, 1],
    [
        249932420, 1507635516, 418400407, 1455931098, 1798331821, 219395913, 967671407,
    ],
    [
        420027540, 1057411591, 328132812, 217796077, 1147686967, 1432067604, 2087546270,
    ],
    [
        155884019, 654771568, 1636205984, 356126182, 599803706, 1696590466, 544132138,
    ],
    [
        669140182, 1883835916, 1430461478, 90835923, 92515503, 1561748253, 731963140,
    ],
    [
        231339423, 721642200, 1349944512, 1333756424, 1546547860, 1347939566, 666560000,
    ],
    [
        1131530000, 1837697502, 1326477062, 1364068631, 2109424084, 938605660, 629063286,
    ],
];

pub const Z_POW_P2: [[u32; 7]; 7] = [
    [1, 1, 1, 1, 1, 1, 1],
    [
        1803832602, 782887483, 1586804983, 1965167389, 1856929877, 372963244, 2026350969,
    ],
    [
        1591818588, 2076120805, 75603410, 247345090, 210033395, 1121012471, 358379851,
    ],
    [
        1697524332, 1219662271, 929458421, 401687366, 1373501145, 2060913949, 1130910364,
    ],
    [
        2068736911, 1813198575, 2101550341, 1947105710, 375042771, 698819630, 697469116,
    ],
    [
        39587578, 2024152476, 10976667, 1358333694, 413844500, 1977602137, 1978969975,
    ],
    [
        934181796, 1083823847, 1953070371, 1649242345, 903686288, 518936657, 648589698,
    ],
];

pub const CURVE_WITNESS_DUMMY_POINT_X: [u32; 7] = [
    546938927, 1509379008, 230266369, 757535510, 1712632789, 595785706, 1272488796,
];

pub const CURVE_WITNESS_DUMMY_POINT_Y: [u32; 7] = [
    585969973, 1703627363, 1435009742, 276846985, 544259301, 968414589, 67451462,
];

pub const CURVE_CUMULATIVE_SUM_START_X: [u32; 7] = [
    1282297783, 884251427, 1390186945, 132125341, 714101915, 511950180, 1023825808,
];

pub const CURVE_CUMULATIVE_SUM_START_Y: [u32; 7] = [
    1188614483, 1724750090, 1138584195, 1198897381, 1166527600, 679696589, 864127960,
];

pub const DIGEST_SUM_START_X: [u32; 7] = [
    768775897, 621980907, 117134017, 851590599, 134734730, 1319921660, 22260775,
];

pub const DIGEST_SUM_START_Y: [u32; 7] = [
    586653771, 814963722, 522795598, 1049960103, 322151949, 1708114902, 491320682,
];

// y^2 = x^3 + 2x + 611*z^5
pub fn curve_formula<F: Any + FieldAlgebra>(x: SepticExtension<F>) -> SepticExtension<F> {
    x.cube()
        + x * F::TWO
        + SepticExtension::from_base_slice(&[
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::from_canonical_u32(611),
            F::ZERO,
        ])
}
