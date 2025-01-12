//! A septic extension with an irreducible polynomial
//! f = z^7 + z^6 + 2130706421*z^5 + 2130706426*z^4 + 28*z^3 + 14*z^2 + 2130706424*z + 1

use super::super::SepticExtension;
use p3_field::FieldAlgebra;

impl<F: FieldAlgebra> SepticExtension<F> {
    pub const EXT_GENERATOR: Self =
        SepticExtension([F::FOUR, F::ONE, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO]);
}

pub const F_ORDER: u32 = 2130706433_u32;

pub const TOP_BITS: usize = 7;

// z^7  + z^6 + 2130706421*z^5 + 2130706426*z^4 + 28*z^3 + 14*z^2 + 2130706424*z + 1 = 0
// z^7  = -z^6 - 2130706421*z^5 - 2130706426*z^4 - 28*z^3 - 14*z^2 - 2130706424*z - 1
pub const EXT_COEFFS: [u32; 7] = [2130706432, 9, 2130706419, 2130706405, 7, 12, 2130706432];

pub const Z_POW_P: [[u32; 7]; 7] = [
    [1, 1, 1, 1, 1, 1, 1],
    [
        1253356728, 376006997, 376006995, 877349718, 877349718, 1002685379, 1629363742,
    ],
    [
        2005370743, 1880035183, 1880035205, 125335626, 125335619, 752014041, 1754699420,
    ],
    [
        752014106, 1504027713, 1504027621, 1378692572, 1378692603, 1880035066, 125335655,
    ],
    [2130706178, 1253, 1588, 2130705823, 2130705708, 77, 62],
    [
        1253357605, 376002740, 376001582, 877351790, 877352188, 1002685117, 1629363531,
    ],
    [
        2005367778, 1880049526, 1880053460, 125328647, 125327289, 752014923, 1754700132,
    ],
];

pub const Z_POW_P2: [[u32; 7]; 7] = [
    [1, 1, 1, 1, 1, 1, 1],
    [
        1754699406, 1378692439, 1378692444, 376006997, 376006997, 125335675, 1002685382,
    ],
    [2130706421, 60, 100, 2130706405, 2130706386, 4, 4],
    [
        877349657, 1754699666, 1754699652, 1253356600, 1253356622, 1128021067, 501342699,
    ],
    [2130706322, 502, 919, 2130706199, 2130705998, 35, 37],
    [
        1504027702, 877351612, 877351193, 626677403, 626677738, 1629363846, 250671399,
    ],
    [2130705595, 3603, 7737, 2130704788, 2130702725, 269, 315],
];

/// The x-coordinate for a curve point used as a witness for padding interactions.
pub const CURVE_WITNESS_DUMMY_POINT_X: [u32; 7] = [
    580628972, 570994498, 1048581654, 197862729, 1266783553, 1996501878, 1732724354,
];

/// The y-coordinate for a curve point used as a witness for padding interactions.
pub const CURVE_WITNESS_DUMMY_POINT_Y: [u32; 7] = [
    1484927732, 389107134, 19585171, 1663839292, 810692232, 1747846785, 312748698,
];

/// The x-coordinate for a curve point used as a starting cumulative sum for global permutation trace generation.
pub const CURVE_CUMULATIVE_SUM_START_X: [u32; 7] = [
    1999306532, 467785808, 1385486227, 641872107, 871901548, 1171633279, 1975150563,
];

/// The y-coordinate for a curve point used as a starting cumulative sum for global permutation trace generation.
pub const CURVE_CUMULATIVE_SUM_START_Y: [u32; 7] = [
    1882251454, 1822622415, 820669592, 1001895671, 1625010158, 602262774, 462733968,
];

/// The x-coordinate for a curve point used as a starting random point for digest accumulation.
pub const DIGEST_SUM_START_X: [u32; 7] = [
    302351816, 1189065052, 1534134752, 1004694753, 1419555682, 1259920004, 742277792,
];

/// The y-coordinate for a curve point used as a starting random point for digest accumulation.
pub const DIGEST_SUM_START_Y: [u32; 7] = [
    337628382, 1503269464, 1028656526, 427999289, 1539447949, 1957709106, 246949828,
];
