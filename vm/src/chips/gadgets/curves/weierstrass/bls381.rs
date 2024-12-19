use crate::chips::gadgets::{
    curves::{
        weierstrass::{SwCurve, WeierstrassParameters},
        AffinePoint, CurveType, EllipticCurve, EllipticCurveParameters,
    },
    utils::field_params::{FieldParameters, FieldType, FpOpField, NumLimbs},
};
use amcl::bls381::{big::Big, bls381::utils::deserialize_g1, fp::FP};
use hybrid_array::{
    typenum::{U48, U94},
    Array,
};
use num::{BigUint, Num, Zero};
use serde::{Deserialize, Serialize};

// Serialization flags
const COMPRESION_FLAG: u8 = 0b_1000_0000;
const Y_IS_ODD_FLAG: u8 = 0b_0010_0000;

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Bls12381 curve parameter
pub struct Bls12381Parameters;

pub type Bls12381 = SwCurve<Bls12381Parameters>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Bls12381 base field parameter
pub struct Bls381BaseField;

impl FieldParameters for Bls381BaseField {
    // The modulus has been taken from py_ecc python library by Ethereum Foundation.
    // // https://github.com/ethereum/py_ecc/blob/7b9e1b3/py_ecc/fields/field_properties.py#L30
    // The below value is the little-endian representation of the modulus.
    const NUM_LIMBS: usize = 48;

    const MODULUS: &'static [u8] = &[
        171, 170, 255, 255, 255, 255, 254, 185, 255, 255, 83, 177, 254, 255, 171, 30, 36, 246, 176,
        246, 160, 210, 48, 103, 191, 18, 133, 243, 132, 75, 119, 100, 215, 172, 75, 67, 182, 167,
        27, 75, 154, 230, 127, 57, 234, 17, 1, 26,
    ];

    // A rough witness-offset estimate given the size of the limbs and the size of the field.
    const WITNESS_OFFSET: usize = 1usize << 15;

    fn modulus() -> BigUint {
        BigUint::from_str_radix(
            "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787",
            10,
        )
            .unwrap()
    }
}

impl FpOpField for Bls381BaseField {
    const FIELD_TYPE: FieldType = FieldType::Bls381;
}

impl NumLimbs for Bls381BaseField {
    type Limbs = U48;
    type Witness = U94;
}

impl EllipticCurveParameters for Bls12381Parameters {
    type BaseField = Bls381BaseField;
    const CURVE_TYPE: CurveType = CurveType::Bls12381;
}

impl WeierstrassParameters for Bls12381Parameters {
    // The values of `A` and `B` has been taken from py_ecc python library by Ethereum Foundation.
    // https://github.com/ethereum/py_ecc/blob/7b9e1b3/py_ecc/bls12_381/bls12_381_curve.py#L31
    const A: Array<u8, U48> = Array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);

    const B: Array<u8, U48> = Array([
        4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);

    fn generator() -> (BigUint, BigUint) {
        let x = BigUint::from_str_radix(
            "3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507",
            10,
        )
            .unwrap();
        let y = BigUint::from_str_radix(
            "1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569",
            10,
        )
            .unwrap();
        (x, y)
    }

    // The prime group order has been taken from py_ecc python library by Ethereum Foundation.
    // https://github.com/ethereum/py_ecc/blob/7b9e1b3/py_ecc/bls12_381/bls12_381_curve.py#L21-L23
    fn prime_group_order() -> num::BigUint {
        BigUint::from_str_radix(
            "52435875175126190479447740508185965837690552500527637822603658699938581184513",
            10,
        )
        .unwrap()
    }

    fn a_int() -> BigUint {
        BigUint::zero()
    }

    fn b_int() -> BigUint {
        BigUint::from(4u32)
    }
}

pub fn bls12381_decompress<E: EllipticCurve>(bytes_be: &[u8], sign_bit: u32) -> AffinePoint<E> {
    let mut g1_bytes_be: [u8; 48] = bytes_be.try_into().unwrap();
    let mut flags = COMPRESION_FLAG;
    if sign_bit == 1 {
        flags |= Y_IS_ODD_FLAG;
    };

    // set sign and compression flag
    g1_bytes_be[0] |= flags;
    let point = deserialize_g1(&g1_bytes_be).unwrap();

    let x_str = point.getx().to_string();
    let x = BigUint::from_str_radix(x_str.as_str(), 16).unwrap();
    let y_str = point.gety().to_string();
    let y = BigUint::from_str_radix(y_str.as_str(), 16).unwrap();

    AffinePoint::new(x, y)
}

pub fn bls12381_sqrt(a: &BigUint) -> BigUint {
    let a_big = Big::from_bytes(a.to_bytes_be().as_slice());

    let a_sqrt = FP::new_big(a_big).sqrt();

    BigUint::from_str_radix(a_sqrt.to_string().as_str(), 16).unwrap()
}
