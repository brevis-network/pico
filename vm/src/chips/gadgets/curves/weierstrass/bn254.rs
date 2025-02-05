use crate::chips::gadgets::{
    curves::{
        weierstrass::{SwCurve, WeierstrassParameters},
        CurveType, EllipticCurveParameters,
    },
    utils::field_params::{FieldParameters, FieldType, FpOpField, NumLimbs},
};
use hybrid_array::{
    typenum::{U32, U62},
    Array,
};
use num::{BigUint, Num, Zero};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// BN254 base field parameter
pub struct Bn254BaseField;

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Bn254 curve parameter
pub struct Bn254Parameters;

pub type Bn254 = SwCurve<Bn254Parameters>;

impl FieldParameters for Bn254BaseField {
    const MODULUS: &'static [u8] = &[
        71, 253, 124, 216, 22, 140, 32, 60, 141, 202, 113, 104, 145, 106, 129, 151, 93, 88, 129,
        129, 182, 69, 80, 184, 41, 160, 49, 225, 114, 78, 100, 48,
    ];

    // A rough witness-offset estimate given the size of the limbs and the size of the field.
    const WITNESS_OFFSET: usize = 1usize << 14;

    fn modulus() -> BigUint {
        BigUint::from_str_radix(
            "21888242871839275222246405745257275088696311157297823662689037894645226208583",
            10,
        )
        .unwrap()
    }
}

impl FpOpField for Bn254BaseField {
    const FIELD_TYPE: FieldType = FieldType::Bn254;
}

impl NumLimbs for Bn254BaseField {
    type Limbs = U32;
    type Witness = U62;
}

impl EllipticCurveParameters for Bn254Parameters {
    type BaseField = Bn254BaseField;

    const CURVE_TYPE: CurveType = CurveType::Bn254;
}

impl WeierstrassParameters for Bn254Parameters {
    // The values have been taken from py_ecc python library by Ethereum Foundation.
    // https://github.com/ethereum/py_pairing/blob/5f609da/py_ecc/bn128/bn128_field_elements.py
    const A: Array<u8, U32> = Array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);

    const B: Array<u8, U32> = Array([
        3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    fn generator() -> (BigUint, BigUint) {
        let x = BigUint::from(1u32);
        let y = BigUint::from(2u32);
        (x, y)
    }

    fn prime_group_order() -> num::BigUint {
        BigUint::from_str_radix(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617",
            10,
        )
        .unwrap()
    }

    fn a_int() -> BigUint {
        BigUint::zero()
    }

    fn b_int() -> BigUint {
        BigUint::from(3u32)
    }
}
