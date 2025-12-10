//! Modulo defining the Secp256r1 curve and its base field. The constants are all taken from
//! https://std.neuromancer.sk/secg/secp256r1
//!
//! Also known as NIST P256

use std::str::FromStr;

use elliptic_curve::{sec1::ToEncodedPoint, subtle::Choice};
use hybrid_array::Array;
use num::{
    traits::{FromBytes, ToBytes},
    BigUint,
};
use p256::{elliptic_curve::point::DecompressPoint, FieldElement};
use serde::{Deserialize, Serialize};
use typenum::{U32, U62};

use super::{SwCurve, WeierstrassParameters};
use crate::chips::gadgets::{
    curves::{AffinePoint, CurveType, EllipticCurve, EllipticCurveParameters},
    utils::field_params::{FieldParameters, NumLimbs},
};

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Secp256r1 curve parameter
pub struct Secp256r1Parameters;

pub type Secp256r1 = SwCurve<Secp256r1Parameters>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Secp256r1 base field parameter
pub struct Secp256r1BaseField;

impl FieldParameters for Secp256r1BaseField {
    const MODULUS: &'static [u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff,
        0xff, 0xff,
    ];

    /// A rough witness-offset estimate given the size of the limbs and the size of the field.
    const WITNESS_OFFSET: usize = 1usize << 14;

    fn modulus() -> BigUint {
        BigUint::from_bytes_le(Self::MODULUS)
    }
}

impl NumLimbs for Secp256r1BaseField {
    type Limbs = U32;
    type Witness = U62;
}

impl EllipticCurveParameters for Secp256r1Parameters {
    type BaseField = Secp256r1BaseField;
    const CURVE_TYPE: CurveType = CurveType::Secp256r1;
}

impl WeierstrassParameters for Secp256r1Parameters {
    const A: Array<u8, U32> = Array([
        0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff,
        0xff, 0xff,
    ]);

    const B: Array<u8, U32> = Array([
        0x4b, 0x60, 0xd2, 0x27, 0x3e, 0x3c, 0xce, 0x3b, 0xf6, 0xb0, 0x53, 0xcc, 0xb0, 0x06, 0x1d,
        0x65, 0xbc, 0x86, 0x98, 0x76, 0x55, 0xbd, 0xeb, 0xb3, 0xe7, 0x93, 0x3a, 0xaa, 0xd8, 0x35,
        0xc6, 0x5a,
    ]);

    fn generator() -> (BigUint, BigUint) {
        let x = BigUint::from_str(
            "48439561293906451759052585252797914202762949526041747995844080717082404635286",
        )
        .unwrap();
        let y = BigUint::from_str(
            "36134250956749795798585127919587881956611106672985015071877198253568414405109",
        )
        .unwrap();
        (x, y)
    }

    fn prime_group_order() -> BigUint {
        BigUint::from_slice(&[
            0xfc632551, 0xf3b9cac2, 0xa7179e84, 0xbce6faad, 0xffffffff, 0xffffffff, 0x00000000,
            0xffffffff,
        ])
    }

    fn a_int() -> BigUint {
        BigUint::from_bytes_le(&Self::A)
    }

    fn b_int() -> BigUint {
        BigUint::from_bytes_le(&Self::B)
    }
}

pub fn secp256r1_decompress<E: EllipticCurve>(bytes_be: &[u8], sign: u32) -> AffinePoint<E> {
    let computed_point = p256::AffinePoint::decompress(bytes_be.into(), Choice::from(sign as u8))
        .expect("bad decompress");
    let point = computed_point.to_encoded_point(false);

    let x = BigUint::from_bytes_be(point.x().unwrap());
    let y = BigUint::from_bytes_be(point.y().unwrap());
    AffinePoint::<E>::new(x, y)
}

pub fn secp256r1_sqrt(n: &BigUint) -> BigUint {
    let be_bytes = n.to_be_bytes();
    let mut bytes = [0_u8; 32];
    bytes[32 - be_bytes.len()..].copy_from_slice(&be_bytes);
    let fe = FieldElement::from_bytes(&bytes.into()).unwrap();
    let result_bytes = fe.sqrt().expect("bad sqrt").to_bytes();
    BigUint::from_be_bytes(&result_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num::bigint::RandBigInt;
    use rand::thread_rng;

    #[test]
    fn test_secp256r1_sqrt() {
        let mut rng = thread_rng();
        for _ in 0..10 {
            // Check that sqrt(x^2)^2 == x^2
            // We use x^2 since not all field elements have a square root
            let x = rng.gen_biguint(256) % Secp256r1BaseField::modulus();
            let x_2 = (&x * &x) % Secp256r1BaseField::modulus();
            let sqrt = secp256r1_sqrt(&x_2);

            println!("sqrt: {}", sqrt);

            let sqrt_2 = (&sqrt * &sqrt) % Secp256r1BaseField::modulus();

            assert_eq!(sqrt_2, x_2);
        }
    }
}
