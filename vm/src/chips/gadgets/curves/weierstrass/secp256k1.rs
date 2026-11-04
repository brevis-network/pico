//! Modulo defining the Secp256k1 curve and its base field. The constants are all taken from
//! https://en.bitcoin.it/wiki/Secp256k1.

use std::str::FromStr;

use elliptic_curve::{sec1::ToEncodedPoint, subtle::Choice};
use hybrid_array::Array;
use k256::{elliptic_curve::point::DecompressPoint, FieldElement};
use num::{
    traits::{FromBytes, ToBytes},
    BigUint, Zero,
};
use serde::{Deserialize, Serialize};
use typenum::{U32, U62};

use super::{SwCurve, WeierstrassParameters};
use crate::chips::gadgets::{
    curves::{AffinePoint, CurveType, EllipticCurve, EllipticCurveParameters},
    utils::field_params::{FieldParameters, NumLimbs},
};

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Secp256k1 curve parameter
pub struct Secp256k1Parameters;

pub type Secp256k1 = SwCurve<Secp256k1Parameters>;

#[derive(Debug, Default, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// Secp256k1 base field parameter
pub struct Secp256k1BaseField;

impl FieldParameters for Secp256k1BaseField {
    const MODULUS: &'static [u8] = &[
        0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];

    /// A rough witness-offset estimate given the size of the limbs and the size of the field.
    const WITNESS_OFFSET: usize = 1usize << 14;

    fn modulus() -> BigUint {
        BigUint::from_bytes_le(Self::MODULUS)
    }
}

impl NumLimbs for Secp256k1BaseField {
    type Limbs = U32;
    type Witness = U62;
}

impl EllipticCurveParameters for Secp256k1Parameters {
    type BaseField = Secp256k1BaseField;
    const CURVE_TYPE: CurveType = CurveType::Secp256k1;
}

impl WeierstrassParameters for Secp256k1Parameters {
    const A: Array<u8, U32> = Array([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);

    const B: Array<u8, U32> = Array([
        7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);
    fn generator() -> (BigUint, BigUint) {
        let x = BigUint::from_str(
            "55066263022277343669578718895168534326250603453777594175500187360389116729240",
        )
        .unwrap();
        let y = BigUint::from_str(
            "32670510020758816978083085130507043184471273380659243275938904335757337482424",
        )
        .unwrap();
        (x, y)
    }

    fn prime_group_order() -> num::BigUint {
        BigUint::from_slice(&[
            0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF,
        ])
    }

    fn a_int() -> BigUint {
        BigUint::zero()
    }

    fn b_int() -> BigUint {
        BigUint::from(7u32)
    }
}

pub fn secp256k1_decompress<E: EllipticCurve>(bytes_be: &[u8], sign: u32) -> AffinePoint<E> {
    let computed_point =
        k256::AffinePoint::decompress(bytes_be.into(), Choice::from(sign as u8)).unwrap();
    let point = computed_point.to_encoded_point(false);

    let x = BigUint::from_bytes_be(point.x().unwrap());
    let y = BigUint::from_bytes_be(point.y().unwrap());
    AffinePoint::<E>::new(x, y)
}

/// The secp256k1 add precompile on its ABI words: `p + q`, each point 16 words, x then y, each
/// coordinate little-endian. The double precompile is [`secp256k1_double_words`].
///
/// The result is the generic [`AffinePoint::sw_add`]'s, the chord formula the add chip's trace
/// computes, for every input: a point off the curve, a coordinate at or above the modulus, equal x.
/// It panics where that one does. Both emulators -- the AOT snapshot and the interpreter that
/// records the events -- compute through here, so they agree.
///
/// libsecp256k1 computes it wherever the two provably agree, as `sw_add` inverts by Fermat on big
/// integers, ~15 us a call in replay, which made these the costliest syscalls of a block's replay
/// (ecrecover is ~257 doubles and ~129 adds). That is when both points parse, which libsecp256k1
/// allows only for coordinates below the modulus on the curve, and their x differ: `q` is then
/// neither `p` nor `-p`, the chord's denominator is non-zero, and both give the canonical affine
/// sum.
pub fn secp256k1_add_words(p: &[u32; 16], q: &[u32; 16]) -> [u32; 16] {
    if let Some(sum) = libsecp256k1_add(p, q) {
        return sum;
    }
    let sum = AffinePoint::<Secp256k1>::from_words_le(p).sw_add(&AffinePoint::from_words_le(q));
    sum.to_words_le().try_into().unwrap()
}

/// The secp256k1 double precompile on its ABI words: [`AffinePoint::sw_double`]'s result for every
/// input, as [`secp256k1_add_words`] is `sw_add`'s. libsecp256k1 computes it for a point that
/// parses: no point on secp256k1 has `y = 0`, the group's order being an odd prime, so the
/// tangent's denominator `2y` is non-zero.
pub fn secp256k1_double_words(p: &[u32; 16]) -> [u32; 16] {
    if let Some(doubled) = libsecp256k1_double(p) {
        return doubled;
    }
    let doubled = AffinePoint::<Secp256k1>::from_words_le(p).sw_double();
    doubled.to_words_le().try_into().unwrap()
}

/// `p + q` through libsecp256k1 where it is `sw_add`'s, else `None`.
fn libsecp256k1_add(p: &[u32; 16], q: &[u32; 16]) -> Option<[u32; 16]> {
    if p[..8] == q[..8] {
        return None;
    }
    let sum = words_to_pubkey(p)?.combine(&words_to_pubkey(q)?).ok()?;
    Some(pubkey_to_words(&sum))
}

/// `2p` through libsecp256k1 where it is `sw_double`'s, else `None`.
fn libsecp256k1_double(p: &[u32; 16]) -> Option<[u32; 16]> {
    let p = words_to_pubkey(p)?;
    // `combine` takes the doubling formula when the two points are equal.
    Some(pubkey_to_words(&p.combine(&p).ok()?))
}

/// SEC1 uncompressed, `0x04 || x_be || y_be`, from the ABI words; `None` unless both coordinates
/// are below the modulus and the point is on the curve.
fn words_to_pubkey(words: &[u32; 16]) -> Option<secp256k1::PublicKey> {
    let mut encoded = [0u8; 65];
    encoded[0] = 0x04;
    for (coord, out) in words
        .as_chunks::<8>()
        .0
        .iter()
        .zip(encoded[1..].as_chunks_mut::<32>().0)
    {
        for (word, be) in coord.iter().rev().zip(out.as_chunks_mut::<4>().0) {
            *be = word.to_be_bytes();
        }
    }
    secp256k1::PublicKey::from_slice(&encoded).ok()
}

fn pubkey_to_words(point: &secp256k1::PublicKey) -> [u32; 16] {
    let encoded = point.serialize_uncompressed();
    let mut words = [0u32; 16];
    for (coord, out) in encoded[1..]
        .as_chunks::<32>()
        .0
        .iter()
        .zip(words.as_chunks_mut::<8>().0)
    {
        for (be, word) in coord.as_chunks::<4>().0.iter().zip(out.iter_mut().rev()) {
            *word = u32::from_be_bytes(*be);
        }
    }
    words
}

pub fn secp256k1_sqrt(n: &BigUint) -> BigUint {
    let be_bytes = n.to_be_bytes();
    let mut bytes = [0_u8; 32];
    bytes[32 - be_bytes.len()..].copy_from_slice(&be_bytes);
    let fe = FieldElement::from_bytes(&bytes.into()).unwrap();
    let result_bytes = fe.sqrt().expect("bad sqrt").normalize().to_bytes();
    BigUint::from_be_bytes(&result_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chips::gadgets::utils::RandBigUint;
    use rand::rng;

    #[test]
    fn test_secp256k1_sqrt() {
        let mut rng = rng();
        for _ in 0..10 {
            // Check that sqrt(x^2)^2 == x^2
            // We use x^2 since not all field elements have a square root
            let x = rng.random_biguint(256) % Secp256k1BaseField::modulus();
            let x_2 = (&x * &x) % Secp256k1BaseField::modulus();
            let sqrt = secp256k1_sqrt(&x_2);

            println!("sqrt: {}", sqrt);

            let sqrt_2 = (&sqrt * &sqrt) % Secp256k1BaseField::modulus();

            assert_eq!(sqrt_2, x_2);
        }
    }

    fn words(p: &AffinePoint<Secp256k1>) -> [u32; 16] {
        p.to_words_le().try_into().unwrap()
    }

    fn point(x: &BigUint, y: &BigUint) -> [u32; 16] {
        words(&AffinePoint::new(x.clone(), y.clone()))
    }

    fn random_point(rng: &mut impl rand::Rng) -> AffinePoint<Secp256k1> {
        let k = rng.random_biguint(256) % Secp256k1Parameters::prime_group_order();
        Secp256k1::generator().sw_scalar_mul(&k)
    }

    fn generic_add(p: &[u32; 16], q: &[u32; 16]) -> [u32; 16] {
        words(&AffinePoint::<Secp256k1>::from_words_le(p).sw_add(&AffinePoint::from_words_le(q)))
    }

    fn generic_double(p: &[u32; 16]) -> [u32; 16] {
        words(&AffinePoint::<Secp256k1>::from_words_le(p).sw_double())
    }

    /// What `f` returns, or the message it panics with.
    fn outcome(
        f: impl FnOnce() -> [u32; 16] + std::panic::UnwindSafe,
    ) -> Result<[u32; 16], String> {
        std::panic::catch_unwind(f).map_err(|panic| {
            panic
                .downcast_ref::<&str>()
                .map(|message| message.to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_default()
        })
    }

    /// On points of the curve libsecp256k1 computes the add and the double, bit for bit the generic
    /// path's: along double-and-add walks from random multiples of the generator, and on
    /// independent random pairs.
    #[test]
    fn valid_points_take_libsecp256k1_and_match_the_generic_path() {
        let mut rng = rng();
        for _ in 0..8 {
            let mut p = random_point(&mut rng);
            for _ in 0..64 {
                let doubled = p.sw_double();
                assert_eq!(libsecp256k1_double(&words(&p)), Some(words(&doubled)));
                assert_eq!(secp256k1_double_words(&words(&p)), words(&doubled));
                let sum = p.sw_add(&doubled);
                assert_eq!(
                    libsecp256k1_add(&words(&p), &words(&doubled)),
                    Some(words(&sum))
                );
                assert_eq!(
                    secp256k1_add_words(&words(&p), &words(&doubled)),
                    words(&sum)
                );
                p = sum;
            }
        }
        for _ in 0..64 {
            let p = words(&random_point(&mut rng));
            let q = words(&random_point(&mut rng));
            assert_eq!(libsecp256k1_add(&p, &q), Some(generic_add(&p, &q)));
            assert_eq!(secp256k1_add_words(&p, &q), generic_add(&p, &q));
        }
    }

    /// Off the curve, at or above the modulus, or at equal x, libsecp256k1 is not asked, and the
    /// add and the double are the generic path's, panics included.
    #[test]
    fn other_inputs_take_the_generic_path() {
        let modulus = Secp256k1BaseField::modulus();
        let zero = BigUint::zero();
        let generator = Secp256k1::generator();
        let g = words(&generator);
        let p = random_point(&mut rng());

        let off_curve = point(&BigUint::from(1u32), &BigUint::from(1u32));
        let all_zero = point(&zero, &zero);
        // No point of the curve has y = 0; this one is off it.
        let y_zero = point(&BigUint::from(5u32), &zero);
        let x_at_modulus = point(&modulus, &generator.y);
        let y_above_modulus = point(&zero, &((BigUint::from(1u32) << 256usize) - 1u32));

        let adds = [
            ("off the curve + G", off_curve, g),
            ("G + off the curve", g, off_curve),
            ("(0, 0) + G", all_zero, g),
            ("G + (0, 0)", g, all_zero),
            ("(0, 0) + (0, 0)", all_zero, all_zero),
            ("P + -P", words(&p), words(&-&p)),
            ("x at the modulus + G", x_at_modulus, g),
            ("G + x at the modulus", g, x_at_modulus),
            ("y above the modulus + G", y_above_modulus, g),
        ];
        for (case, p, q) in adds {
            assert_eq!(libsecp256k1_add(&p, &q), None, "{case}");
            assert_eq!(
                outcome(|| secp256k1_add_words(&p, &q)),
                outcome(|| generic_add(&p, &q)),
                "{case}"
            );
        }

        let doubles = [
            ("off the curve", off_curve),
            ("(0, 0)", all_zero),
            ("y = 0", y_zero),
            ("x at the modulus", x_at_modulus),
            ("y above the modulus", y_above_modulus),
        ];
        for (case, p) in doubles {
            assert_eq!(libsecp256k1_double(&p), None, "{case}");
            assert_eq!(
                outcome(|| secp256k1_double_words(&p)),
                outcome(|| generic_double(&p)),
                "{case}"
            );
        }
    }

    /// The generic add refuses two equal points rather than double them, where libsecp256k1 would
    /// return `2P`; so does this one.
    #[test]
    fn adding_a_point_to_itself_panics_as_the_generic_add_does() {
        let p = words(&random_point(&mut rng()));
        assert_eq!(libsecp256k1_add(&p, &p), None);
        let generic = outcome(|| generic_add(&p, &p));
        assert!(
            generic
                .as_ref()
                .is_err_and(|message| message.contains("Points are the same")),
            "{generic:?}"
        );
        assert_eq!(outcome(|| secp256k1_add_words(&p, &p)), generic);
    }
}
