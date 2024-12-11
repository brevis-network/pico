use crate::chips::gadgets::utils::limbs::{Limbs, BITS_PER_LIMB};
use core::ops::Div;
use hybrid_array::{
    typenum::{Unsigned, U2, U4},
    Array, ArraySize,
};
use num::BigUint;
use p3_field::Field;
use serde::{de::DeserializeOwned, Serialize};

pub trait FieldParameters:
    Send + Sync + Copy + 'static + Serialize + DeserializeOwned + NumLimbs
{
    const NUM_BITS_PER_LIMB: usize = BITS_PER_LIMB;
    const NUM_LIMBS: usize = Self::Limbs::USIZE;
    const NUM_WITNESS_LIMBS: usize = Self::Witness::USIZE;
    const WITNESS_OFFSET: usize;

    /// The bytes of the modulus in little-endian order.
    const MODULUS: &'static [u8];

    fn modulus() -> BigUint {
        BigUint::from_bytes_le(Self::MODULUS)
    }

    fn num_bits() -> usize {
        Self::NUM_BITS_PER_LIMB * Self::NUM_LIMBS
    }

    fn modulus_field_iter<F: Field>() -> impl Iterator<Item = F> {
        Self::MODULUS
            .iter()
            .map(|x| F::from_canonical_u8(*x))
            .take(Self::NUM_LIMBS)
    }

    /// Convert a BigUint to a Boxed u8 limb slice (with len NUM_LIMBS).
    fn to_limbs(x: &BigUint) -> Box<[u8]> {
        let mut bytes = x.to_bytes_le();
        bytes.resize(Self::NUM_LIMBS, 0u8);
        bytes.into_boxed_slice()
    }

    /// Convert a BigUint to a Boxed slice of E limbs (with len NUM_LIMBS) after coercing through F.
    fn to_limbs_field_slice<E: From<F>, F: Field>(x: &BigUint) -> Box<[E]> {
        Self::to_limbs(x)
            .iter()
            .map(|x| F::from_canonical_u8(*x).into())
            .collect::<Box<[_]>>()
    }

    /// Convert a BigUint to Limbs<E, Self::Limbs> after coercing through F.
    fn to_limbs_field<E: From<F>, F: Field>(x: &BigUint) -> Limbs<E, Self::Limbs> {
        let limbs = Self::to_limbs(x);
        let iter = limbs.iter().map(|x| F::from_canonical_u8(*x).into());
        let result = Array::try_from_iter(iter).expect("wrong number of limbs in iter");
        Limbs(result)
    }
}

/// Convert a vec of F limbs to a Limbs of N length.
pub fn limbs_from_slice<E: From<F>, N: ArraySize, F: Field>(limbs: impl AsRef<[F]>) -> Limbs<E, N> {
    let limbs = limbs.as_ref();
    debug_assert_eq!(limbs.len(), N::USIZE);
    let mut result = Array::<E, N>::from_fn(|_| F::ZERO.into());
    for (i, limb) in limbs.iter().enumerate() {
        result[i] = (*limb).into();
    }
    Limbs(result)
}

/// Trait that holds the typenum values for # of limbs and # of witness limbs.
pub trait NumLimbs: Clone {
    type Limbs: ArraySize;
    type Witness: ArraySize;
}

/// Trait that holds number of words needed to represent a field element and a curve point.
pub trait NumWords: Clone {
    /// The number of words needed to represent a field element.
    type WordsFieldElement: ArraySize;
    /// The number of words needed to represent a curve point (two field elements).
    type WordsCurvePoint: ArraySize;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldType {
    Bls381,
    Bn254,
}

pub trait FpOpField: FieldParameters + NumWords {
    const FIELD_TYPE: FieldType;
}

/// Implement NumWords for NumLimbs where # Limbs is divisible by 4.
///
/// Using typenum we can do N/4 and N/2 in type-level arithmetic. Having it as a separate trait
/// avoids needing the Div where clauses everywhere.
impl<N: NumLimbs> NumWords for N
where
    N::Limbs: Div<U4>,
    N::Limbs: Div<U2>,
    <N::Limbs as Div<U4>>::Output: ArraySize,
    <N::Limbs as Div<U2>>::Output: ArraySize,
{
    /// Each word has 4 limbs so we divide by 4.
    type WordsFieldElement = <N::Limbs as Div<U4>>::Output;
    /// Curve point has 2 field elements so we divide by 2.
    type WordsCurvePoint = <N::Limbs as Div<U2>>::Output;
}
