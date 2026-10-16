//! Canonical-value serde for prime-field elements inside hashed preimages.
//!
//! The vk pre-hash, the per-AIR constraint digests and the rendered constraint dump are hashes of
//! postcard-serialized structures that contain field elements. Plonky3's own `Serialize` for
//! `MontyField31` emitted the canonical value up to the fork this crate was built on and switches
//! to the Montgomery representation from 0.5 on, which would silently change every such hash.
//! Everything that enters those preimages therefore goes through this module: a field element is
//! always `serialize_u32(canonical value)` — byte-identical to what the preimages contained so far
//! (postcard encodes `u32` as a varint), and independent of the field type's own serde.

use p3_field::PrimeField64;
use serde::{ser::SerializeTuple, Deserialize, Deserializer, Serialize, Serializer};

fn to_u32<F: PrimeField64>(x: &F) -> u32 {
    u32::try_from(x.as_canonical_u64()).expect("canonical field element must fit in u32")
}

/// `#[serde(with = "canonical_field")]` for a single field element.
pub mod canonical_field {
    use super::*;

    pub fn serialize<F: PrimeField64, S: Serializer>(x: &F, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u32(to_u32(x))
    }

    pub fn deserialize<'de, F: PrimeField64, D: Deserializer<'de>>(d: D) -> Result<F, D::Error> {
        let v = u32::deserialize(d)?;
        Ok(F::from_u64(u64::from(v)))
    }
}

/// A digest (fixed-size array of field elements) viewed as its canonical values. Serializes exactly
/// like the array itself did with canonical-value field serde: a tuple of `u32`s, no length prefix.
pub struct CanonicalDigest<'a, F>(pub &'a [F]);

impl<F: PrimeField64> Serialize for CanonicalDigest<'_, F> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut t = s.serialize_tuple(self.0.len())?;
        for x in self.0 {
            t.serialize_element(&to_u32(x))?;
        }
        t.end()
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;
    use serde::Serialize;

    use super::*;

    #[derive(Serialize)]
    struct Wrapped(#[serde(with = "canonical_field")] KoalaBear);

    /// The encoding is the postcard varint of the canonical value -- pinned as bytes so that a
    /// change in the field type's own serde cannot move it.
    #[test]
    fn canonical_field_is_the_varint_of_the_canonical_value() {
        for v in [0u32, 1, 127, 128, 300, 16_383, 16_384, 2_130_706_432] {
            let ours = postcard::to_allocvec(&Wrapped(KoalaBear::from_u32(v))).unwrap();
            assert_eq!(ours, postcard::to_allocvec(&v).unwrap(), "v = {v}");
        }
    }

    #[test]
    fn canonical_digest_is_a_tuple_of_varints() {
        let d: [KoalaBear; 8] = core::array::from_fn(|i| KoalaBear::from_u32(1000 * i as u32 + 7));
        let ours = postcard::to_allocvec(&CanonicalDigest(&d)).unwrap();
        let expected: [u32; 8] = core::array::from_fn(|i| 1000 * i as u32 + 7);
        assert_eq!(ours, postcard::to_allocvec(&expected).unwrap());
        // No length prefix: a tuple, not a sequence.
        assert_ne!(ours, postcard::to_allocvec(&expected.to_vec()).unwrap());
    }

    #[test]
    fn canonical_field_roundtrips() {
        #[derive(Serialize, serde::Deserialize, PartialEq, Debug)]
        struct W(#[serde(with = "canonical_field")] KoalaBear);
        let w = W(KoalaBear::from_u32(123_456_789));
        let bytes = postcard::to_allocvec(&w).unwrap();
        assert_eq!(postcard::from_bytes::<W>(&bytes).unwrap(), w);
    }
}
