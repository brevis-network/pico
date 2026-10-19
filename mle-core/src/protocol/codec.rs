use std::{
    array::from_fn,
    io::{self, Cursor, Read, Result, Write},
};

use p3_field::{BasedVectorSpace, PrimeField32};

use crate::StarkProtocolConfig;

/// Hardware and language independent encoding.
/// Uses the Writer pattern for more efficient encoding without intermediate buffers.
// @dev Trait just for implementation sanity
pub trait Encode {
    /// Writes the encoded representation of `self` to the given writer.
    fn encode<W: Write>(&self, writer: &mut W) -> Result<()>;

    /// Convenience method to encode into a `Vec<u8>`
    fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        self.encode(&mut buffer)?;
        Ok(buffer)
    }
}

/// Hardware and language independent decoding.
/// Uses the Reader pattern for efficient decoding.
pub trait Decode: Sized {
    /// Reads and decodes a value from the given reader.
    fn decode<R: Read>(reader: &mut R) -> Result<Self>;
    fn decode_from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = Cursor::new(bytes);
        Self::decode(&mut reader)
    }
}

// ==================== Untrusted-preallocation guard ====================

/// Byte budget for a single up-front decode reservation from an untrusted (`u32`) length prefix.
/// Growth past it is on-demand and bounded by EOF, so a lie can't preallocate gigabytes.
const DECODE_PREALLOC_CAP: usize = 16 * 1024 * 1024;

/// `Vec::with_capacity` capped to [`DECODE_PREALLOC_CAP`] bytes. Behavior-preserving: valid lengths
/// sit far below the cap, so capacity equals `len` exactly.
pub(crate) fn with_capacity_capped<T>(len: usize) -> Vec<T> {
    let elem_size = std::mem::size_of::<T>().max(1); // avoid div-by-zero on ZSTs
    Vec::with_capacity(len.min(DECODE_PREALLOC_CAP / elem_size))
}

/// [StarkProtocolConfig] that has encodable associated types.
/// This is a separate trait to avoid Rust's orphan rule.
pub trait EncodableConfig: StarkProtocolConfig {
    fn encode_base_field<W: Write>(val: &Self::F, writer: &mut W) -> Result<()>;

    fn encode_extension_field<W: Write>(val: &Self::EF, writer: &mut W) -> Result<()>;

    fn encode_digest<W: Write>(val: &Self::Digest, writer: &mut W) -> Result<()>;

    /// Encode each element from an iterator (no length prefix).
    fn encode_base_field_iter<'a, W: Write>(
        iter: impl Iterator<Item = &'a Self::F>,
        writer: &mut W,
    ) -> Result<()>
    where
        Self::F: 'a,
    {
        for val in iter {
            Self::encode_base_field(val, writer)?;
        }
        Ok(())
    }

    /// Encode each element from an iterator (no length prefix).
    fn encode_extension_field_iter<'a, W: Write>(
        iter: impl Iterator<Item = &'a Self::EF>,
        writer: &mut W,
    ) -> Result<()>
    where
        Self::EF: 'a,
    {
        for val in iter {
            Self::encode_extension_field(val, writer)?;
        }
        Ok(())
    }

    /// Encode each element from an iterator (no length prefix).
    fn encode_digest_iter<'a, W: Write>(
        iter: impl Iterator<Item = &'a Self::Digest>,
        writer: &mut W,
    ) -> Result<()>
    where
        Self::Digest: 'a,
    {
        for val in iter {
            Self::encode_digest(val, writer)?;
        }
        Ok(())
    }

    /// Encode length-prefixed slice of base field elements.
    fn encode_base_field_slice<W: Write>(vals: &[Self::F], writer: &mut W) -> Result<()> {
        vals.len().encode(writer)?;
        Self::encode_base_field_iter(vals.iter(), writer)
    }

    /// Encode length-prefixed slice of extension field elements.
    fn encode_extension_field_slice<W: Write>(vals: &[Self::EF], writer: &mut W) -> Result<()> {
        vals.len().encode(writer)?;
        Self::encode_extension_field_iter(vals.iter(), writer)
    }

    /// Encode length-prefixed slice of digests.
    fn encode_digest_slice<W: Write>(vals: &[Self::Digest], writer: &mut W) -> Result<()> {
        vals.len().encode(writer)?;
        Self::encode_digest_iter(vals.iter(), writer)
    }
}

/// [StarkProtocolConfig] that has decodable associated types.
/// This is a separate trait to avoid Rust's orphan rule.
pub trait DecodableConfig: StarkProtocolConfig {
    fn decode_base_field<R: Read>(reader: &mut R) -> Result<Self::F>;

    fn decode_extension_field<R: Read>(reader: &mut R) -> Result<Self::EF>;

    fn decode_digest<R: Read>(reader: &mut R) -> Result<Self::Digest>;

    /// Decode `n` base field elements (known length, no length prefix).
    fn decode_base_field_n<R: Read>(reader: &mut R, n: usize) -> Result<Vec<Self::F>> {
        let mut vec = with_capacity_capped(n);
        for _ in 0..n {
            vec.push(Self::decode_base_field(reader)?);
        }
        Ok(vec)
    }

    /// Decode `n` extension field elements (known length, no length prefix).
    fn decode_extension_field_n<R: Read>(reader: &mut R, n: usize) -> Result<Vec<Self::EF>> {
        let mut vec = with_capacity_capped(n);
        for _ in 0..n {
            vec.push(Self::decode_extension_field(reader)?);
        }
        Ok(vec)
    }

    /// Decode `n` digests (known length, no length prefix).
    fn decode_digest_n<R: Read>(reader: &mut R, n: usize) -> Result<Vec<Self::Digest>> {
        let mut vec = with_capacity_capped(n);
        for _ in 0..n {
            vec.push(Self::decode_digest(reader)?);
        }
        Ok(vec)
    }

    /// Decode a length-prefixed vector of base field elements.
    fn decode_base_field_vec<R: Read>(reader: &mut R) -> Result<Vec<Self::F>> {
        let len = usize::decode(reader)?;
        Self::decode_base_field_n(reader, len)
    }

    /// Decode a length-prefixed vector of extension field elements.
    fn decode_extension_field_vec<R: Read>(reader: &mut R) -> Result<Vec<Self::EF>> {
        let len = usize::decode(reader)?;
        Self::decode_extension_field_n(reader, len)
    }

    /// Decode a length-prefixed vector of digests.
    fn decode_digest_vec<R: Read>(reader: &mut R) -> Result<Vec<Self::Digest>> {
        let len = usize::decode(reader)?;
        Self::decode_digest_n(reader, len)
    }
}

// ==================== Encode implementations for basic types ====================

impl Encode for bool {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[*self as u8])?;
        Ok(())
    }
}

impl Encode for u8 {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[*self])
    }
}

impl Encode for u32 {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.to_le_bytes())
    }
}

impl Encode for usize {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<()> {
        let x: u32 = (*self).try_into().map_err(io::Error::other)?;
        x.encode(writer)
    }
}

// ==================== Generic field codec helpers ====================

/// Encode a `PrimeField32` element as 4 little-endian bytes of its canonical u32 value.
pub fn encode_prime_field32<F: PrimeField32, W: Write>(val: &F, writer: &mut W) -> Result<()> {
    writer.write_all(&val.as_canonical_u32().to_le_bytes())
}

/// Decode a `PrimeField32` element from 4 little-endian bytes.
pub fn decode_prime_field32<F: PrimeField32, R: Read>(reader: &mut R) -> Result<F> {
    let mut bytes = [0u8; 4];
    reader.read_exact(&mut bytes)?;
    let value = u32::from_le_bytes(bytes);
    if value < F::ORDER_U32 {
        Ok(F::from_u32(value))
    } else {
        Err(io::Error::other(format!(
            "Attempted read of {} into F >= F::ORDER_U32 {}",
            value,
            F::ORDER_U32
        )))
    }
}

/// Encode an extension field element by encoding each basis coefficient.
pub fn encode_extension_field32<F: PrimeField32, EF: BasedVectorSpace<F>, W: Write>(
    val: &EF,
    writer: &mut W,
) -> Result<()> {
    let base_slice: &[F] = val.as_basis_coefficients_slice();
    for v in base_slice {
        encode_prime_field32(v, writer)?;
    }
    Ok(())
}

/// Decode an extension field element by decoding each basis coefficient.
pub fn decode_extension_field32<F: PrimeField32, EF: BasedVectorSpace<F>, R: Read>(
    reader: &mut R,
) -> Result<EF> {
    let d = <EF as BasedVectorSpace<F>>::DIMENSION;
    // `d` is a compile-time constant; capped only for uniformity.
    let mut base_vec = with_capacity_capped(d);
    for _ in 0..d {
        base_vec.push(decode_prime_field32(reader)?);
    }
    EF::from_basis_coefficients_slice(&base_vec)
        .ok_or_else(|| io::Error::other("extension field element: wrong number of coefficients"))
}

// ==================== Encode helpers ====================

/// Encodes length of slice and then each element
pub fn encode_slice<T: Encode, W: Write>(slice: &[T], writer: &mut W) -> Result<()> {
    slice.len().encode(writer)?;
    for elt in slice {
        elt.encode(writer)?;
    }
    Ok(())
}

impl<T: Encode, const N: usize> Encode for [T; N] {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<()> {
        for val in self {
            val.encode(writer)?;
        }
        Ok(())
    }
}

impl<T: Encode> Encode for Vec<T> {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<()> {
        encode_slice(self, writer)
    }
}

impl<S: Encode, T: Encode> Encode for (S, T) {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.0.encode(writer)?;
        self.1.encode(writer)
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.is_some().encode(writer)?;
        if let Some(val) = self {
            val.encode(writer)?;
        }
        Ok(())
    }
}

// ==================== Decode implementations for basic types ====================

impl Decode for bool {
    fn decode<R: Read>(reader: &mut R) -> Result<Self> {
        let mut bytes = [0u8; 1];
        reader.read_exact(&mut bytes)?;
        Ok(bytes[0] != 0)
    }
}

impl Decode for u8 {
    fn decode<R: Read>(reader: &mut R) -> Result<Self> {
        let mut bytes = [0u8; 1];
        reader.read_exact(&mut bytes)?;
        Ok(bytes[0])
    }
}

impl Decode for u32 {
    fn decode<R: Read>(reader: &mut R) -> Result<Self> {
        let mut bytes = [0u8; 4];
        reader.read_exact(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
}

impl Decode for usize {
    fn decode<R: Read>(reader: &mut R) -> Result<Self> {
        let val = u32::decode(reader)?;
        Ok(val as usize)
    }
}

// ==================== Decode helpers ====================

impl<T: Decode + Default, const N: usize> Decode for [T; N] {
    fn decode<R: Read>(reader: &mut R) -> Result<Self> {
        let mut result = from_fn(|_| T::default());
        for val in &mut result {
            *val = T::decode(reader)?;
        }
        Ok(result)
    }
}

impl<T: Decode> Decode for Vec<T> {
    fn decode<R: Read>(reader: &mut R) -> Result<Self> {
        let len = usize::decode(reader)?;
        let mut vec = with_capacity_capped(len);
        for _ in 0..len {
            vec.push(T::decode(reader)?);
        }
        Ok(vec)
    }
}

impl<S: Decode, T: Decode> Decode for (S, T) {
    fn decode<R: Read>(reader: &mut R) -> Result<Self> {
        Ok((S::decode(reader)?, T::decode(reader)?))
    }
}

impl<T: Decode> Decode for Option<T> {
    fn decode<R: Read>(reader: &mut R) -> Result<Self> {
        let is_some = bool::decode(reader)?;
        if is_some {
            Ok(Some(T::decode(reader)?))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The preallocation guard caps a hostile length while honoring a small one exactly.
    #[test]
    fn with_capacity_capped_bounds_hostile_length() {
        // A near-`u32::MAX` element count must not reserve gigabytes.
        let capped = with_capacity_capped::<u64>(u32::MAX as usize);
        assert_eq!(capped.len(), 0);
        assert!(
            capped.capacity() <= DECODE_PREALLOC_CAP,
            "capacity {} was not capped",
            capped.capacity()
        );
        assert!(
            capped.capacity() < u32::MAX as usize,
            "capacity was not capped"
        );
        // A small length is honored exactly (behavior-preserving for valid proofs).
        assert!(with_capacity_capped::<u64>(7).capacity() >= 7);
    }

    /// A length prefix claiming `u32::MAX` elements with no payload must fail fast (EOF) in bounded
    /// memory, not attempt a multi-gigabyte allocation.
    #[test]
    fn vec_decode_rejects_oversized_prefix_without_ooming() {
        let bytes = u32::MAX.to_le_bytes();
        assert!(Vec::<u32>::decode_from_bytes(&bytes).is_err());
    }

    /// `decode_prime_field32` round-trips canonical values (as 4 little-endian bytes) and rejects any
    /// 4-byte word `≥ F::ORDER_U32`, so a non-canonical field element cannot be smuggled in via a
    /// wrapped value.
    #[test]
    fn prime_field32_codec_roundtrip_and_range_check() {
        use p3_field::{PrimeCharacteristicRing, PrimeField32};
        use p3_koala_bear::KoalaBear;
        type F = KoalaBear;

        for v in [0u32, 1, 2, 1000, F::ORDER_U32 - 1] {
            let x = F::from_u32(v);
            let mut buf = Vec::new();
            encode_prime_field32(&x, &mut buf).unwrap();
            assert_eq!(buf, v.to_le_bytes(), "encoding must be canonical LE bytes");
            let got: F = decode_prime_field32(&mut buf.as_slice()).unwrap();
            assert_eq!(got, x);
        }

        // `ORDER_U32` itself (and anything larger, up to `u32::MAX`) is non-canonical ⇒ rejected.
        for bad in [F::ORDER_U32, F::ORDER_U32 + 1, u32::MAX] {
            let bytes = bad.to_le_bytes();
            assert!(decode_prime_field32::<F, _>(&mut bytes.as_slice()).is_err());
        }
    }

    /// `usize` is serialized as a 4-byte `u32`; it round-trips for every value up to `u32::MAX` and
    /// *errors* (rather than silently truncating) on a value that overflows the wire width.
    #[test]
    fn usize_codec_roundtrips_within_u32_and_rejects_overflow() {
        for v in [0usize, 1, 255, 1 << 20, u32::MAX as usize] {
            let bytes = v.encode_to_vec().unwrap();
            assert_eq!(bytes.len(), 4);
            assert_eq!(usize::decode_from_bytes(&bytes).unwrap(), v);
        }
        assert!((u32::MAX as usize + 1).encode_to_vec().is_err());
    }
}
