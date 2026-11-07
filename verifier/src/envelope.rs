//! The v3 proof envelope a whitelist-mode root is submitted as:
//! `PICOMLE\0` | 3 (u32 LE) | zstd(bincode of [`MleRootProofV3`]). Field order is the wire format;
//! ethproofs' verifier declares the same struct, so none of this may change.
//!
//! A compress proof travels as `PICOMLE\0` | 4 (u32 LE) | zstd(bincode of [`MleCompressProofV4`]):
//! the proof alone, since its key is the whitelist's one compress key, which the verifier holds.

use std::{io::Read, sync::Arc};

use bincode::Options;
use pico_mle_core::{
    codec::{Decode, Encode},
    keygen::types::MultiStarkVerifyingKey,
    proof::Proof,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{ProofWithVk, Sc, VerifyError};

pub const PROOF_MAGIC: [u8; 8] = *b"PICOMLE\0";
pub const ENVELOPE_V3: u32 = 3;
/// The envelope of a compress proof, under its own version so that neither kind decodes as the
/// other.
pub const ENVELOPE_V4_COMPRESS: u32 = 4;

/// zstd level for the v3 body. This runs inside the reported proving time, so a fast level: on a
/// fib root under the earlier 100-bit parameters -3 gave 480 KB in 1.3 ms, -19 gave 459 KB in
/// 111 ms.
const PROOF_ZSTD_LEVEL: i32 = 3;

/// Bounds what a hostile envelope can make a decoder allocate. Real roots were under 1 MB
/// decompressed under the earlier 100-bit parameters (fib's ~800 KB), far below this bound.
const MAX_BODY: u64 = 32 << 20;

/// The v3 body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MleRootProofV3 {
    /// The combine root proof in `mle-core`'s canonical versioned wire format.
    pub proof: Vec<u8>,
    /// bincode of the root's `MultiStarkVerifyingKey`. Untrusted by design: the verifier accepts it
    /// only as a member of the whitelist its VK bundle pins.
    pub root_vk: Vec<u8>,
}

impl MleRootProofV3 {
    /// The body of a root proof and its vk.
    pub fn from_root(root: &ProofWithVk) -> Result<Self, VerifyError> {
        let err = |e: &dyn std::fmt::Display| VerifyError::Envelope(e.to_string());
        Ok(Self {
            proof: root.0.encode_to_vec().map_err(|e| err(&e))?,
            root_vk: bincode::serialize(&*root.1).map_err(|e| err(&e))?,
        })
    }

    /// Decode the proof and vk the body carries.
    pub fn to_root(&self) -> Result<ProofWithVk, VerifyError> {
        let proof = decode_proof(&self.proof, "root")?;
        let vk: MultiStarkVerifyingKey<Sc> = bincode_options()
            .deserialize(&self.root_vk)
            .map_err(|e| VerifyError::Envelope(format!("root vk does not decode: {e}")))?;
        Ok((proof, Arc::new(vk)))
    }
}

/// The v4 body: a compress proof without its key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MleCompressProofV4 {
    /// The compress proof in `mle-core`'s canonical versioned wire format.
    pub proof: Vec<u8>,
}

impl MleCompressProofV4 {
    pub fn from_proof(proof: &Proof<Sc>) -> Result<Self, VerifyError> {
        Ok(Self {
            proof: proof
                .encode_to_vec()
                .map_err(|e| VerifyError::Envelope(e.to_string()))?,
        })
    }

    pub fn to_proof(&self) -> Result<Proof<Sc>, VerifyError> {
        decode_proof(&self.proof, "compress")
    }
}

/// The proof the bytes hold, and nothing after it.
fn decode_proof(bytes: &[u8], what: &str) -> Result<Proof<Sc>, VerifyError> {
    let mut reader = std::io::Cursor::new(bytes);
    let proof = Proof::<Sc>::decode(&mut reader)
        .map_err(|e| VerifyError::Envelope(format!("{what} proof does not decode: {e}")))?;
    if reader.position() != bytes.len() as u64 {
        return Err(VerifyError::Envelope(format!(
            "{what} proof has trailing bytes"
        )));
    }
    Ok(proof)
}

/// The fixint encoding `bincode::serialize` writes, with a size limit.
fn bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_BODY)
}

/// Encode a v3 envelope.
pub fn encode_v3(body: &MleRootProofV3) -> Result<Vec<u8>, VerifyError> {
    encode_versioned(ENVELOPE_V3, body)
}

/// Encode a compress envelope.
pub fn encode_compress_v4(body: &MleCompressProofV4) -> Result<Vec<u8>, VerifyError> {
    encode_versioned(ENVELOPE_V4_COMPRESS, body)
}

fn encode_versioned<T: Serialize>(version: u32, body: &T) -> Result<Vec<u8>, VerifyError> {
    let err = |e: &dyn std::fmt::Display| VerifyError::Envelope(e.to_string());
    let raw = bincode::serialize(body).map_err(|e| err(&e))?;
    let zstd = zstd::encode_all(raw.as_slice(), PROOF_ZSTD_LEVEL).map_err(|e| err(&e))?;
    let mut out = Vec::with_capacity(PROOF_MAGIC.len() + 4 + zstd.len());
    out.extend_from_slice(&PROOF_MAGIC);
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&zstd);
    Ok(out)
}

/// Decode a v3 envelope, bounded against hostile input.
pub fn decode_v3(bytes: &[u8]) -> Result<MleRootProofV3, VerifyError> {
    decode_versioned(bytes, ENVELOPE_V3)
}

/// Decode a compress envelope ([`encode_compress_v4`]); a v3 root envelope is refused.
pub fn decode_compress_v4(bytes: &[u8]) -> Result<MleCompressProofV4, VerifyError> {
    decode_versioned(bytes, ENVELOPE_V4_COMPRESS)
}

fn decode_versioned<T: DeserializeOwned>(bytes: &[u8], expected: u32) -> Result<T, VerifyError> {
    let err = |m: String| VerifyError::Envelope(m);
    if bytes.len() < 12 || bytes[..8] != PROOF_MAGIC {
        return Err(err("not an MLE proof envelope (magic)".into()));
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes"));
    if version != expected {
        return Err(err(format!(
            "MLE proof envelope version {version}, expected {expected}"
        )));
    }
    let mut raw = Vec::new();
    zstd::Decoder::new(&bytes[12..])
        .map_err(|e| err(e.to_string()))?
        .take(MAX_BODY + 1)
        .read_to_end(&mut raw)
        .map_err(|e| err(e.to_string()))?;
    if raw.len() as u64 > MAX_BODY {
        return Err(err("MLE proof envelope body too large".into()));
    }
    bincode_options()
        .deserialize(&raw)
        .map_err(|e| err(e.to_string()))
}

/// [`decode_v3`] then [`MleRootProofV3::to_root`].
pub fn decode_root_proof_v3(bytes: &[u8]) -> Result<ProofWithVk, VerifyError> {
    decode_v3(bytes)?.to_root()
}

/// [`decode_compress_v4`] then the proof it carries.
pub fn decode_compress_proof_v4(bytes: &[u8]) -> Result<Proof<Sc>, VerifyError> {
    decode_compress_v4(bytes)?.to_proof()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> MleRootProofV3 {
        MleRootProofV3 {
            proof: vec![7; 64],
            root_vk: vec![9; 32],
        }
    }

    /// The bytes: the magic, the version as u32 LE, then zstd of the bincode of the body, proof
    /// first. Pinned against plain `bincode::deserialize`, which is what the external verifier
    /// uses.
    #[test]
    fn v3_wire_format() {
        let bytes = encode_v3(&body()).unwrap();
        assert_eq!(bytes[..8], PROOF_MAGIC);
        assert_eq!(
            u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            ENVELOPE_V3
        );
        let raw = zstd::decode_all(&bytes[12..]).unwrap();
        let plain: MleRootProofV3 = bincode::deserialize(&raw).unwrap();
        assert_eq!(plain, body());
        // proof's u64 length prefix, then its bytes, then root_vk's.
        assert_eq!(raw[..8], 64u64.to_le_bytes());
        assert_eq!(raw[8..72], [7u8; 64]);
        assert_eq!(decode_v3(&bytes).unwrap(), body());
    }

    #[test]
    fn decode_refuses_what_it_does_not_know() {
        let bytes = encode_v3(&body()).unwrap();
        let mut v2 = bytes.clone();
        v2[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert!(decode_v3(&v2).is_err());
        let mut foreign = bytes.clone();
        foreign[..8].copy_from_slice(b"PICOMLEV");
        assert!(decode_v3(&foreign).is_err());
        assert!(decode_v3(&bytes[..bytes.len() / 2]).is_err());
        assert!(decode_v3(&bytes[..11]).is_err());
    }

    /// The compress envelope: the magic, version 4, then zstd of the bincode of the proof bytes
    /// alone. Neither kind decodes as the other.
    #[test]
    fn v4_wire_format() {
        let v4 = MleCompressProofV4 { proof: vec![7; 64] };
        let bytes = encode_compress_v4(&v4).unwrap();
        assert_eq!(bytes[..8], PROOF_MAGIC);
        assert_eq!(
            u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            ENVELOPE_V4_COMPRESS
        );
        let raw = zstd::decode_all(&bytes[12..]).unwrap();
        assert_eq!(raw[..8], 64u64.to_le_bytes());
        assert_eq!(raw[8..], [7u8; 64]);
        assert_eq!(decode_compress_v4(&bytes).unwrap(), v4);
        assert!(decode_v3(&bytes).is_err());
        assert!(decode_compress_v4(&encode_v3(&body()).unwrap()).is_err());
    }

    /// A body past the cap is refused before it is deserialized.
    #[test]
    fn an_oversized_body_is_refused() {
        let at_cap = |extra: u64| MleRootProofV3 {
            // The bincode body adds two u64 length prefixes to the two vecs.
            proof: vec![0; (MAX_BODY - 16 + extra) as usize],
            root_vk: Vec::new(),
        };
        assert_eq!(
            decode_v3(&encode_v3(&at_cap(0)).unwrap()).unwrap(),
            at_cap(0)
        );
        let err = decode_v3(&encode_v3(&at_cap(1)).unwrap()).unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
    }

    /// Bytes that are not a proof and a vk are refused when decoded, not misread.
    #[test]
    fn garbage_proof_and_vk_are_refused() {
        assert!(matches!(body().to_root(), Err(VerifyError::Envelope(_))));
    }
}
