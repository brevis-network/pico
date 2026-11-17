//! The v3 proof envelope a whitelist-mode root is submitted as:
//! `PICOMLE\0` | 3 (u32 LE) | zstd(bincode of [`MleRootProofV3`]). Field order is the wire format;
//! ethproofs' verifier declares the same struct, so none of this may change.
//!
//! A compress proof travels as `PICOMLE\0` | 5 (u32 LE) | zstd(bincode of [`MleCompressProofV5`]):
//! the proof alone, since its key is the whitelist's one compress key, which the verifier holds,
//! with its WHIR Merkle openings as multiproofs (`pico_mle_core::protocol::multiproof`). The
//! decoder rebuilds the flat proof, which the verifier checks as any other. It is the compress
//! proof's only wire form: version 4, the flat proof, is retired and refused.

use std::{io::Read, sync::Arc};

use bincode::Options;
use pico_mle_core::{
    codec::{Decode, Encode},
    config::koala_bear_poseidon2::default_koalabear_hasher,
    keygen::types::MultiStarkVerifyingKey,
    proof::Proof,
    protocol::multiproof::{decode_multiproof, encode_multiproof},
    verifier::replay_transcript,
    StarkEngine,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{Engine, ProofWithVk, Sc, VerifyError};

pub const PROOF_MAGIC: [u8; 8] = *b"PICOMLE\0";
pub const ENVELOPE_V3: u32 = 3;
/// The envelope of a compress proof, under its own version so that neither kind decodes as the
/// other. Version 4 was the flat compress proof; it is retired, so a v4 envelope is refused.
pub const ENVELOPE_V5_COMPRESS: u32 = 5;

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

/// The v5 body: a compress proof without its key, its Merkle openings as multiproofs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MleCompressProofV5 {
    /// The compress proof in `mle-core`'s multiproof form.
    pub proof: Vec<u8>,
}

impl MleCompressProofV5 {
    /// The body of `proof` under `vk`, its compress key. The key is needed to replay the proof's
    /// transcript for the WHIR query indices the multiproofs are taken at; it does not travel.
    ///
    /// The body is decoded again before it is returned, and refused unless it rebuilds `proof`
    /// exactly: a body that goes out always verifies as the proof it was made from.
    pub fn from_proof(
        proof: &Proof<Sc>,
        vk: &MultiStarkVerifyingKey<Sc>,
    ) -> Result<Self, VerifyError> {
        let err = |e: &dyn std::fmt::Display| VerifyError::Envelope(e.to_string());
        let engine: Engine = StarkEngine::new(vk.inner.params.clone());
        let walk = replay_transcript(engine.config(), vk, proof, &mut engine.initial_transcript())
            .map_err(|e| err(&e))?;
        let mut bytes = Vec::new();
        encode_multiproof(proof, walk.whir_query_indices(), &mut bytes).map_err(|e| err(&e))?;
        let body = Self { proof: bytes };
        if body.to_proof()? != *proof {
            return Err(VerifyError::Envelope(
                "compress multiproof does not rebuild its proof".into(),
            ));
        }
        Ok(body)
    }

    /// The proof, its flat Merkle paths rebuilt. Not checked: verify it as any decoded proof.
    pub fn to_proof(&self) -> Result<Proof<Sc>, VerifyError> {
        let mut reader = std::io::Cursor::new(&self.proof[..]);
        let proof = decode_multiproof::<Sc, _>(&default_koalabear_hasher(), &mut reader)
            .map_err(|e| VerifyError::Envelope(format!("compress proof does not decode: {e}")))?;
        if reader.position() != self.proof.len() as u64 {
            return Err(VerifyError::Envelope(
                "compress proof has trailing bytes".into(),
            ));
        }
        Ok(proof)
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

/// Encode a compress envelope.
pub fn encode_compress_v5(body: &MleCompressProofV5) -> Result<Vec<u8>, VerifyError> {
    encode_versioned(ENVELOPE_V5_COMPRESS, body)
}

/// Decode a v3 envelope, bounded against hostile input.
pub fn decode_v3(bytes: &[u8]) -> Result<MleRootProofV3, VerifyError> {
    decode_versioned(bytes, ENVELOPE_V3)
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

/// Decode a compress envelope ([`encode_compress_v5`]); any other version is refused, the retired
/// flat v4 and the v3 root among them.
pub fn decode_compress_v5(bytes: &[u8]) -> Result<MleCompressProofV5, VerifyError> {
    decode_versioned(bytes, ENVELOPE_V5_COMPRESS)
}

/// [`decode_v3`] then [`MleRootProofV3::to_root`].
pub fn decode_root_proof_v3(bytes: &[u8]) -> Result<ProofWithVk, VerifyError> {
    decode_v3(bytes)?.to_root()
}

/// [`decode_compress_v5`] then the proof it carries, its flat Merkle paths rebuilt.
pub fn decode_compress_proof_v5(bytes: &[u8]) -> Result<Proof<Sc>, VerifyError> {
    decode_compress_v5(bytes)?.to_proof()
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

    /// The compress envelope: the magic, version 5, then zstd of the bincode of the proof bytes
    /// alone. Neither kind decodes as the other, and the retired flat v4 is refused.
    #[test]
    fn v5_wire_format() {
        let v5 = MleCompressProofV5 { proof: vec![7; 64] };
        let bytes = encode_compress_v5(&v5).unwrap();
        assert_eq!(bytes[..8], PROOF_MAGIC);
        assert_eq!(
            u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            ENVELOPE_V5_COMPRESS
        );
        let raw = zstd::decode_all(&bytes[12..]).unwrap();
        assert_eq!(raw[..8], 64u64.to_le_bytes());
        assert_eq!(raw[8..], [7u8; 64]);
        assert_eq!(decode_compress_v5(&bytes).unwrap(), v5);
        assert!(decode_v3(&bytes).is_err());
        assert!(decode_compress_v5(&encode_v3(&body()).unwrap()).is_err());
        let mut v4 = bytes.clone();
        v4[8..12].copy_from_slice(&4u32.to_le_bytes());
        let err = decode_compress_v5(&v4).unwrap_err();
        assert!(err.to_string().contains("version 4"), "{err}");
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
