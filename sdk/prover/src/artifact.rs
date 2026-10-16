//! The proof container: a minimal, versioned file plus the one entry point that can answer for it.
//!
//! **Everything in the file is attacker input.** Two consequences decide the design, and both are
//! the reason this container carries so little:
//!
//! - The proof commits to a SHA-256 of the guest's output, not to the output itself, so the stored
//!   bytes are rebound by hash against the *verified* proof before they are readable
//!   ([`crate::binding`]).
//! - A verifying key and child layouts taken from a file are hints, never trust anchors. Compiling
//!   them into a verifier circuit lets a crafted file keygen a circuit that constrains nothing and
//!   then pass, which `vm/src/mle/machine/combine.rs` says in as many words. **No child layouts are
//!   stored, and nothing here reaches `preregister_root_shape`.**
//!
//! That leaves an asymmetry between phases, and it is what the container may carry:
//!
//! | phase | verifiable from a file in a fresh process? |
//! |---|---|
//! | [`Phase::Riscv`] | yes — the RISC-V key is a function of the program, and the verifier holds the program |
//! | [`Phase::Combine`] | only against an independently pinned whitelist, or on the prover that produced it |
//! | [`Phase::Convert`], [`Phase::Embed`], [`Phase::Wrap`] | no, in any configuration — so they are not written |
//!
//! # The two version fields, and what each one covers
//!
//! - [`FORMAT_VERSION`] covers this container: the header, the body's serde shape, **and the serde
//!   shape of the verifying key inside it**. A field added to or reordered in
//!   `MultiStarkVerifyingKey` changes these bytes while leaving the proof codec alone, so it is a
//!   `FORMAT_VERSION` bump — nothing else records it.
//! - `CODEC_VERSION` covers the proofs, which travel in `mle-core`'s own hand-written codec.
//!
//! A bump that was missed anyway does not pass silently: the key's lean pre-hash is written into the
//! fixed header, parsed by hand rather than by serde, and compared against the pre-hash recomputed
//! from the key the body decodes to. Both halves come from the same file, so this is internal
//! consistency and never authenticity — what it catches is a container this build would otherwise
//! read as a different key than the one that was written, and a key whose body was altered while
//! its stored identity was kept.

use std::path::Path;

use bincode::Options as _;
use pico_mle_core::{
    codec::{Decode, Encode},
    keygen::compute_vk_pre_hash,
    proof::CODEC_VERSION,
};
use pico_vm::mle::machine::{
    convert::ProofWithVk,
    riscv::{RiscvProof, RISCV_APP_PREP_AIR_IDS},
};
use serde::{Deserialize, Serialize};

use crate::{
    error::ProveError,
    phase::Phase,
    proof::{digest_words, Payload, Proof},
    prover::ProgramId,
    types::{InnerProof, Sc, VerifyingKey},
};

const MAGIC: &[u8; 4] = b"PICO";

/// The container's own version, independent of the proof codec's.
pub const FORMAT_VERSION: u32 = 2;

/// Fixed prefix: magic, container version, proof-codec version, the stored key's lean pre-hash.
const HEADER_LEN: usize = 4 + 4 + 4 + 32;

/// Written from borrows (`K = &VerifyingKey`) and read into owned values (`K = VerifyingKey`): one
/// definition for both directions, so the two cannot drift apart, and a reference serializes
/// exactly as the value it points to.
#[derive(Serialize, Deserialize)]
enum StoredPayload<K> {
    Riscv { vk: K, chunk_proofs: Vec<Vec<u8>> },
    Combine { vk: K, proof: Vec<u8> },
}

impl<K> StoredPayload<K> {
    fn vk(&self) -> &K {
        match self {
            Self::Riscv { vk, .. } | Self::Combine { vk, .. } => vk,
        }
    }
}

/// The phase is **not** stored: the payload variant is what it is, and a second copy of the same
/// fact in a file that is attacker input is only a way for the two to disagree.
///
/// `B` is `&[u8]` when writing and `Vec<u8>` when reading, which encode alike.
#[derive(Serialize, Deserialize)]
struct Body<K, B> {
    log_stacked_height: u32,
    verify_keys: bool,
    program_id: [u32; 8],
    committed: B,
    payload: StoredPayload<K>,
}

pub(crate) enum LoadedPayload {
    Riscv(RiscvProof),
    Combine(Box<ProofWithVk>),
}

impl LoadedPayload {
    pub(crate) fn phase(&self) -> Phase {
        match self {
            Self::Riscv(_) => Phase::Riscv,
            Self::Combine(_) => Phase::Combine,
        }
    }
}

/// A proof read back from a file. Nothing on it has been verified.
///
/// [`crate::Prover::verify_artifact`] is the only way to turn one into a [`Proof`], and the
/// committed bytes are unreachable until it does.
pub struct ProofArtifact {
    pub(crate) log_stacked_height: usize,
    pub(crate) verify_keys: bool,
    pub(crate) program_id: ProgramId,
    pub(crate) committed: Vec<u8>,
    pub(crate) payload: LoadedPayload,
}

impl std::fmt::Debug for ProofArtifact {
    /// The claims only, and labelled as claims: nothing here has been checked.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofArtifact")
            .field("phase", &self.phase())
            .field("claimed_program_id", &self.program_id)
            .field("claimed_log_stacked_height", &self.log_stacked_height)
            .field("claimed_verify_keys", &self.verify_keys)
            .field(
                "committed",
                &format_args!("{} unverified byte(s)", self.committed.len()),
            )
            .finish()
    }
}

impl ProofArtifact {
    /// Which phase this file carries. Read from the payload it actually holds, so it cannot
    /// disagree with what will be verified.
    pub fn phase(&self) -> Phase {
        self.payload.phase()
    }

    /// The program the file claims to attest to. A hint: the verification entry point compares it
    /// against the program it holds and rejects a mismatch.
    pub fn claimed_program_id(&self) -> ProgramId {
        self.program_id
    }

    /// Load a container, checking the two version fields before anything else is decoded.
    pub fn read(path: impl AsRef<Path>) -> Result<Self, ProveError> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)
            .map_err(|e| ProveError::io(format!("cannot read `{}`", path.display()), e))?;
        Self::from_bytes(&bytes)
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, ProveError> {
        if bytes.len() < HEADER_LEN || &bytes[..4] != MAGIC {
            return Err(ProveError::Format(
                "missing the PICO container header".into(),
            ));
        }
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());

        let format_version = word(4);
        if format_version != FORMAT_VERSION {
            return Err(ProveError::FormatVersion {
                expected: FORMAT_VERSION,
                found: format_version,
            });
        }
        let codec_version = word(8);
        if codec_version != CODEC_VERSION {
            return Err(ProveError::CodecVersion {
                expected: CODEC_VERSION,
                found: codec_version,
            });
        }
        let header_vk_pre_hash: [u32; 8] = std::array::from_fn(|i| word(12 + i * 4));

        // A reader rather than a slice, because bincode's slice entry point replaces any limit
        // with none. A byte buffer or a string is reserved at its claimed length before it is
        // read, so the limit, the body's own length, is what turns a prefix claiming more than the
        // file holds into an error rather than an allocation that aborts. A sequence's length is
        // not checked against it: serde's derived impls reserve a bounded capacity and read until
        // the body runs out, which the tests below pin. The encoding is `bincode::serialize`'s own.
        let body_bytes = &bytes[HEADER_LEN..];
        let body: Body<VerifyingKey, Vec<u8>> = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(body_bytes.len() as u64)
            .deserialize_from(std::io::Cursor::new(body_bytes))
            .map_err(|e| {
                ProveError::Format(format!(
                    "cannot decode the container body: {e}. A build whose stored types serialize \
                     differently writes a body this one cannot read; re-prove with a matching build"
                ))
            })?;

        let stored_vk = body.payload.vk();
        let recomputed = digest_words(&recompute_pre_hash(stored_vk));
        if recomputed != header_vk_pre_hash || digest_words(&stored_vk.pre_hash) != recomputed {
            return Err(ProveError::VkIdentityMismatch {
                header: header_vk_pre_hash,
                decoded: recomputed,
            });
        }

        let decode = |encoded: &[u8]| -> Result<InnerProof, ProveError> {
            InnerProof::decode_from_bytes(encoded)
                .map_err(|e| ProveError::Format(format!("cannot decode a stored proof: {e}")))
        };
        let Body {
            log_stacked_height,
            verify_keys,
            program_id,
            committed,
            payload,
        } = body;
        let payload = match payload {
            StoredPayload::Riscv { vk, chunk_proofs } => LoadedPayload::Riscv(RiscvProof {
                vk: std::sync::Arc::new(vk),
                chunk_proofs: chunk_proofs
                    .iter()
                    .map(|p| decode(p))
                    .collect::<Result<_, _>>()?,
            }),
            StoredPayload::Combine { vk, proof } => {
                LoadedPayload::Combine(Box::new((decode(&proof)?, std::sync::Arc::new(vk))))
            }
        };

        Ok(Self {
            log_stacked_height: log_stacked_height as usize,
            verify_keys,
            program_id: ProgramId::from_stored_words(program_id)?,
            committed,
            payload,
        })
    }
}

/// The lean pre-hash of `vk`, from its body rather than its stored field.
///
/// The RISC-V app-identity ids are the ones a RISC-V key was keygen'd with; a recursion key is
/// merged-preprocessed, which excludes every commitment whatever the ids, so one call covers both.
fn recompute_pre_hash(vk: &VerifyingKey) -> [crate::types::Kb; 8] {
    let config = Sc::default_from_params(vk.inner.params.clone());
    compute_vk_pre_hash(&config, &vk.inner, RISCV_APP_PREP_AIR_IDS)
}

pub(crate) fn write(proof: &Proof, path: &Path) -> Result<(), ProveError> {
    let bytes = to_bytes(proof)?;
    std::fs::write(path, bytes)
        .map_err(|e| ProveError::io(format!("cannot write `{}`", path.display()), e))
}

fn to_bytes(proof: &Proof) -> Result<Vec<u8>, ProveError> {
    let payload = match &proof.payload {
        Payload::Riscv(bundle) => StoredPayload::Riscv {
            vk: &*bundle.vk,
            chunk_proofs: bundle
                .chunk_proofs
                .iter()
                .map(encode_one)
                .collect::<Result<_, _>>()?,
        },
        Payload::Combine(root) => StoredPayload::Combine {
            vk: &*root.1,
            proof: encode_one(&root.0)?,
        },
        _ => {
            return Err(ProveError::UnverifiableInFreshProcess { phase: proof.phase });
        }
    };

    let body = Body {
        log_stacked_height: proof.log_stacked_height as u32,
        verify_keys: proof.verify_keys,
        program_id: proof.program_id.as_words(),
        committed: proof.committed.as_slice(),
        payload,
    };

    let vk_pre_hash = digest_words(&body.payload.vk().pre_hash);

    let mut bytes = Vec::with_capacity(HEADER_LEN);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&CODEC_VERSION.to_le_bytes());
    for word in vk_pre_hash {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bincode::serialize_into(&mut bytes, &body)
        .map_err(|e| ProveError::Format(format!("cannot encode the container body: {e}")))?;
    Ok(bytes)
}

fn encode_one(proof: &InnerProof) -> Result<Vec<u8>, ProveError> {
    proof
        .encode_to_vec()
        .map_err(|e| ProveError::io("cannot encode a proof", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&CODEC_VERSION.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 32]);
        bytes
    }

    /// A container is attacker input, and its length prefixes are the cheapest thing in it to lie
    /// about. A lie must come back as an error, not as an allocation failure.
    #[test]
    fn a_byte_vector_longer_than_the_file_is_an_error() {
        let mut bytes = header();
        // `log_stacked_height`, `verify_keys`, `program_id`, then a `committed` of 2^60 bytes.
        bytes.extend_from_slice(&22u32.to_le_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(&(1u64 << 60).to_le_bytes());
        assert!(matches!(
            ProofArtifact::from_bytes(&bytes),
            Err(ProveError::Format(_))
        ));
    }

    /// The same lie as a sequence count inside the stored key, which the limit does not check: what
    /// keeps it an error is that the key's types do not reserve a count before reading it.
    #[test]
    fn a_sequence_longer_than_the_file_is_an_error() {
        let mut bytes = header();
        // `log_stacked_height`, `verify_keys`, `program_id`, an empty `committed`, the
        // `StoredPayload::Riscv` discriminant, the key's `SystemParams`, then a `per_air` count of
        // 2^60.
        bytes.extend_from_slice(&22u32.to_le_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        let params = pico_mle_core::config::riscv_params_with_100_bits_security(22);
        bytes.extend_from_slice(&bincode::serialize(&params).expect("encode the params"));
        bytes.extend_from_slice(&(1u64 << 60).to_le_bytes());
        assert!(matches!(
            ProofArtifact::from_bytes(&bytes),
            Err(ProveError::Format(_))
        ));
    }

    /// What makes writing from borrows safe: the borrowed body and the owned one it is read back
    /// as encode to the same bytes, so the write side needs no copy of the key or the output.
    #[test]
    fn the_borrowed_body_encodes_as_the_owned_one() {
        let committed = vec![1u8, 2, 3];
        let key = 7u32;
        let borrowed = Body {
            log_stacked_height: 22,
            verify_keys: true,
            program_id: [9; 8],
            committed: committed.as_slice(),
            payload: StoredPayload::Combine {
                vk: &key,
                proof: vec![4, 5],
            },
        };
        let owned = Body {
            log_stacked_height: 22,
            verify_keys: true,
            program_id: [9; 8],
            committed: committed.clone(),
            payload: StoredPayload::Combine {
                vk: key,
                proof: vec![4, 5],
            },
        };
        assert_eq!(
            bincode::serialize(&borrowed).unwrap(),
            bincode::serialize(&owned).unwrap()
        );
    }

    #[test]
    fn a_file_that_is_not_a_container_is_an_error() {
        assert!(matches!(
            ProofArtifact::from_bytes(b"not a proof"),
            Err(ProveError::Format(_))
        ));
        assert!(matches!(
            ProofArtifact::from_bytes(&[]),
            Err(ProveError::Format(_))
        ));
    }

    /// Both version fields are answered by name, and before anything else is decoded.
    #[test]
    fn each_version_field_is_named() {
        let mut bytes = header();
        bytes[4..8].copy_from_slice(&7u32.to_le_bytes());
        assert!(matches!(
            ProofArtifact::from_bytes(&bytes),
            Err(ProveError::FormatVersion { found: 7, .. })
        ));

        let mut bytes = header();
        bytes[8..12].copy_from_slice(&7u32.to_le_bytes());
        assert!(matches!(
            ProofArtifact::from_bytes(&bytes),
            Err(ProveError::CodecVersion { found: 7, .. })
        ));
    }
}
