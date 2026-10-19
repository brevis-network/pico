//! The on-chain path's inputs: the gnark circuit and witness a Groth16 proof is made from, and the
//! wrap circuit's two public inputs.
//!
//! The Groth16 proving key, the Groth16 proof and the verifier contract are made outside this crate:
//! `cargo pico prove --evm` makes the proof with gnark, and `contracts/` holds the verifier.

use std::path::Path;

use pico_mle_core::p3_field::PrimeField;
use pico_vm::mle::machine::wrap::WrapArtifacts;

use crate::{
    committed::CommittedValues,
    error::ProveError,
    phase::Phase,
    proof::{digest_words, Payload, Proof, WRAP_CONSTRAINTS_FILE, WRAP_WITNESS_FILE},
    prover::ProgramId,
};

/// A verified [`crate::Phase::Wrap`] proof made in whitelist mode, in the form the on-chain path
/// takes it. Only [`crate::Prover::prove_evm`] returns one.
#[derive(Debug)]
pub struct EvmBundle {
    pub(crate) proof: Proof,
    pub(crate) vk_root: [u32; 8],
}

impl EvmBundle {
    /// The one way a bundle is made: refuses a dev-mode proof, a circuit that does not pin
    /// `vk_root`, a proof of a guest that never committed, and a proof whose witness disagrees
    /// with what the proof attests to.
    pub(crate) fn from_wrap_proof(proof: Proof, vk_root: [u32; 8]) -> Result<Self, ProveError> {
        if !proof.verify_keys() {
            return Err(ProveError::EvmRequiresWhitelist);
        }
        check_pinned_root(&proof, vk_root)?;
        check_public_inputs(&proof)?;
        Ok(Self { proof, vk_root })
    }

    /// The program this proof attests to, in whitelist mode. Its [`ProgramId::vkey_hash`] is the
    /// wrap circuit's first public input, and the value a verifier contract pins.
    pub fn program_id(&self) -> ProgramId {
        self.proof.program_id()
    }

    /// The wrap circuit's second public input, as 32 big-endian bytes: the SHA-256 of
    /// [`Self::committed`]'s bytes with its top three bits cleared.
    ///
    /// Cleared so the digest fits the one BN254 element the circuit carries it in; every other bit
    /// equals [`Proof::committed_value_digest`]'s, which is therefore not the value to pass on-chain.
    /// Equal to the witness [`Self::write_to`] writes.
    pub fn committed_value_digest(&self) -> [u8; 32] {
        be32(artifacts(&self.proof).committed_values_digest)
    }

    /// The guest's committed output, as a fresh reader.
    pub fn committed(&self) -> CommittedValues {
        self.proof.committed()
    }

    /// The whitelist root the wrap circuit bakes in. It is not a public input: a Groth16 key made
    /// from [`Self::write_to`]'s circuit is bound to this root, and rejects a bundle made under any
    /// other. Check it against the root the deployed verifier was set up for.
    pub fn vk_root(&self) -> [u32; 8] {
        self.vk_root
    }

    /// The verified proof the bundle was made from.
    pub fn proof(&self) -> &Proof {
        &self.proof
    }

    /// The bundle's proof, consuming the bundle.
    pub fn into_proof(self) -> Proof {
        self.proof
    }

    /// Write the gnark circuit and witness into `dir`, creating it if needed, as
    /// [`crate::WRAP_CONSTRAINTS_FILE`] and [`crate::WRAP_WITNESS_FILE`]. The gnark prover reads
    /// other names by default, so pass them with `-constraints` and `-witness`.
    pub fn write_to(&self, dir: impl AsRef<Path>) -> Result<(), ProveError> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir)
            .map_err(|e| ProveError::io(format!("cannot create {}", dir.display()), e))?;
        self.proof
            .write_wrap_artifacts(dir.join(WRAP_CONSTRAINTS_FILE), dir.join(WRAP_WITNESS_FILE))
    }
}

fn artifacts(proof: &Proof) -> &WrapArtifacts {
    match &proof.payload {
        Payload::Wrap { artifacts, .. } => artifacts,
        _ => unreachable!("an EvmBundle holds a Phase::Wrap proof"),
    }
}

fn wrap_artifacts(proof: &Proof) -> Result<&WrapArtifacts, ProveError> {
    match &proof.payload {
        Payload::Wrap { artifacts, .. } => Ok(artifacts),
        _ => Err(ProveError::proving(
            Phase::Wrap,
            format!("expected a Phase::Wrap proof, got a {} one", proof.phase),
        )),
    }
}

/// The root the wrap circuit pins against the one the bundle reports. A circuit that pins none is
/// a dev-mode wrap whatever the proof's flags say, and one that pins another root belongs to
/// another whitelist: a verifier set up for `vk_root` accepts neither.
pub(crate) fn check_pinned_root(proof: &Proof, vk_root: [u32; 8]) -> Result<(), ProveError> {
    match wrap_artifacts(proof)?.vk_root.as_ref().map(digest_words) {
        None => Err(ProveError::EvmRequiresWhitelist),
        Some(pinned) if pinned != vk_root => Err(ProveError::verification(
            Phase::Wrap,
            format!("the wrap circuit pins whitelist root {pinned:?}, not {vk_root:?}"),
        )),
        Some(_) => Ok(()),
    }
}

/// The witness's two public inputs against the host's own reading of the proof, both as the
/// strings the witness file carries and as the values the bundle reports. They come from separate
/// code, and a witness that disagrees with the proof would be solved for something else.
pub(crate) fn check_public_inputs(proof: &Proof) -> Result<(), ProveError> {
    let artifacts = wrap_artifacts(proof)?;
    let digest = proof.committed_value_digest();
    if digest == [0u8; 32] {
        return Err(ProveError::EvmNoCommittedDigest);
    }
    let mismatch = |what: &str| {
        ProveError::verification(
            Phase::Wrap,
            format!("the wrap witness's {what} is not the one the proof attests to"),
        )
    };
    fn written(value: impl PrimeField) -> String {
        value.as_canonical_biguint().to_string()
    }
    if be32(artifacts.vkey_hash) != proof.program_id().vkey_hash()
        || artifacts.witness.vkey_hash != written(artifacts.vkey_hash)
    {
        return Err(mismatch("vkey_hash"));
    }
    if be32(artifacts.committed_values_digest) != wrap_input_digest(digest)
        || artifacts.witness.committed_values_digest != written(artifacts.committed_values_digest)
    {
        return Err(mismatch("committed_values_digest"));
    }
    Ok(())
}

/// A SHA-256 digest as the wrap circuit packs it: 32 bytes, big-endian, into one BN254 element,
/// which cannot hold 256 bits, so the first byte keeps only its low five.
pub(crate) fn wrap_input_digest(mut digest: [u8; 32]) -> [u8; 32] {
    digest[0] &= 0x1f;
    digest
}

/// A field element as the 32 big-endian bytes a public input is read as.
pub(crate) fn be32(x: impl PrimeField) -> [u8; 32] {
    let be = x.as_canonical_biguint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    out
}
