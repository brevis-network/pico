//! The verified proof and the facts a caller can read off it.

use std::path::Path;

use pico_mle_core::{codec::Encode, p3_field::PrimeField32};
use pico_vm::mle::machine::{convert::ProofWithVk, riscv::RiscvProof};

use crate::{
    committed::CommittedValues,
    error::ProveError,
    phase::Phase,
    prover::ProgramId,
    types::{Kb, VerifyingKey},
};

#[cfg(feature = "multi-field-transcript")]
use pico_vm::mle::machine::{embed::EmbedProofWithVk, wrap::WrapArtifacts};

pub(crate) fn digest_words(digest: &[Kb; 8]) -> [u32; 8] {
    digest.map(|f| f.as_canonical_u32())
}

/// What a phase produced, kept whole so the proof can be re-verified or written out.
pub(crate) enum Payload {
    Riscv(RiscvProof),
    Convert(Vec<ProofWithVk>),
    Combine(Box<ProofWithVk>),
    #[cfg(feature = "multi-field-transcript")]
    Embed(EmbedProofWithVk),
    #[cfg(feature = "multi-field-transcript")]
    Wrap {
        /// Kept beside the artifacts it was compiled from: the artifacts constrain this proof and
        /// nothing else, so separating them would let the two be paired wrongly.
        embed: EmbedProofWithVk,
        artifacts: Box<WrapArtifacts>,
    },
}

/// A proof that has been verified, and whose committed bytes are bound to it.
///
/// There is no public constructor: every `Proof` came out of a [`crate::Prover`] proving method or
/// [`crate::Prover::verify_artifact`], all of which verify before they return and reject bytes that
/// do not hash to the proof's `committed_value_digest`. That is what makes
/// [`Proof::committed`] mean *this proof's output* rather than *bytes that were nearby*.
pub struct Proof {
    pub(crate) phase: Phase,
    pub(crate) program_id: ProgramId,
    pub(crate) log_stacked_height: usize,
    pub(crate) verify_keys: bool,
    pub(crate) committed: Vec<u8>,
    pub(crate) committed_value_digest: [u8; 32],
    pub(crate) chunk_count: Option<usize>,
    pub(crate) distinct_shapes: Option<usize>,
    pub(crate) payload: Payload,
}

impl Proof {
    /// The phase this proof stops at.
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The program this proof attests to, at this operating point. See [`ProgramId`] for which one
    /// an on-chain verifier pins.
    pub fn program_id(&self) -> ProgramId {
        self.program_id
    }

    /// The guest's committed output, as a fresh reader.
    ///
    /// Bound by SHA-256 to what this proof attests to, which is not the same statement at every
    /// phase — [`Self::binds_complete_execution`] is the difference.
    pub fn committed(&self) -> CommittedValues {
        CommittedValues::new(self.committed.clone())
    }

    /// The SHA-256 the proof commits to, and which [`Self::committed`]'s bytes hash to.
    pub fn committed_value_digest(&self) -> [u8; 32] {
        self.committed_value_digest
    }

    /// How many chunk proofs the RISC-V layer produced — one per emulation record, which runs
    /// ahead of the chunk count because the deferred split emits records after the guest halts.
    /// `None` only where no bundle is at hand to count: a [`Phase::Combine`] proof loaded from a
    /// container, which stores one root proof and no count. A loaded RISC-V bundle carries its
    /// chunks, so it reports them, and every proof this prover produced counts the run it emulated.
    pub fn chunk_count(&self) -> Option<usize> {
        self.chunk_count
    }

    /// How many distinct circuit shapes the prover holds for the phase this proof stops at.
    ///
    /// A property of the prover rather than of this proof: the recursion machines keygen lazily
    /// and keep what they build, so a second `prove` whose shapes are already held adds nothing and
    /// reports the same number. `None` on a proof that was verified rather than produced —
    /// verification keygens nothing, and against a whitelist it never consults a proving machine
    /// at all.
    pub fn distinct_shapes(&self) -> Option<usize> {
        self.distinct_shapes
    }

    /// Whether this proof binds the committed bytes to **one whole execution**.
    ///
    /// True from [`Phase::Combine`] on: the root carries `flag_complete`, so the in-circuit
    /// continuity assertions ran and the chunks are pinned into a single run. Below it the chunks
    /// are each proved, each carries exit code 0, and their global cumulative sums cancel, but
    /// nothing ties them into one execution: chunk continuity is enforced only at Combine. A caller
    /// that needs the stronger guarantee checks this rather than the phase.
    pub fn binds_complete_execution(&self) -> bool {
        self.phase >= Phase::Combine
    }

    /// The lean pre-hash of the verifying key this proof verifies under. `None` for
    /// [`Phase::Embed`] and [`Phase::Wrap`], whose keys live under the outer config and whose
    /// digests are not KoalaBear limbs.
    ///
    /// A [`Phase::Convert`] proof is a set with one key per chunk layout, and this is the key of
    /// the set's first proof only: two sets that share a first key report the same value.
    ///
    /// Not a program identity: under `verify_keys(true)` it is the same for every program by
    /// design, because whitelist mode fixes the key's shape. [`Self::program_id`] is the identity.
    pub fn vk_pre_hash(&self) -> Option<[u32; 8]> {
        self.koalabear_vk().map(|vk| digest_words(&vk.pre_hash))
    }

    /// The merged-preprocessed commitment of that key, for a recursion proof; for a
    /// [`Phase::Convert`] set, the first proof's key, as in [`Self::vk_pre_hash`].
    pub fn vk_merged_commit(&self) -> Option<[u32; 8]> {
        self.koalabear_vk()?
            .inner
            .merged_preprocessed_commit
            .as_ref()
            .map(digest_words)
    }

    /// The key of a phase up to [`Phase::Combine`]; a convert set's first proof stands for the set.
    fn koalabear_vk(&self) -> Option<&VerifyingKey> {
        match &self.payload {
            Payload::Riscv(bundle) => Some(&*bundle.vk),
            Payload::Convert(proofs) => proofs.first().map(|(_, vk)| &**vk),
            Payload::Combine(root) => Some(&*root.1),
            #[cfg(feature = "multi-field-transcript")]
            Payload::Embed(_) | Payload::Wrap { .. } => None,
        }
    }

    /// Log2 of the stacked trace height the chain was proved at.
    pub fn log_stacked_height(&self) -> usize {
        self.log_stacked_height
    }

    /// Whether the whitelist was on.
    pub fn verify_keys(&self) -> bool {
        self.verify_keys
    }

    /// Write a container a fresh process can load with [`crate::ProofArtifact::read`].
    ///
    /// Only [`Phase::Riscv`] and [`Phase::Combine`] can be written: those are the two the single
    /// verification entry point can answer for from a file. See [`crate::ProofArtifact`].
    pub fn write(&self, path: impl AsRef<Path>) -> Result<(), ProveError> {
        crate::artifact::write(self, path.as_ref())
    }

    /// How many individual proofs the payload holds: one per chunk up to [`Phase::Convert`], one
    /// at every phase after it.
    pub fn proof_count(&self) -> usize {
        match &self.payload {
            Payload::Riscv(bundle) => bundle.chunk_proofs.len(),
            Payload::Convert(proofs) => proofs.len(),
            Payload::Combine(_) => 1,
            #[cfg(feature = "multi-field-transcript")]
            Payload::Embed(_) | Payload::Wrap { .. } => 1,
        }
    }

    /// The payload's size in the canonical wire codec — what would actually be transmitted or
    /// stored, the verifying key excluded.
    ///
    /// Costs one full serialization; intended for reporting, not a hot path.
    pub fn size_bytes(&self) -> Result<usize, ProveError> {
        let size = |encoded: std::io::Result<Vec<u8>>| -> Result<usize, ProveError> {
            encoded
                .map(|b| b.len())
                .map_err(|e| ProveError::io("cannot encode a proof", e))
        };
        match &self.payload {
            Payload::Riscv(bundle) => bundle
                .chunk_proofs
                .iter()
                .try_fold(0usize, |acc, p| Ok(acc + size(p.encode_to_vec())?)),
            Payload::Convert(proofs) => proofs
                .iter()
                .try_fold(0usize, |acc, (p, _)| Ok(acc + size(p.encode_to_vec())?)),
            Payload::Combine(root) => size(root.0.encode_to_vec()),
            #[cfg(feature = "multi-field-transcript")]
            Payload::Embed((p, _)) => size(p.encode_to_vec()),
            #[cfg(feature = "multi-field-transcript")]
            Payload::Wrap { embed, .. } => size(embed.0.encode_to_vec()),
        }
    }

    /// The gnark circuit and witness of a [`Phase::Wrap`] proof.
    ///
    /// Neither path is replaced until both files are written. A failed write leaves the old pair;
    /// a witness that cannot be moved into place takes the new circuit with it. Short of the
    /// process dying between the two moves, a new circuit is never left beside an old witness.
    ///
    /// Refused before anything is written: a path that is not valid UTF-8, and two paths that
    /// would collide, the same path twice among them.
    #[cfg(feature = "multi-field-transcript")]
    pub fn write_wrap_artifacts(
        &self,
        constraints: impl AsRef<Path>,
        witness: impl AsRef<Path>,
    ) -> Result<(), ProveError> {
        let Payload::Wrap { artifacts, .. } = &self.payload else {
            return Err(ProveError::InconsistentOptions(format!(
                "wrap artifacts exist only on a Phase::Wrap proof; this one stops at {}",
                self.phase
            )));
        };
        write_wrap_files(artifacts, constraints.as_ref(), witness.as_ref())
    }
}

/// The file name the gnark circuit is written under. The gnark prover reads
/// `./data/constraints.json` unless given `-constraints`.
#[cfg(feature = "multi-field-transcript")]
pub const WRAP_CONSTRAINTS_FILE: &str = "wrap_constraints.json";
/// The file name the gnark witness is written under, beside [`WRAP_CONSTRAINTS_FILE`]. The gnark
/// prover reads `./data/groth16_witness.json` unless given `-witness`.
#[cfg(feature = "multi-field-transcript")]
pub const WRAP_WITNESS_FILE: &str = "wrap_groth16_witness.json";

/// Write both files beside their destinations, then move them into place.
///
/// `WrapArtifacts::save` panics when it cannot write the witness, so it runs under `catch_unwind`
/// and only ever on the staged paths.
#[cfg(feature = "multi-field-transcript")]
pub(crate) fn write_wrap_files(
    artifacts: &WrapArtifacts,
    constraints: &Path,
    witness: &Path,
) -> Result<(), ProveError> {
    let staged = [staged_path(constraints)?, staged_path(witness)?];
    // Each move must leave the other three paths alone.
    if constraints == witness || staged[0] == witness || staged[1] == constraints {
        return Err(ProveError::io(
            format!(
                "{} and {} collide as wrap artifact paths",
                constraints.display(),
                witness.display()
            ),
            std::io::ErrorKind::InvalidInput.into(),
        ));
    }
    let staged_str = [utf8(&staged[0])?, utf8(&staged[1])?];
    let discard = || {
        for path in &staged {
            let _ = std::fs::remove_file(path);
        }
    };

    let saved = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        artifacts.save(staged_str[0], staged_str[1])
    }));
    let failure = match saved {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(e.to_string()),
        Err(payload) => Some(crate::prover::panic_message(&*payload)),
    };
    if let Some(message) = failure {
        discard();
        return Err(ProveError::io(
            "cannot write the wrap artifacts",
            std::io::Error::other(message),
        ));
    }

    let moved = |from: &Path, to: &Path| {
        std::fs::rename(from, to).map_err(|e| {
            ProveError::io(
                format!("cannot move the wrap artifacts into {}", to.display()),
                e,
            )
        })
    };
    if let Err(e) = moved(&staged[0], constraints) {
        discard();
        return Err(e);
    }
    if let Err(e) = moved(&staged[1], witness) {
        discard();
        // The new circuit is in place without its witness, and must not pair with the old one.
        let _ = std::fs::remove_file(constraints);
        return Err(e);
    }
    Ok(())
}

/// Where `path` is written before it is moved into place: beside it, so the move stays on one
/// filesystem, and named by process, so two processes writing one directory do not share it.
#[cfg(feature = "multi-field-transcript")]
pub(crate) fn staged_path(path: &Path) -> Result<std::path::PathBuf, ProveError> {
    let name = path.file_name().ok_or_else(|| {
        ProveError::io(
            format!("{} names no file", path.display()),
            std::io::ErrorKind::InvalidInput.into(),
        )
    })?;
    let mut staged = name.to_os_string();
    staged.push(format!(".{}.partial", std::process::id()));
    Ok(path.with_file_name(staged))
}

/// The vm's writer takes `&str`; a lossy conversion would write somewhere the caller never named.
#[cfg(feature = "multi-field-transcript")]
fn utf8(path: &Path) -> Result<&str, ProveError> {
    path.to_str().ok_or_else(|| {
        ProveError::io(
            format!("{} is not valid UTF-8", path.display()),
            std::io::ErrorKind::InvalidInput.into(),
        )
    })
}

impl std::fmt::Debug for Proof {
    /// Identities and counts only: the payload is megabytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proof")
            .field("phase", &self.phase)
            .field("program_id", &self.program_id)
            .field("log_stacked_height", &self.log_stacked_height)
            .field("verify_keys", &self.verify_keys)
            .field("chunk_count", &self.chunk_count)
            .field("distinct_shapes", &self.distinct_shapes)
            .field(
                "committed",
                &format_args!("{} byte(s)", self.committed.len()),
            )
            .finish()
    }
}
