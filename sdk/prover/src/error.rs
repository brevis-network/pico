//! The one error type the crate returns, and the reader error beside it.

use pico_mle_core::config::soundness::UnderBudgetError;
use pico_vm::{
    emulator::riscv::{emulator::error::EmulationError, syscalls::SyscallCode},
    mle::machine::{riscv::EmulateError, vk_map::VkMapError},
};

use crate::phase::Phase;

/// Why a prove, a load or a verification did not produce a proof.
///
/// Composes the typed errors the VM already defines rather than restating them: [`EmulateError`]
/// and [`VkMapError`] arrive by `#[from]`, and the emulator's own `UnsupportedSyscall` is lifted
/// into [`ProveError::UnsupportedSyscall`] so the caller is told which precompile its guest needs
/// instead of being handed an opcode number.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProveError {
    /// The ELF handed to the builder is not a program this VM can run. Reported by
    /// [`crate::ProverBuilder::build`] and [`crate::ProverBuilder::execute`].
    #[error("invalid ELF: {0}")]
    InvalidElf(String),

    /// The emulation did not reach a halt.
    #[error(transparent)]
    Emulate(#[from] EmulateError),

    /// The emulator aborted on this guest or input instead of returning an error. Every input to
    /// emulation is the caller's or the guest's, so the abort is reported rather than let through
    /// to the embedding process.
    ///
    /// Caught by unwinding, so only a binary that unwinds on panic sees this; built with
    /// `panic = "abort"`, the process exits instead.
    #[error("the emulator aborted: {0}")]
    EmulationAborted(String),

    /// The guest called a syscall this VM does not implement. Every syscall the machine serves is
    /// in the chip list and the syscall map; a guest that needs one outside it cannot be proved
    /// here, whatever the host does.
    #[error("guest called syscall {code:#x} ({name}), which this VM does not implement")]
    UnsupportedSyscall { code: u32, name: String },

    /// The guest ran on chips the emulator serves but the RISC-V machine has no AIR for, so the
    /// run cannot be proved. Reported before anything is proved, naming each such chip.
    #[error("the run used chip(s) {chips:?}, which this machine emulates but cannot prove")]
    UnsupportedChip { chips: Vec<String> },

    /// The options do not describe a provable shape.
    #[error("{0}")]
    InconsistentOptions(String),

    /// [`crate::ProverBuilder::aot`] was given the bootstrap stub, which has no compiled code.
    #[cfg(feature = "aot")]
    #[error(
        "the AOT program is the bootstrap stub, which has no compiled code: run `cargo pico aot` \
         on the guest's ELF, then rebuild"
    )]
    AotNotGenerated,

    /// [`crate::ProverBuilder::aot`] was given code generated from another ELF than the builder's:
    /// a stale generated crate, whose snapshots would not be this program's.
    #[cfg(feature = "aot")]
    #[error(
        "the AOT program was generated from the ELF with SHA-256 {}, and the prover's ELF has \
         SHA-256 {}: run `cargo pico aot` on this ELF, then rebuild",
        hex(.generated_from),
        hex(.elf)
    )]
    AotElfMismatch {
        generated_from: [u8; 32],
        elf: [u8; 32],
    },

    /// The process cannot take this AOT program: it holds a different one, or AOT code installed
    /// without `pico_aot_runtime::register`.
    #[cfg(any(feature = "aot", feature = "cuda"))]
    #[error("cannot register the AOT program: {0}")]
    AotRegistration(#[source] pico_aot_runtime::AotError),

    /// An element of [`crate::Stdin`] could not be serialized, so the guest would not read what
    /// the caller wrote. Recorded where it happened and reported here, because the setter that
    /// produced it chains and has no error to return.
    #[error("stdin element {index} could not be serialized: {message}")]
    InvalidInput { index: usize, message: String },

    /// A phase whose implementation is compiled out was requested.
    #[error("`Phase::{phase:?}` needs the `{feature}` feature; rebuild with it enabled")]
    FeatureMissing { phase: Phase, feature: &'static str },

    /// A machine failed to produce a proof.
    #[error("{phase:?}: proving failed: {message}")]
    Proving { phase: Phase, message: String },

    /// A proof did not verify, or its public values fail a check this crate makes on them: a
    /// readable output digest, copies of it that agree, a global cumulative sum and an exit code on
    /// every chunk, a wrap witness that matches the proof. Whether it was produced by this run or
    /// loaded by [`crate::Prover::verify_artifact`].
    #[error("{phase:?}: the proof does not verify: {message}")]
    Verification { phase: Phase, message: String },

    /// Under `verify_keys(true)`, a verifying key this run needs is not a member of the loaded
    /// whitelist, so nothing proved under it could verify against that whitelist.
    #[error(
        "{phase:?}: {missing} of this run's verifying key(s) are not in the whitelist, which does \
         not cover this guest's shapes"
    )]
    KeyNotWhitelisted { phase: Phase, missing: usize },

    /// The whitelist artifact could not be loaded or rebuilt.
    #[error(transparent)]
    VkMap(#[from] VkMapError),

    /// Keygen produced a verifying key that scores below the production soundness budget, so it
    /// is refused rather than proved under.
    #[error(transparent)]
    UnderBudget(#[from] UnderBudgetError),

    /// The loaded whitelist rebuilds a root other than the one pinned out of band. Self-consistency
    /// is all the artifact can prove about itself; this is the check that makes it authentic.
    #[error(
        "whitelist root mismatch: artifact rebuilds {loaded:?}, the pinned root is {pinned:?}"
    )]
    VkRootMismatch { loaded: [u32; 8], pinned: [u32; 8] },

    /// The container is not one this build can read: no header, a body or a stored proof that does
    /// not decode, a stored program id that is not canonical. Also a container body that cannot be
    /// encoded.
    #[error("not a readable proof artifact: {0}")]
    Format(String),

    /// The GPU pipeline failed or produced no root.
    #[cfg(feature = "cuda")]
    #[error("GPU proving failed: {0}")]
    Gpu(String),

    /// A previous GPU prove failed in this process and may have left the pipeline mid-run; restart
    /// the process to prove on the GPU again.
    #[cfg(feature = "cuda")]
    #[error("a previous GPU prove failed in this process; restart the process to prove again")]
    GpuPoisoned,

    /// The container was written by a different container format.
    #[error("proof artifact format version mismatch: expected {expected}, file claims {found}")]
    FormatVersion { expected: u32, found: u32 },

    /// The container holds proofs in a wire format this build does not speak. Reported before any
    /// verification runs, because "re-prove with a matching build" is a different instruction from
    /// "this proof is invalid".
    #[error("proof codec version mismatch: expected {expected}, file claims {found}")]
    CodecVersion { expected: u32, found: u32 },

    /// The verifying key the container's body decodes to does not hash to the pre-hash its header
    /// names, or does not carry that pre-hash itself. Both come from the same file, so this is
    /// internal consistency rather than authenticity: what it catches is a container whose stored
    /// types this build serializes differently, or a key whose body was altered under its original
    /// identity.
    #[error(
        "the container's verifying key does not match its header: the header names {header:?}, \
         the body's key hashes to {decoded:?} — re-prove with a matching build"
    )]
    VkIdentityMismatch { header: [u32; 8], decoded: [u32; 8] },

    /// The file attests to a different program than the one this prover holds.
    #[error("program mismatch: the artifact attests to {found}, this prover holds {expected}")]
    ProgramMismatch {
        expected: crate::prover::ProgramId,
        found: crate::prover::ProgramId,
    },

    /// The file was produced at a different operating point. The caller's expectation decides; a
    /// verifier that silently re-keygen'd to match the file would be taking the file's word for the
    /// shape it is verified under.
    #[error(
        "operating point mismatch: the artifact was proved at log_stacked_height \
         {found_log_stacked_height} with verify_keys = {found_verify_keys}, this prover is at \
         {expected_log_stacked_height} with verify_keys = {expected_verify_keys}"
    )]
    OperatingPointMismatch {
        expected_log_stacked_height: usize,
        found_log_stacked_height: usize,
        expected_verify_keys: bool,
        found_verify_keys: bool,
    },

    /// The committed bytes in the container do not hash to the `committed_value_digest` the proof
    /// commits to. They are not this proof's output.
    #[error(
        "committed bytes are not bound to this proof: SHA-256 of the stored bytes does not equal \
         the verified proof's committed_value_digest"
    )]
    CommittedValuesUnbound,

    /// A verified RISC-V bundle's public values carry a non-zero exit code in chunk `chunk`.
    #[error("chunk {chunk}'s public values carry exit code {exit_code}, not 0")]
    NonZeroExitCode { chunk: usize, exit_code: u32 },

    /// A recursion proof was offered for verification with no authenticated key set. The recursion
    /// shape is not a function of the ELF, so there is nothing to derive an honest key from, and
    /// keygen'ing from the file's own layouts would let it choose the circuit it is checked
    /// against.
    #[error(
        "verifying a {phase:?} proof needs an authenticated whitelist: build the prover with \
         `verify_keys(true)`, `vk_map(path)` and `trusted_vk_root(root)`, or verify it on the \
         prover that produced it"
    )]
    WhitelistRequired { phase: Phase },

    /// `Prover::prove_evm` on a prover built without the whitelist. Outside whitelist mode the wrap
    /// circuit bakes in no whitelist root, so it is a different circuit from the one the on-chain
    /// verifier is set up for, and no deployed verifier accepts a proof of it.
    #[error(
        "an on-chain proof needs whitelist mode: build the prover with `verify_keys(true)`, \
         `vk_map(path)` and `trusted_vk_root(root)`. `prove_to(stdin, Phase::Wrap)` proves without \
         it, for testing"
    )]
    EvmRequiresWhitelist,

    /// `Prover::prove_evm` on a guest that never ran the COMMIT ecall. Its proof commits to an
    /// all-zero digest, which is not the SHA-256 of any public values a caller could present, so
    /// no on-chain verifier would accept it. A guest built on `pico-sdk`'s entrypoint always
    /// commits, even with no output.
    #[error(
        "an on-chain proof needs a committed digest, and this guest never ran the COMMIT ecall: \
         end it through pico-sdk's entrypoint"
    )]
    EvmNoCommittedDigest,

    /// `what` exists only for a whitelist-mode proof or prover: the VK bundle and the v3 envelope
    /// name the whitelist a verifier pins, and outside whitelist mode there is none.
    #[error(
        "{what} needs whitelist mode: build the prover with `shipped_whitelist()`, or \
         `verify_keys(true)` with `vk_map(path)` and `trusted_vk_root(root)`"
    )]
    WhitelistModeRequired { what: &'static str },

    /// [`crate::Proof::export_v3`] on a proof that does not stop at [`Phase::Combine`].
    #[error("only a Combine root exports as a v3 envelope; this proof stops at {phase:?}")]
    NotARootProof { phase: Phase },

    /// The phase has no verification path that works from a container alone, in any configuration.
    #[error("a {phase:?} proof cannot be verified from a file in a fresh process")]
    UnverifiableInFreshProcess { phase: Phase },

    /// A root proof that does not claim to be complete. None of the in-circuit completeness
    /// assertions ran, so it attests to a fragment of an execution rather than to one.
    #[error("the proof is not a complete root (flag_complete != 1)")]
    Incomplete,

    /// Reading or writing a file failed.
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
}

impl ProveError {
    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    pub(crate) fn proving(phase: Phase, message: impl Into<String>) -> Self {
        Self::Proving {
            phase,
            message: message.into(),
        }
    }

    /// Also a proof whose public values fail a check made on them: a property of the proof, not of
    /// any file it came from.
    pub(crate) fn verification(phase: Phase, message: impl Into<String>) -> Self {
        Self::Verification {
            phase,
            message: message.into(),
        }
    }

    /// Lift an emulation failure, naming the syscall when that is what went wrong.
    pub(crate) fn from_emulate(error: EmulateError) -> Self {
        if let EmulateError::Emulation(EmulationError::UnsupportedSyscall(code)) = &error {
            return Self::UnsupportedSyscall {
                code: *code,
                name: SyscallCode::try_from_u32(*code)
                    .map_or_else(|| "unrecognised".to_string(), |c| format!("{c:?}")),
            };
        }
        Self::Emulate(error)
    }

    /// Lift a GPU pipeline failure, keeping a poisoned process distinguishable.
    #[cfg(feature = "cuda")]
    pub(crate) fn from_embed(error: distributed_vm::mle::embed::EmbedError) -> Self {
        match error {
            distributed_vm::mle::embed::EmbedError::Poisoned => Self::GpuPoisoned,
            other => Self::Gpu(other.to_string()),
        }
    }
}

#[cfg(feature = "aot")]
fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Why a value could not be read out of [`crate::CommittedValues`].
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// The bytes at the cursor are not a `T` in the encoding the guest's `io::commit` writes.
    #[error("cannot decode the committed bytes at offset {offset}: {source}")]
    Decode {
        offset: usize,
        #[source]
        source: bincode::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unsupported_syscall_arrives_named() {
        let lifted = ProveError::from_emulate(EmulateError::Emulation(
            EmulationError::UnsupportedSyscall(SyscallCode::SHA_EXTEND as u32),
        ));
        match lifted {
            ProveError::UnsupportedSyscall { code, name } => {
                assert_eq!(code, SyscallCode::SHA_EXTEND as u32);
                assert_eq!(name, "SHA_EXTEND");
            }
            other => panic!("expected UnsupportedSyscall, got {other}"),
        }
    }

    #[test]
    fn a_code_outside_the_map_is_still_a_syscall_failure() {
        let lifted = ProveError::from_emulate(EmulateError::Emulation(
            EmulationError::UnsupportedSyscall(0xDEAD_BEEF),
        ));
        match lifted {
            ProveError::UnsupportedSyscall { code, name } => {
                assert_eq!(code, 0xDEAD_BEEF);
                assert_eq!(name, "unrecognised");
            }
            other => panic!("expected UnsupportedSyscall, got {other}"),
        }
    }

    #[test]
    fn any_other_emulation_failure_keeps_its_variant() {
        let lifted = ProveError::from_emulate(EmulateError::Emulation(
            EmulationError::HaltWithNonZeroExitCode(1),
        ));
        assert!(matches!(lifted, ProveError::Emulate(_)), "got {lifted}");
    }
}
