//! Take an ELF and an input; get back a verified proof.
//!
//! ```no_run
//! use pico_prover::{Prover, Stdin};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let elf = std::fs::read("app/elf/riscv64im-pico-zkvm-elf")?;
//! let mut prover = Prover::new(&elf)?;
//! let proof = prover.prove(Stdin::from(&10u32))?;
//!
//! // One host read per guest write. `as_bytes` mirrors `io::commit_bytes`: a guest that commits an
//! // ABI-encoded struct that way, such as `PublicValuesStruct` in `examples/fibonacci/lib`, is
//! // decoded from these bytes with the same type, `PublicValuesStruct::abi_decode(bytes, true)`.
//! let committed = proof.committed();
//! let bytes: &[u8] = committed.as_bytes();
//!
//! // `read::<T>()` mirrors `io::commit(&T)` instead. On ABI-encoded bytes it decodes the words'
//! // leading zero padding, and reports no error.
//! # let _ = bytes;
//! # Ok(())
//! # }
//! ```
//!
//! The example is compiled, not run: proving takes minutes, and compiling it is what keeps it in
//! step with the API.
//!
//! [`Prover::prove`] emulates, proves every phase to [`Phase::Combine`], **verifies the result**,
//! and binds the guest's committed bytes to it by SHA-256 before returning. There is no separate
//! verify step and no way to hold an unverified [`Proof`]: bytes sitting beside a proof are not
//! proof-authenticated output, and this API does not let them look like it.
//!
//! [`Prover::prove_to`] stops at any [`Phase`]. `Prover::prove_evm` proves to [`Phase::Wrap`] in
//! whitelist mode only, and returns an `EvmBundle`: the gnark inputs and the wrap circuit's two
//! public inputs. [`Prover::execute`] emulates without proving, and returns an [`Execution`] whose
//! bytes are explicitly *not* authenticated. [`ProverBuilder::execute`] does the same without
//! keygen.
//!
//! # Verifying outside this crate
//!
//! In whitelist mode ([`ProverBuilder::shipped_whitelist`] needs no files), [`Prover::vk_bundle`]
//! and [`Proof::export_v3`] give the bytes `pico_verifier::verify(bundle, envelope, committed)`
//! takes, on stable Rust and without this crate. Under a whitelist other than the shipped one,
//! `pico_verifier::verify_with_root` takes its root.
//!
//! # Persisting a proof
//!
//! [`Proof::write`] and [`ProofArtifact::read`] move a proof between processes, and
//! [`Prover::verify_artifact`] is the single entry point that can answer for one. What it can
//! answer depends on the phase, and the asymmetry is real rather than a limitation of the
//! implementation: a RISC-V verifying key is a function of the program, so a verifier holding the
//! ELF can derive it, while a recursion circuit's shape is not, so a verifier has nothing to derive
//! an honest key from and needs an authenticated whitelist. [`Prover::verify_artifact`] documents
//! what each phase is bound to.
//!
//! # What the options decide, and what they do not
//!
//! Every [`ProverBuilder`] setter outranks the environment: the emulator options are constructed
//! field by field rather than from `EmulatorOpts::default`, which reads three variables, and the
//! proving concurrency is passed as an argument rather than left to `PROVE_CONCURRENCY`.
//!
//! What remains environment-controlled is stated here rather than implied, variable by variable:
//!
//! | variable | read by | reaches this crate? |
//! |---|---|---|
//! | `CHUNK_SIZE` | `EmulatorOpts::default` | **no** — superseded by [`ProverBuilder::chunk_size`] |
//! | `CHUNK_BATCH_SIZE` | `EmulatorOpts::default` | **no** — stated as 1, the VM's own pin |
//! | `SPLIT_THRESHOLD` | `EmulatorOpts::default` | **no** — derived from the chunk size, and the record split on this path reads none of the split options |
//! | `PROVE_CONCURRENCY` | `RiscvMachine::prove` | **no** — superseded by [`ProverBuilder::concurrency`] |
//! | `MLE_VK_ROOT` | `MleVkMap::try_load` | **no** — the whitelist is loaded without it, and [`ProverBuilder::trusted_vk_root`] pins the root |
//! | `CHUNK_EVENT_LIMITS_OFF`, `CHUNK_EVENT_LIMIT_SCALE` | chunk splitting | **yes, and refused by [`ProverBuilder::build`]**: switched off, or scaled above 1, the event limits let a chunk's memory events outgrow `2^log_stacked_height`, which depends on the guest's data and so cannot be checked before proving. [`ProverBuilder::execute`] refuses them too, so it chunks as a built prover would. A scale the VM does not parse, or outside 1 to 16, it reads as 1, and so does the check |
//! | `CHUNK_COMMIT_TAIL_HOLD_OFF` | chunk splitting | **yes, and it breaks proving**: `1` lets a chunk end inside the guest's commit tail, which the recursion rejects; it exists for tests that need such a cut |
//! | `DEFERRED_TAIL_MERGE` | the deferred memory split | **yes, and it changes the proof**: `0` gives every deferred bucket its own record |
//! | `MLE_FORCE_CATCH_ALL` | whitelist-mode shape selection | **yes, and it changes the proof**: every chunk takes the catch-all shape |
//! | `RECURSION_EARLY_EXIT_TS` | recursion emulation | **yes, and it breaks proving**: it truncates the recursion run, and a value that does not parse aborts |
//! | `MLE_WITNESS_HASH`, `MLE_TRANSCRIPT_PROF`, `MLE_WALKER_XCHECK` | recursion witness generation | **yes**, and deliberately |
//! | `MLE_REC_PARALLEL_CHILDREN` | recursion node interpretation | **yes**, and deliberately |
//! | `MEMORY_POOL_SIZE` | the AOT pipeline's memory pool | **yes, with the `aot` feature**: the pool holds this many emulator memories. A replay worker keeps one between its batches, so the run needs one per worker plus one per segment of the batch being cut: unset, it is raised to that, and a smaller value is refused by `build` and `execute` |
//! | `MEMORY_POOL_EAGER`, `MEMORY_POOL_LOW_WATER`, `MEMORY_RECYCLER_THREADS` | the AOT pipeline's memory pool | **yes, with the `aot` feature**: how the pool is filled and recycled. A setting that leaves the pool empty, or `MEMORY_RECYCLER_THREADS=0`, which never returns a memory to it, is refused by `build` and `execute` |
//! | `MLE_SPLIT_REPLAY`, `MLE_SPLIT_CHUNKS`, `NUM_THREADS`, `PROVER_COUNT` | the AOT snapshot thread | **yes, with the `aot` feature**: whether the replay of the leading chunks is cut into segments, which the workers fold back into one record per chunk. `NUM_THREADS` and `PROVER_COUNT` cut only together, and neither sets the worker count. A cut into more segments than the pool holds is refused by `build` and `execute` |
//! | `MLE_RECORD_DIGEST` | the AOT pipeline's workers | with the `aot` feature, as a diagnostic only: `1` logs a digest of every record |
//! | `MLE_SHAPE_MARGIN`, `CHUNK_SPLIT_DEBUG`, `DEBUG_MEMORY_EVENTS`, `DEBUG_LOCAL_MEMORY` | logging | yes, as diagnostics only |
//!
//! The six proof-changing variables are experiment or test knobs; leave them unset. A caller that
//! sets one of the four not refused gets proofs another process with the same options would not
//! produce.
//! `CHUNK_EVENT_LIMITS_OFF`, `CHUNK_EVENT_LIMIT_SCALE` and `DEFERRED_TAIL_MERGE` are read once per
//! process, the other three on every use. The AOT pipeline's variables take effect once per
//! process, on its first run.
//!
//! The witness and interpretation rows are four process-global diagnostics and controls, each
//! resolved once per process on first use — the VM lists them as one table, `witness_flags`. Three
//! are measurement knobs, default off; `MLE_REC_PARALLEL_CHILDREN` interprets a combine node's two
//! children concurrently, and defaults **on**. None of these is a builder option, and none can be:
//! by the time a `Prover` exists they may already be resolved, so a setter would be a promise this
//! crate could not keep.
//!
//! `MLE_WITNESS_WALKER`, `MLE_WITNESS_PARALLEL` and `MLE_WITNESS_XCHECK` are no longer read: the
//! recursion witness always takes the transcript-only derive, one child after another.
//! [`ENV_NO_LONGER_READ`] lists them, so a caller can warn that setting one does nothing.
//!
//! # AOT emulation
//!
//! With the `aot` feature, `ProverBuilder::aot` emulates with the guest's AOT-compiled code, which
//! `cargo pico aot` generates: the AOT code runs ahead in the snapshot pipeline, and interpreters
//! replay its snapshots into the records. It changes how the records are made, not what is
//! proved.
//!
//! # Not here
//!
//! The Groth16 proving key, the Groth16 proof and the on-chain verifier are made outside this
//! crate: its EVM path stops at the two files the gnark prover is given.
//! `cargo pico prove --evm` takes them the rest of the way with gnark, and `contracts/` holds the
//! verifier.

mod artifact;
mod binding;
mod committed;
mod error;
#[cfg(feature = "multi-field-transcript")]
mod evm;
mod phase;
mod proof;
mod prover;
mod stdin;
mod types;

pub use artifact::{ProofArtifact, FORMAT_VERSION};
pub use committed::CommittedValues;
pub use error::{ProveError, ReadError};
#[cfg(feature = "multi-field-transcript")]
pub use evm::EvmBundle;
pub use phase::Phase;
pub use proof::Proof;
#[cfg(feature = "multi-field-transcript")]
pub use proof::{WRAP_CONSTRAINTS_FILE, WRAP_WITNESS_FILE};
pub use prover::{Execution, ProgramId, Prover, ProverBuilder};
pub use stdin::Stdin;

/// The proof wire-format version this build reads and writes. A container recording a different
/// one is rejected by name before any verification runs.
pub use pico_mle_core::proof::CODEC_VERSION;

/// The variables the crate documentation's table marks, in bold, as reaching it, each with what
/// setting one does; the logging diagnostics are left out, and the AOT pipeline's are listed only
/// with the `aot` feature. No [`ProverBuilder`] option overrides them, so a caller that reads its
/// options from the environment warns about these.
pub const ENV_READ_BY_PROVER: &[(&str, &str)] = &[
    (
        "CHUNK_EVENT_LIMITS_OFF",
        "is refused by `ProverBuilder::build` when it is 1",
    ),
    (
        "CHUNK_EVENT_LIMIT_SCALE",
        "is refused by `ProverBuilder::build` above 1; outside 1 to 16 the VM reads it as 1",
    ),
    (
        "CHUNK_COMMIT_TAIL_HOLD_OFF",
        "lets a chunk end inside the commit tail and breaks proving",
    ),
    ("DEFERRED_TAIL_MERGE", "can change the proof"),
    ("MLE_FORCE_CATCH_ALL", "can change the proof"),
    (
        "RECURSION_EARLY_EXIT_TS",
        "can truncate the recursion run and break proving",
    ),
    ("MLE_WITNESS_HASH", "is a recursion witness diagnostic"),
    ("MLE_TRANSCRIPT_PROF", "is a recursion witness diagnostic"),
    ("MLE_WALKER_XCHECK", "is a recursion witness diagnostic"),
    (
        "MLE_REC_PARALLEL_CHILDREN",
        "selects how recursion nodes are interpreted",
    ),
    #[cfg(feature = "aot")]
    (
        "MEMORY_POOL_SIZE",
        "caps the AOT replay workers running at once; 0 is refused",
    ),
    #[cfg(feature = "aot")]
    (
        "MEMORY_POOL_EAGER",
        "sizes how the AOT memory pool is filled",
    ),
    #[cfg(feature = "aot")]
    (
        "MEMORY_POOL_LOW_WATER",
        "sizes how the AOT memory pool is filled",
    ),
    #[cfg(feature = "aot")]
    (
        "MEMORY_RECYCLER_THREADS",
        "sizes how the AOT memory pool is recycled; 0 is refused",
    ),
    #[cfg(feature = "aot")]
    (
        "MLE_SPLIT_REPLAY",
        "decides whether AOT chunk replays are cut into segments",
    ),
    #[cfg(feature = "aot")]
    (
        "MLE_SPLIT_CHUNKS",
        "decides how many AOT chunk replays are cut into segments",
    ),
    #[cfg(feature = "aot")]
    (
        "NUM_THREADS",
        "with PROVER_COUNT, decides whether AOT chunk replays are cut into segments",
    ),
    #[cfg(feature = "aot")]
    (
        "PROVER_COUNT",
        "with NUM_THREADS, decides whether AOT chunk replays are cut into segments",
    ),
];

/// Variables the prover read once and reads no longer, each with what stands in its place. A run
/// that sets one gets none of what it asked for, so a caller that warns about
/// [`ENV_READ_BY_PROVER`] warns about these too.
pub const ENV_NO_LONGER_READ: &[(&str, &str)] = &[
    (
        "MLE_WITNESS_WALKER",
        "the recursion witness always takes the transcript-only derive",
    ),
    (
        "MLE_WITNESS_PARALLEL",
        "the recursion witness derives a combine node's children one after another",
    ),
    (
        "MLE_WITNESS_XCHECK",
        "the recursion witness has no concurrent derive; MLE_WALKER_XCHECK checks the derive",
    ),
];

#[cfg(test)]
mod tests;
