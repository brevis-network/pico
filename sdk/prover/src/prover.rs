//! The prover: keygen once, prove many, verify before returning.

use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroUsize,
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

use pico_mle_core::{
    config::{
        compress_params_with_128_bits_security, recursion_params_with_128_bits_security,
        try_riscv_params_with_128_bits_security, MAX_RISCV_LOG_STACKED_HEIGHT,
    },
    p3_field::PrimeField32,
    AirRef, StarkEngine,
};
#[cfg(feature = "cuda")]
use pico_vm::proverchain::riscv::default_pipeline_workers;
use pico_vm::{
    compiler::{
        program::ProgramBehavior,
        riscv::{
            compiler::{Compiler, SourceType},
            program::Program,
        },
    },
    emulator::{
        opts::{EmulatorOpts, ReplayWorkers, SnapshotMainMode},
        riscv::{
            chunk_split::{event_limit_scale, event_limits_off, ChunkSplitConfig},
            record::EmulationRecord,
            syscalls::SyscallCode,
        },
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::{chip::ChipBehavior, report::EmulationReport, septic::SepticDigest},
    mle::machine::{
        apex::MleApexVerifier,
        combine::CombineMachine,
        compress::CompressMachine,
        convert::{ConvertMachine, ProofWithVk},
        exe::RiscvVmVk,
        recursion::extract_recursion_vk_layout,
        riscv::{self, RiscvMachine, RiscvProof},
        vk_bundle::encode_vk_bundle_v2,
        vk_map::{vk_identity, MleVkMap, VkMapError},
    },
    primitives::consts::MAX_LOG_NUMBER_OF_CHUNKS,
    proverchain::riscv::{check_pipeline, max_pipeline_workers},
};
#[cfg(feature = "aot")]
use {
    pico_aot_runtime::AotProgram,
    sha2::{Digest, Sha256},
};

use crate::{
    artifact::{LoadedPayload, ProofArtifact},
    binding,
    cost::CostEstimate,
    error::ProveError,
    phase::Phase,
    proof::{digest_words, Payload, Proof},
    pure::{elf_sha256, PureOptions},
    stdin::Stdin,
    types::{Kb, Sc, VerifyingKey},
    ExecuteEngine, PureExecution, PureLibrary, PureProgram,
};

/// The one stacked height whitelist mode proves at. Its shapes pad `Cpu`, `MemoryReadWrite` and
/// `Global` to `2^23`, which a lower stack cannot pack, and its recursion tiers are sized for a
/// RISC-V proof at 23 (`vm/src/mle/machine/shape.rs`).
pub(crate) const WHITELIST_LOG_STACKED_HEIGHT: usize = riscv::DEFAULT_LOG_STACKED_HEIGHT;

/// One chunk per emulation batch, matching the VM's own pin — a larger batch drops a batch's own
/// precompile events at the sequencer (`vm/src/emulator/opts.rs`).
const CHUNK_BATCH_SIZE: u32 = 1;

/// Chunks proved at once. Stated rather than left to `PROVE_CONCURRENCY`, which the VM would
/// otherwise consult; the value is the VM's own default.
const DEFAULT_CONCURRENCY: NonZeroUsize = NonZeroUsize::new(4).unwrap();

/// Most replay workers a build runs without being told how many. Each holds the snapshot memory of
/// the batch it replays, so the default stops here rather than following the core count up on a
/// large machine; [`ProverBuilder::emulation_workers`] raises it.
pub(crate) const DEFAULT_MAX_EMULATION_WORKERS: usize = 16;

/// Recursion keys a machine keeps between proves at natural heights. A layout there follows each
/// chunk's per-AIR heights, so new inputs bring new keys and an unbounded cache grows with every
/// distinct input a long-lived prover serves. Convert keys past the bound go least recently used
/// first; combine, compress and embed keys past it are dropped all at once.
///
/// In whitelist mode convert keys take [`MAX_RETAINED_WHITELIST_CONVERT_KEYS`], combine node keys
/// are kept (they are among the [`CombineMachine::standard_node_count`] standard nodes, each
/// keygened the first time a tree needs it, about 0.27 GiB of host memory per node key), and
/// compress and embed keep this bound (in whitelist mode compress has one key, the whitelist's
/// compress leaf).
const MAX_RETAINED_KEYS: usize = 16;

/// Convert keys a whitelist-mode prover keeps between proves, least recently used dropped first.
/// Whitelist layouts repeat across inputs (the GPU pipeline's 80 p99 reth blocks share 184, 32 per
/// block on average and up to 40), and a convert key with its program holds about 0.35 GiB of host
/// memory (0.75 GiB for the catch-all row), so the bound holds about 11 GiB.
const MAX_RETAINED_WHITELIST_CONVERT_KEYS: usize = 32;

/// The largest chunk whose clock, four ticks per instruction, fits the AIRs' chunk-clock limbs.
/// The emulator asserts it rather than reporting it. The tallest stack the backend admits is no
/// wider, so `resolved_chunk_size`'s chunk-width check refuses every chunk past it.
const MAX_CHUNK_SIZE: u32 = 1 << (ChunkSplitConfig::MAX_CHUNK_CLK_BITS - 2);
const _: () = assert!(1u64 << MAX_RISCV_LOG_STACKED_HEIGHT <= MAX_CHUNK_SIZE as u64);

/// Which program a proof attests to, at the operating point it was proved at.
///
/// The VM-layer exe identity — program-table commitment, entry pc, initial memory summary — folded
/// into one digest. It moves with the operating point, because the program-table commitment does;
/// that is why a stored proof records the operating point beside it.
///
/// It depends on [`ProverBuilder::verify_keys`] too: whitelist mode pads the program table to a
/// fixed height before committing to it, so one ELF has one id per mode. The whitelist-mode id is
/// the one an on-chain verifier pins, as [`Self::vkey_hash`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProgramId([u32; 8]);

impl ProgramId {
    pub fn as_words(&self) -> [u32; 8] {
        self.0
    }

    /// The id as the wrap circuit's `vkey_hash` public input: the eight words packed base `2^31`,
    /// first word most significant, into one BN254 element, as 32 big-endian bytes.
    ///
    /// Eight KoalaBear words fill 248 bits, below the BN254 modulus, so the packing never reduces.
    pub fn vkey_hash(&self) -> [u8; 32] {
        let mut limbs = [0u64; 4];
        for word in self.0 {
            let mut carry = u128::from(word);
            for limb in &mut limbs {
                let wide = (u128::from(*limb) << 31) + carry;
                *limb = wide as u64;
                carry = wide >> 64;
            }
        }
        let mut out = [0u8; 32];
        for (chunk, limb) in out
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(limbs.iter().rev())
        {
            chunk.copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    #[cfg(test)]
    pub(crate) fn from_words(words: [u32; 8]) -> Self {
        Self(words)
    }

    /// An id read from a file. [`Self::vkey_hash`] is injective only on canonical KoalaBear words,
    /// so a word at or above the modulus could print as the same hex as a different id.
    pub(crate) fn from_stored_words(words: [u32; 8]) -> Result<Self, ProveError> {
        if words.iter().any(|&word| word >= Kb::ORDER_U32) {
            return Err(ProveError::Format(format!(
                "the stored program id {words:?} is not eight canonical KoalaBear words"
            )));
        }
        Ok(Self(words))
    }
}

/// The on-chain spelling, `0x` and [`ProgramId::vkey_hash`] in hex, so a printed id and the one an
/// error names compare as they are.
impl std::fmt::Display for ProgramId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("0x")?;
        for byte in self.vkey_hash() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for ProgramId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProgramId({self})")
    }
}

/// What one emulation produced. **Not proof-authenticated**: nothing here has been proved, so
/// `committed_bytes` is what the emulator says the guest wrote, not what a proof attests to. The
/// authenticated form is [`Proof::committed`], and the two types are deliberately different.
#[derive(Debug)]
pub struct Execution {
    /// The bytes the guest committed, in commit order.
    pub committed_bytes: Vec<u8>,
    /// The emulator's final global clock.
    pub cycles: u64,
    /// How many chunks the run took. Not the record count: the deferred split emits records after
    /// the guest halts.
    pub chunks: u32,
    /// One per emulation batch, in order. Cycle tracking and cost estimation are emulator options
    /// this builder does not expose, so their fields are `None` here; what remains is the per-batch
    /// shape of the run.
    pub reports: Vec<EmulationReport>,
    /// How many times the guest called each precompile, by the exact code it called. The
    /// emulator's own syscall counts coalesce some codes into one — `BLS12381_FP_SUB` and
    /// `BLS12381_FP_MUL` into `BLS12381_FP_ADD`, through `SyscallCode::count_map` — and these do
    /// not. A precompile the run never called has no entry.
    pub precompile_calls: BTreeMap<SyscallCode, u64>,
    /// Loads and stores whose address is not a multiple of their width (Zicclsm), outside
    /// unconstrained blocks: the count the standard RISC-V target asks every proof to report.
    pub misaligned_accesses: u64,
}

/// One emulation: the records proving needs, and what [`Execution`] reports about them.
pub(crate) struct Emulation {
    pub(crate) records: Vec<EmulationRecord>,
    pub(crate) execution: Execution,
}

/// Where a whitelist-mode prover's whitelist comes from.
enum VkMapSource {
    Path(PathBuf),
    Shipped,
}

/// Which emulator makes a run's records. Either way `execute`, and a `cuda` build's GPU prove,
/// run the snapshot pipeline with `workers` interpreters replaying its snapshot thread.
#[derive(Clone, Copy, Debug)]
enum EmulationPath {
    /// One interpreter, on the calling thread: [`ProverBuilder::serial_emulation`].
    Serial,
    /// The snapshot pipeline: a snapshot thread runs ahead, on the registered AOT program or an
    /// interpreter as `snapshot_main` says, and `workers` replay its snapshots into the records,
    /// on interpreters or on the AOT program as `replay_workers` says.
    Pipeline {
        workers: NonZeroUsize,
        snapshot_main: SnapshotMainMode,
        replay_workers: ReplayWorkers,
    },
}

/// Options for a [`Prover`].
///
/// Every knob here outranks the environment. What the options do **not** cover is stated in the
/// crate documentation, variable by variable.
#[cfg_attr(
    not(feature = "aot"),
    doc = "\n\nEmulating with AOT-compiled code needs the crate's `aot` feature; without it there is \
           no `aot` method:\n\n```compile_fail,E0599\nlet _ = \
           pico_prover::Prover::builder(&[]).aot(todo!());\n```"
)]
pub struct ProverBuilder {
    elf: Vec<u8>,
    log_stacked_height: usize,
    chunk_size: Option<u32>,
    concurrency: NonZeroUsize,
    verify_keys: bool,
    vk_map: Option<VkMapSource>,
    trusted_vk_root: Option<[u32; 8]>,
    #[cfg(feature = "aot")]
    aot: Option<&'static AotProgram>,
    #[cfg(feature = "aot")]
    replay_workers: ReplayWorkers,
    emulation_workers: Option<NonZeroUsize>,
    serial_emulation: bool,
    #[cfg(feature = "cuda")]
    gpu_event_pool_size: Option<NonZeroUsize>,
    #[cfg(feature = "cuda")]
    interpreted_aot_runtime: bool,
    pure: PureOptions,
    /// The decoded ELF and its SHA-256, for [`Self::execute`]: a host keeps one builder and
    /// executes many inputs, and a large ELF takes a noticeable share of each run to decode and
    /// hash.
    pure_program: OnceLock<(Arc<Program>, [u8; 32])>,
}

impl ProverBuilder {
    pub(crate) fn new(elf: &[u8]) -> Self {
        Self {
            elf: elf.to_vec(),
            log_stacked_height: riscv::DEFAULT_LOG_STACKED_HEIGHT,
            chunk_size: None,
            concurrency: DEFAULT_CONCURRENCY,
            verify_keys: false,
            vk_map: None,
            trusted_vk_root: None,
            #[cfg(feature = "aot")]
            aot: None,
            #[cfg(feature = "aot")]
            replay_workers: ReplayWorkers::Interpreter,
            emulation_workers: None,
            serial_emulation: false,
            #[cfg(feature = "cuda")]
            gpu_event_pool_size: None,
            #[cfg(feature = "cuda")]
            interpreted_aot_runtime: true,
            pure: PureOptions::default(),
            pure_program: OnceLock::new(),
        }
    }

    /// Log2 of the stacked trace height the chain proves at. Defaults to 23.
    pub fn log_stacked_height(mut self, n: usize) -> Self {
        self.log_stacked_height = n;
        self
    }

    /// Instructions per emulation chunk. Defaults to `1 << log_stacked_height`.
    ///
    /// The snapshot pipeline gives every chunk a memory from its pool, gigabytes of address space,
    /// and resets it before it is used again, so a chunk far below the default makes a long run
    /// slow there; [`Self::serial_emulation`] keeps one memory for the whole run.
    ///
    /// Fixed for the life of the [`Prover`], not per `prove`: in a `cuda` build the pinned host
    /// buffers are sized from this once per process, so two provers in one process would otherwise
    /// silently share whichever resolved first.
    pub fn chunk_size(mut self, n: u32) -> Self {
        self.chunk_size = Some(n);
        self
    }

    /// How many RISC-V chunks are proved at once. Defaults to 4, in both modes.
    ///
    /// Always passed through as an argument, so `PROVE_CONCURRENCY` never decides it. The bound
    /// caps the RISC-V phase's peak memory: one full proving working set per in-flight chunk. It
    /// does not reach [`Phase::Convert`], which proves every chunk's recursion proof at once.
    ///
    /// Measured peak resident memory proving reth block 18884864 (9 RISC-V chunks plus 6
    /// precompile chunks) to [`Phase::Combine`] in whitelist mode at the default stacked height,
    /// with the peak in the RISC-V phase each time: 124 GiB at 1, 150 GiB at 2 and 261 GiB at 4.
    /// 4 is the largest of 1, 2 and 4 whose peak stays within 75% of a 920 GiB machine; a smaller
    /// machine needs a lower setting. With every chunk forced onto the catch-all shape, proving
    /// one at a time peaks at about 413 GiB (measured to [`Phase::Riscv`]), so a block whose chunks
    /// fall to the catch-all should be proved at concurrency 1 even there.
    pub fn concurrency(mut self, n: NonZeroUsize) -> Self {
        self.concurrency = n;
        self
    }

    /// Prove against a finite whitelist of recursion verifying keys: shapes are padded to a fixed
    /// set, and every key a run uses must be a member. Off by default.
    ///
    /// On, it requires both [`Self::vk_map`] and [`Self::trusted_vk_root`]: the artifact can only
    /// prove itself self-consistent, and a root pinned out of band is what makes it authentic. It
    /// also requires the default stacked height, the one its shape tables are sized for.
    pub fn verify_keys(mut self, on: bool) -> Self {
        self.verify_keys = on;
        self
    }

    /// Whether the prover [`Self::build`] makes runs in whitelist mode, known before its keygen.
    pub fn whitelist_mode(&self) -> bool {
        self.verify_keys
    }

    /// The whitelist artifact as `mle_build_vk_map` writes it: the `.bin` form, which is what the
    /// repo ships (`vm/src/mle/shape_vk_bins/`), or its `.json` twin. Read by extension.
    pub fn vk_map(mut self, path: impl Into<PathBuf>) -> Self {
        self.vk_map = Some(VkMapSource::Path(path.into()));
        self
    }

    /// Whitelist mode under the whitelist compiled into this build, pinned to the root shipped
    /// beside it; no file is read at runtime. A [`Self::trusted_vk_root`], when set, must match.
    pub fn shipped_whitelist(mut self) -> Self {
        self.verify_keys = true;
        self.vk_map = Some(VkMapSource::Shipped);
        self
    }

    /// The whitelist root this caller trusts, obtained from somewhere other than the artifact — the
    /// release notes, a configuration file, a contract. The artifact is rejected unless it rebuilds
    /// exactly this.
    ///
    /// Root and entries both live in the artifact, so an attacker who replaces the two together
    /// passes every check the file can make about itself. This is the check it cannot forge.
    pub fn trusted_vk_root(mut self, root: [u32; 8]) -> Self {
        self.trusted_vk_root = Some(root);
        self
    }

    /// Emulate with `program`, the guest's AOT-compiled code — what `cargo pico aot` generates as
    /// `pico_aot_dispatch::AOT` — running ahead of the interpreters that make the records.
    ///
    /// [`Self::build`] refuses the bootstrap stub ([`ProveError::AotNotGenerated`]), code
    /// generated from another ELF ([`ProveError::AotElfMismatch`]), and a program the process
    /// cannot register ([`ProveError::AotRegistration`]). [`Self::execute_chunked`] checks the same.
    ///
    /// **One AOT program per process.** The registry is process-wide and keeps the first program
    /// a `build` or an `execute` registers, so a builder given a different one is refused for as
    /// long as the process lives. A server proving several guests with AOT runs one process per
    /// guest.
    ///
    /// **Prover-side only.** The AOT code produces the witness and nothing else: the circuits, the
    /// verifier and the [`ProgramId`] are the interpreter's, so a proof made with it verifies
    /// wherever one made without it does. An AOT fault fails the prove, or yields output bytes the
    /// output binding refuses.
    #[cfg(feature = "aot")]
    pub fn aot(mut self, program: &'static AotProgram) -> Self {
        self.aot = Some(program);
        self
    }

    /// Replay the snapshot pipeline's chunks on [`Self::aot`]'s program too, rather than on
    /// interpreters: its recording blocks write the records the interpreter would. Needs `aot` with
    /// a program that has a recording entry point, which `cargo pico aot` always generates;
    /// [`Self::build`] and [`Self::execute_chunked`] refuse it otherwise.
    #[cfg(feature = "aot")]
    pub fn aot_workers(mut self) -> Self {
        self.replay_workers = ReplayWorkers::Aot;
        self
    }

    /// Replay workers the snapshot pipeline runs beside its snapshot thread, with or without
    /// `aot`. [`Self::serial_emulation`] has none, and is refused with this.
    ///
    /// Defaults to this machine's core count, at most 16; a `cuda` build's GPU prove defaults to
    /// [`default_pipeline_workers`](pico_vm::proverchain::riscv::default_pipeline_workers)
    /// instead, beside the cards' preparers and provers. [`Self::build`] accepts no more than the
    /// core count: the pipeline runs one replay worker per core at most.
    ///
    /// With `aot`, or in a `cuda` build on the interpreted AOT runtime, a worker holds an emulator
    /// memory from a pool of `MEMORY_POOL_SIZE` while it replays. Unset, the pool is 16, raised
    /// where that is fewer to one per worker plus the batch being cut, so every worker replays at
    /// once; a smaller size caps how many do, and [`Self::build`] refuses only a pool that cannot
    /// hold the batch being cut.
    pub fn emulation_workers(mut self, n: NonZeroUsize) -> Self {
        self.emulation_workers = Some(n);
        self
    }

    /// Records the GPU prove holds at once, each in a pinned host history slot of one chunk; they
    /// bound how far emulation runs ahead of the cards. All are pinned on the first GPU prove and
    /// stay pinned at that count, so a later prove asking for another count is refused. Defaults
    /// to [`distributed_vm::mle::embed::default_event_pool_size`], sized to the host's memory;
    /// `MLE_HISTORY_SLOTS` does not apply here. A size that cannot hold one chunk's replay
    /// segments is refused when proving starts, without poisoning the process.
    #[cfg(feature = "cuda")]
    pub fn gpu_event_pool_size(mut self, n: NonZeroUsize) -> Self {
        self.gpu_event_pool_size = Some(n);
        self
    }

    /// Whether, without [`Self::aot`], the snapshot thread is the AOT runtime interpreting every
    /// block (no compiled code, any ELF) rather than the VM's interpreter. Defaults to `true`:
    /// the runtime's interpreter and precompile backends emulate a reth block in about half the
    /// time. It changes how records are made, not what is proved. [`Self::serial_emulation`]
    /// overrides it.
    ///
    /// The runtime, like an [`Self::aot`] program, is registered once per process, whichever
    /// comes first, by `build`, `execute` or `estimate_cost`: after a default builder, a builder
    /// with [`Self::aot`] is refused ([`ProveError::AotRegistration`]), and after one with
    /// [`Self::aot`], a default builder is refused the same way; `interpreted_aot_runtime(false)`
    /// registers nothing and works after either.
    #[cfg(feature = "cuda")]
    pub fn interpreted_aot_runtime(mut self, on: bool) -> Self {
        self.interpreted_aot_runtime = on;
        self
    }

    /// Emulate on one interpreter, on the calling thread, instead of through the snapshot
    /// pipeline. For a machine the pipeline's workers do not fit, and for comparing the two paths,
    /// whose records are equal.
    ///
    /// Refused by [`Self::build`] and [`Self::execute_chunked`] together with [`Self::emulation_workers`]
    /// or `aot`, which both need the pipeline.
    pub fn serial_emulation(mut self) -> Self {
        self.serial_emulation = true;
        self
    }

    /// Run [`Self::execute`] on `program`, the guest's pure-mode AOT code linked into this build:
    /// the generated dispatch crate's `PURE`.
    pub fn pure_aot(mut self, program: &'static PureProgram) -> Self {
        self.pure.set_static(program);
        self
    }

    /// Run [`Self::execute`] on the guest's pure-mode AOT code from a dynamic library, as
    /// [`PureLibrary::load`] loads one. Several builders, for several guests, may hold libraries
    /// at once.
    pub fn pure_aot_library(mut self, library: Arc<PureLibrary>) -> Self {
        self.pure.set_library(library);
        self
    }

    /// Have [`Self::execute`] refuse to run without pure-mode AOT code
    /// ([`ProveError::PureAotRequired`]) rather than fall back to the stepping interpreter, so that
    /// a measurement cannot silently take the slow path.
    pub fn require_pure_aot(mut self, on: bool) -> Self {
        self.pure.require_aot(on);
        self
    }

    /// Record why the guest has no pure-mode AOT code, say a library that would not build; logs it
    /// as a warning now, and [`Self::execute_fallback_reason`] reports it.
    pub fn pure_aot_unavailable(mut self, reason: impl Into<String>) -> Self {
        self.pure.unavailable(reason.into());
        self
    }

    /// Turn pure-mode AOT code off on purpose: [`Self::execute`] runs the stepping interpreter
    /// without the warning a missing program logs. For a caller with an opt-out switch. It drops a
    /// program set before it; one set after it turns pure mode back on.
    pub fn disable_pure_aot(mut self) -> Self {
        self.pure.disable();
        self
    }

    /// What [`Self::execute`] runs on.
    pub fn execute_engine(&self) -> ExecuteEngine {
        self.pure.engine()
    }

    /// Why [`Self::execute`] runs the interpreter, if it does and a reason was recorded.
    pub fn execute_fallback_reason(&self) -> Option<&str> {
        self.pure.fallback_reason()
    }

    /// Run the guest to its halt, and report what it committed and how many instructions it ran:
    /// none of what proving needs, so no chunks, records or keygen. On the guest's pure-mode AOT
    /// code when it has some ([`Self::pure_aot`], [`Self::pure_aot_library`]), else on the stepping
    /// interpreter, with a warning. [`Self::execute_chunked`] emulates as proving does.
    ///
    /// A run past the cycle limit [`Self::execute_chunked`] applies fails the same way.
    ///
    /// A run that passes is not necessarily provable. Pure execution keeps plain memory, so it
    /// cannot tell a dword the guest wrote as zero from one it never wrote: a `HINT_READ` into the
    /// former passes here and fails [`Self::execute_chunked`] with `InvalidHintRead`. Only a guest
    /// bug reads a hint into memory it already wrote.
    pub fn execute(&self, stdin: Stdin) -> Result<PureExecution, ProveError> {
        check_stdin(&stdin)?;
        let max_cycles = emulator_opts(self.checked_chunk_size()?).max_cycles;
        let (program, sha) = match self.pure_program.get() {
            Some(cached) => cached.clone(),
            None => {
                let parsed = (compile(&self.elf)?, elf_sha256(&self.elf));
                self.pure_program.get_or_init(|| parsed).clone()
            }
        };
        self.pure.execute(program, sha, stdin, max_cycles)
    }

    /// Emulate without proving: no keygen, no whitelist. Chunks exactly as the built prover would.
    ///
    /// On the snapshot pipeline, each record is dropped as soon as its counts are read.
    ///
    /// The whitelist options go unchecked: they bind proving only.
    pub fn execute_chunked(&self, stdin: Stdin) -> Result<Execution, ProveError> {
        let (program, opts, path) = self.emulation_setup()?;
        execute_program(program, opts, path, stdin)
    }

    /// Emulate without proving, and report what proving the run would fill per RISC-V AIR. No
    /// keygen and no trace generation: see [`CostEstimate`] for what the rows count.
    pub fn estimate_cost(&self, stdin: Stdin) -> Result<CostEstimate, ProveError> {
        self.emulate(stdin).map(CostEstimate::from_emulation)
    }

    /// The emulation behind [`Self::execute_chunked`] and [`Self::estimate_cost`], with the options
    /// [`Self::build`] would give the prover.
    fn emulate(&self, stdin: Stdin) -> Result<Emulation, ProveError> {
        let (program, opts, path) = self.emulation_setup()?;
        emulate_program(program, opts, path, stdin)
    }

    /// What an emulation of [`Self::execute_chunked`] or [`Self::emulate`] runs with.
    fn emulation_setup(&self) -> Result<(Arc<Program>, EmulatorOpts, EmulationPath), ProveError> {
        let chunk_size = self.resolved_chunk_size()?;
        let opts = emulator_opts(chunk_size);
        let path = self.resolved_emulation(chunk_size)?;
        let program = compile(&self.elf)?;
        self.register_aot()?;
        // The tier latches on first read, so a whitelist builder that emulates before `build`
        // must pick the cards' tier here, not lock in the default.
        #[cfg(feature = "cuda")]
        if self.verify_keys {
            latch_gpu_memory_tier()?;
        }
        Ok((program, opts, path))
    }

    /// Keygen the RISC-V air set and check the options against each other.
    pub fn build(self) -> Result<Prover, ProveError> {
        let chunk_size = self.resolved_chunk_size()?;
        let emulation = self.resolved_emulation(chunk_size)?;

        let vk_map = if self.verify_keys {
            if self.log_stacked_height != WHITELIST_LOG_STACKED_HEIGHT {
                return Err(ProveError::InconsistentOptions(format!(
                    "verify_keys(true) proves at log_stacked_height \
                     {WHITELIST_LOG_STACKED_HEIGHT} only, the height its shape tables are sized \
                     for; got {}",
                    self.log_stacked_height
                )));
            }
            let source = self.vk_map.as_ref().ok_or_else(|| {
                ProveError::InconsistentOptions(
                    "verify_keys(true) needs vk_map(path) or shipped_whitelist(): the whitelist \
                     is an artifact, and a whitelist built from this run's own keys would only \
                     be as trustworthy as this run"
                        .into(),
                )
            })?;
            let (map, pinned) = match source {
                VkMapSource::Path(path) => {
                    let pinned = self.trusted_vk_root.ok_or_else(|| {
                        ProveError::InconsistentOptions(
                            "verify_keys(true) needs trusted_vk_root(root): the artifact carries \
                             its own root, so loading it proves consistency, never authenticity"
                                .into(),
                        )
                    })?;
                    (load_vk_map(path)?, pinned)
                }
                // Checked against the shipped root on load; a caller's root pins it further.
                VkMapSource::Shipped => {
                    let map = MleVkMap::shipped()?;
                    let pinned = self
                        .trusted_vk_root
                        .unwrap_or_else(|| digest_words(&map.root()));
                    (map, pinned)
                }
            };
            let loaded = digest_words(&map.root());
            if loaded != pinned {
                return Err(ProveError::VkRootMismatch { loaded, pinned });
            }
            Some(Arc::new(map))
        } else {
            if self.vk_map.is_some() || self.trusted_vk_root.is_some() {
                return Err(ProveError::InconsistentOptions(
                    "a whitelist was supplied with verify_keys(false); nothing would read it"
                        .into(),
                ));
            }
            None
        };

        // A whitelist prover proves Combine on the GPU: latch the cards' memory tier before any
        // emulation of this prover reads the default.
        #[cfg(feature = "cuda")]
        if vk_map.is_some() {
            latch_gpu_memory_tier()?;
        }

        let program = compile(&self.elf)?;

        // The riscv machine below keygens on the GPU in a `cuda` build, which needs the pool.
        #[cfg(feature = "cuda")]
        pico_vm::mle::machine::riscv::init_mle_gpu_pool(0);

        // Built once and handed on: the fit check and keygen need the same air set, and in
        // whitelist mode building it pads the program table to its bucket.
        let airs = riscv::mle_riscv_air_refs(program.clone(), self.verify_keys);
        check_preprocessed_fit(&airs, self.log_stacked_height)?;

        let machine = RiscvMachine::from_airs(airs, self.log_stacked_height, self.verify_keys)?
            .with_concurrency(self.concurrency);
        let riscv_vm_vk = RiscvVmVk::from_program_and_vk(&program, machine.vk());
        let program_id = ProgramId(digest_words(&riscv_vm_vk.digest()));
        let expected_vk_pre_hash = machine.vk().pre_hash;
        // Every id keygen marked, so the recomputed pre-hash and the commitments pinned beside it
        // cover the same split. An id with no preprocessed table has no commitment to pin.
        let expected_app_commits = riscv::RISCV_APP_PREP_AIR_IDS
            .iter()
            .filter_map(|&id| {
                machine.vk().inner.per_air[id]
                    .preprocessed_data
                    .as_ref()
                    .map(|prep| (id, prep.commit))
            })
            .collect();
        let initial_gcs = program.initial_global_cumulative_sum();

        let combine = combine_machine(riscv_vm_vk.clone(), self.verify_keys);

        // One verifier for every later `verify_artifact`, rather than one engine per proof checked.
        let apex = vk_map.as_ref().map(|map| {
            MleApexVerifier::new(
                recursion_params_with_128_bits_security(),
                compress_params_with_128_bits_security(),
                Arc::clone(map),
                riscv_vm_vk.clone(),
                map.root(),
            )
        });

        // Last, because it is the one step with an effect that outlives this builder.
        self.register_aot()?;

        Ok(Prover {
            pure: self.pure.clone(),
            elf_sha256: elf_sha256(&self.elf),
            program,
            opts: emulator_opts(chunk_size),
            emulation,
            log_stacked_height: self.log_stacked_height,
            concurrency: self.concurrency,
            verify_keys: self.verify_keys,
            vk_map,
            riscv: machine,
            riscv_vm_vk,
            program_id,
            expected_vk_pre_hash,
            expected_app_commits,
            initial_gcs,
            convert: None,
            combine,
            apex,
            compress: None,
            #[cfg(feature = "cuda")]
            gpu_compress: None,
            #[cfg(feature = "multi-field-transcript")]
            embed: None,
            #[cfg(feature = "cuda")]
            elf: Arc::from(self.elf.as_slice()),
            #[cfg(feature = "cuda")]
            gpu_event_pool_size: self
                .gpu_event_pool_size
                .unwrap_or_else(distributed_vm::mle::embed::default_event_pool_size),
            // Beside the GPU's preparers and provers, not the AOT path's one per core.
            #[cfg(feature = "cuda")]
            gpu_emulation_workers: self
                .emulation_workers
                .unwrap_or_else(default_pipeline_workers),
        })
    }

    /// The chunk size these options resolve to, checked against the stacked height and the chunk
    /// clock, with the chunk-split variables that would void the height check refused. Shared by
    /// [`Self::build`] and [`Self::execute_chunked`], so the two cannot chunk differently.
    pub(crate) fn resolved_chunk_size(&self) -> Result<u32, ProveError> {
        let chunk_size = self.checked_chunk_size()?;

        // The height check holds only with the memory-event limit on at scale 1. Without it,
        // whether a chunk's memory events outgrow the stacked height depends on the guest's data,
        // so it cannot be checked here and would fail mid-proof. Read through the VM's own readers,
        // which resolve each variable once per process, so what is refused is what the emulator
        // uses.
        if event_limits_off() {
            return Err(ProveError::InconsistentOptions(format!(
                "CHUNK_EVENT_LIMITS_OFF=1 removes the memory-event limit on a chunk, so its memory \
                 events can outgrow 2^{} and fail proving; unset it",
                self.log_stacked_height
            )));
        }
        let scale = event_limit_scale();
        if scale > 1.0 {
            return Err(ProveError::InconsistentOptions(format!(
                "CHUNK_EVENT_LIMIT_SCALE={scale} raises the memory-event limit on a chunk, so its \
                 memory events can outgrow 2^{} and fail proving; unset it",
                self.log_stacked_height
            )));
        }
        Ok(chunk_size)
    }

    /// The chunk size checked against the stacked height and the chunk clock, without the
    /// chunk-split variables: pure [`Self::execute`] chunks nothing and only takes its cycle limit
    /// from it.
    fn checked_chunk_size(&self) -> Result<u32, ProveError> {
        try_riscv_params_with_128_bits_security(self.log_stacked_height).map_err(|err| {
            ProveError::InconsistentOptions(format!(
                "log_stacked_height {} is not a height the backend can prove (maximum \
                 {MAX_RISCV_LOG_STACKED_HEIGHT}): {err}",
                self.log_stacked_height
            ))
        })?;
        let chunk_size = self.chunk_size.unwrap_or(1u32 << self.log_stacked_height);

        // `max_cycles` is derived from the chunk size, so a zero caps the run at zero cycles and
        // every emulation fails on its first instruction — a bad option reported as a mid-run
        // emulation failure. `EmulatorOpts::from_env_chunk_size` drops a zero from the environment
        // for the same reason; an explicit one is named here instead.
        if chunk_size == 0 {
            return Err(ProveError::InconsistentOptions(
                "chunk_size 0 leaves no cycles to emulate: pass the instructions per chunk, or \
                 leave it unset for 2^log_stacked_height"
                    .into(),
            ));
        }

        // A chunk holds one CPU row per instruction, so a full chunk of `2^n` instructions needs a
        // stacked height of at least `n`. A wider chunk proves the wrong shape.
        if u64::from(chunk_size) > (1u64 << self.log_stacked_height) {
            return Err(ProveError::InconsistentOptions(format!(
                "chunk_size {chunk_size} exceeds 2^{}: a chunk of 2^n instructions needs a \
                 stacked height of at least n",
                self.log_stacked_height
            )));
        }
        Ok(chunk_size)
    }

    /// The emulator these options resolve to, with an AOT program checked against the ELF and the
    /// pipeline against this machine. Shared by [`Self::build`] and [`Self::execute_chunked`], so the two
    /// emulate alike; neither registers the program before its last fallible step.
    fn resolved_emulation(&self, chunk_size: u32) -> Result<EmulationPath, ProveError> {
        #[cfg(feature = "aot")]
        if self.aot.is_none() && self.replay_workers == ReplayWorkers::Aot {
            return Err(ProveError::InconsistentOptions(
                "aot_workers() was set without aot(program); the replay workers run the program \
                 aot registers"
                    .into(),
            ));
        }
        if self.serial_emulation {
            if let Some(workers) = self.emulation_workers {
                return Err(ProveError::InconsistentOptions(format!(
                    "emulation_workers({workers}) was set with serial_emulation(); the serial \
                     path runs no replay workers"
                )));
            }
            #[cfg(feature = "aot")]
            if self.aot.is_some() {
                return Err(ProveError::InconsistentOptions(
                    "aot(program) was set with serial_emulation(); only the snapshot pipeline \
                     runs AOT code"
                        .into(),
                ));
            }
            return Ok(EmulationPath::Serial);
        }

        #[cfg(feature = "aot")]
        let compiled = self.aot.is_some();
        #[cfg(not(feature = "aot"))]
        let compiled = false;
        // A `cuda` build without a compiled program puts the AOT runtime, interpreting every
        // block, on the snapshot thread (see `interpreted_aot_runtime`).
        #[cfg(feature = "cuda")]
        let interpreted_runtime = self.interpreted_aot_runtime;
        #[cfg(not(feature = "cuda"))]
        let interpreted_runtime = false;
        let snapshot_main = if compiled || interpreted_runtime {
            SnapshotMainMode::Aot
        } else {
            SnapshotMainMode::Interpreter
        };
        #[cfg(feature = "aot")]
        let replay_workers = self.replay_workers;
        #[cfg(not(feature = "aot"))]
        let replay_workers = ReplayWorkers::Interpreter;

        // Checked here because the pipeline would refuse it only once a prove had started.
        let cores = max_pipeline_workers();
        let workers = self.emulation_workers.unwrap_or_else(|| {
            NonZeroUsize::new(cores.min(DEFAULT_MAX_EMULATION_WORKERS)).unwrap_or(NonZeroUsize::MIN)
        });
        if workers.get() > cores {
            return Err(ProveError::InconsistentOptions(format!(
                "emulation_workers({workers}) exceeds this machine's {cores} cores; the pipeline \
                 runs at most one replay worker per core"
            )));
        }
        // The pipeline refuses the same, but only once a prove has started. The replay workers stay
        // out of it: they need the program registered, which comes last, and `aot_workers` without
        // `aot` is refused above.
        check_pipeline(
            workers,
            &EmulatorOpts {
                snapshot_main,
                ..emulator_opts(chunk_size)
            },
        )
        .map_err(|e| ProveError::InconsistentOptions(e.to_string()))?;

        #[cfg(feature = "aot")]
        if let Some(program) = self.aot {
            if program.is_stub() {
                return Err(ProveError::AotNotGenerated);
            }
            let elf: [u8; 32] = Sha256::digest(&self.elf).into();
            if program.elf_sha256() != elf {
                return Err(ProveError::AotElfMismatch {
                    generated_from: program.elf_sha256(),
                    elf,
                });
            }
            // Refused before anything registers; the pipeline would refuse it only once a prove
            // has started. Nothing falls back.
            if self.replay_workers == ReplayWorkers::Aot && program.record_entry().is_none() {
                return Err(ProveError::InconsistentOptions(
                    "aot_workers() was set with a program that has no recording entry point, \
                     which the AOT replay workers run; regenerate it from the guest's ELF with \
                     `cargo pico aot`"
                        .into(),
                ));
            }
        }
        Ok(EmulationPath::Pipeline {
            workers,
            snapshot_main,
            replay_workers,
        })
    }

    /// Registers the AOT program, or in a `cuda` build the interpreted runtime, for the process:
    /// what the pipeline's snapshot thread will run.
    fn register_aot(&self) -> Result<(), ProveError> {
        #[cfg(feature = "aot")]
        if let Some(program) = self.aot {
            return pico_aot_runtime::register(program).map_err(ProveError::AotRegistration);
        }
        #[cfg(feature = "cuda")]
        if self.interpreted_aot_runtime && !self.serial_emulation {
            pico_aot_runtime::register_interpreted().map_err(ProveError::AotRegistration)?;
        }
        Ok(())
    }
}

fn combine_machine(riscv_vm_vk: RiscvVmVk, verify_keys: bool) -> CombineMachine {
    CombineMachine::new(
        recursion_params_with_128_bits_security(),
        riscv_vm_vk,
        verify_keys,
    )
}

fn compile(elf: &[u8]) -> Result<Arc<Program>, ProveError> {
    Ok(Compiler::new(SourceType::RISCV, elf)
        .map_err(|e| ProveError::InvalidElf(e.to_string()))?
        .compile())
}

/// Latch the visible cards' memory tier (`PICO_GPU_MEM` overrides) before any emulation reads
/// the default.
#[cfg(feature = "cuda")]
fn latch_gpu_memory_tier() -> Result<(), ProveError> {
    distributed_vm::mle::embed::init_memory_tier()
        .map(drop)
        .map_err(ProveError::from_embed)
}

/// The one emulation entry point, behind proving and both `execute`s, on any [`EmulationPath`].
///
/// Any abort the emulator still has on guest or caller input is returned as an error, and every
/// record's digests are made final. The emulator is built inside the call and dropped with it, so
/// nothing an unwind interrupted outlives it.
fn emulate_program(
    program: Arc<Program>,
    opts: EmulatorOpts,
    path: EmulationPath,
    stdin: Stdin,
) -> Result<Emulation, ProveError> {
    check_stdin(&stdin)?;
    let stdin = stdin.into_emulator_stdin();
    let mut emulated = std::panic::catch_unwind(AssertUnwindSafe(|| match path {
        EmulationPath::Serial => riscv::emulate_with_opts(program, &stdin, opts),
        EmulationPath::Pipeline {
            workers,
            snapshot_main,
            replay_workers,
        } => riscv::emulate_with_pipeline(
            program,
            &stdin,
            EmulatorOpts {
                snapshot_main,
                replay_workers,
                ..opts
            },
            workers,
        ),
    }))
    .map_err(|payload| ProveError::EmulationAborted(panic_message(&*payload)))?
    .map_err(ProveError::from_emulate)?;
    binding::backfill_final_digests(&mut emulated.records);
    let mut precompile_calls = BTreeMap::new();
    for record in &emulated.records {
        count_precompile_calls(&mut precompile_calls, record);
    }
    // Each report carries the running count; the last one ends the run.
    let misaligned_accesses = emulated
        .reports
        .last()
        .map_or(0, |report| report.misaligned_accesses);
    Ok(Emulation {
        records: emulated.records,
        execution: Execution {
            committed_bytes: emulated.committed_bytes,
            cycles: emulated.cycles,
            chunks: emulated.chunks,
            reports: emulated.reports,
            precompile_calls,
            misaligned_accesses,
        },
    })
}

/// [`emulate_program`]'s [`Execution`], without keeping the records: on the snapshot pipeline
/// each is dropped as soon as its precompile calls are counted.
fn execute_program(
    program: Arc<Program>,
    opts: EmulatorOpts,
    path: EmulationPath,
    stdin: Stdin,
) -> Result<Execution, ProveError> {
    let EmulationPath::Pipeline {
        workers,
        snapshot_main,
        replay_workers,
    } = path
    else {
        return emulate_program(program, opts, path, stdin).map(|emulated| {
            pico_vm::mle::ledger::drop_records(emulated.records);
            emulated.execution
        });
    };
    check_stdin(&stdin)?;
    let stdin = stdin.into_emulator_stdin();
    let opts = EmulatorOpts {
        snapshot_main,
        replay_workers,
        ..opts
    };
    let mut calls = BTreeMap::new();
    let executed = std::panic::catch_unwind(AssertUnwindSafe(|| {
        riscv::emulate_with_pipeline_streaming(program, &stdin, opts, workers, |record| {
            count_precompile_calls(&mut calls, &record)
        })
    }))
    .map_err(|payload| ProveError::EmulationAborted(panic_message(&*payload)))?
    .map_err(ProveError::from_emulate)?;
    // Ends the ledger run, as dropping a prove's records does.
    pico_vm::mle::ledger::drop_records(Vec::new());
    // Each report carries the running count; the last one ends the run.
    let misaligned_accesses = executed
        .reports
        .last()
        .map_or(0, |report| report.misaligned_accesses);
    Ok(Execution {
        committed_bytes: executed.committed_bytes,
        cycles: executed.cycles,
        chunks: executed.chunks,
        reports: executed.reports,
        precompile_calls: calls,
        misaligned_accesses,
    })
}

/// Adds `record`'s calls per precompile to `calls`, by the code the guest called.
///
/// Read from each event's own id rather than from the group it is filed under, because the
/// field-arithmetic precompiles file a `SUB` or `MUL` event under their `ADD`'s code. The id is the
/// low byte of the code, and the codes one group coalesces differ in nothing else.
fn count_precompile_calls(calls: &mut BTreeMap<SyscallCode, u64>, record: &EmulationRecord) {
    for (&filed_under, events) in &record.precompile_events.events {
        for (event, _) in events {
            let called = if event.syscall_id == filed_under.syscall_id() {
                filed_under
            } else {
                SyscallCode::try_from_u32((filed_under as u32 & !0xff) | event.syscall_id)
                    .filter(|code| code.count_map() == filed_under.count_map())
                    .unwrap_or_else(|| {
                        panic!(
                            "a precompile event with syscall id {:#x} is filed under \
                             {filed_under}, which does not coalesce it",
                            event.syscall_id
                        )
                    })
            };
            *calls.entry(called).or_insert(0) += 1;
        }
    }
}

/// Load a whitelist artifact by extension, the naming `mle_build_vk_map` writes: `.bin` is the
/// bincode form, anything else JSON. Not `MleVkMap::try_load`, which would also hold the file to
/// `MLE_VK_ROOT` and so let the environment refuse a whitelist the caller pinned with
/// `trusted_vk_root`.
pub(crate) fn load_vk_map(path: &Path) -> Result<MleVkMap, VkMapError> {
    if path.extension().is_some_and(|e| e == "bin") {
        MleVkMap::try_load_bin(path)
    } else {
        MleVkMap::try_load_json(path)
    }
}

/// Refuse a stacked height no preprocessed table of this program fits in.
///
/// The backend's stacked commitment aborts on that pair rather than reporting it
/// (`mle-core/src/keygen/mod.rs`, the `stacked_commit(..).unwrap()`), and it is a caller's option
/// that produced it, so it is answered here while it is still one.
///
/// Neither RISC-V preprocessed AIR declares its geometry, so `preprocessed_dims` generates the byte
/// and program tables to read their heights, and keygen generates them again.
fn check_preprocessed_fit(
    airs: &[AirRef<Sc>],
    log_stacked_height: usize,
) -> Result<(), ProveError> {
    let tallest = airs
        .iter()
        .filter_map(|air| air.preprocessed_dims())
        .map(|dims| dims.height.next_power_of_two().trailing_zeros() as usize)
        .max()
        .unwrap_or(0);
    if tallest > log_stacked_height {
        return Err(ProveError::InconsistentOptions(format!(
            "this program's preprocessed tables need a stacked height of at least 2^{tallest}; \
             log_stacked_height is {log_stacked_height}"
        )));
    }
    Ok(())
}

/// Refuse a run that used a chip with no AIR in the RISC-V machine, before anything is proved.
///
/// A guard for a chip added to the pool without an MLE air: proving a record that used one would
/// abort in trace assembly (`riscv::build_ctx` panics) rather than return an error. Every chip in
/// `RiscvChipType::all_chip_variants` has an air today, so this refuses nothing. Records straight
/// from the emulator carry no shape, so `is_active` here is the event-driven test proving would
/// apply.
fn check_chips_provable(records: &[EmulationRecord]) -> Result<(), ProveError> {
    let unprovable: Vec<RiscvChipType<Kb>> = RiscvChipType::<Kb>::all_chip_variants()
        .into_iter()
        .filter(|chip| riscv::air_id_for(&chip.name()).is_none())
        .collect();
    let chips: BTreeSet<String> = records
        .iter()
        .flat_map(|record| {
            unprovable
                .iter()
                .filter(|chip| chip.is_active(record))
                .map(|chip| chip.name())
        })
        .collect();
    if chips.is_empty() {
        Ok(())
    } else {
        Err(ProveError::UnsupportedChip {
            chips: chips.into_iter().collect(),
        })
    }
}

/// Report an input element that would not serialize, before anything is emulated.
fn check_stdin(stdin: &Stdin) -> Result<(), ProveError> {
    match stdin.failure() {
        Some((index, message)) => Err(ProveError::InvalidInput {
            index,
            message: message.to_string(),
        }),
        None => Ok(()),
    }
}

/// Every emulator option stated, so no environment variable can decide one.
///
/// `EmulatorOpts::default` reads `CHUNK_SIZE` and `CHUNK_BATCH_SIZE`, and
/// `from_env_chunk_size` reads the first of them, so neither is a usable starting point here.
pub(crate) fn emulator_opts(chunk_size: u32) -> EmulatorOpts {
    EmulatorOpts {
        chunk_size,
        chunk_batch_size: CHUNK_BATCH_SIZE,
        max_cycles: Some((chunk_size as u64) * (2 << MAX_LOG_NUMBER_OF_CHUNKS)),
        cycle_tracker: false,
        cost_estimator: false,
        // The pipeline path states its own in `emulate_program`; `emulate_with_opts` refuses an
        // AOT request rather than silently interpreting it, so the serial path keeps this one.
        snapshot_main: SnapshotMainMode::Interpreter,
        replay_workers: ReplayWorkers::Interpreter,
    }
}

/// Takes an ELF and an input, and returns a verified proof.
///
/// Keygen runs once, in [`ProverBuilder::build`]; each `prove` reuses it. The recursion machines —
/// convert, combine, compress and embed — keygen lazily per circuit shape and are kept here too, up
/// to a fixed number of keys per machine, so a second `prove` whose shapes repeat pays neither cost
/// again, which is why the proving methods take `&mut self`.
pub struct Prover {
    program: Arc<Program>,
    pure: PureOptions,
    elf_sha256: [u8; 32],
    opts: EmulatorOpts,
    emulation: EmulationPath,
    log_stacked_height: usize,
    concurrency: NonZeroUsize,
    verify_keys: bool,
    vk_map: Option<Arc<MleVkMap>>,
    riscv: RiscvMachine,
    riscv_vm_vk: RiscvVmVk,
    program_id: ProgramId,
    expected_vk_pre_hash: [Kb; 8],
    expected_app_commits: Vec<(usize, [Kb; 8])>,
    initial_gcs: SepticDigest<Kb>,
    /// Built on the first prove that reaches [`Phase::Convert`], then extended in place, so a
    /// layout a later run repeats is keyed once while its key is retained.
    convert: Option<ConvertMachine>,
    combine: CombineMachine,
    /// The whitelist verifier, built with the map rather than per call. `None` without a
    /// whitelist, where [`Self::verify_artifact`] falls back to the machine that keygen'd.
    apex: Option<MleApexVerifier>,
    /// The final compression layer; built on the first prove that reaches [`Phase::Compress`]. In a
    /// `cuda` build it keygens and verifies, and `gpu_compress` proves.
    compress: Option<CompressMachine>,
    /// A `cuda` build's compress prover, beside `compress`, which keygens the same key and accepts
    /// the proof. Its device keys stay on card 0 until `bound_key_caches` drops them with `compress`.
    #[cfg(feature = "cuda")]
    gpu_compress: Option<pico_vm::mle::machine::compress::GpuCompressMachine>,
    #[cfg(feature = "multi-field-transcript")]
    embed: Option<pico_vm::mle::machine::embed::EmbedMachine>,
    /// The ELF the GPU pipeline compiles for itself.
    #[cfg(feature = "cuda")]
    elf: Arc<[u8]>,
    #[cfg(feature = "cuda")]
    gpu_event_pool_size: NonZeroUsize,
    /// The GPU prove's replay workers.
    #[cfg(feature = "cuda")]
    gpu_emulation_workers: NonZeroUsize,
}

impl std::fmt::Debug for Prover {
    /// The options and the identity; the keys and machines are megabytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prover")
            .field("program_id", &self.program_id)
            .field("log_stacked_height", &self.log_stacked_height)
            .field("chunk_size", &self.opts.chunk_size)
            .field("concurrency", &self.concurrency)
            .field("verify_keys", &self.verify_keys)
            .field("emulation", &self.emulation)
            .finish()
    }
}

impl Prover {
    /// Keygen for `elf` at the default operating point.
    pub fn new(elf: &[u8]) -> Result<Self, ProveError> {
        Self::builder(elf).build()
    }

    /// Keygen for `elf` with options.
    pub fn builder(elf: &[u8]) -> ProverBuilder {
        ProverBuilder::new(elf)
    }

    /// The program this prover attests to.
    pub fn program_id(&self) -> ProgramId {
        self.program_id
    }

    /// Log2 of the stacked trace height this prover proves at.
    pub fn log_stacked_height(&self) -> usize {
        self.log_stacked_height
    }

    /// Whether the whitelist is on.
    pub fn verify_keys(&self) -> bool {
        self.verify_keys
    }

    /// How many chunks this prover proves at once.
    pub fn concurrency(&self) -> NonZeroUsize {
        self.concurrency
    }

    /// Instructions per emulation chunk.
    pub fn chunk_size(&self) -> u32 {
        self.opts.chunk_size
    }

    /// The v2 VK bundle (`pico_verifier::bundle`) a verifier of this prover's proofs is handed:
    /// the program's exe identity, the pinned whitelist root, and the membership of every key a
    /// root or a compress proof can carry. Whitelist mode only. See [`Proof::export_v3`].
    pub fn vk_bundle(&self) -> Result<Vec<u8>, ProveError> {
        let map = self
            .vk_map
            .as_ref()
            .ok_or(ProveError::WhitelistModeRequired {
                what: "a VK bundle",
            })?;
        encode_vk_bundle_v2(&self.riscv_vm_vk, map)
            .map_err(|e| ProveError::Format(format!("cannot encode the VK bundle: {e}")))
    }

    /// How many replay workers the snapshot pipeline runs; `None` when this prover emulates
    /// serially ([`ProverBuilder::serial_emulation`]).
    pub fn emulation_workers(&self) -> Option<NonZeroUsize> {
        match self.emulation {
            EmulationPath::Serial => None,
            EmulationPath::Pipeline { workers, .. } => Some(workers),
        }
    }

    /// Whether the snapshot pipeline's snapshot thread runs the AOT program ([`ProverBuilder::aot`])
    /// rather than an interpreter; `false` when this prover emulates serially.
    pub fn emulates_with_aot(&self) -> bool {
        matches!(
            self.emulation,
            EmulationPath::Pipeline {
                snapshot_main: SnapshotMainMode::Aot,
                ..
            }
        )
    }

    /// Whether the snapshot pipeline's replay workers run the AOT program's recording blocks
    /// ([`ProverBuilder::aot_workers`]) rather than interpreters; `false` when this prover
    /// emulates serially.
    pub fn replays_with_aot(&self) -> bool {
        matches!(
            self.emulation,
            EmulationPath::Pipeline {
                replay_workers: ReplayWorkers::Aot,
                ..
            }
        )
    }

    /// [`ProverBuilder::execute`] with this prover's program and pure-execution options.
    pub fn execute(&self, stdin: Stdin) -> Result<PureExecution, ProveError> {
        check_stdin(&stdin)?;
        self.pure.execute(
            self.program.clone(),
            self.elf_sha256,
            stdin,
            self.opts.max_cycles,
        )
    }

    /// What [`Self::execute`] runs on.
    pub fn execute_engine(&self) -> ExecuteEngine {
        self.pure.engine()
    }

    /// Emulate without proving. [`ProverBuilder::execute_chunked`] does the same without keygen.
    pub fn execute_chunked(&self, stdin: Stdin) -> Result<Execution, ProveError> {
        execute_program(self.program.clone(), self.opts, self.emulation, stdin)
    }

    /// [`ProverBuilder::estimate_cost`] with this prover's options.
    pub fn estimate_cost(&self, stdin: Stdin) -> Result<CostEstimate, ProveError> {
        self.emulate(stdin).map(CostEstimate::from_emulation)
    }

    /// Prove to [`Phase::Combine`]: a single complete root proof over the whole execution, which a
    /// deferred-proof node verifies (`docs/deferred.md`). [`Self::prove_to`] goes on along the
    /// chain (compress, embed, wrap).
    pub fn prove(&mut self, stdin: Stdin) -> Result<Proof, ProveError> {
        self.prove_to(stdin, Phase::Combine)
    }

    /// Prove up to `phase`, verify the result, and bind the guest's output to it.
    ///
    /// The returned [`Proof`] has been verified; there is no separate `verify` step and no way to
    /// obtain an unverified one.
    ///
    /// A `cuda` build proves a whitelist-mode [`Phase::Combine`] through the GPU pipeline on every
    /// visible card, and a whitelist-mode [`Phase::Compress`] the same way to the root, then the
    /// compress layer on card 0. Any other mode or phase takes the path below, where the feature
    /// swaps the RISC-V and compress proving engine for the GPU's on card 0, while convert, combine
    /// and embed prove on the CPU. Build without `cuda` to prove everything on the CPU.
    ///
    /// A [`Phase::Wrap`] proof made with `verify_keys(false)` is not accepted by the on-chain
    /// verifier: the wrap circuit bakes in the whitelist root only when there is one, so without it
    /// the circuit, and therefore its Groth16 key, is a different one.
    pub fn prove_to(&mut self, stdin: Stdin, phase: Phase) -> Result<Proof, ProveError> {
        phase.ensure_available()?;

        // Whitelist Combine and Compress go to every visible card; the rest prove on card 0 (see
        // `cuda`).
        #[cfg(feature = "cuda")]
        if matches!(phase, Phase::Combine | Phase::Compress) && self.vk_map.is_some() {
            return self.prove_gpu(stdin, phase);
        }

        let mut emulated = self.emulate(stdin)?;
        let committed = emulated.execution.committed_bytes;
        let misaligned = emulated.execution.misaligned_accesses;
        let proved = self.prove_records(std::mem::take(&mut emulated.records), committed, phase);
        // Empty: the prove took the records and dropped each with its prove job. This ends the
        // ledger run.
        pico_vm::mle::ledger::drop_records(emulated.records);
        proved.map(|proof| proof.counting(misaligned))
    }

    /// Prove to [`Phase::Wrap`] for the on-chain verifier, and return the gnark inputs with the
    /// wrap circuit's two public inputs.
    ///
    /// Needs `verify_keys(true)`, and without it refuses before anything is emulated, with
    /// [`ProveError::EvmRequiresWhitelist`]: the one on-chain verifier is set up for the circuit
    /// that bakes in the whitelist root. A guest that never commits is refused after emulation,
    /// before proving, with [`ProveError::EvmNoCommittedDigest`].
    #[cfg(feature = "multi-field-transcript")]
    pub fn prove_evm(&mut self, stdin: Stdin) -> Result<crate::EvmBundle, ProveError> {
        // The root `prove_outer` bakes into the wrap circuit comes from this map.
        let Some(vk_root) = self.vk_map.as_ref().map(|map| digest_words(&map.root())) else {
            return Err(ProveError::EvmRequiresWhitelist);
        };
        let mut emulated = self.emulate(stdin)?;
        let misaligned = emulated.execution.misaligned_accesses;
        let proved = if binding::commits(&emulated.records) {
            let committed = emulated.execution.committed_bytes;
            self.prove_records(
                std::mem::take(&mut emulated.records),
                committed,
                Phase::Wrap,
            )
            .map(|proof| proof.counting(misaligned))
        } else {
            Err(ProveError::EvmNoCommittedDigest)
        };
        // Empty when the prove took them; still full when there was no committed digest to prove.
        // Either way this drops what is left and ends the ledger run.
        pico_vm::mle::ledger::drop_records(emulated.records);
        crate::EvmBundle::from_wrap_proof(proved?, vk_root)
    }

    pub(crate) fn emulate(&self, stdin: Stdin) -> Result<Emulation, ProveError> {
        emulate_program(self.program.clone(), self.opts, self.emulation, stdin)
    }

    /// Bound each machine's recursion keys (see [`MAX_RETAINED_KEYS`]) before this run adds its
    /// own. Convert keys are kept in order of last use, so trimming the front drops the least
    /// recently used.
    fn bound_key_caches(&mut self) {
        let convert_bound = if self.verify_keys {
            MAX_RETAINED_WHITELIST_CONVERT_KEYS
        } else {
            MAX_RETAINED_KEYS
        };
        if let Some(convert) = &mut self.convert {
            let excess = convert.pks.len().saturating_sub(convert_bound);
            convert.pks.drain(..excess);
        }
        if !self.verify_keys && self.combine.num_distinct_shapes() > MAX_RETAINED_KEYS {
            self.combine = combine_machine(self.riscv_vm_vk.clone(), self.verify_keys);
        }
        if self
            .compress
            .as_ref()
            .is_some_and(|compress| compress.num_distinct_shapes() > MAX_RETAINED_KEYS)
        {
            self.compress = None;
            #[cfg(feature = "cuda")]
            {
                self.gpu_compress = None;
            }
        }
        #[cfg(feature = "multi-field-transcript")]
        if self
            .embed
            .as_ref()
            .is_some_and(|embed| embed.num_distinct_shapes() > MAX_RETAINED_KEYS)
        {
            self.embed = None;
        }
    }

    /// Takes the records: the riscv prove uses each without a copy and drops it when that chunk's
    /// prove job is done with it, so no record is held into the recursion phases.
    pub(crate) fn prove_records(
        &mut self,
        records: Vec<EmulationRecord>,
        committed: Vec<u8>,
        phase: Phase,
    ) -> Result<Proof, ProveError> {
        check_chips_provable(&records)?;
        self.riscv.check_chunk_shapes(&records)?;
        let bundle = self
            .riscv
            .prove_owned(records)
            .map_err(|e| ProveError::proving(Phase::Riscv, e.to_string()))?;
        self.riscv
            .verify(&bundle, self.initial_gcs)
            .map_err(|e| ProveError::verification(Phase::Riscv, e.to_string()))?;
        binding::ensure_exit_code_zero(binding::public_values(&bundle.chunk_proofs))?;

        if phase == Phase::Riscv {
            return self.riscv_proof(bundle, committed, Some(1));
        }
        let chunk_count = Some(bundle.chunk_proofs.len());

        let (riscv_vk, riscv_proofs) = bundle.into_parts();
        self.bound_key_caches();
        let vk_map = self.vk_map.clone();
        // `new` keygens one circuit per distinct RISC-V proof layout and `register_layouts` only
        // the layouts not yet keyed. The RISC-V key cannot have moved — it is this prover's own,
        // keygen'd once in `build`.
        let kept = self.convert.as_ref().map_or(0, |convert| convert.pks.len());
        let convert = match &mut self.convert {
            Some(convert) => {
                convert
                    .register_layouts(&riscv_proofs)
                    .map_err(|e| ProveError::proving(Phase::Convert, e.to_string()))?;
                convert
            }
            none => none.insert(
                ConvertMachine::new(
                    riscv_vk,
                    self.riscv_vm_vk.clone(),
                    &riscv_proofs,
                    recursion_params_with_128_bits_security(),
                    self.verify_keys,
                )
                .map_err(|e| ProveError::proving(Phase::Convert, e.to_string()))?,
            ),
        };

        if let Some(map) = &vk_map {
            // Checked before anything is proved under the new keys. They are dropped again, so a
            // later run that does not need the missing shape is not refused for it.
            let missing = not_whitelisted(map, convert.pks[kept..].iter().map(|entry| &*entry.3));
            if missing > 0 {
                convert.pks.truncate(kept);
                return Err(ProveError::KeyNotWhitelisted {
                    phase: Phase::Convert,
                    missing,
                });
            }
            // Every recursion proof witnesses the whitelist root, so it must be set before any of
            // them is proved.
            convert
                .set_vk_root(map.root())
                .map_err(|e| ProveError::proving(Phase::Convert, e.to_string()))?;
        }

        let convert_proofs = convert
            .prove_with_vks(&riscv_proofs)
            .map_err(|e| ProveError::proving(Phase::Convert, format!("{e:#}")))?;
        // The keys this prove used move to the end, so `pks` runs from least to most recently used.
        let (older, used): (Vec<_>, Vec<_>) = std::mem::take(&mut convert.pks)
            .into_iter()
            .partition(|entry| {
                !convert_proofs
                    .iter()
                    .any(|(_, vk)| Arc::ptr_eq(vk, &entry.3))
            });
        convert.pks = older;
        convert.pks.extend(used);
        for (proof, vk) in &convert_proofs {
            convert
                .engine
                .verify(&**vk, proof)
                .map_err(|e| ProveError::verification(Phase::Convert, format!("{e:?}")))?;
        }

        if phase == Phase::Convert {
            let digest = binding::recursion_committed_digest_over(
                convert_proofs
                    .iter()
                    .map(|(p, _)| p.public_values.as_slice()),
                Phase::Convert,
            )?;
            let bound = binding::rebind(committed, digest)?;
            let shapes = Some(convert.pks.len());
            return Ok(self.finish(
                phase,
                bound,
                chunk_count,
                shapes,
                Payload::Convert(convert_proofs),
            ));
        }

        if let Some(map) = vk_map {
            // One node key stands for the whitelist's combine leaves before any node is proved:
            // every node key comes from the same circuit and tier, so an artifact that does not
            // match this binary's combine machinery is refused here, with an error, rather than in
            // a node's witness. The tree keygens each other node key the first time it needs it.
            let bootstrap = self.combine.bootstrap_node_vk(&convert.pks[0].3)?;
            let missing = not_whitelisted(&map, std::iter::once(&*bootstrap));
            if missing > 0 {
                return Err(ProveError::KeyNotWhitelisted {
                    phase: Phase::Combine,
                    missing,
                });
            }
            self.combine.set_vk_map(map);
        }

        let root = self
            .combine
            .prove_tree(convert_proofs)
            .map_err(|e| ProveError::proving(Phase::Combine, format!("{e:#}")))?;
        self.combine
            .verify(&root)
            .map_err(|e| ProveError::verification(Phase::Combine, format!("{e:#}")))?;

        if phase == Phase::Combine {
            let shapes = Some(self.combine.num_distinct_shapes());
            return self.combine_proof(Box::new(root), committed, chunk_count, shapes);
        }
        // The chain goes on through compress: its proof is the one handed out, and embed's child.
        let (compress, shapes) = self.compress_root(root)?;
        if phase == Phase::Compress {
            return self.compress_proof(Box::new(compress), committed, chunk_count, Some(shapes));
        }

        self.prove_outer(compress, committed, chunk_count, phase)
    }

    /// The complete root re-proved under the inner config at the compress preset, and verified: the
    /// final compression layer, the proof that is handed out, and embed's child.
    ///
    /// In whitelist mode the compress key is looked up in the whitelist before anything is proved
    /// (its leaf is the last): the key is keygen'd once (`keygen_for` keeps it; a
    /// `cuda` build also keygens it on the device to prove) and a stale artifact is refused as
    /// [`ProveError::KeyNotWhitelisted`] rather than answered with a proof no apex accepts. The
    /// circuit re-runs the root's membership check in-circuit.
    ///
    /// Returns the verified proof and the number of compress shapes keygen'd so far.
    fn compress_root(&mut self, root: ProofWithVk) -> Result<(ProofWithVk, usize), ProveError> {
        let (riscv_vm_vk, verify_keys) = (&self.riscv_vm_vk, self.verify_keys);
        let compress = self.compress.get_or_insert_with(|| {
            CompressMachine::new(
                compress_params_with_128_bits_security(),
                riscv_vm_vk.clone(),
                verify_keys,
            )
        });
        if let Some(map) = &self.vk_map {
            compress.set_vk_map(Arc::clone(map));
            let layout = extract_recursion_vk_layout(&root.1, Some(&root.0));
            let vk = compress.preregister(&layout)?;
            let missing = not_whitelisted(map, std::iter::once(&*vk));
            if missing > 0 {
                return Err(ProveError::KeyNotWhitelisted {
                    phase: Phase::Compress,
                    missing,
                });
            }
        }
        #[cfg(not(feature = "cuda"))]
        let proof = compress
            .prove(root)
            .map_err(|e| ProveError::proving(Phase::Compress, format!("{e:#}")))?;
        // A `cuda` build proves on the GPU machine, as the GPU pipeline does: the CPU machine would
        // hand the GPU engine a merged-preprocessed key, which it cannot take. The CPU machine
        // keygens the same layout's key and accepts the proof.
        #[cfg(feature = "cuda")]
        let proof = {
            // Card 0, where `build` set up the pool: a GPU pipeline run that panicked while setting
            // up another card can leave this thread bound to it.
            pico_vm::mle::cuda_mle::runtime::context::set_device(0)
                .map_err(|e| ProveError::Gpu(format!("cannot bind card 0: {e:?}")))?;
            let gpu = self.gpu_compress.get_or_insert_with(|| {
                pico_vm::mle::machine::compress::GpuCompressMachine::new(
                    compress_params_with_128_bits_security(),
                    verify_keys,
                )
            });
            if let Some(map) = &self.vk_map {
                gpu.set_vk_map(Arc::clone(map));
            }
            let proved = gpu
                .prove(&root)
                .map_err(|e| ProveError::proving(Phase::Compress, format!("{e:#}")))?;
            // Verified below under the key the CPU machine keygens, and handed on with that key.
            let vk = compress.preregister(&proved.root_layout)?;
            (proved.proof.0, vk)
        };
        compress
            .verify(&proof)
            .map_err(|e| ProveError::verification(Phase::Compress, format!("{e:#}")))?;
        Ok((proof, compress.num_distinct_shapes()))
    }

    #[cfg(not(feature = "multi-field-transcript"))]
    fn prove_outer(
        &mut self,
        _compress: ProofWithVk,
        _committed: Vec<u8>,
        _chunk_count: Option<usize>,
        phase: Phase,
    ) -> Result<Proof, ProveError> {
        Err(ProveError::FeatureMissing {
            phase,
            feature: "multi-field-transcript",
        })
    }

    /// Embed over the verified compress proof, verified, then for [`Phase::Wrap`] the wrap circuit
    /// and witness built from the embed proof.
    #[cfg(feature = "multi-field-transcript")]
    fn prove_outer(
        &mut self,
        compress: ProofWithVk,
        committed: Vec<u8>,
        chunk_count: Option<usize>,
        phase: Phase,
    ) -> Result<Proof, ProveError> {
        use pico_vm::mle::machine::{
            embed::EmbedMachine,
            wrap::{build_wrap_artifacts, VkRootPin},
        };

        let (riscv_vm_vk, verify_keys) = (&self.riscv_vm_vk, self.verify_keys);
        let embed = self.embed.get_or_insert_with(|| {
            EmbedMachine::new(
                pico_mle_core::config::embed_params_with_128_bits_security(),
                riscv_vm_vk.clone(),
                verify_keys,
            )
        });
        if let Some(map) = &self.vk_map {
            embed.set_vk_map(Arc::clone(map));
        }
        let embed_proof = embed
            .prove(compress)
            .map_err(|e| ProveError::proving(Phase::Embed, format!("{e:#}")))?;
        embed
            .verify(&embed_proof)
            .map_err(|e| ProveError::verification(Phase::Embed, format!("{e:#}")))?;

        let digest =
            binding::recursion_committed_digest(&embed_proof.0.public_values, Phase::Embed)?;
        let bound = binding::rebind(committed, digest)?;
        let shapes = Some(embed.num_distinct_shapes());

        if phase == Phase::Embed {
            return Ok(self.finish(
                phase,
                bound,
                chunk_count,
                shapes,
                Payload::Embed(embed_proof),
            ));
        }

        // Whitelist mode pins its root into the circuit. Outside it the wrap pins no root and is
        // for testing only: `prove_evm` refuses it.
        let vk_root = match &self.vk_map {
            Some(map) => VkRootPin::Trusted(map.root()),
            None => VkRootPin::DevUnpinned,
        };
        let artifacts = build_wrap_artifacts(&embed_proof, vk_root)
            .map_err(|e| ProveError::proving(Phase::Wrap, format!("{e:#}")))?;
        Ok(self.finish(
            phase,
            bound,
            chunk_count,
            shapes,
            Payload::Wrap {
                embed: embed_proof,
                artifacts: Box::new(artifacts),
            },
        ))
    }

    /// A verified RISC-V bundle as a [`Proof`], once `committed` is bound to it.
    fn riscv_proof(
        &self,
        bundle: RiscvProof,
        committed: Vec<u8>,
        distinct_shapes: Option<usize>,
    ) -> Result<Proof, ProveError> {
        let digest = binding::riscv_committed_digest(&bundle.chunk_proofs)?;
        let bound = binding::rebind(committed, digest)?;
        let chunk_count = Some(bundle.chunk_proofs.len());
        Ok(self.finish(
            Phase::Riscv,
            bound,
            chunk_count,
            distinct_shapes,
            Payload::Riscv(bundle),
        ))
    }

    /// A verified compress proof as a [`Proof`], once `committed` is bound to it. The compress
    /// proof carries the root's public values unchanged, so the digest is read the same way.
    fn compress_proof(
        &self,
        compress: Box<ProofWithVk>,
        committed: Vec<u8>,
        chunk_count: Option<usize>,
        distinct_shapes: Option<usize>,
    ) -> Result<Proof, ProveError> {
        let digest =
            binding::recursion_committed_digest(&compress.0.public_values, Phase::Compress)?;
        let bound = binding::rebind(committed, digest)?;
        Ok(self.finish(
            Phase::Compress,
            bound,
            chunk_count,
            distinct_shapes,
            Payload::Compress(compress),
        ))
    }

    /// [`Phase::Combine`] or [`Phase::Compress`] in whitelist mode: the root on every visible GPU,
    /// then for `Compress` the compress layer over it, as the CPU path proves it.
    #[cfg(feature = "cuda")]
    fn prove_gpu(&mut self, stdin: Stdin, phase: Phase) -> Result<Proof, ProveError> {
        let (root, committed) = self.prove_root_gpu(stdin)?;
        if phase == Phase::Combine {
            return self.combine_proof(root, committed, None, None);
        }
        let (compress, shapes) = self.compress_root(*root)?;
        self.bound_key_caches();
        self.compress_proof(Box::new(compress), committed, None, Some(shapes))
    }

    /// The complete root on every visible GPU, in whitelist mode, and the committed bytes. The root
    /// is verified by the GPU pipeline and again here, by the checks [`Self::verify_artifact`] runs
    /// on a loaded root.
    #[cfg(feature = "cuda")]
    fn prove_root_gpu(&mut self, stdin: Stdin) -> Result<(Box<ProofWithVk>, Vec<u8>), ProveError> {
        use pico_mle_core::codec::Decode;

        let Some(vk_map) = &self.vk_map else {
            return Err(ProveError::WhitelistModeRequired {
                what: "GPU proving",
            });
        };
        let program = distributed_vm::mle::embed::EmbeddedProgram {
            elf: Arc::clone(&self.elf),
            whitelist: Arc::clone(vk_map),
            trusted_root: vk_map.root(),
            // The chunk size, and so the program id, stay this prover's.
            emulator_opts: match self.emulation {
                EmulationPath::Pipeline {
                    snapshot_main,
                    replay_workers,
                    ..
                } => EmulatorOpts {
                    snapshot_main,
                    replay_workers,
                    ..self.opts
                },
                EmulationPath::Serial => self.opts,
            },
            event_pool_size: self.gpu_event_pool_size,
            emulation_workers: self.gpu_emulation_workers,
        };
        let out = distributed_vm::mle::embed::prove(program, stdin.into_emulator_stdin())
            .map_err(ProveError::from_embed)?;

        let root_vk = out
            .root
            .root_vk
            .ok_or_else(|| ProveError::Gpu("whitelist root exported without its vk".into()))?;
        let proof = crate::types::InnerProof::decode_from_bytes(&out.root.proof)
            .map_err(|e| ProveError::Gpu(format!("cannot decode the root proof: {e}")))?;
        let vk: VerifyingKey = bincode::deserialize(&root_vk)
            .map_err(|e| ProveError::Gpu(format!("cannot decode the root vk: {e}")))?;
        let root: Box<ProofWithVk> = Box::new((proof, Arc::new(vk)));

        self.verify_root(&root)?;
        Ok((root, out.committed))
    }

    /// A root this prover did not just prove on the CPU: it must be complete, then pass the apex
    /// or, without a whitelist, the combine machine that keygen'd its shape.
    fn verify_root(&self, root: &ProofWithVk) -> Result<(), ProveError> {
        let phase = Phase::Combine;
        if !binding::is_complete_root(&root.0.public_values) {
            return Err(ProveError::Incomplete);
        }
        match &self.apex {
            // The whitelist authenticates the supplied key by membership, which is what lets a
            // machine that keygen'd nothing accept this proof.
            Some(apex) => apex
                .verify(root)
                .map_err(|e| ProveError::verification(phase, format!("{e:#}"))),
            // Otherwise only the machine that keygen'd the shape can select an honest key for it.
            // Deriving one from the file would be letting the file choose the circuit it is
            // checked against.
            None => {
                if self.combine.honest_root_vk(&root.1).is_none() {
                    return Err(ProveError::WhitelistRequired { phase });
                }
                self.combine
                    .verify(root)
                    .map_err(|e| ProveError::verification(phase, format!("{e:#}")))
            }
        }
    }

    /// A verified combine root as a [`Proof`], once `committed` is bound to it.
    fn combine_proof(
        &self,
        root: Box<ProofWithVk>,
        committed: Vec<u8>,
        chunk_count: Option<usize>,
        distinct_shapes: Option<usize>,
    ) -> Result<Proof, ProveError> {
        let digest = binding::recursion_committed_digest(&root.0.public_values, Phase::Combine)?;
        let bound = binding::rebind(committed, digest)?;
        Ok(self.finish(
            Phase::Combine,
            bound,
            chunk_count,
            distinct_shapes,
            Payload::Combine(root),
        ))
    }

    /// Takes the output as [`binding::Bound`], so no path reaches a [`Proof`] without rebinding.
    fn finish(
        &self,
        phase: Phase,
        bound: binding::Bound,
        chunk_count: Option<usize>,
        distinct_shapes: Option<usize>,
        payload: Payload,
    ) -> Proof {
        let (committed, committed_value_digest) = bound.into_parts();
        Proof {
            phase,
            program_id: self.program_id,
            log_stacked_height: self.log_stacked_height,
            verify_keys: self.verify_keys,
            committed,
            committed_value_digest,
            chunk_count,
            distinct_shapes,
            misaligned_accesses: None,
            payload,
        }
    }

    /// The one entry point for a proof loaded from a file.
    ///
    /// Checks, in order: the operating point, the program identity, then a phase-specific
    /// verification, then the SHA-256 rebinding of the stored output bytes. Only then does a
    /// [`Proof`] exist, so the bytes cannot be read before the proof that covers them is verified.
    /// The operating point goes first because the program identity moves with it: a file proved at
    /// another height would otherwise be reported as another program.
    ///
    /// | phase | what this does | what the committed bytes are then bound to |
    /// |---|---|---|
    /// | [`Phase::Riscv`] | verifies against keys derived from **this prover's** ELF — sound in a fresh process — then refuses any chunk whose public values carry an exit code other than 0, with [`ProveError::NonZeroExitCode`] | a set of chunks, each proved and each carrying exit code 0 in its public values, whose global cumulative sums cancel the program's initial one. Whether they form one run that reached its halt is what [`Proof::binds_complete_execution`] reports, and it is false here |
    /// | [`Phase::Combine`] | verifies against the pinned whitelist, or against the shapes this prover keygen'd while proving and still retains; with neither, [`ProveError::WhitelistRequired`] | one complete execution: the root carries `flag_complete`, so the in-circuit continuity and halting asserts ran |
    /// | [`Phase::Compress`] | verifies against the pinned whitelist (the compress key is a whitelist leaf, checked by the apex under the compress preset), or against the compress shape this prover keygen'd while proving and still retains; with neither, [`ProveError::WhitelistRequired`] | the same complete execution as the root it re-proves: the public values are the root's, unchanged |
    ///
    /// The artifact's own verifying key is never compiled into a verifier circuit, and its child
    /// layouts are not stored at all. A file that cannot be answered for is refused by name rather
    /// than answered with something that resembles verification.
    pub fn verify_artifact(&self, artifact: ProofArtifact) -> Result<Proof, ProveError> {
        if artifact.log_stacked_height != self.log_stacked_height
            || artifact.verify_keys != self.verify_keys
        {
            return Err(ProveError::OperatingPointMismatch {
                expected_log_stacked_height: self.log_stacked_height,
                found_log_stacked_height: artifact.log_stacked_height,
                expected_verify_keys: self.verify_keys,
                found_verify_keys: artifact.verify_keys,
            });
        }
        if artifact.program_id != self.program_id {
            return Err(ProveError::ProgramMismatch {
                expected: self.program_id,
                found: artifact.program_id,
            });
        }

        let phase = artifact.phase();
        let ProofArtifact {
            committed, payload, ..
        } = artifact;

        match payload {
            LoadedPayload::Riscv(bundle) => {
                binding::ensure_chunk_gcs(binding::public_values(&bundle.chunk_proofs))?;
                riscv::verify_riscv(
                    &bundle,
                    self.expected_vk_pre_hash,
                    &self.expected_app_commits,
                    self.initial_gcs,
                )
                .map_err(|e| ProveError::verification(phase, e.to_string()))?;
                binding::ensure_exit_code_zero(binding::public_values(&bundle.chunk_proofs))?;
                self.riscv_proof(bundle, committed, None)
            }
            LoadedPayload::Combine(root) => {
                self.verify_root(&root)?;
                self.combine_proof(root, committed, None, None)
            }
            LoadedPayload::Compress(compress) => {
                if !binding::is_complete_root(&compress.0.public_values) {
                    return Err(ProveError::Incomplete);
                }
                match &self.apex {
                    // The compress key is a whitelist leaf, so membership authenticates it as it
                    // does a root's: a machine that keygen'd nothing accepts the proof.
                    Some(apex) => apex
                        .verify_compress(&compress)
                        .map_err(|e| ProveError::verification(phase, format!("{e:#}")))?,
                    // Otherwise only the machine that keygen'd the compress shape can select an
                    // honest key for it.
                    None => {
                        let Some(machine) = self
                            .compress
                            .as_ref()
                            .filter(|machine| machine.honest_compress_vk(&compress.1).is_some())
                        else {
                            return Err(ProveError::WhitelistRequired { phase });
                        };
                        machine
                            .verify(&compress)
                            .map_err(|e| ProveError::verification(phase, format!("{e:#}")))?
                    }
                }
                self.compress_proof(compress, committed, None, None)
            }
        }
    }
}

/// How many of `vks` the whitelist does not contain.
fn not_whitelisted<'a>(map: &MleVkMap, vks: impl Iterator<Item = &'a VerifyingKey>) -> usize {
    vks.filter(|vk| map.find(&vk_identity(vk)).is_none())
        .count()
}

pub(crate) fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|message| message.to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic with a non-string payload".into())
}
