//! Embeddable single-node GPU proving: one ELF and stdin in, one verified whitelist-mode root out.
//!
//! Library callers (`pico-prover`'s `cuda` feature) use this instead of the CLI and its
//! environment: the program, the whitelist and the emulator options come in as arguments, and the
//! cards are the visible ones.

use std::{fmt, num::NonZeroUsize, sync::Arc};

use p3_koala_bear::KoalaBear;
use pico_vm::{
    emulator::{
        opts::EmulatorOpts,
        riscv::record::{GpuMemoryTier, TierAlreadySet},
    },
    mle::machine::vk_map::MleVkMap,
};

#[cfg(feature = "cuda")]
use pico_vm::{compiler::riscv::program::Program, emulator::stdin::EmulatorStdin};

#[cfg(feature = "cuda")]
use super::{config::Step, run_step, BlockJob, MleSingleNodeConfig, RootProofExport};

/// The program and whitelist a [`prove`] call proves under, carried on the single-node config.
#[derive(Clone)]
pub struct EmbeddedProgram {
    pub elf: Arc<[u8]>,
    pub whitelist: Arc<MleVkMap>,
    /// The root the apex accepts; the whitelist must carry it.
    pub trusted_root: [KoalaBear; 8],
    pub emulator_opts: EmulatorOpts,
    /// Pinned CPU and ALU event buffers, each holding `emulator_opts.chunk_size` events, that
    /// bound how far emulation runs ahead of proving. They stay allocated for the life of the
    /// process. See [`DEFAULT_EVENT_POOL_SIZE`] and [`pinned_event_bytes`].
    pub event_pool_size: NonZeroUsize,
    /// Interpreters replaying the snapshot thread's snapshots into records. See
    /// [`default_pipeline_workers`](pico_vm::proverchain::riscv::default_pipeline_workers).
    pub emulation_workers: NonZeroUsize,
}

/// [`EmbeddedProgram::event_pool_size`]'s default. The entry pins buffers on demand, so a small
/// guest pins only the few it uses; a reth block pins up to all 32. Each in-flight chunk holds one
/// CPU and two ALU buffers, and the pipeline lets replay run only as far ahead as the pools hold.
pub const DEFAULT_EVENT_POOL_SIZE: NonZeroUsize = NonZeroUsize::new(32).unwrap();

/// The most of the host's memory the event pools may pin; the rest is the emulation's and the
/// provers' working set. A pool past it is refused up front instead of failing mid-run.
pub const MAX_PINNED_EVENT_FRACTION: f64 = 0.5;

/// Host memory the event pools pin: `pool_size` CPU and ALU buffers of `chunk_size` events each.
pub fn pinned_event_bytes(pool_size: NonZeroUsize, chunk_size: u32) -> u64 {
    use pico_vm::chips::chips::{alu::event::AluEvent, riscv_cpu::event::CpuEvent};
    let per_slot = (size_of::<CpuEvent>() + size_of::<AluEvent>()) as u64;
    (pool_size.get() as u64)
        .saturating_mul(u64::from(chunk_size))
        .saturating_mul(per_slot)
}

impl fmt::Debug for EmbeddedProgram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmbeddedProgram")
            .field("elf_len", &self.elf.len())
            .field("trusted_root", &self.trusted_root)
            .field("emulator_opts", &self.emulator_opts)
            .field("event_pool_size", &self.event_pool_size)
            .field("emulation_workers", &self.emulation_workers)
            .finish_non_exhaustive()
    }
}

/// Smallest card the 24 GB tier fits on. A nominal 24 GB card reports a little under 24 GiB.
pub const MIN_CARD_BYTES: usize = 22 << 30;
/// Smallest card that gets the 32 GB tier.
pub const TIER_32GB_CARD_BYTES: usize = 30 << 30;

#[derive(Debug)]
pub enum EmbedError {
    NoDevice(String),
    CardTooSmall {
        card: usize,
        bytes: usize,
    },
    WhitelistRootMismatch,
    /// An earlier emulation latched another memory tier than the cards need.
    TierLatched(TierAlreadySet),
    /// The event pools cannot hold one chunk's replay segments, so the run could not finish.
    EventPoolTooSmall(String),
    /// The event pools would pin more of the host's memory than [`MAX_PINNED_EVENT_FRACTION`].
    EventPoolTooLarge {
        pool_size: usize,
        pinned_bytes: u64,
        host_bytes: u64,
    },
    NoRoot,
    /// The guest's emulation failed, or the emulator panicked (a host-side emulator bug
    /// included). The run was drained, and the process can prove again.
    Guest(super::GuestFailure),
    Panicked(String),
    /// An earlier call failed and may have left the pipeline's threads and scheduler mid-run.
    Poisoned,
}

impl fmt::Display for EmbedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDevice(e) => write!(f, "no usable CUDA device: {e}"),
            Self::CardTooSmall { card, bytes } => write!(
                f,
                "card {card} has {:.1} GiB; GPU proving needs at least {} GiB",
                *bytes as f64 / (1u64 << 30) as f64,
                MIN_CARD_BYTES >> 30
            ),
            Self::WhitelistRootMismatch => {
                write!(f, "the whitelist does not carry the trusted root")
            }
            Self::TierLatched(e) => write!(f, "{e}"),
            Self::EventPoolTooSmall(why) => write!(f, "{why}; raise the event pool size"),
            Self::EventPoolTooLarge {
                pool_size,
                pinned_bytes,
                host_bytes,
            } => write!(
                f,
                "an event pool of {pool_size} would pin {:.0} GiB of this host's {:.0} GiB; \
                 lower the pool size",
                *pinned_bytes as f64 / (1u64 << 30) as f64,
                *host_bytes as f64 / (1u64 << 30) as f64,
            ),
            Self::NoRoot => write!(f, "the pipeline produced no root proof"),
            Self::Guest(failure) => write!(f, "the guest failed: {failure}"),
            Self::Panicked(msg) => write!(f, "GPU proving failed: {msg}"),
            Self::Poisoned => write!(
                f,
                "a previous GPU prove failed in this process; restart the process to prove again"
            ),
        }
    }
}

impl std::error::Error for EmbedError {}

/// The visible cards and the memory tier they get.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpuResources {
    pub cards: usize,
    /// Total memory of the smallest card, in bytes.
    pub min_card_bytes: usize,
}

impl GpuResources {
    /// The memory tier matching the smallest card.
    pub fn memory_tier(&self) -> GpuMemoryTier {
        if self.min_card_bytes >= TIER_32GB_CARD_BYTES {
            GpuMemoryTier::Tier32GB
        } else {
            GpuMemoryTier::Tier24GB
        }
    }
}

/// Latches the precompile-split memory tier for the visible cards (`PICO_GPU_MEM` overrides)
/// before any emulation reads it. Fails if an earlier emulation latched another tier.
#[cfg(feature = "cuda")]
pub fn init_memory_tier() -> Result<GpuResources, EmbedError> {
    use pico_vm::emulator::riscv::record::{gpu_memory_tier_from_env, init_prover_hardware_config};

    let gpus = gpu_resources()?;
    let tier = gpu_memory_tier_from_env().unwrap_or(gpus.memory_tier());
    init_prover_hardware_config(tier).map_err(EmbedError::TierLatched)?;
    Ok(gpus)
}

/// Counts the visible cards and checks each is big enough.
#[cfg(feature = "cuda")]
pub fn gpu_resources() -> Result<GpuResources, EmbedError> {
    use pico_vm::mle::cuda_mle::runtime::{context::set_device, memory_manager::device_mem_info};

    let cards = cudart::device::get_device_count()
        .map_err(|e| EmbedError::NoDevice(format!("{e:?}")))? as usize;
    if cards == 0 {
        return Err(EmbedError::NoDevice("device count is 0".into()));
    }
    let mut min_card_bytes = usize::MAX;
    for card in 0..cards {
        set_device(card as i32).map_err(|e| EmbedError::NoDevice(format!("{e:?}")))?;
        let (_, total) = device_mem_info();
        if total < MIN_CARD_BYTES {
            return Err(EmbedError::CardTooSmall { card, bytes: total });
        }
        min_card_bytes = min_card_bytes.min(total);
    }
    set_device(0).map_err(|e| EmbedError::NoDevice(format!("{e:?}")))?;
    Ok(GpuResources {
        cards,
        min_card_bytes,
    })
}

/// A verified root and what the run committed.
#[cfg(feature = "cuda")]
pub struct EmbeddedProof {
    /// The root in `mle-core`'s wire format, with its vk (`root_vk` is always set here).
    pub root: RootProofExport,
    /// The bytes the guest committed; the root's `committed_value_digest` binds them.
    pub committed: Vec<u8>,
    pub cycles: u64,
}

/// Set once a pipeline run fails other than by its guest (a device error, a panicking stage, no
/// root): the run can leave worker threads and scheduler state behind, so the process proves
/// nothing more.
#[cfg(feature = "cuda")]
static POISONED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Proves `program` on `stdin` to one complete whitelist-mode root on all visible cards, and
/// verifies it with the apex before returning. One call at a time per process. A guest whose
/// emulation fails returns [`EmbedError::Guest`] and leaves the process able to prove; after any
/// other failed run every later call returns [`EmbedError::Poisoned`].
///
/// The memory tier is latched as [`init_memory_tier`] does; a caller that emulates before its
/// first call should run that first.
#[cfg(feature = "cuda")]
pub fn prove(
    program: EmbeddedProgram,
    stdin: EmulatorStdin<Program, Vec<u8>>,
) -> Result<EmbeddedProof, EmbedError> {
    static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    if POISONED.load(std::sync::atomic::Ordering::Acquire) {
        return Err(EmbedError::Poisoned);
    }

    if program.whitelist.root() != program.trusted_root {
        return Err(EmbedError::WhitelistRootMismatch);
    }
    check_pinned_memory(&program)?;
    let gpus = init_memory_tier()?;

    let cfg = MleSingleNodeConfig {
        step: Step::Combine,
        elf: "embedded".into(),
        n: 0,
        prover_count: gpus.cards,
        // The height the whitelist's shapes are sized for.
        log_stacked_height: pico_vm::mle::machine::riscv::DEFAULT_LOG_STACKED_HEIGHT,
        embedded: Some(program),
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_step(&cfg, None, Some(BlockJob { block: 0, stdin }))
    }));
    let mut outcome = match outcome {
        Ok(outcome) => outcome,
        Err(payload) => {
            POISONED.store(true, std::sync::atomic::Ordering::Release);
            return Err(EmbedError::Panicked(super::watch::panic_message(&*payload)));
        }
    };
    // The guest failed and the run drained cleanly: the process can prove again.
    if let Some(failure) = outcome.guest_failure.take() {
        return Err(EmbedError::Guest(failure));
    }
    let Some(root) = outcome.root.take() else {
        POISONED.store(true, std::sync::atomic::Ordering::Release);
        return Err(EmbedError::NoRoot);
    };
    Ok(EmbeddedProof {
        root,
        committed: outcome.committed,
        cycles: outcome.cycles,
    })
}

/// Refuses event pools too small for one chunk's replay segments, or that would pin more than
/// [`MAX_PINNED_EVENT_FRACTION`] of the host: up front, where a refusal poisons nothing.
#[cfg(feature = "cuda")]
fn check_pinned_memory(program: &EmbeddedProgram) -> Result<(), EmbedError> {
    use pico_vm::proverchain::riscv::{chunk_segments, event_pool_refusal};
    let pool = Some(program.event_pool_size.get());
    let segments = chunk_segments(program.emulator_opts.snapshot_main);
    if let Some(error) = event_pool_refusal(pool, pool, segments) {
        return Err(EmbedError::EventPoolTooSmall(error.to_string()));
    }
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    // A container's limit, where there is one, is the host it gets.
    let host_bytes = sys.cgroup_limits().map_or(sys.total_memory(), |limits| {
        limits.total_memory.min(sys.total_memory())
    });
    let pinned_bytes =
        pinned_event_bytes(program.event_pool_size, program.emulator_opts.chunk_size);
    if pinned_bytes as f64 > host_bytes as f64 * MAX_PINNED_EVENT_FRACTION {
        return Err(EmbedError::EventPoolTooLarge {
            pool_size: program.event_pool_size.get(),
            pinned_bytes,
            host_bytes,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_tier_follows_the_smallest_card() {
        let tier = |gib: usize| {
            GpuResources {
                cards: 1,
                min_card_bytes: gib << 30,
            }
            .memory_tier()
        };
        assert_eq!(tier(23), GpuMemoryTier::Tier24GB);
        assert_eq!(tier(31), GpuMemoryTier::Tier32GB);
        assert_eq!(tier(80), GpuMemoryTier::Tier32GB);
    }
}
