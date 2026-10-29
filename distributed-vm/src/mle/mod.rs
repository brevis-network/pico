//! MLE/WHIR single-node orchestration (KoalaBear).
//!
//! In-process pipeline:
//! - emulation runs `emulate_snapshot_pipeline` with `bench_riscv_ops` opts; it self-initializes
//!   the shared snapshot memory-pool/recycler (sized via `MEMORY_POOL_SIZE`) and streams records
//!   to a preparer thread. (Distinct from the CPU/ALU event-buffer pool this module pre-sizes via
//!   `MLE_EVENT_POOL_SIZE`.) `PICO_GPU_MEM=5090` selects the precompile-split thresholds;
//! - a [`GlobalScheduler`] hands chunk indices to a worker pool. Without `--step combine` it runs
//!   in no-combine mode and completes by count (chunk proofs are terminal); with it, the scheduler
//!   also runs its aggregation tree — convert proofs are reported into its proof tree, adjacent
//!   pairs become combine tasks, and the same worker pool proves those nodes;
//! - each worker proves its chunk via the shared [`RiscvMachine`];
//! - cross-chunk memory consistency is checked at the end (`Σ gcs + initial == 0`);
//! - `--step combine` then hands the tree's root to the CPU `CombineMachine` for the four-step
//!   host-side acceptance, so that check lives in exactly one place.

pub mod config;
pub mod embed;
pub mod ethproofs;
pub mod two_machine;
mod watch;

use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use p3_koala_bear::KoalaBear;
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        opts::EmulatorOpts,
        record::RecordBehavior,
        riscv::{
            alu_event_pool::size_alu_event_buffer_pool,
            cpu_event_pool::size_cpu_event_buffer_pool,
            event_pool::{pooled_event_buffers, HostAllocFlags, Pinning},
            record::EmulationRecord,
        },
        stdin::EmulatorStdin,
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::{septic::SepticDigest, witness::ProvingWitness},
    mle::{
        env_flag,
        machine::{
            convert::ProofWithVk,
            riscv::{corrupt_one_record, PreparedChunk, RiscvMachine},
        },
    },
    proverchain::riscv::{
        emulate_snapshot_pipeline, emulate_snapshot_pipeline_with, DeferredSplit,
    },
};
use tracing::{info, warn};
use watch::SpawnWatched;

// The streaming convert stage is GPU-only (no CPU path); its types exist only under `cuda`.
#[cfg(feature = "cuda")]
use pico_vm::mle::machine::{
    apex::MleApexVerifier,
    convert::GpuConvertMachine,
    exe::RiscvVmVk,
    vk_map::{pinned_root_from_env, MleVkMap},
};
use pico_vm::mle::spans::{self, LaneId, Role, WorkKind};

use crate::common::{
    gcs_digest::take_remote_digests,
    global_scheduler::GlobalScheduler,
    machine_role::{get_worker_label, set_mle_chunk_assignment_defaults},
    mle_scheduler_singleton::{
        get_mle_scheduler, is_mle_secondary, mle_acquire_task_unified_async,
        mle_finalize_emulation, mle_register_chunk, mle_report_chunk_terminal,
        mle_report_gcs_digest, reset_mle_scheduler, MleAcquireResult,
    },
};
// The combine-preparer feed names the task type; on CPU builds the dispatcher's combine arm is
// `unreachable!` and never names it.
#[cfg(feature = "cuda")]
use crate::common::global_scheduler::CombineTask;
// Reached only from the convert/combine reporting arms, which are GPU-only.
#[cfg(feature = "cuda")]
use crate::{
    common::mle_scheduler_singleton::mle_report_proof, gateway::handler::proof_tree::IndexedProof,
};
use config::{MleSingleNodeConfig, Step};

/// The RISCV chunk proof type. It flows to the convert stage over a channel; it never enters the
/// scheduler (see [`SchedulerProof`]).
type MleProof = pico_vm::mle::proof::Proof<pico_vm::mle::machine::riscv::Sc>;

/// The final combine node, handed from the worker that proved it to the main thread.
///
/// `proof` is the `Arc` the scheduler's `IndexedProof` already wraps, so stashing it costs a
/// refcount rather than a deep copy of the proof.
#[cfg(feature = "cuda")]
struct RootRecord {
    proof: Arc<SchedulerProof>,
    /// The root node's ORDERED child layouts — required to register its shape on the CPU
    /// `CombineMachine` before that machine will accept the root (see its `verify` CONTRACT).
    child_layouts: Vec<pico_vm::mle::compiler::recursion::RecursionVkLayout>,
}

/// What the scheduler's proof tree holds: a **convert** proof with its vk.
///
/// The tree exists to pair adjacent proofs into combine tasks, and combine verifies *convert*
/// proofs — so the convert layer, not the riscv layer, is what gets reported. The riscv level
/// reports terminally (payload-free, [`GlobalScheduler::report_chunk_terminal`]) in every mode,
/// which is what keeps the riscv proof type out of this alias. Mirrors FRI, where a chunk task
/// spans riscv+convert inside the worker and the gateway reports the convert proof.
type SchedulerProof = ProofWithVk;

/// One block handed to [`run_pipeline`] from outside, in place of the fixture `--elf`/`--n` names.
///
/// The ethproofs entry point owns the block number (RSP chose it) and the witness bytes (RSP sent
/// them), so it builds the stdin itself; the fixture path in [`stdin_for_block`] stays for the
/// benchmark and sweep entry points. Nothing downstream of the stdin differs between the two.
pub struct BlockJob {
    /// The block this stdin proves. Carried only so a caller need not track it alongside.
    pub block: u64,
    pub stdin: EmulatorStdin<Program, Vec<u8>>,
}

/// What one block produced, for a caller that has to report it somewhere rather than only log it.
///
/// A benchmark run discards this -- the log lines are its product. The ethproofs entry needs the
/// same numbers as DATA, because they become `ProofInfo` fields that a public leaderboard reads.
#[derive(Default)]
pub struct BlockOutcome {
    /// Emulated RISC-V cycles, from `emulate_snapshot_pipeline`'s second return value. Reported to
    /// ethproofs as `proving_cycles`.
    pub cycles: u64,
    /// The `e2e=` window: emulate through the collapsed proof tree, excluding setup and root
    /// acceptance. NOT what gets reported as `proving_time` -- see the ethproofs entry, which
    /// measures from the gRPC boundary because that is the span a verifier can hold us to.
    pub e2e_wall: Duration,
    /// Host-side root acceptance, which follows the `e2e=` window rather than sitting inside it.
    pub root_accept: Duration,
    /// `None` without `--step combine` (there is no root), and on an MLE secondary (the root is
    /// proved and accepted on the primary by construction).
    pub root: Option<RootProofExport>,
    /// The bytes the guest committed, from the emulation. Bound to a proof only by the root's
    /// `committed_value_digest`, which a verifier checks.
    pub committed: Vec<u8>,
}

/// The combine root, packaged so somebody else can verify it.
///
/// The proof bytes are NOT self-contained: `CombineMachine::verify` checks a root against a vk the
/// verifying machine keygen'd itself, so it must first `register_shape(child_layouts, true)`. Ship
/// the layouts with the proof or the recipient has nothing to register and cannot check anything.
pub struct RootProofExport {
    /// `mle-core`'s canonical versioned wire format.
    pub proof: Vec<u8>,
    /// The root node's ORDERED child layouts.
    pub child_layouts: Vec<pico_vm::mle::compiler::recursion::RecursionVkLayout>,
    /// `RiscvVmVk::digest()`, the exe identity the root is pinned against.
    pub riscv_vk_digest: String,
    /// Whitelist mode only: bincode of the root's verifying key. A verifier does not trust it --
    /// the apex accepts it only as a member of the pinned whitelist -- which is what lets the root
    /// be checked from artifacts alone, without the child layouts (and without trusting them).
    pub root_vk: Option<Vec<u8>>,
}

/// Whether the caller explicitly asked for MLE two-machine, which is what decides if the
/// single-node pin below is applied. Opt-in and off by default, so single-node keeps the exact
/// behaviour it had when the pin was unconditional.
///
/// Nothing sets this yet — MLE has no two-machine launch shape — so this is the seam a
/// two-machine launch would use, not a live switch.
/// Whether THIS process owns the program's initial GCS seed. Exactly one process in the run may,
/// and it is the primary (or the single node). See the seeding rule at the constructor loop.
/// How many other machines owe this one a GCS partial. Derived from the scheduler topology rather
/// than hardcoded to 1, so a wider topology does not silently close the sum over a subset.
fn expected_remote_digests() -> usize {
    if !mle_two_machine_requested() || is_mle_secondary() {
        return 0;
    }
    crate::common::machine_role::get_runtime_mode()
        .topology()
        .worker_count()
        .saturating_sub(1)
}

/// Take a chunk's prepared trace, waiting for the local emulator if it has not got there yet.
///
/// Single-node registered a chunk only after storing it, so acquiring one implied it was present
/// and an `expect` was safe. Two-machine breaks that: the chunk registry is global — the primary's
/// emulator drives it — while the store is per-process, and the two emulators run independently
/// (both emulate the whole block). So either side can be handed a chunk it owns before
/// its OWN emulator has produced the trace. Both machines hit this in turn, as
/// `prepared chunk missing for acquired task`.
///
/// Acquisition means "this chunk is yours", not "your trace is ready". Waiting is therefore the
/// correct reading, not a workaround — the trace is coming, from this machine's own emulator. The
/// timeout keeps a genuine loss (an emulator that died, a chunk index nobody will produce) from
/// becoming a silent hang.
fn take_prepared_chunk(store: &DashMap<usize, PreparedChunk>, chunk_idx: usize) -> PreparedChunk {
    if let Some((_, chunk)) = store.remove(&chunk_idx) {
        return chunk;
    }
    let t = Instant::now();
    let deadline = Duration::from_secs(600);
    loop {
        if let Some((_, chunk)) = store.remove(&chunk_idx) {
            info!(
                "chunk {chunk_idx}: waited {:.3}s for the local emulator",
                t.elapsed().as_secs_f64()
            );
            return chunk;
        }
        assert!(
            t.elapsed() < deadline,
            "prepared chunk {chunk_idx} never arrived from this machine's emulator \
             ({}s); it was acquired from the scheduler, so either this machine's emulation \
             stopped early or the chunk index does not exist",
            deadline.as_secs()
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// `VK_VERIFICATION=true`, parsed as the e2e parses it: riscv chunks take whitelist shapes and the
/// recursion machines witness the whitelist. Off by default, as the prover ships.
fn vk_verification() -> bool {
    std::env::var("VK_VERIFICATION").is_ok_and(|v| v.eq_ignore_ascii_case("true"))
}

/// The whitelist artifact (`MLE_VK_MAP`, checked against `MLE_VK_ROOT` by the loader). The GPU
/// pipeline has no self-map fallback: it keygens convert VKs as chunks arrive, so the whitelist
/// must exist before the first proof.
#[cfg(feature = "cuda")]
fn whitelist_map() -> Arc<MleVkMap> {
    let path = std::env::var("MLE_VK_MAP")
        .expect("VK_VERIFICATION=true needs MLE_VK_MAP, the whitelist artifact");
    let map = MleVkMap::load(&path);
    info!(
        "whitelist: `{path}`, {} entries, root = {:?}",
        map.entries.len(),
        map.root()
    );
    Arc::new(map)
}

fn keeps_initial_gcs_seed() -> bool {
    !mle_two_machine_requested() || crate::common::machine_role::get_machine_role().is_primary()
}

/// Whether this machine must build a `PreparedChunk` for `chunk_idx`.
///
/// Both machines emulate the whole block — the primary because it registers every chunk with the
/// scheduler, the secondary because records cannot be shipped — but each proves only its share,
/// so preparing the other's chunks is work whose only consumer is the eviction that throws it
/// away. Worse, a prepared chunk pins an event buffer until something drops it, and the other
/// machine's half is dropped only once that machine proves it and reports back: that is what
/// coupled emulation to the peer and made a 64-buffer pool stall the emulator.
///
/// Deliberately routed through the scheduler's own predicate rather than re-deriving the split.
/// If this said "not mine" about a chunk the scheduler later handed us, `take_prepared_chunk`
/// would wait on a record that is never coming, so the two must agree by construction and not by
/// two copies of the same rule. Dynamic chunks answer `true` for both machines, which is correct:
/// either may be assigned one, so both must hold it ready.
fn prepares_chunk(chunk_idx: usize) -> bool {
    if !mle_two_machine_requested() {
        return true;
    }
    crate::common::machine_role::get_runtime_mode()
        .worker_can_handle_chunk_for_worker(&get_worker_label(), chunk_idx)
}

fn mle_two_machine_requested() -> bool {
    std::env::var("MLE_TWO_MACHINE")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            !(v.is_empty() || v == "0" || v == "false")
        })
        .unwrap_or(false)
}

/// Two prover lanes per card — riscv and recursion — unless `MLE_RECURSION_LANE=0` asks for one.
///
/// Off is not "the second lane idles": the single lane takes riscv, convert and combine on one
/// `select!`, which is the shape the split was carved out of.
///
/// Read ONCE in `run_pipeline` and passed down as a `bool`. Everything derived from it has to
/// agree — which lane is handed the riscv queue, which one holds the [`RiscvLane`] handles, and
/// whether that lane's `items_open` starts live. Two reads of an env that moved in between would
/// give the queue to one lane and the exit condition to another, which does not error, it hangs.
///
/// Both sides are allow-lists, and a value outside them **warns**. That is stricter than the
/// neighbouring readers (`common::parse::env_flag` allows on-words and silently drops the rest;
/// `mle_two_machine_requested` above uses a deny-list), deliberately: this is the only one of the
/// three whose default is ON, so an unrecognised value would leave the faster shape running under
/// someone who had asked for the slower one, and they would have no reason to go looking. The name
/// reads like a count, which makes `MLE_RECURSION_LANE=2` a spelling people reach for — it does not
/// mean "two lanes", and now it says so instead of passing. An empty value reads as unset.
fn recursion_lane_enabled() -> bool {
    recursion_lane_from(std::env::var("MLE_RECURSION_LANE").ok().as_deref())
}

/// The word lists, split out from the read so they can be tested: they are this change's whole
/// user interface, and a value quietly falling through to the default is the failure that costs
/// someone a benchmark. Reading the env itself is not testable in-process — Rust runs tests in
/// threads of one process, so a test that set the variable would race every other test.
fn recursion_lane_from(raw: Option<&str>) -> bool {
    let Some(raw) = raw else { return true };
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        // `raw`, not the normalised form: the point of this line is to show the reader what they
        // typed, and echoing `" Two "` back as `"two"` hides half of what was wrong with it.
        _ => {
            warn!(
                "MLE_RECURSION_LANE={raw:?} is neither on (1/true/yes/on) nor off \
                 (0/false/no/off); keeping both prover lanes per card"
            );
            true
        }
    }
}

/// Pre-build each chunk's convert verify program during the riscv prove that precedes it —
/// **default ON**, `MLE_CONVERT_PREBUILD=0` restores the pre-change path exactly.
///
/// It ships on because it is measured: 58 paired ratios over 5 queues and 9 blocks put it at
/// **−2.63 % E2E on the production p99 blocks**, re-measured after a rebase at −1.9 to −3.0 %
/// with every cut's interval excluding 1.00. Correctness is unchanged by construction — the
/// program is a pure function of the layout, so pre-building computes the same program earlier,
/// and a pre-build that turns out wrong is discarded by the consumer's own equality check.
///
/// Same allow-list treatment as [`recursion_lane_from`], and for the same reason: this default is
/// ON, so an unrecognised value would silently leave the new path running under someone who asked
/// for the old one while they were trying to bisect a regression. An empty value reads as unset.
#[cfg(feature = "cuda")]
fn convert_prebuild_enabled() -> bool {
    convert_prebuild_from(std::env::var("MLE_CONVERT_PREBUILD").ok().as_deref())
}

/// The card a convert chunk belongs to: drawn round-robin the first time anyone asks, and
/// remembered so the pre-build and the preparer agree.
///
/// Both sides go through this. If they each drew for themselves the counter would advance twice
/// per chunk and the preparer would only ever see every other card — the same halving the routing
/// comment in the preparer warns about. The map is never pruned: it is one entry per chunk, and
/// removing on read would reintroduce the double draw for a chunk pre-built after its preparer ran.
///
/// Ungated so the tests below can reach it without CUDA — the double draw it exists to prevent is
/// a property of the counter and the map, not of any device.
#[cfg_attr(not(feature = "cuda"), allow(dead_code))]
fn convert_card_for(
    chunk_idx: usize,
    claimed: &DashMap<usize, usize>,
    card_rr: &AtomicUsize,
    cards: usize,
) -> usize {
    *claimed
        .entry(chunk_idx)
        .or_insert_with(|| card_rr.fetch_add(1, Ordering::Relaxed) % cards)
}

/// `MLE_CONVERT_PREBUILD_PK` has the pre-build warm the device proving key as well as the program.
/// **Default ON**, `MLE_CONVERT_PREBUILD_PK=0` restores the program-only pre-build.
///
/// It ships on because it is measured: with the combine half below, fourteen paired runs over the
/// p99 blocks put the two at **-2.15 % E2E**, eleven pairs faster, one tied, two slower, with peak
/// VRAM unchanged. What it costs is that those workers bind a card and do device work, which the
/// program half deliberately avoids — see [`ConvertPrebuild`].
///
/// Same allow-list treatment as [`convert_prebuild_from`], and for the same reason: the default is
/// ON, so an unrecognised value must not silently leave the new path running under someone who
/// asked for the old one.
#[cfg(feature = "cuda")]
fn convert_prebuild_pk_enabled() -> bool {
    convert_prebuild_from(std::env::var("MLE_CONVERT_PREBUILD_PK").ok().as_deref())
}

/// Split from the read so the word lists are testable; reading the env in-process is not, because
/// Rust runs tests as threads of one process and a test that set the variable would race.
///
/// Ungated so `cargo test -p distributed-vm` runs its tests without CUDA, exactly as the sibling
/// `recursion_lane_from` does — the word lists are this flag's whole user interface, and a
/// mistyped value silently keeping the new path on is what they exist to catch.
#[cfg_attr(not(feature = "cuda"), allow(dead_code))]
fn convert_prebuild_from(raw: Option<&str>) -> bool {
    let Some(raw) = raw else { return true };
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => {
            warn!(
                "MLE_CONVERT_PREBUILD={raw:?} is neither on (1/true/yes/on) nor off \
                 (0/false/no/off); keeping the convert pre-build enabled"
            );
            true
        }
    }
}

#[cfg(test)]
mod convert_prebuild_tests {
    use super::{convert_card_for, convert_prebuild_from};
    use dashmap::DashMap;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[test]
    fn unset_and_empty_leave_the_prebuild_on() {
        assert!(convert_prebuild_from(None));
        assert!(convert_prebuild_from(Some("")));
        assert!(convert_prebuild_from(Some("   ")));
    }

    #[test]
    fn every_off_word_turns_the_prebuild_off() {
        for v in ["0", "false", "no", "off", " OFF ", "False"] {
            assert!(!convert_prebuild_from(Some(v)), "{v:?} should turn it off");
        }
    }

    #[test]
    fn every_on_word_leaves_it_on() {
        for v in ["1", "true", "yes", "on", " ON ", "True"] {
            assert!(convert_prebuild_from(Some(v)), "{v:?} should leave it on");
        }
    }

    #[test]
    fn a_value_in_neither_list_keeps_the_default() {
        // The kill switch is what someone reaches for mid-bisect; a typo in it must not read as
        // "off" by accident, and must not pass silently either.
        for v in ["disabled", "none", "nope", "-1", "2"] {
            assert!(
                convert_prebuild_from(Some(v)),
                "{v:?} should keep the default"
            );
        }
    }

    #[test]
    fn a_chunks_card_is_drawn_once_however_many_callers_ask() {
        let claimed = DashMap::new();
        let rr = AtomicUsize::new(0);

        // The pre-build and the preparer both ask for the same chunk: one draw, one answer. Two
        // draws would advance the counter twice per chunk and hand the preparer every other card.
        let first = convert_card_for(7, &claimed, &rr, 4);
        assert_eq!(convert_card_for(7, &claimed, &rr, 4), first);
        assert_eq!(rr.load(Ordering::Relaxed), 1);

        // And over a run the cards still come out round-robin, not halved.
        let cards: Vec<usize> = (0..8)
            .map(|c| convert_card_for(c, &claimed, &rr, 4))
            .collect();
        assert_eq!(cards, vec![1, 2, 3, 0, 1, 2, 3, 0]);
    }

    #[test]
    fn concurrent_askers_still_draw_a_chunks_card_once() {
        let claimed = Arc::new(DashMap::new());
        let rr = Arc::new(AtomicUsize::new(0));
        let seen: Vec<usize> = std::thread::scope(|s| {
            (0..16)
                .map(|_| {
                    let (claimed, rr) = (Arc::clone(&claimed), Arc::clone(&rr));
                    s.spawn(move || convert_card_for(3, &claimed, &rr, 4))
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().expect("asker panicked"))
                .collect()
        });
        assert!(
            seen.iter().all(|&c| c == seen[0]),
            "one chunk, one card: {seen:?}"
        );
        assert_eq!(rr.load(Ordering::Relaxed), 1);
    }
}

#[cfg(test)]
mod recursion_lane_tests {
    use super::recursion_lane_from;

    #[test]
    fn unset_and_empty_leave_both_lanes_on() {
        assert!(recursion_lane_from(None));
        assert!(recursion_lane_from(Some("")));
        assert!(recursion_lane_from(Some("   ")));
    }

    #[test]
    fn every_off_word_turns_the_lane_off() {
        for v in ["0", "false", "no", "off", " OFF ", "False"] {
            assert!(!recursion_lane_from(Some(v)), "{v:?} should turn it off");
        }
    }

    #[test]
    fn every_on_word_leaves_it_on() {
        for v in ["1", "true", "yes", "on", " ON ", "True"] {
            assert!(recursion_lane_from(Some(v)), "{v:?} should leave it on");
        }
    }

    #[test]
    fn a_value_in_neither_list_keeps_the_default() {
        // `2` is the one that matters: the name reads like a count, so it is a spelling people
        // reach for, and it is NOT "two lanes". It keeps the default and warns rather than being
        // read as an off word.
        for v in ["2", "disabled", "none", "nope", "-1"] {
            assert!(
                recursion_lane_from(Some(v)),
                "{v:?} should keep the default"
            );
        }
    }
}

/// One item of GPU prove work, taken off one queue shared by every card, FIFO, no polling.
///
/// Which thread does the taking is what [`recursion_lane_enabled`] switches: the card's riscv lane
/// by default, or its single prover lane when the recursion lane is off. Prepare-kind work stays on
/// the CPU preparer pools either way. Combine work is not a variant here: the dispatcher routes
/// combine tasks to the combine preparers, whose output reaches the prover on its own ready lane as
/// [`CombineWork`].
enum ProverItem {
    /// A riscv chunk, by index — the `PreparedChunk` is resolved from the store at prove time, so
    /// buffering these descriptors costs no VRAM.
    Riscv { chunk_idx: usize },
}

/// Bind a prover thread to its card and to its telemetry lane. Every prover thread does this: the
/// device binding is per thread (the machines' keys are device-`k` resident and the ctxs routed
/// here were built on card `k`), and the lane id is what every span this thread records is keyed
/// on -- two threads sharing one would record over each other.
fn bind_prover_lane(k: usize, role: Role) {
    #[cfg(feature = "cuda")]
    pico_vm::mle::cuda_mle::runtime::context::set_device(k as i32)
        .unwrap_or_else(|e| panic!("{}-{k} could not bind card {k}: {e:?}", role.as_str()));
    spans::bind_lane(LaneId::new(role, k));
}

/// What the riscv lane's hook sends a pre-build worker: the chunk and its per-air heights.
#[cfg(feature = "cuda")]
type PrebuildTx = crossbeam::channel::Sender<(usize, Vec<Option<usize>>)>;

#[cfg(feature = "cuda")]
impl Drop for ConvertPrebuild {
    /// The backstop for the early returns between the explicit shutdown and the end of the
    /// pipeline: the machines outlive this pool, so no worker may still be keygening into them.
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Off-critical-path convert **program** pre-builds.
///
/// The riscv lane learns a chunk's committed trace heights when trace-gen returns, early in the
/// prove, and those heights fully determine the chunk's convert layout. Building the convert
/// verify program is the dominant term of a convert keygen miss and is pure CPU work on a
/// card-independent input, so building it during the rest of the prove takes it off the tail's
/// critical path.
///
/// A pool and not a spawn-per-chunk: the send has to be microseconds because it happens **on the
/// proving thread**, mid-prove. Width defaults to the card count — one chunk is in flight per card
/// and each wants its pre-build finished inside its own prove, so a width of 1 would serialise
/// those builds past the slack available.
///
/// Bounded and non-blocking by construction: the queue is unbounded and `send` never waits, and
/// nothing downstream depends on a pre-build completing. If a build is late, or the flag is off,
/// or the pool is saturated, the convert preparer simply builds the program itself exactly as it
/// does today. The program half is a pure host computation, so a dropped one costs only the CPU.
///
/// The key half (`MLE_CONVERT_PREBUILD_PK`, on by default) is not that cheap and not that inert: it
/// binds a card, runs the real keygen, and holds the card's pk-cache lock while it does — so a
/// preparer that would have hit the cache on that card can wait behind it, and a keygen that panics
/// takes the run with it, since the binary's panic hook exits the process. `=0` turns it off.
///
/// Under `MLE_CONVERT_PREBUILD_PK` a worker additionally warms the device proving key, and then
/// the card stops being irrelevant: a key lives on one card, so the worker claims the chunk's card
/// from the counter the preparers draw from and leaves it in the map for the preparer to follow.
#[cfg(feature = "cuda")]
struct ConvertPrebuild {
    /// Taken by [`Self::shutdown`]: dropping the last sender is what wakes the workers out of
    /// `recv`, so it cannot live on as a field while the shutdown waits for them.
    tx: std::sync::Mutex<Option<PrebuildTx>>,
    /// Set by [`Self::shutdown`]; a worker checks it before taking on more speculative work.
    stop: Arc<AtomicBool>,
    workers: std::sync::Mutex<Vec<thread::JoinHandle<()>>>,
}

#[cfg(feature = "cuda")]
impl ConvertPrebuild {
    /// `MLE_CONVERT_PREBUILD` gates the whole mechanism — **default ON**, `=0` is the kill switch.
    /// `MLE_CONVERT_PREBUILDERS` overrides the pool width. Returns `None` when disabled, in which
    /// case the riscv lane takes the unhooked path and the pre-change behaviour is restored
    /// exactly.
    fn new(
        machines: Vec<Arc<GpuConvertMachine>>,
        card_rr: Arc<AtomicUsize>,
        claimed: Arc<DashMap<usize, usize>>,
        lane_base: usize,
    ) -> Option<Self> {
        let cards = machines.len();
        if !convert_prebuild_enabled() {
            return None;
        }
        let width = std::env::var("MLE_CONVERT_PREBUILDERS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(cards)
            .max(1);
        let warm_pk = convert_prebuild_pk_enabled();
        let stop = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::with_capacity(width);
        let (tx, rx) = crossbeam::channel::unbounded::<(usize, Vec<Option<usize>>)>();
        for w in 0..width {
            let rx = rx.clone();
            let machines = machines.clone();
            let card_rr = Arc::clone(&card_rr);
            let claimed = Arc::clone(&claimed);
            let stop = Arc::clone(&stop);
            workers.push(
                std::thread::Builder::new()
                    .name(format!("convert-prebuild-{w}"))
                    .spawn_watched(move || {
                        // Its own lane, of the preparers' role but past their indices: the keygen
                        // this thread does is convert preparation, and a span opened on a thread
                        // that binds no lane is dropped — which would take these keygens out of the
                        // record, and out of any comparison of the kinds of work two runs exported.
                        spans::bind_lane(LaneId::new(Role::ConvertPreparer, lane_base + w));
                        while let Some((chunk_idx, heights)) =
                            recv_idle(&rx, WorkKind::PrepareConvert)
                        {
                            let _b = spans::busy(WorkKind::PrepareConvert, Some(chunk_idx as u32));
                            // Speculative work only, so a backlog is dropped rather than drained: a
                            // key built after the pipeline has moved on lands in the NEXT block's
                            // cache (the machines are resident) and evicts an entry someone needs.
                            if stop.load(Ordering::Relaxed) {
                                break;
                            }
                            if !warm_pk {
                                // No card is bound and none is needed: `prebuild_program` touches no
                                // device and takes no pk-cache lock, so this thread cannot block a
                                // prove or a keygen.
                                machines[0].prebuild_program(&heights);
                                continue;
                            }
                            // Claim the chunk's card from the counter the preparer draws from, so the
                            // key lands on the card that will prove the node and the round-robin
                            // balance is the one this arm's control has.
                            let card =
                                convert_card_for(chunk_idx, &claimed, &card_rr, machines.len());
                            if let Err(e) =
                                pico_vm::mle::cuda_mle::runtime::context::set_device(card as i32)
                            {
                                warn!("convert pre-build: binding to card {card} failed: {e:?}");
                                continue;
                            }
                            machines[card].prebuild_pk(&heights);
                        }
                    })
                    .expect("spawning a convert pre-build worker"),
            );
        }
        info!("MLE convert prebuild: {width} worker(s) ({cards} card(s), pk = {warm_pk})");
        Some(Self {
            tx: std::sync::Mutex::new(Some(tx)),
            stop,
            workers: std::sync::Mutex::new(workers),
        })
    }

    /// A sender for the riscv lane's hook, or `None` once the pool has been shut down.
    fn sender(&self) -> Option<PrebuildTx> {
        self.tx
            .lock()
            .expect("convert pre-build sender poisoned")
            .clone()
    }

    /// Stop taking new work and wait for whatever is in flight, before the caller's machines are
    /// handed to the next block. One in-flight keygen is bounded; the queue behind it is dropped.
    fn shutdown(&self) {
        self.stop.store(true, Ordering::Relaxed);
        // Drop the pool's own sender first. The lanes' clones went with the lanes, so this is the
        // last one, and only then does `recv` return `Err` and let a parked worker see `stop`.
        drop(
            self.tx
                .lock()
                .expect("convert pre-build sender poisoned")
                .take(),
        );
        for h in self
            .workers
            .lock()
            .expect("convert pre-build worker list poisoned")
            .drain(..)
        {
            let _ = h.join();
        }
    }
}

/// A card's riscv proving: the handles a chunk prove needs, and the prove.
///
/// A struct rather than a free function's argument list because both lane shapes run exactly this
/// body -- the riscv lane's own thread by default, the single prover lane's riscv arm under
/// `MLE_RECURSION_LANE=0` -- and a body written out at both sites is where the two would drift.
///
/// Exactly ONE thread per card may hold it. It owns a `convert_tx` clone, and a spare clone parked
/// on a lane that never sends would keep the convert preparers' channel open past the last chunk:
/// the convert chain could then never drain and the final join would hang.
struct RiscvLane {
    store: Arc<DashMap<usize, PreparedChunk>>,
    prover: Arc<RiscvMachine>,
    convert_tx: Option<crossbeam::channel::Sender<(usize, MleProof)>>,
    prove_nanos: Arc<AtomicU64>,
    prove_count: Arc<AtomicUsize>,
    verify: bool,
    with_combine: bool,
    /// Set only when `MLE_CONVERT_PREBUILD` is on. Shared by every card's riscv lane: the
    /// pre-build reads only `riscv_vk` (identical on every card) and writes into a
    /// PROCESS-GLOBAL program cache, so which card's machine backs it is irrelevant — which is
    /// exactly what makes the hoist survive the convert preparers picking a card round-robin.
    #[cfg(feature = "cuda")]
    convert_prebuild: Option<Arc<ConvertPrebuild>>,
}

impl RiscvLane {
    /// Prove one chunk and hand the proof on. `worker_id` is the calling lane's, so the `[bench]`
    /// lines are keyed on the thread that actually did the work under either shape.
    fn prove(&self, chunk_idx: usize, worker_id: &str) {
        let _b = spans::busy(WorkKind::ProveRiscv, Some(chunk_idx as u32));
        let chunk = take_prepared_chunk(&self.store, chunk_idx);
        let t = Instant::now();
        // Unlike the convert arm, this timer CANNOT exclude the debug-only verify: `verify` is a
        // parameter of `prove`, not a separate call, so hoisting it out would mean changing the
        // prove signature for a path only `MLE_VERIFY=1` takes. Consequence, stated rather than
        // hidden: under `MLE_VERIFY=1` this figure includes the verify it would be used to judge.
        // Benchmarks set `MLE_VERIFY=0`, so no published number is affected.
        // The hook fires the moment trace-gen has fixed this chunk's committed heights and
        // before commit starts, so the convert program build overlaps the remaining ~505 ms of
        // this very prove. `send` on an unbounded channel is the only work done on this thread.
        #[cfg(feature = "cuda")]
        // One look at the sender, not two: it can be taken by the pool's shutdown at any moment,
        // and a `None` here just means this chunk proves without a pre-build, as it did before.
        let proof = match self.convert_prebuild.as_ref().and_then(|pb| pb.sender()) {
            Some(tx) => {
                let hook = move |heights: Vec<Option<usize>>| {
                    // A full queue cannot happen (unbounded) and a hung-up receiver only means
                    // the workers are gone; either way a dropped pre-build is a no-op, because
                    // the convert preparer builds the program itself on a miss.
                    let _ = tx.send((chunk_idx, heights));
                };
                chunk.prove_hooked(&self.prover, self.verify, Some(&hook))
            }
            None => chunk.prove(&self.prover, self.verify),
        };
        #[cfg(not(feature = "cuda"))]
        let proof = chunk.prove(&self.prover, self.verify);
        let elapsed = t.elapsed();
        self.prove_nanos
            .fetch_add(elapsed.as_nanos() as u64, Ordering::SeqCst);
        self.prove_count.fetch_add(1, Ordering::SeqCst);
        // Per-chunk bench line, format-aligned with the FRI prover's `riscv-gpu-prover: running=`
        // lines for side-by-side extraction.
        info!(
            target: "bench",
            "[bench][{worker_id}](chunk-{chunk_idx}) mle-gpu-prover: running={} ms",
            elapsed.as_millis()
        );
        // `MLE_BREAKDOWN` one-line per-chunk phase split (us), mirroring the FRI prover's
        // `(Prep/Commit/...)` line. `residual = total - sum(measured)` captures un-instrumented
        // glue (H2D / transcript / alloc). zerocheck is folded into rap_constraints.
        #[cfg(feature = "cuda")]
        if pico_vm::mle::cuda_mle::breakdown::enabled() {
            let (tracegen, commit, rap, openings) = pico_vm::mle::cuda_mle::breakdown::take();
            let total = elapsed.as_micros() as u64;
            let residual = total.saturating_sub(tracegen + commit + rap + openings);
            info!(
                target: "bench",
                "[bench][{worker_id}](chunk-{chunk_idx}) mle-breakdown: total={total}us \
                 (tracegen={tracegen} commit={commit} rap_constraints={rap} \
                 openings={openings} residual={residual})"
            );
        }
        match (&self.convert_tx, self.with_combine) {
            // Combine mode: this chunk task spans riscv + convert (the FRI shape), so it is NOT
            // reported here — the convert prove reports the convert proof, which is what enters the
            // proof tree. `in_flight` therefore stays held across both halves, which is also what
            // stops completion from latching early.
            (Some(convert_tx), true) => convert_tx
                .send((chunk_idx, proof))
                .expect("convert preparer hung up"),
            // Convert-only: the riscv proof flows into the convert pipeline; the scheduler keeps its
            // riscv-level bookkeeping via the terminal report, and convert completion is joined via
            // the channels draining.
            (Some(convert_tx), false) => {
                mle_report_chunk_terminal(chunk_idx);
                convert_tx
                    .send((chunk_idx, proof))
                    .expect("convert preparer hung up");
            }
            // Riscv-only: chunk proofs are terminal. Payload-free by design — this is exactly what
            // `report_proof`'s no-combine branch does (it drops the proof anyway), and it keeps the
            // riscv proof type out of the scheduler's `P`.
            (None, _) => mle_report_chunk_terminal(chunk_idx),
        }
        info!("[{worker_id}] chunk {chunk_idx}: MLE prove OK");
    }
}

/// A card's recursion proving: the machines a convert or a combine node needs, the counters they
/// report into, and the two run-wide flags they read.
///
/// A struct rather than an argument list for the same reason as [`RiscvLane`]: both of the card's
/// lanes can run exactly this body -- the recursion lane always, the riscv lane once no further
/// chunk can arrive -- and a body written out at both sites is where the two would drift.
///
/// Unlike [`RiscvLane`] it may be held by more than one thread at a time: it owns no sender, so a
/// spare handle keeps no channel open.
#[cfg(feature = "cuda")]
struct CardRecursion {
    convert: Option<Arc<GpuConvertMachine>>,
    combine: Option<Arc<pico_vm::mle::machine::combine::GpuCombineMachine>>,
    root_slot: Arc<std::sync::Mutex<Option<RootRecord>>>,
    convert_prove_nanos: Arc<AtomicU64>,
    convert_done: Arc<AtomicUsize>,
    combine_nanos: Arc<AtomicU64>,
    combine_count: Arc<AtomicUsize>,
    verify: bool,
    with_combine: bool,
}

#[cfg(feature = "cuda")]
impl CardRecursion {
    /// Prove one convert off this card's ready lane. `worker_id` is the calling lane's, so the
    /// `[bench]` line names the thread that did the work rather than the card.
    fn prove_convert(&self, chunk_idx: usize, work: ConvertWork, worker_id: &str) {
        let Self {
            convert,
            convert_prove_nanos,
            convert_done,
            verify,
            with_combine,
            ..
        } = self;
        let _b = spans::busy(WorkKind::ProveConvert, Some(chunk_idx as u32));
        let machine = convert
            .as_ref()
            .expect("convert work with no convert machine");
        let t = Instant::now();
        let ConvertWork(built) = work;
        let (convert_proof, vk) = machine
            .prove_built(built)
            .unwrap_or_else(|e| panic!("convert prove failed for chunk {chunk_idx}: {e:?}"));
        // Stop the clock before the debug-only verify, so `MLE_VERIFY=1`
        // does not inflate the figure it would be used to judge.
        let elapsed = t.elapsed();
        if *verify {
            machine
                .verify(&vk, &convert_proof)
                .unwrap_or_else(|e| panic!("convert verify failed for chunk {chunk_idx}: {e:?}"));
        }
        convert_prove_nanos.fetch_add(elapsed.as_nanos() as u64, Ordering::SeqCst);
        convert_done.fetch_add(1, Ordering::SeqCst);
        info!(
            target: "bench",
            "[bench][{worker_id}](chunk-{chunk_idx}) mle-convert-prover: running={} ms",
            elapsed.as_millis()
        );
        // Drain this prove's thread-local phase timers, as the riscv and combine
        // arms do: undrained, they leak into whichever arm reports next on this lane.
        if pico_vm::mle::cuda_mle::breakdown::enabled() {
            let (tracegen, commit, rap, openings) = pico_vm::mle::cuda_mle::breakdown::take();
            let total = elapsed.as_micros() as u64;
            let residual = total.saturating_sub(tracegen + commit + rap + openings);
            // Not `mle-breakdown`: the riscv arm prints that under the same
            // `(chunk-N)` key, and the two would collide in any extractor
            // that keys on the chunk rather than the lane.
            info!(
                target: "bench",
                "[bench][{worker_id}](chunk-{chunk_idx}) mle-convert-breakdown: total={total}us \
                 (tracegen={tracegen} commit={commit} rap_constraints={rap} \
                 openings={openings} residual={residual})"
            );
        }
        // Combine mode: THIS is where the chunk task ends. The convert proof
        // enters the scheduler's proof tree (which is what combine pairs),
        // releasing the `in_flight` slot taken at chunk acquisition. Without it
        // the tree stays empty and no combine task is ever generated.
        if *with_combine {
            mle_report_proof(
                IndexedProof::new((convert_proof, vk), chunk_idx, chunk_idx),
                worker_id,
            );
        }
    }

    /// Prove one combine node off this card's ready lane. Same reason for `worker_id`.
    fn prove_combine(&self, work: CombineWork, worker_id: &str) {
        let Self {
            combine,
            root_slot,
            combine_nanos,
            combine_count,
            verify,
            ..
        } = self;
        let combine = combine
            .as_ref()
            .expect("combine work with no combine machine — no_combine is misset");
        let CombineWork {
            start_chunk: start,
            end_chunk: end,
            built,
        } = work;
        let _b = spans::busy(WorkKind::ProveCombine, Some(start as u32));
        let t = Instant::now();
        // Prove only: the ctx was built on the preparer under the
        // window, so the `running=` figure covers the GPU half
        // alone; keygen/setup are on the preparer's
        // `gpu_combine_timing` line.
        let node = combine
            .prove_built_node(built)
            .unwrap_or_else(|e| panic!("combine prove failed for [{start},{end}]: {e:?}"));
        // The shape truth, baked at keygen by the preparer — using
        // it here means the reported role can never diverge from
        // what was proven.
        let is_final = node.is_complete;
        let elapsed = t.elapsed();
        combine_nanos.fetch_add(elapsed.as_nanos() as u64, Ordering::SeqCst);
        combine_count.fetch_add(1, Ordering::SeqCst);
        info!(
            target: "bench",
            "[bench][{worker_id}](combine-{start}-{end}) mle-combine-prover: \
             running={} ms is_final={is_final}",
            elapsed.as_millis()
        );
        // Drain the thread-local phase timers for THIS prove.
        //
        // What actually leaks is `tracegen`, and only that: `breakdown.rs` SETS
        // commit/rap/openings, so the next prove overwrites them whatever we do here.
        // `tracegen` is different: a convert ctx build sets it on THIS thread, so
        // an undrained value survives to be reported against whichever chunk or
        // node reports next. Draining all four is still right (one operation, no
        // partial state), but the reason is the one field, not all of them.
        if pico_vm::mle::cuda_mle::breakdown::enabled() {
            let (tracegen, commit, rap, openings) = pico_vm::mle::cuda_mle::breakdown::take();
            let total = elapsed.as_micros() as u64;
            let residual = total.saturating_sub(tracegen + commit + rap + openings);
            info!(
                target: "bench",
                "[bench][{worker_id}](combine-{start}-{end}) mle-breakdown: total={total}us \
                 (tracegen={tracegen} commit={commit} rap_constraints={rap} \
                 openings={openings} residual={residual})"
            );
        }
        // Early-failure net only — NOT the security check (no honest-vk substitution).
        if *verify {
            combine
                .verify_node(&node.proof.1, &node.proof.0)
                .unwrap_or_else(|e| {
                    panic!("combine node [{start},{end}] failed self-verify: {e:?}")
                });
        }

        // Build the IndexedProof first so the root stash shares its `Arc`.
        let indexed = IndexedProof::new(node.proof, start, end);
        if is_final {
            let prev = root_slot
                .lock()
                .expect("root slot mutex poisoned")
                .replace(RootRecord {
                    proof: indexed.get_inner(),
                    child_layouts: node.child_layouts,
                });
            assert!(
                prev.is_none(),
                "two final combine nodes were proved — the tree collapsed twice"
            );
        }
        mle_report_proof(indexed, worker_id);
        info!("[{worker_id}] combine [{start},{end}]: OK (is_final={is_final})");
    }
}

/// Per-card VRAM watermark, off unless `MLE_VRAM_POLL_MS=<n>` asks for it.
///
/// Two prover lanes on a card means two working sets on it, so whether the second fits is a number
/// the split has to be judged on, and there was no per-card instrument: the bench script's figure
/// is nvidia-smi's whole-box maximum, which reads a neighbouring CARD's allocation as ours. This
/// asks the driver about one card. It still cannot separate our use of that card from a co-tenant's
/// -- `cudaMemGetInfo` is total minus free for the device, not for the process.
///
/// Per CARD and not per lane, so it is deliberately NOT tied to `MLE_RECURSION_LANE`: the one-lane
/// shape is exactly the arm whose residency this is used to compare against. Unset (the default) it
/// spawns nothing and prints nothing, on either shape.
struct VramWatch {
    stop: Arc<AtomicBool>,
    peaks: Vec<Arc<AtomicUsize>>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl VramWatch {
    fn start(prover_count: usize) -> Self {
        let poll_ms: u64 = std::env::var("MLE_VRAM_POLL_MS")
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        let stop = Arc::new(AtomicBool::new(false));
        // Only the `cuda` build pushes into these.
        #[cfg_attr(not(feature = "cuda"), allow(unused_mut))]
        let mut peaks = Vec::new();
        #[cfg_attr(not(feature = "cuda"), allow(unused_mut))]
        let mut threads = Vec::new();
        #[cfg(feature = "cuda")]
        if poll_ms > 0 {
            for k in 0..prover_count {
                let peak = Arc::new(AtomicUsize::new(0));
                peaks.push(Arc::clone(&peak));
                let stop = Arc::clone(&stop);
                threads.push(
                    thread::Builder::new()
                        .name(format!("mle-vram-{k}"))
                        .spawn(move || {
                            if pico_vm::mle::cuda_mle::runtime::context::set_device(k as i32)
                                .is_err()
                            {
                                return;
                            }
                            while !stop.load(Ordering::Relaxed) {
                                let used = pico_vm::mle::cuda_mle::runtime::memory_manager::
                                    device_memory_used();
                                peak.fetch_max(used, Ordering::Relaxed);
                                thread::sleep(Duration::from_millis(poll_ms));
                            }
                        })
                        .expect("spawn mle-vram"),
                );
            }
        }
        #[cfg(not(feature = "cuda"))]
        let _ = (poll_ms, prover_count);
        Self {
            stop,
            peaks,
            threads,
        }
    }
}

/// Stop the samplers and report on the way out. In `Drop` rather than a `finish()` the caller has
/// to remember: `run_pipeline` returns early on an empty program and asserts on a lone chunk, and
/// on either path the samplers would otherwise poll their card for the life of the process --
/// which `MLE_REPEAT` then accumulates. A no-op when the watch was never armed.
impl Drop for VramWatch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for h in self.threads.drain(..) {
            let _ = h.join();
        }
        for (k, peak) in self.peaks.iter().enumerate() {
            info!(
                target: "bench",
                "[bench] mle-vram-peak: card={k} peak={} MiB",
                peak.load(Ordering::Relaxed) >> 20
            );
        }
    }
}

/// Convert work arriving at the prover slot: a ctx already built on the preparer.
///
/// A convert ctx is a few hundred MB and parks in the lane. The bound is not one: the build
/// precedes the blocking send, so every preparer blocked on the bounded(1) lane holds a built ctx
/// of its own — up to `MLE_CONVERT_PREPARERS` + 1 per card. That residency is what sizes the pool
/// (see `preparer_pool`); twelve of them is what a single card cannot afford.
#[cfg(feature = "cuda")]
struct ConvertWork(pico_vm::mle::machine::convert::BuiltConvert);
/// CPU build: uninhabited — the ready lane closes without ever carrying an item, and the prover's
/// match arm is `match work {}`.
#[cfg(not(feature = "cuda"))]
enum ConvertWork {}

/// Combine work arriving at the prover slot: a node ctx already built on its preparer. Same size
/// and same bound as [`ConvertWork`], with `MLE_COMBINE_PREPARERS` setting it here.
#[cfg(feature = "cuda")]
struct CombineWork {
    start_chunk: usize,
    end_chunk: usize,
    built: pico_vm::mle::machine::combine::BuiltCombine,
}
/// CPU build: uninhabited, exactly like [`ConvertWork`].
#[cfg(not(feature = "cuda"))]
enum CombineWork {}

const RV64_DIR: &str = "./perf/bench_data/rv64";

/// Where the witnesses are. `MLE_INPUT_DIR` is what `sweep_reth_mle.sh` exports and what its
/// `[input-dir]` argument means, and until this read existed that argument was a lie: the launcher
/// discovered and hash-validated one directory while the prover proved from another, so the
/// script's own usage example panicked on the first block.
///
/// Witnesses only, deliberately. The guest ELF is not part of the pool — a witness set is moved,
/// copied and shared between trees while the guest belongs to the tree that built it — so pointing
/// this at a pool must not take the ELF path with it.
///
/// ⚠️ Not the same knob as `RETH_INPUT_DIR` ([`crate::io::stdins::load_reth_input_for_block`]),
/// which the FRI and two-machine launchers export: that one defaults to `perf/bench_data/bins` and
/// names files `<block>.bin`, and nothing on this binary's path reads it. Two names for one concept
/// is a trap, and the reason this path keeps its own is that the launcher that feeds it already
/// exports this name; unifying them would change three other launchers for no defect.
/// The five aliases, as data rather than as a match arm — `load_reth_input` needs the table in both
/// directions (a selector to a block, and a block back to the spelling a witness file may carry),
/// and `sweep_reth_mle.sh` parses THIS to check its own copy has not drifted. Adding a pair here is
/// the only edit needed; writing it as a match arm is what made a reverse lookup a second copy.
const RETH_ALIASES: [(u32, u32); 5] = [
    (171, 17106222),
    (188, 18884864),
    (239, 23993050),
    (240, 24000020),
    (246, 24600825),
];

fn rv64_input_dir() -> String {
    std::env::var("MLE_INPUT_DIR").unwrap_or_else(|_| RV64_DIR.to_string())
}

fn load_elf(name: &str) -> Vec<u8> {
    let path = format!("{RV64_DIR}/{name}-elf");
    std::fs::read(&path).unwrap_or_else(|e| panic!("failed to read ELF {path}: {e}"))
}

fn load_reth_input(n: u32) -> Vec<u8> {
    let block = RETH_ALIASES
        .iter()
        .find_map(|&(alias, real)| (alias == n).then_some(real))
        .unwrap_or(n);
    let dir = rv64_input_dir();
    // Every spelling the launcher accepts, because it accepts three and `ci/test_sweep_launcher.sh`
    // asserts all three — `reth-<block>.bin`, a bare `<block>.bin`, and the five alias names — while
    // resolving any of them to a block NUMBER before handing it over. So the prover cannot recover
    // the filename it was given and has to try the spellings back: opening only the first turns a
    // pool of bare-named files (what `perf/bench_data/bins` and `io/stdins.rs` use, and what an
    // archive dump produces) into a first-block panic on a directory just hash-validated, and
    // opening only the first two does the same to an alias-named pool.
    //
    // Safe to try several: the launcher's dedup refuses a directory where two names resolve to one
    // block, so no other witness can be sitting under one of these spellings.
    let mut names = vec![format!("reth-{block}.bin"), format!("{block}.bin")];
    if let Some(&(alias, _)) = RETH_ALIASES.iter().find(|&&(_, real)| real == block) {
        names.push(format!("{alias}.bin"));
    }
    let mut last: Option<std::io::Error> = None;
    for name in &names {
        let path = format!("{dir}/{name}");
        match std::fs::read(&path) {
            Ok(bytes) => return bytes,
            // Only a missing file falls through to the next spelling. A permission or I/O error is
            // reported against the name it happened on rather than reported as "not found".
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => last = Some(e),
            Err(e) => panic!("failed to read reth input {path}: {e}"),
        }
    }
    panic!(
        "failed to read reth input for block {block} in {dir}: tried {} ({})",
        names.join(", "),
        last.map(|e| e.to_string()).unwrap_or_default()
    )
}

/// Build `(elf_bytes, stdin)` for the configured program.
///
/// `KoalaBearPoseidon2` is used only as the stdin builder's config type-parameter
/// (mirroring `test_mle_riscv`); it does not pull in any FRI proving.
/// The guest ELF for the configured program. **Block-independent**: which ELF to run is a property
/// of `--elf`, not of `--n`, so a process that proves several blocks compiles it once.
///
/// An ELF from disk is read once per process and name, so a file replaced or deleted under a
/// running server neither changes nor breaks what it proves.
fn load_program_elf(cfg: &MleSingleNodeConfig) -> Arc<[u8]> {
    if let Some(embedded) = &cfg.embedded {
        return Arc::clone(&embedded.elf);
    }
    static FIB: std::sync::OnceLock<Arc<[u8]>> = std::sync::OnceLock::new();
    static RETH: std::sync::OnceLock<Arc<[u8]>> = std::sync::OnceLock::new();
    let (name, read) = match cfg.elf.as_str() {
        "fib" | "fibonacci" | "f" => ("fib", &FIB),
        "reth" => ("reth", &RETH),
        other => panic!("unsupported --elf {other} (supported: fib | reth)"),
    };
    Arc::clone(read.get_or_init(|| load_elf(name).into()))
}

/// The stdin for **one** block. This is the only thing a sweep changes between blocks; everything
/// else it holds resident, which is the whole point of the split.
fn stdin_for_block(cfg: &MleSingleNodeConfig, n: u32) -> EmulatorStdin<Program, Vec<u8>> {
    let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    match cfg.elf.as_str() {
        "fib" | "fibonacci" | "f" => {
            stdin.write(&n);
            info!("MLE single-node: fibonacci n={n}");
        }
        "reth" => {
            stdin.write_slice(&load_reth_input(n));
            info!("MLE single-node: reth block selector {n}");
        }
        other => panic!("unsupported --elf {other} (supported: fib | reth)"),
    }
    stdin.finalize()
}

/// Receive, recording the block as `Idle` — a shortage of input, to be fixed upstream, as against
/// `Wait`, which is contention over something someone else holds.
///
/// Every stage loop below begins this way, so the three lines that draw that distinction are written
/// once instead of four times; and because it returns an `Option`, those loops keep the plain
/// `while let` shape they had before any of this was instrumented.
fn recv_idle<T>(rx: &crossbeam::channel::Receiver<T>, work: WorkKind) -> Option<T> {
    let _i = spans::idle(work);
    rx.recv().ok()
}

/// `MLE_VRAM_CENSUS` (cached): the block-boundary census. Cached because the alternative is an
/// environment read per boundary, and because a switch that could change mid-process would make
/// the rows it produces incomparable with each other.
#[cfg(feature = "cuda")]
fn vram_census_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| env_flag("MLE_VRAM_CENSUS"))
}

/// `MLE_VRAM_PROBE` (cached): the in-block probes, on a SEPARATE switch from the census and off
/// unless asked for.
///
/// Separate because of where they sit. The boundary census runs in `run`, outside the window
/// `e2e=` measures; ten of the thirteen probe points are inside it -- two run before `t_e2e`
/// starts and one after it is read. Sharing one switch meant that turning the census on for a
/// sweep also put driver reads, a device rebind and a manager lock inside every block's measured
/// window -- and `d_malloc` holds that same lock across its OOM self-heal, so a probe could stall
/// the thread it was measuring. Off, what the window pays is one atomic load per point.
#[cfg(feature = "cuda")]
fn vram_probe_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| env_flag("MLE_VRAM_PROBE"))
}

/// Which side of a block a census line is taken on. Not decoration: the `Pre` line is the one that
/// zeroes the pools' high-water marks, so a wrong value here silently stops the peaks from being
/// per-block.
#[derive(Clone, Copy)]
enum CensusPhase {
    Pre,
    Post,
}

#[cfg(feature = "cuda")]
impl CensusPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pre => "pre",
            Self::Post => "post",
        }
    }
}

/// Restores the calling thread's CUDA device when the census leaves, including out of a panic in
/// one of the caches it reads. Leaving the thread bound to the last card walked would silently
/// move where the next block's keygen lands.
#[cfg(feature = "cuda")]
struct DeviceBinding(Option<i32>);

#[cfg(feature = "cuda")]
impl Drop for DeviceBinding {
    fn drop(&mut self) {
        if let Some(dev) = self.0 {
            let _ = pico_vm::mle::cuda_mle::runtime::context::set_device(dev);
        }
    }
}

/// Per-card device-memory census at a block boundary, behind `MLE_VRAM_CENSUS=1`. Only the
/// directory sweep reaches it: a single-block or `MLE_REPEAT` run sets the flag and gets nothing.
///
/// A block boundary is the quiescent point: `run_pipeline` joins the threads it spawned before
/// returning, so these numbers are what a block LEFT BEHIND rather than what it was using. That
/// distinction is the whole instrument — a boundary `nvidia-smi` sample catches the next block's
/// ramp at a random phase and shows no trend where there is one. The one path that returns without
/// joining is the degenerate zero-chunk program, which proves nothing anyway. Joining is not
/// enough on its own; each card is synchronised first, or the read lands while its stream drains.
///
/// The quantities separate failures that look alike:
///   - `pool_used` / `tracked_live` / `out_of_pool` are the RESTING live set. A climb here is
///     something holding device memory across blocks — the counts on the same line say who.
///   - `tracked_peak` / `pool_used_high` / `pool_reserved_high` are the block's own PEAK, zeroed
///     at its `pre`. A `pre` line therefore carries whatever accumulated since the last reset —
///     the previous block, or for the first one, process start-up.
///   - `pool_reserved` climbing is NOT by itself evidence: the external pool never releases below
///     its threshold and the default one is asked to do the same, best-effort — `MLE_POOL_RETAIN=0`
///     or a failing driver call leaves it releasing eagerly, and that verdict is cached for the
///     process. It means something only when the peaks beside it are flat, and then fragmentation.
///
/// Four ways a figure here misleads rather than lies:
///   - `dev_used` is `cudaMemGetInfo`, which reports the whole card, so a co-tenant process lands
///     entirely in `out_of_pool`.
///   - a pool whose attribute read fails contributes zero rather than an error, so an
///     `out_of_pool` that jumps by a whole reservation while `pool_reserved` collapses on the same
///     line is a failed read and not a leak.
///   - `set_device` forces a primary context, so this walk CREATES one on any card the prover has
///     not reached yet and then reports it as that card's `out_of_pool`.
///   - the first `pre` line runs before `init_mle_gpu_pool` does, so it always reports
///     `ext_pool=0` with neither pool's threshold raised yet. Otherwise `ext_pool=1` means a
///     distinct external pool was counted into the pool totals; zero is ordinary when none is
///     registered or the registered one IS the device default, in which case `pool_*` already
///     covers it exactly once, and abnormal when the card's manager could not be read at all.
///
/// Not a read-only observer, which is why it is behind a flag as much as for its cost: the `pre`
/// line zeroes both pools' high-water attributes on a pool shared with pico, and the tracked peak
/// that the `GPU mem:` line's `peak=` and the `gpu_mem.local_peak_bytes` gauge report.
///
/// A card that could not be read emits a `vram_census_note:` line instead of a census row, so a
/// `vram_census:` row is always one per card per boundary with every field present.
#[cfg(feature = "cuda")]
fn vram_census(phase: CensusPhase, epoch: usize, block: u32, cards: usize) {
    use pico_vm::mle::cuda_mle::runtime::{context, memory_manager as mm, stream};
    if !vram_census_enabled() {
        return;
    }
    const MIB: f64 = (1024 * 1024) as f64;
    let phase_name = phase.as_str();
    let _binding = DeviceBinding(context::get_device().ok());
    for k in 0..cards {
        if context::set_device(k as i32).is_err() {
            // Said out loud, because this card also skips the high-water reset below: the next
            // `post` line's two peaks are then the process's, not that block's, and silently look
            // like a peak jump.
            info!(
                target: "bench",
                "vram_census_note: phase={phase_name} epoch={epoch} block={block} card={k} \
                 skipped=set_device"
            );
            continue;
        }
        if stream::device_synchronize().is_err() {
            // Every figure below is then read off a faulted context and looks perfectly plausible.
            info!(
                target: "bench",
                "vram_census_note: phase={phase_name} epoch={epoch} block={block} card={k} \
                 degraded=device_synchronize"
            );
        }
        let (live, peak) = mm::tracked_bytes_for(k);
        let pools = mm::pool_bytes_for(k);
        let (free, total) = mm::device_mem_info();
        let dev_used = total.saturating_sub(free) as u64;
        // Everything the driver counts that neither pool backs: the plain `cudaMalloc` sites in
        // the `.cu` units, loaded JIT modules, the CUDA context itself.
        let out_of_pool = dev_used.saturating_sub(pools.reserved_total());
        let resident = resident_snapshot();
        let resident = resident.as_deref();
        let (conv_n, conv_cap) = resident
            .and_then(|r| r.converts.get(k))
            .map_or((0, 0), |m| m.cache_len());
        let (comb_n, comb_cap) = resident
            .and_then(|r| r.combines.get(k))
            .map_or((0, 0), |m| m.cache_len());
        let comb = resident
            .and_then(|r| r.combines.get(k))
            .map(|m| m.shape_stats());
        let (modules, kernels) = pico_vm::mle::cuda_mle::jit_cache_len(k as i32);
        info!(
            target: "bench",
            "vram_census: phase={phase_name} epoch={epoch} block={block} card={k} \
             tracked_live_mib={:.2} tracked_peak_mib={:.2} \
             pool_used_mib={:.2} pool_used_high_mib={:.2} \
             pool_reserved_mib={:.2} pool_reserved_high_mib={:.2} \
             dev_used_mib={:.2} out_of_pool_mib={:.2} ext_pool={} bufcache_mib={:.2} \
             air_entries={} jit_modules={modules} jit_kernels={kernels} \
             streams_created={} streams_recycled={} \
             pk_convert={conv_n}/{conv_cap} pk_combine={comb_n}/{comb_cap} \
             comb_keygens={} comb_evictions={}",
            live as f64 / MIB,
            peak as f64 / MIB,
            pools.used_total() as f64 / MIB,
            pools.used_high_total() as f64 / MIB,
            pools.reserved_total() as f64 / MIB,
            pools.reserved_high_total() as f64 / MIB,
            dev_used as f64 / MIB,
            out_of_pool as f64 / MIB,
            u8::from(pools.external.is_some()),
            pico_vm::mle::cuda_mle::logup_zerocheck::gkr_buf_cache_bytes(k as i32) as f64 / MIB,
            pico_vm::mle::cuda_mle::air_data_cache_len(k as u32),
            pico_vm::cuda_adaptor::streams_created(k),
            // Streams handed back by threads that finished on this card. After the hand-back
            // landed, `streams_created` is flat by construction, so this is the count that says
            // how many threads a card has been through — the axis a per-thread leak grows along.
            pico_vm::cuda_adaptor::release_stats(k).0,
            comb.as_ref().map_or(0, |c| c.keygens),
            comb.as_ref().map_or(0, |c| c.evictions),
        );
        // Reset AFTER reading, and only at the block's start, so the `post` line's two high-water
        // figures belong to this block instead of to the whole process.
        if matches!(phase, CensusPhase::Pre) {
            mm::reset_tracked_peak_for(k);
            mm::reset_pool_high_water(k);
        }
    }
}

/// Device totals at a named point INSIDE a block, for locating which phase of the pipeline a
/// per-block leak happens in. Behind its own `MLE_VRAM_PROBE`, off by default, with the same
/// caveats as the census: `dev_used` is the whole card, and binding a card the prover has not reached creates
/// its primary context.
///
/// Deliberately thinner than the census, and with no `device_synchronize`: these points sit
/// between pipeline stages with work still in flight, and syncing here would change what is being
/// measured. So a single reading is not a live set — the signal is one probe point compared ACROSS
/// blocks, where a systematic offset from unsettled work cancels. It also does not reset anything,
/// which is why it needs none of the census's write caveats.
///
/// The labels say where the reading was taken, not which stage drained there. Every prover LANE
/// drains at `after_workers` — a lane only exits once its own feeds are closed — so no per-stage
/// attribution can be read out of the points after it. Nor are those points purely host
/// bookkeeping: with `MLE_CONVERT_PREBUILD_PK` on, which is the default, the pre-build pool is
/// still keygening on a card until its shutdown, which sits between `after_workers` and
/// `after_convert_report`.
///
/// Two things it can do that the boundary census cannot. `pool_bytes_for` takes the card's manager
/// lock, which `d_malloc` holds across its OOM self-heal (a whole-device synchronise plus two pool
/// trims), so a probe can stall the very thread it is measuring — likeliest on exactly the filling
/// card this exists to explain. And `dev_used` and the pool figures are read at different instants
/// with no lock between them and the pool figures first: a pool trimmed in between
/// clamps `out_of_pool` to 0.00, which reads identically to "nothing outside the pools", while one
/// growing in between overstates it.
#[cfg(feature = "cuda")]
fn vram_probe(at: &str, epoch: usize, cards: usize) {
    use pico_vm::mle::cuda_mle::runtime::{context, memory_manager as mm};
    // First statement, and a cached load: ten of the thirteen call sites are inside the window
    // `e2e=` measures, so what this costs when switched off has to be countable.
    if !vram_probe_enabled() {
        return;
    }
    const MIB: f64 = (1024 * 1024) as f64;
    let _binding = DeviceBinding(context::get_device().ok());
    for k in 0..cards {
        if context::set_device(k as i32).is_err() {
            // Said out loud for the census's reason: a card that silently emits nothing reads as a
            // card that had nothing to report.
            info!(
                target: "bench",
                "vram_probe_note: at={at} epoch={epoch} card={k} skipped=set_device"
            );
            continue;
        }
        let pools = mm::pool_bytes_for(k);
        let (free, total) = mm::device_mem_info();
        let dev_used = total.saturating_sub(free) as u64;
        info!(
            target: "bench",
            "vram_probe: at={at} epoch={epoch} card={k} dev_used_mib={:.2} \
             pool_reserved_mib={:.2} out_of_pool_mib={:.2}",
            dev_used as f64 / MIB,
            pools.reserved_total() as f64 / MIB,
            dev_used.saturating_sub(pools.reserved_total()) as f64 / MIB,
        );
    }
}

#[cfg(not(feature = "cuda"))]
fn vram_probe(_at: &str, _epoch: usize, _cards: usize) {}

/// The census is GPU-only; the CPU build keeps the call sites rather than cfg-ing them.
#[cfg(not(feature = "cuda"))]
fn vram_census(_phase: CensusPhase, _epoch: usize, _block: u32, _cards: usize) {}

/// Single-node entry: dispatch on the requested proving step. `riscv` and `convert` are wired
/// (`convert` = the riscv pipeline with the streaming convert stage spliced in, FRI-style);
/// `combine` is planned.
///
/// `iteration` is which `MLE_REPEAT` pass this call is, `None` for a plain single run. It reaches
/// only the span export, which names its file after it (see [`spans::csv_path_for_iteration`]).
pub fn run(cfg: &MleSingleNodeConfig, iteration: Option<usize>) {
    // Directory sweep: prove every block in `MLE_BLOCKS` from this one process, reusing
    // the compiled program and the per-card machines across all of them (see `Resident`).
    //
    // The epoch index is what names the span export (`run.spans.csv.iterK`), which the sweep's
    // `manifest.csv` maps back to a block number — so it must count blocks, not restart per block.
    // `MLE_REPEAT` keeps its own meaning: it repeats whatever this resolves to.
    if let Ok(list) = std::env::var("MLE_BLOCKS") {
        let blocks: Vec<u32> = list
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.parse::<u32>()
                    .unwrap_or_else(|_| panic!("MLE_BLOCKS: '{s}' is not a block number"))
            })
            .collect();
        assert!(
            !blocks.is_empty(),
            "MLE_BLOCKS was set but parsed to nothing"
        );
        info!("MLE sweep: {} block(s) in one process", blocks.len());
        for (i, n) in blocks.iter().enumerate() {
            let mut per_block = cfg.clone();
            per_block.n = *n;
            // A delimiter pair per block, because every existing way of slicing this log is wrong
            // here: a slicer keyed on `MLE repeat:` markers sees nothing, since they only appear
            // when MLE_REPEAT > 1. Without these, the per-block extractors -- `tail -1`,
            // `grep -m1`, `grep -c` -- all read some other block's numbers and report them under
            // this block's name.
            info!(
                target: "bench",
                "MLE block: {}/{} block={n} starting", i + 1, blocks.len()
            );
            vram_census(CensusPhase::Pre, i + 1, *n, cfg.prover_count.max(1));
            run_step(&per_block, Some(i + 1), None);
            vram_census(CensusPhase::Post, i + 1, *n, cfg.prover_count.max(1));
            info!(
                target: "bench",
                "MLE block: {}/{} block={n} done", i + 1, blocks.len()
            );
        }
        return;
    }
    run_step(cfg, iteration, None);
}

/// One block, on whichever step was configured.
pub fn run_step(
    cfg: &MleSingleNodeConfig,
    iteration: Option<usize>,
    job: Option<BlockJob>,
) -> BlockOutcome {
    match cfg.step {
        Step::Riscv => run_pipeline(cfg, false, false, iteration, job),
        #[cfg(feature = "cuda")]
        Step::Convert => run_pipeline(cfg, true, false, iteration, job),
        #[cfg(not(feature = "cuda"))]
        Step::Convert => panic!("--step convert requires the `cuda` feature"),
        #[cfg(feature = "cuda")]
        Step::Combine => run_pipeline(cfg, true, true, iteration, job),
        #[cfg(not(feature = "cuda"))]
        Step::Combine => panic!("--step combine requires the `cuda` feature"),
    }
}

/// CPU preparer pool size for one work kind: one on a single card, the multi-card size above that.
///
/// A convert or combine preparer blocked on its bounded ready lane parks a device-resident ctx, so
/// twelve of them leave the memory pool with nothing to trim and a 16 GiB allocation on a heavy
/// block fails outright — block 24600825 aborts every time at 6/12/7 and completes every time at
/// 1/1/1. The riscv pool comes down with them for a different reason: its lane is unbounded and
/// `prepare_chunk` takes no device memory, so it never held ctxs, but one preparer already keeps a
/// single prover lane fed.
///
/// Do not re-derive these from a measured prepare/prove ratio. That was tried: a four-card A/B put
/// the ratio-matched sizes 10-19% behind 6/12/7, because the ratio moves with every guest rebuild.
fn preparer_pool(kind: &str, env: &str, multi_card_size: usize, cards: usize) -> usize {
    let n = std::env::var(env)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(if cards <= 1 { 1 } else { multi_card_size })
        .max(1);
    // Logged because the pools are no longer pinned by the bench box: a report that cannot say
    // which sizes ran cannot be read against another arm's.
    info!("MLE {kind} preparers: {n} ({cards} card(s))");
    n
}

/// The block-independent half of the pipeline: the compiled program and the per-card machines.
///
/// Held while the program stays the same, so a sweep pays for it once. Everything in here is a
/// function of the ELF and the card count alone — `RiscvMachine::new` takes the program and a
/// config constant and nothing else, and the code below it asserts the keygen is deterministic
/// across cards, so there is nothing per-block to get wrong by keeping it.
///
/// What is deliberately **not** here: the scheduler reset, the transfer-stats reset, and the nine
/// per-block accumulators. Those live where they already were, below this, inside the proving
/// window. Moving them up is the single most dangerous mistake available in this refactor and it
/// does not announce itself — `reset_mle_scheduler` is what clears `completed`, the proof tree and
/// `emulation_done`, so a setup-side reset leaves block 2's dispatcher taking `Complete` on its
/// first poll and proving nothing, and leaves `emulation_done` latched so every later block
/// silently measures stale lane behaviour while the report claims otherwise.
struct Resident {
    program: Arc<Program>,
    provers: Vec<Arc<RiscvMachine>>,
    #[cfg(feature = "cuda")]
    converts: Vec<Arc<GpuConvertMachine>>,
    #[cfg(feature = "cuda")]
    riscv_vm_vk: Option<RiscvVmVk>,
    #[cfg(feature = "cuda")]
    combines: Vec<Arc<pico_vm::mle::machine::combine::GpuCombineMachine>>,
    /// The whitelist, in whitelist mode: the root verify reads it after the tree; the apex holds
    /// its own reference.
    #[cfg(feature = "cuda")]
    vk_map: Option<Arc<MleVkMap>>,
    /// The standalone apex verifier, in whitelist mode with a combine stage: built once, against
    /// the deployment's pinned root (`MLE_VK_ROOT`, else the artifact's own), and reused for every
    /// block's root.
    #[cfg(feature = "cuda")]
    apex: Option<Arc<MleApexVerifier>>,
    /// Reported once, in `setup.csv`. A resident process pays it on block 1 and never again, so
    /// carrying it in the per-block table would describe a cost that is not there.
    keygen_wall: Duration,
    /// The shape these machines were built for. A second block asking for a different one is a
    /// caller bug: the machines are per-card and the lane count decides the spawn count.
    shape: (usize, bool, bool),
}

/// What the resident machines were built from. A block whose key differs gets new machines: the
/// keys are per program, so reusing them would prove another program.
#[derive(PartialEq, Eq)]
struct ResidentKey {
    elf: Arc<[u8]>,
    vk_on: bool,
    log_stacked_height: usize,
    embedded_root: Option<[KoalaBear; 8]>,
}

static RESIDENT: std::sync::Mutex<Option<(ResidentKey, Arc<Resident>)>> =
    std::sync::Mutex::new(None);

/// The resident machines for `key`, built by `build` when the slot holds none or holds another
/// program's. The old machines are dropped before the new ones are built, so their device memory
/// returns to the pool first.
fn resident_for(key: ResidentKey, build: impl FnOnce(Arc<[u8]>) -> Resident) -> Arc<Resident> {
    let mut slot = RESIDENT.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((held, resident)) = slot.as_ref() {
        if *held == key {
            return Arc::clone(resident);
        }
        info!("MLE resident: program or settings changed; rebuilding the machines");
    }
    *slot = None;
    let resident = Arc::new(build(Arc::clone(&key.elf)));
    *slot = Some((key, Arc::clone(&resident)));
    resident
}

/// The resident machines, if any, for reporting only.
#[cfg(feature = "cuda")]
fn resident_snapshot() -> Option<Arc<Resident>> {
    RESIDENT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|(_, resident)| Arc::clone(resident))
}

/// The single-node proving pipeline: keygen (+ eager JIT warmup) first on the quiescent main
/// thread, then an emulate thread streams records to a preparer thread which publishes prepared
/// chunks to the scheduler; a worker pool proves chunks as they arrive; finally the cross-chunk
/// GCS is asserted.
///
/// With `with_convert`, the streaming convert stage is spliced in FRI-style: each riscv chunk
/// proof flows (never batched) into a convert-preparer pool (CPU: layout + keygen-cache + emulate)
/// and on to a convert-prover pool (GPU: trace-gen + prove); the step completes when every chunk's
/// convert proof is done. The GlobalScheduler keeps tracking the riscv level (chunks report
/// terminal there); convert completion is joined via the pipeline channels draining.
///
/// With `with_combine` (which implies `with_convert`), the scheduler additionally runs its combine
/// tree: convert proofs are reported into its proof tree, which pairs adjacent ones into
/// `SchedulerTask::Combine`, and the same worker pool proves those nodes. See the `no_combine`
/// switch below for why the riscv level must then stop reporting terminally.
fn run_pipeline(
    cfg: &MleSingleNodeConfig,
    with_convert: bool,
    with_combine: bool,
    iteration: Option<usize>,
    job: Option<BlockJob>,
) -> BlockOutcome {
    assert!(
        with_convert || !with_combine,
        "with_combine implies with_convert"
    );
    watch::reset();
    // Scheduling mode. This used to be an unconditional `set_var("USECASE", "local_single_node")`
    // nail: the GlobalScheduler reads the mode from USECASE / MACHINE_ROLE, and a stray two-machine
    // value (these benchmark hosts also run two-machine FRI) would role-partition chunks so the
    // riscv-only worker pool never acquired them all and hung.
    //
    // The nail is now an opt-out rather than a clobber: single-node remains the default and is
    // still pinned exactly as before, so the env cannot leak in by accident, but asking for
    // two-machine explicitly is no longer overwritten.
    //
    // Removing the pin alone is NOT sufficient to make two-machine work: MLE's worker ids must also
    // carry the role label (see `worker_label` below), or `worker_index_for_id` falls through to
    // `unwrap_or(0)` and elects every worker on both machines the leader.
    if !mle_two_machine_requested() {
        std::env::set_var("USECASE", "local_single_node");
    }
    // Chunk-assignment sizing, set before anything reads it. Inert in single-node (the assignment
    // is only consulted in the two-machine modes), but set here so the value travels with the MLE
    // entry point rather than being remembered at launch time: FRI's 8/16 leaves an 8-chunk MLE
    // block entirely inside the primary's reserved range. See
    // `set_mle_chunk_assignment_defaults` for the values and the trade-off.
    set_mle_chunk_assignment_defaults();
    // Bring up whichever half of the two-machine shape this process is, before the pipeline starts:
    // the primary must be serving before a secondary can acquire, and the secondary must hold a
    // client before its first `mle_register_chunk`. A no-op in single-node.
    if mle_two_machine_requested() {
        two_machine::init_mle_two_machine();
    }

    // `prover_count` = number of GPU cards, each getting two prover threads (riscv, recursion) —
    // one under `MLE_RECURSION_LANE=0` — plus its own machine set: proving keys and pk caches are
    // device-resident, so nothing device-touching is shared between cards. Per-card threads bind
    // their card at spawn (`set_device`), and the machine layer resolves the device from the
    // calling thread.
    let prover_count = cfg.prover_count.max(1);
    assert!(
        cfg!(feature = "cuda") || prover_count == 1,
        "prover_count={prover_count}: the CPU build has no multi-card path"
    );
    // Read here and never again -- see `recursion_lane_enabled` for why a second read is a hang
    // rather than an error. Logged because a report that cannot say which topology ran cannot be
    // read against another arm's, the same reason `preparer_pool` logs its sizes.
    let rec_lane = recursion_lane_enabled();
    // Derived once, so the spawn count, the log line and the bench headline cannot disagree about
    // the shape that actually ran.
    let lanes_per_card = if rec_lane { 2 } else { 1 };
    info!(
        // `bench`, like the `MLE lane:` lines this is the header for, so an archived log filtered
        // to that target alone still says which shape produced it.
        target: "bench",
        "MLE prover lanes: {lanes_per_card} per card ({prover_count} card(s)){}",
        if rec_lane {
            ""
        } else {
            " — MLE_RECURSION_LANE=0: one lane takes riscv, convert and combine"
        }
    );

    // GPU proving shares pico's memory pool: initialize one per card at process entry (an invalid
    // card index fails loudly here, before any thread spawns). Process-level resources, so the
    // provers below need no pool setup of their own.
    #[cfg(feature = "cuda")]
    for k in 0..prover_count {
        pico_vm::mle::machine::riscv::init_mle_gpu_pool(k);
    }
    vram_probe("enter", iteration.unwrap_or(0), prover_count);

    let t_total = Instant::now();
    let verify = env_flag("MLE_VERIFY");
    // Negative-test hook: tamper one cross-chunk pass-through cell so `Σ gcs != 0`.
    let corrupt_memory = env_flag("CORRUPT_MEMORY");

    // Time each setup stage (program load / compile / pools) so per-run variance
    // (disk / page-cache effects) is attributable from the bench log.
    // Per block. The ELF and the compiled program are resident (see `Resident`); only this is not.
    let t_load = Instant::now();
    // A caller-supplied block wins over the fixture selector: the ethproofs entry has already
    // turned RSP's `input_buffer` into a stdin and there is no file for it to name.
    let stdin = match job {
        Some(job) => job.stdin,
        None => stdin_for_block(cfg, cfg.n),
    };
    info!(
        "MLE program load done in {:.3}s",
        t_load.elapsed().as_secs_f64()
    );

    // Work scheduler + prepared-chunk store.
    //
    // `no_combine` off means the scheduler runs its full path: reported proofs enter the proof
    // tree, adjacent pairs become `SchedulerTask::Combine`, and completion switches from
    // count-based (`chunks_proven == total`) to tree-based (`is_proof_tree_complete`).
    //
    // IMPORTANT: that switch is why the riscv level must NOT call `report_chunk_terminal` in
    // combine mode. That entry point only ever consults the count-based predicate, and the
    // predicate checks neither the `no_combine` flag nor the combine queue. With combine on, it
    // would latch completion as soon as every chunk was proven — with combine tasks still queued —
    // and wake every worker with `Complete`. See the reporting match in the worker loop.
    // The singleton, not a private `Arc`. Holding its own instance meant MLE's scheduler and the one
    // a gRPC server would serve were two different objects, so a secondary connecting in would find
    // no work. Same object now, which is what a two-machine run needs.
    //
    // A singleton outlives the run where a fresh `GlobalScheduler` did not, and `MLE_REPEAT` calls
    // this function N times in one process — so reset before anything registers a chunk, or
    // iteration 2 inherits iteration 1's proof tree and completion state.
    reset_mle_scheduler();
    // Per-block, not cumulative: `MLE_REPEAT` runs this function several times in one process and
    // the figure is wanted per block.
    crate::common::transfer_stats::reset();
    let scheduler: Arc<GlobalScheduler<SchedulerProof>> = get_mle_scheduler();
    scheduler.set_no_combine(!with_combine);
    let store: Arc<DashMap<usize, PreparedChunk>> = Arc::new(DashMap::new());

    // Per-chunk prove timing (pure-prove throughput), independent of emulate/transport.
    let prove_nanos = Arc::new(AtomicU64::new(0));
    let prove_count = Arc::new(AtomicUsize::new(0));

    // Event buffer pools must exist before emulation starts. Streaming lowers the requirement
    // from "≥ total chunk count" (collect-all held every record's pooled buffer at once — a pool
    // smaller than the chunk count deadlocked) to "≥ in-flight chunks": when emulation runs
    // ahead of proving, `get_buffer` blocking on an empty pool is natural backpressure, released
    // as workers finish chunks and drop their records.
    //
    // The embedded entry states its size; the CLI reads `MLE_EVENT_POOL_SIZE`. Sized rather than
    // initialised-if-absent, so pools a host emulation left empty earlier in the process (growable
    // mode) do not leave this run unbounded; the scope keeps such an emulation out while it runs.
    let _pooled = pooled_event_buffers();
    let pool_size = match &cfg.embedded {
        Some(embedded) => embedded.event_pool_size.get(),
        None => std::env::var("MLE_EVENT_POOL_SIZE")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(256),
    };
    // One buffer holds one chunk's events, so the embedded entry sizes them from the chunk it cuts;
    // the CLI's chunk and buffers both follow `CHUNK_SIZE`.
    let buffer_capacity = cfg
        .embedded
        .as_ref()
        .map(|e| e.emulator_opts.chunk_size as usize);
    let t_pools = Instant::now();
    // The embedded entry pins on demand, so a small guest pins only the few buffers it uses.
    let pinning = if cfg.embedded.is_some() {
        Pinning::OnDemand
    } else {
        Pinning::UpFront
    };
    size_cpu_event_buffer_pool(pool_size, buffer_capacity, pinning, HostAllocFlags::DEFAULT);
    size_alu_event_buffer_pool(pool_size, buffer_capacity, pinning, HostAllocFlags::DEFAULT);
    // MLE_PACKED_EVENTS=1: pinned staging pools for the packed FFI event mirror. The buffers live
    // only from the preparers packing to that chunk's upload, so a small pool suffices. Its own
    // `initialized` check, not the alu pool's: nesting it there would silently leave packing off
    // for a run that found the alu pool already up. GPU build only: the CPU build has no preparer.
    #[cfg(feature = "cuda")]
    if pico_vm::instances::preparer::packed_events_enabled()
        && !pico_vm::instances::preparer::packed_pools_initialized()
    {
        // One slot per in-flight chunk, held until the chunk is PROVEN and dropped (the stage
        // lives inside `PreparedChunk`) — so the bound on live slots is the event pools' own
        // bound, and the default follows the same `pool_size`: a smaller fixed default silently
        // reverts the overflow chunks to pageable fat uploads on the prove threads. Slots are
        // pinned up front, ~1.4 GB each at CHUNK_SIZE=2^23, so the total tracks `pool_size`:
        // ~88 GiB under `single_node_mle.sh`'s MLE_EVENT_POOL_SIZE=64, but ~358 GiB at this
        // function's own default of 256. The init log prints the exact total; set
        // MLE_PACKED_POOL_SIZE on a host that cannot spare it — `two_machine_mle.sh` pins 16.
        let packed_pool_size = std::env::var("MLE_PACKED_POOL_SIZE")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(pool_size);
        pico_vm::instances::preparer::init_packed_event_pools(
            packed_pool_size,
            HostAllocFlags::DEFAULT,
        );
    }
    info!(
        "MLE event pools pre-sized to {pool_size} buffers in {:.3}s",
        t_pools.elapsed().as_secs_f64()
    );

    // Keygen (+ eager JIT warmup) on the main thread BEFORE the emulate/preparer/worker threads
    // spawn: `RiscvMachine::new` nvrtc-compiles the JIT kernels here, and that must run while the
    // process is quiescent or libnvrtc deadlocks in the heavily-threaded prover. Cost: the old
    // keygen↔emulate overlap is gone (~7s more end-to-end wall), but sum(prove)/e2e= are
    // unaffected (both exclude setup). No-op when JIT is off.
    //
    // One machine per card, built sequentially with the main thread bound to the target card
    // (proving keys are device-resident). Card 0 compiles the JIT kernels; later cards load the
    // same cubins from the shared disk cache and only pay the module load.
    //
    // Held across blocks while the program and settings stay the same (see `resident_for`). The
    // block a machine proves is an argument to `prove_chunk`, not a property of the machine, so
    // nothing below this line is per-block — which is exactly why it can be hoisted and why the
    // per-block state above it must not be.
    let embedded = cfg.embedded.as_ref();
    let vk_on = embedded.is_some() || vk_verification();
    let resident_key = ResidentKey {
        elf: load_program_elf(cfg),
        vk_on,
        log_stacked_height: cfg.log_stacked_height,
        embedded_root: embedded.map(|e| e.trusted_root),
    };
    let resident = resident_for(resident_key, |elf| {
        let t_compile = Instant::now();
        let program: Arc<Program> = Compiler::new(SourceType::RISCV, &elf)
            .expect("failed to parse RISC-V ELF")
            .compile();
        info!(
            "MLE program compile done in {:.3}s",
            t_compile.elapsed().as_secs_f64()
        );
        #[cfg(feature = "cuda")]
        let vk_map: Option<Arc<MleVkMap>> = match embedded {
            Some(e) => Some(Arc::clone(&e.whitelist)),
            None => vk_on.then(whitelist_map),
        };
        let t_keygen = Instant::now();
        let mut provers: Vec<Arc<RiscvMachine>> = Vec::with_capacity(prover_count);
        for k in 0..prover_count {
            #[cfg(feature = "cuda")]
            pico_vm::mle::cuda_mle::runtime::context::set_device(k as i32)
                .unwrap_or_else(|e| panic!("binding the main thread to card {k} failed: {e:?}"));
            #[cfg(not(feature = "cuda"))]
            let _ = k;
            let machine = RiscvMachine::new(program.clone(), cfg.log_stacked_height, vk_on)
                .unwrap_or_else(|e| panic!("{e}"));
            // Every constructor seeds the program's initial GCS, and the aggregate must count that seed
            // exactly ONCE — globally, not once per process. Single-node: card 0 keeps it. Two-machine:
            // the primary's card 0 keeps it and **the secondary unseeds every one of its cards**, since
            // two processes each applying the per-card rule locally would count the seed twice and the
            // sum could never close.
            //
            // This is invisible to every type check, and it fails as a
            // `cross-chunk global cumulative sum is not zero (memory inconsistency)` panic that reads
            // exactly like a real memory bug — a packing mismatch once failed exactly this way.
            if k > 0 || !keeps_initial_gcs_seed() {
                machine.unseed_initial_gcs();
            }
            provers.push(Arc::new(machine));
        }
        // Card 0's machine doubles as the vk source below; keygen is deterministic, so every card
        // holds the same vk (asserted here rather than surfacing later as a verify failure).
        let prover = Arc::clone(&provers[0]);
        for (k, p) in provers.iter().enumerate().skip(1) {
            assert_eq!(
                p.vk_pre_hash(),
                prover.vk_pre_hash(),
                "card {k} keygen'd a different riscv vk than card 0 — keygen is not deterministic"
            );
        }
        let keygen_wall = t_keygen.elapsed();
        info!(
            "MLE keygen done in {:.3}s ({prover_count} card(s))",
            keygen_wall.as_secs_f64()
        );

        // Convert machine + JIT warmup, STILL on the quiescent main thread (the warmup keygen
        // nvrtc-compiles the recursion kernels; libnvrtc deadlocks once the prover threads exist).
        // GPU-only: the convert stage does not exist in a CPU build.
        #[cfg(not(feature = "cuda"))]
        let _ = with_convert;
        // `riscv_vm_vk` is kept: combine hands the root back to the CPU `CombineMachine`, whose
        // acceptance pins the root's `riscv_vk_digest` against this trusted identity.
        #[cfg(feature = "cuda")]
        let (converts, riscv_vm_vk) = if with_convert {
            let t = Instant::now();
            let riscv_vk = Arc::new(prover.vk().clone());
            let riscv_vm_vk = RiscvVmVk::from_program_and_vk(&program, &riscv_vk);
            // The identity a verifier has to be handed (an ethproofs VK bundle's `vm_vk`): the
            // digest preimage without its domain tag, as canonical u32s. Logged from the binary
            // that proves, so the bundle cannot drift from what the roots are pinned against.
            {
                use p3_field::PrimeField32;
                let preimage = riscv_vm_vk.digest_preimage();
                let vm_vk: Vec<String> = preimage[1..]
                    .iter()
                    .map(|e| e.as_canonical_u32().to_string())
                    .collect();
                info!(
                    "exe identity: digest {} | vm_vk ({} u32) = {}",
                    riscv_vm_vk.digest_hex(),
                    vm_vk.len(),
                    vm_vk.join(" ")
                );
            }
            // One machine per card: the per-shape pk cache is device-resident. The warmup keygen
            // nvrtc-compiles once (card 0); later cards hit the cubin disk cache.
            let mut machines = Vec::with_capacity(prover_count);
            for k in 0..prover_count {
                pico_vm::mle::cuda_mle::runtime::context::set_device(k as i32).unwrap_or_else(
                    |e| panic!("binding the main thread to card {k} failed: {e:?}"),
                );
                let mut machine = GpuConvertMachine::new(
                    Arc::clone(&riscv_vk),
                    riscv_vm_vk.clone(),
                    pico_vm::mle::recursion_params_with_100_bits_security(),
                    vk_on,
                );
                if let Some(map) = &vk_map {
                    machine.set_vk_root(map.root());
                }
                let machine = Arc::new(machine);
                machine.pre_keygen_warmup();
                machines.push(machine);
            }
            info!(
                "MLE convert warmup keygen done in {:.3}s ({prover_count} card(s))",
                t.elapsed().as_secs_f64()
            );
            (machines, Some(riscv_vm_vk))
        } else {
            (Vec::new(), None)
        };

        // Combine machines (per card, like convert). Not warmed up: convert's warmup already
        // compiled every cubin combine needs (same chips, same constraint-only JIT sources).
        // Construction is host-side; the pk cache fills lazily on the (bound) preparer threads.
        #[cfg(feature = "cuda")]
        let combines: Vec<Arc<pico_vm::mle::machine::combine::GpuCombineMachine>> = if with_combine
        {
            (0..prover_count)
                .map(|k| {
                    // Bind to the target card first, exactly as the riscv and convert loops above do.
                    // Construction is NOT purely host-side: the JIT kernel handles reached through this
                    // machine are `CUfunction`s, which belong to the loading device's primary context
                    // (see `cuda/jit.rs`'s cache, keyed by device for this reason). Without the bind the
                    // whole vector was built on whatever card the convert loop left current —
                    // `prover_count - 1` — so every card but the last proved against another card's
                    // handles: `cuLaunchKernel` 400, then a sticky illegal access surfacing at an
                    // unrelated free. Invisible at N=1, where that leftover card IS card 0.
                    pico_vm::mle::cuda_mle::runtime::context::set_device(k as i32).unwrap_or_else(
                        |e| panic!("binding the main thread to card {k} failed: {e:?}"),
                    );
                    let mut machine = pico_vm::mle::machine::combine::GpuCombineMachine::new(
                        pico_vm::mle::recursion_params_with_100_bits_security(),
                        vk_on,
                    );
                    if let Some(map) = &vk_map {
                        machine.set_vk_map(Arc::clone(map));
                    }
                    Arc::new(machine)
                })
                .collect()
        } else {
            Vec::new()
        };
        #[cfg(feature = "cuda")]
        let apex = match (&vk_map, &riscv_vm_vk) {
            (Some(map), Some(vm_vk)) if with_combine => {
                let trusted_root = match embedded {
                    Some(e) => e.trusted_root,
                    None => pinned_root_from_env().unwrap_or_else(|| map.root()),
                };
                Some(Arc::new(MleApexVerifier::new(
                    pico_vm::mle::recursion_params_with_100_bits_security(),
                    Arc::clone(map),
                    vm_vk.clone(),
                    trusted_root,
                )))
            }
            _ => None,
        };
        Resident {
            program,
            provers,
            #[cfg(feature = "cuda")]
            converts,
            #[cfg(feature = "cuda")]
            riscv_vm_vk,
            #[cfg(feature = "cuda")]
            combines,
            #[cfg(feature = "cuda")]
            vk_map,
            #[cfg(feature = "cuda")]
            apex,
            keygen_wall,
            shape: (prover_count, with_convert, with_combine),
        }
    });
    // A second block asking for a different shape would silently prove against machines built for
    // the first one — wrong card count, or a convert stage that was never constructed.
    assert_eq!(
        resident.shape,
        (prover_count, with_convert, with_combine),
        "resident machines were built for a different shape; one process serves one shape"
    );
    // Rebound with the names the pipeline below already uses, so the proving window is untouched
    // by the hoist. Every one of these is an `Arc` clone.
    let program = Arc::clone(&resident.program);
    let provers = resident.provers.clone();
    #[cfg(feature = "cuda")]
    let converts = resident.converts.clone();
    #[cfg(feature = "cuda")]
    let riscv_vm_vk = resident.riscv_vm_vk.clone();
    #[cfg(feature = "cuda")]
    let combines = resident.combines.clone();
    #[cfg(feature = "cuda")]
    let vk_map = resident.vk_map.clone();
    #[cfg(feature = "cuda")]
    let apex = resident.apex.clone();
    let keygen_wall = resident.keygen_wall;
    // Per-block shape statistics, by snapshot-and-difference rather than by reset.
    //
    // The combine machines are resident, so `shapes` and the pk cache it indexes accumulate across
    // blocks — deliberately. A tree's shapes fit its cache and survive into the next block, which
    // is the whole source of the cross-block hits a sweep is expected to show.
    //
    // Resetting `shapes` per block is the obvious alternative and breaks the credit path: a hit is
    // credited by finding the record whose `shape_id` matches the cache entry's, so clearing the
    // records leaves block 2's hit on block 1's pk with nothing to credit. `shape_nodes` then comes
    // out short of `nodes` and the assertion below fires on a run that is entirely correct — in
    // exactly the case this design predicts and wants to measure.
    #[cfg(feature = "cuda")]
    let shape_baseline: Vec<(usize, usize, usize)> = combines
        .iter()
        .map(|m| {
            let s = m.shape_stats();
            (s.keygens, s.hits, s.evictions)
        })
        .collect();
    // Machine construction is done — rebind the main thread to card 0 (it constructed card k's
    // machines while bound to k; everything it does from here on is host-side or card-0).
    #[cfg(feature = "cuda")]
    pico_vm::mle::cuda_mle::runtime::context::set_device(0)
        .expect("rebinding the main thread to card 0 failed");
    vram_probe("after_setup", iteration.unwrap_or(0), prover_count);

    // The root node's proof + its ordered child layouts, stashed by whichever worker proves the
    // final node. Written exactly once (asserted), read on the main thread after the join.
    #[cfg(feature = "cuda")]
    let root_slot: Arc<std::sync::Mutex<Option<RootRecord>>> =
        Arc::new(std::sync::Mutex::new(None));
    // Combine node timing. Kept OUT of `prove_nanos` / `prove_count` on purpose: those two are the
    // riscv chunk figures the `chunks=` / `sum(prove)` bench fields report, and mixing combine into
    // them would break comparability with the riscv/convert baselines.
    #[cfg(feature = "cuda")]
    let combine_nanos = Arc::new(AtomicU64::new(0));
    #[cfg(feature = "cuda")]
    let combine_count = Arc::new(AtomicUsize::new(0));

    // --- Emulation via the shared snapshot+sequencer pipeline. ---
    // Segments through `emulate_snapshot_pipeline` (same emulator + `bench_riscv_ops` opts). The
    // pipeline self-inits the memory pool + recycler threads; `MEMORY_POOL_SIZE` keeps the pool
    // larger than the chunk count so the blocking snapshot `recv` never starves. The emulation-only
    // witness carries no proving keys — MLE proves with its own `RiscvMachine`. `handle_record`
    // forwards each record to the preparer thread (crossbeam Sender is Send+Sync, which the
    // pipeline's handler requires); the event precompute in `prepare_chunk` stays off this thread.
    // `MLE_PREWARM=1`: pay the process's first-touch page-fault cost HERE, before the `e2e=` window
    // opens, instead of inside the first chunk's emulate/prepare where it lands on the pipeline's
    // critical path. The prove lane IS the critical path at that moment but has nothing to work on
    // yet, so every millisecond the first chunk spends faulting pages in passes 1:1 into
    // `prove(wall)`. Measured on reth-171 (n>=3, control and treatment interleaved): the first
    // iteration's `e2e=` runs 419±52 ms slower than the warm ones, and this drops that to
    // 42±107 ms — indistinguishable from zero, with the warm iterations unchanged.
    //
    // Two things get pre-paid: the emulator memory pool's `Lazy` (which would otherwise initialize
    // inside the window), and `MLE_HEAP_PREWARM_GB` GB of heap pages that are touched and then
    // freed, so the ~30 per-chunk event `Vec`s in `prepare_chunk` — the single biggest contributor,
    // 201 of the 419 ms — reuse warm pages instead of faulting fresh ones.
    //
    // REQUIRES `TCMALLOC_RELEASE_RATE=0` to do most of its work: gperftools tcmalloc hands freed
    // large spans back to the kernel with `MADV_DONTNEED`, which throws the pre-faulted pages away
    // before `prepare_chunk` ever asks for them. Prewarm alone recovers only ~1/3 of the gap;
    // `TCMALLOC_RELEASE_RATE=0` alone recovers nothing (nothing has been freed yet on the first
    // iteration, so there are no pages to retain). `single_node_mle.sh` sets both.
    //
    // Process-level, not per-iteration: `MLE_REPEAT` calls this function N times, and re-growing
    // and re-freeing the arena on every iteration churns exactly the pages the previous iteration
    // warmed — which cost ~50 ms per warm iteration when this was first written per-iteration.
    if env_flag("MLE_PREWARM") {
        static PREWARMED: std::sync::Once = std::sync::Once::new();
        PREWARMED.call_once(|| {
            let t = Instant::now();
            pico_vm::emulator::riscv::memory::init_memory_pool();
            let gb: usize = std::env::var("MLE_HEAP_PREWARM_GB")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let mut bufs: Vec<Vec<u8>> = Vec::with_capacity(gb);
            for _ in 0..gb {
                bufs.push(vec![1u8; 1 << 30]);
            }
            drop(bufs);
            info!("MLE prewarm done in {:.3}s", t.elapsed().as_secs_f64());
        });
    }
    // Rendezvous with the peer before the window opens, so the two machines emulate against the
    // same clock instead of whenever each personally finished building. Without it the halves ran
    // in SERIES rather than parallel — see `wait_for_peer_worker` for the reth-24006677 timeline
    // showing zero overlap between the two machines' chunk proving.
    //
    // Primary side only. The secondary is already gated: it blocks on connecting to the primary's
    // scheduler at launch, so it cannot start before the primary is serving. This closes the other
    // direction, which was open.
    if mle_two_machine_requested() && !is_mle_secondary() {
        let secs = std::env::var("MLE_PEER_WAIT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(600);
        let t_wait = Instant::now();
        info!("MLE primary: waiting for the peer machine's pipeline before starting");
        if crate::common::machine_role::wait_for_peer_worker(Duration::from_secs(secs)) {
            info!(
                "MLE primary: peer ready after {:.3}s — starting the pipeline",
                t_wait.elapsed().as_secs_f64()
            );
        } else {
            // Not fatal: fall through to the pre-barrier behaviour rather than fail a run that
            // could still complete. Loud, because a run that silently lost half its hardware is
            // exactly the thing that took a long time to notice in the first place.
            warn!(
                "MLE primary: no peer worker polled within {secs}s — starting alone. Two-machine \
                 will be no faster than single-node, and probably slower."
            );
        }
    }
    // Pipeline scope start — the FRI-`E2E_total`-comparable window (emulate→prove→GCS;
    // the compile/keygen/pools setup above this line is excluded). Reported as `e2e=`.
    let t_e2e = Instant::now();
    // Span recording starts with the window, so the one-time setup above — which no per-chunk change
    // can move — is outside it and stays unrecorded. Every span timestamp is relative to here.
    spans::set_origin(t_e2e);
    // Records are index-stamped at the source with the position they hold in the emulation, because
    // the scheduler, the combine tree and the tail barrier are all keyed by that index. Delivery is
    // not in that order once anything upstream runs concurrently — several riscv preparers, or
    // `NUM_THREADS > 1` in the emulator — so it is the stamp that downstream restores order from.
    // Where the stamp comes from is at the send below.
    let (record_tx, record_rx) = crossbeam::channel::unbounded::<(usize, EmulationRecord)>();
    let emulator_opts = embedded
        .map(|e| e.emulator_opts)
        .unwrap_or_else(EmulatorOpts::bench_riscv_ops);
    let emulation_workers = embedded.map(|e| e.emulation_workers);
    let emulate_handle = {
        let program = program.clone();
        thread::Builder::new()
            .name("mle-emulate".into())
            .spawn_watched(move || {
            let t = Instant::now();
            // Inside the thread, so the window the phase probes localised the leak to can be split
            // between this thread's own work and everything running beside it. The first of these
            // is also this thread's first CUDA call, so whatever per-thread state that costs shows
            // up as `preparers_spawned -> emu_start` rather than inside the thread's own span.
            vram_probe("emu_start", iteration.unwrap_or(0), prover_count);
            let corrupted = Arc::new(AtomicBool::new(false));
            let witness = ProvingWitness::<KoalaBearPoseidon2, RiscvChipType<KoalaBear>, Vec<u8>>::
                setup_for_mle_riscv(program, stdin, emulator_opts);
            vram_probe("emu_witness", iteration.unwrap_or(0), prover_count);
            let (emulated_cycles, committed) = {
                let corrupted = Arc::clone(&corrupted);
                let on_record = move |mut record: EmulationRecord, _done: bool| {
                    // Nothing downstream will take it: end the emulation rather than run on.
                    if watch::failed() {
                        panic!("emulation stopped: the pipeline failed");
                    }
                    if corrupt_memory && !corrupted.load(Ordering::Relaxed) {
                        // Tamper the first tamperable record (exactly one).
                        if corrupt_one_record(&mut record) {
                            corrupted.store(true, Ordering::Relaxed);
                        }
                    }
                    // Stamp with the record's own position: `public_values.chunk`, 1-based, so the
                    // sinks' 0-based index is one less. Not an arrival counter — under
                    // `NUM_THREADS > 1` records finish out of order, and a counter would have the
                    // combine tree pairing chunks that are not adjacent. FRI's coordinator keys on
                    // the same field.
                    let seq = record.chunk_index() - 1;
                    record_tx.send((seq, record)).expect("preparer hung up");
                };
                // The embedded entry states its replay workers; the CLI reads `NUM_THREADS`.
                let (_reports, total_cycles, pv_stream) = match emulation_workers {
                    Some(workers) => emulate_snapshot_pipeline_with(
                        &witness,
                        workers,
                        DeferredSplit::FromChunk16,
                        on_record,
                    ),
                    None => emulate_snapshot_pipeline(&witness, on_record),
                }
                .expect("snapshot pipeline failed");
                // record_tx drops here → the preparer sees the end of the stream.
                //
                // The cycle count used to go with it: the whole tuple was discarded by the
                // `.expect`, and ethproofs requires `proving_cycles` on every submission, so there
                // was no way to fill that field without re-emulating the block.
                (total_cycles, pv_stream)
            };
            if corrupt_memory && !corrupted.load(Ordering::Relaxed) {
                panic!(
                    "CORRUPT_MEMORY: no pass-through cell found to tamper; negative test could not run"
                );
            }
            vram_probe("emu_end", iteration.unwrap_or(0), prover_count);
            (t.elapsed(), emulated_cycles, committed)
        })
        .expect("spawn mle-emulate")
    };
    vram_probe("emulate_spawned", iteration.unwrap_or(0), prover_count);

    // ---- Stage topology: one GPU card = two prover lanes, or one under MLE_RECURSION_LANE=0. ----
    //
    //   CPU  mle-riscv-preparer xR  --(idx, PreparedChunk)--> store, then a scheduler task
    //        mle-convert-preparer xC --(ConvertWork)--> the card's recursion-serving lane
    //        mle-combine-preparer xB --(CombineWork)--> the card's recursion-serving lane
    //   GPU  mle-prover-k:     riscv, plus its card's ready lanes once the chunk feed is drained --
    //                          a lane with nothing left to do should not sit parked while its card
    //                          has work, which is what the pre-split single lane already did
    //        mle-prover-rec-k: convert + combine, selecting across the two ready lanes
    //        one mle-dispatch thread feeds a single shared chunk lane that any idle card drains,
    //        routes combine tasks to the preparer pool, and closes the drain channel when no
    //        further chunk can be dispatched.
    //
    // Under `MLE_RECURSION_LANE=0` there is no `mle-prover-rec-k`: `mle-prover-k` selects across
    // all three feeds from the start, which is the shape the second lane was split out of — and
    // the drain transition above does NOT apply to it. That lane is its card's only recursion
    // consumer, so deferring recursion behind a queued chunk there would push the whole combine
    // tree past the last riscv prove. Nothing else in this
    // diagram moves -- the preparer pools are sized by CARD (`preparer_pool`), the ready lanes are
    // one per card either way, and the riscv queue is untouched (see its own note below).
    //
    // Card affinity: a chunk has none. The old rule was `idx % N` fixed at the riscv routing
    // point, but the riscv preparers are an unrouted pool and `prepare_chunk` allocates no device
    // memory, so a prepared chunk is host-side and whichever card is free proves it. Convert work
    // is handed out round-robin as well — its preparer binds the card it is about to send to,
    // which is all the per-card pk cache requires — as are combine nodes. Every GPU-touching
    // thread binds its card; the machine layer resolves the device from the thread.
    // Preparer pools: one per kind on a single card, the benchmarked multi-card sizes above that
    // (see `preparer_pool`); the env overrides for A/B work. The pool used to be pinned to
    // 1 because ordering depended on it; it no longer does (see the publish branch below), so the
    // env is honored.
    let riscv_preparer_count = preparer_pool("riscv", "MLE_RISCV_PREPARERS", 6, prover_count);

    // Upstream's upload-ahead preparer barrier is not here: `prepare_chunk` allocates no device
    // memory, so a prepare cannot contend with a tail's prove.
    let preparer_handle = {
        let mut hs = Vec::new();
        for pidx in 0..riscv_preparer_count {
            let record_rx = record_rx.clone();
            let store = Arc::clone(&store);
            let shaper = Arc::clone(&provers[0]);
            hs.push(
                thread::Builder::new()
                    .name(format!("mle-riscv-preparer-{pidx}"))
                    .spawn_watched(move || {
                        spans::bind_lane(LaneId::new(Role::RiscvPreparer, pidx));
                        let t = Instant::now();
                        let mut n = 0usize;
                        while let Some((idx, record)) =
                            recv_idle(&record_rx, WorkKind::PrepareRiscv)
                        {
                            if watch::failed() {
                                break;
                            }
                            // This lane has no `Wait`: `prepare_chunk` takes no gate (`:505-506`
                            // records that it allocates no device memory) and its downstream is
                            // unbounded, so it can only ever block for want of input.
                            let _b = spans::busy(WorkKind::PrepareRiscv, Some(idx as u32));
                            // Not ours to prove: drop the record now, which returns its event
                            // buffer to the pool immediately instead of holding it until the
                            // other machine proves the chunk and says so. Still registered
                            // below — the scheduler learns the block's chunks from the primary,
                            // which must announce every one of them, including the secondary's.
                            if !prepares_chunk(idx) {
                                drop(record);
                                mle_register_chunk(idx);
                                n += 1;
                                continue;
                            }
                            // Whitelist mode: the shape goes on the record before the device
                            // event staging copies it (decided from the event counter the
                            // packaging computes anyway); plain packaging otherwise.
                            let chunk = shaper.prepare_chunk_shaped(record);
                            // Stamps need not arrive ascending: the store is a map and
                            // `register_chunk` keeps only a min/max. They must be distinct — an
                            // overwrite drops a chunk while `register_chunk` early-returns on
                            // the duplicate, leaving the block proven a chunk short.
                            let displaced = store.insert(idx, chunk);
                            assert!(
                                displaced.is_none(),
                                "chunk stamp {idx} arrived twice — the earlier chunk was lost"
                            );
                            mle_register_chunk(idx);
                            n += 1;
                        }
                        (n, t.elapsed())
                    })
                    .expect("spawn mle-riscv-preparer"),
            );
        }
        // Aggregator: keeps the downstream join's single (chunk_count, wall) shape across R
        // preparers, and owns finalize_emulation.
        thread::Builder::new()
            .name("mle-riscv-preparer-join".into())
            .spawn_watched(move || {
                let mut total = 0usize;
                let mut wall = Duration::ZERO;
                for h in hs {
                    let (n, w) = h.join().expect("riscv preparer panicked");
                    total += n;
                    wall = wall.max(w);
                }
                mle_finalize_emulation();
                (total, wall)
            })
            .expect("spawn mle-riscv-preparer-join")
    };
    vram_probe("preparers_spawned", iteration.unwrap_or(0), prover_count);

    // Convert work reaches the prover on its own bounded(1) ready lane, carrying device-built
    // prepares — each parked ctx is a few hundred MB of VRAM (see `ConvertWork`), so the preparer
    // count bounds real residency, not just backpressure. One lane per card: a convert proves on
    // the card its preparer picked round-robin, which is where that preparer cached its pk.
    let (convert_ready_txs, convert_ready_rxs): (Vec<_>, Vec<_>) = (0..prover_count)
        .map(|_| crossbeam::channel::bounded::<(usize, ConvertWork)>(1))
        .unzip();

    #[cfg(feature = "cuda")]
    let convert_prove_nanos = Arc::new(AtomicU64::new(0));
    #[cfg(feature = "cuda")]
    let convert_done = Arc::new(AtomicUsize::new(0));
    // CPU build: no convert stage — the prover reports terminally (the `None` arm below).
    #[cfg(not(feature = "cuda"))]
    let convert_tx: Option<crossbeam::channel::Sender<(usize, MleProof)>> = None;
    // Shared by the convert preparers and the pre-build: one round-robin counter so both hand out
    // the same cards, and the map of the cards the pre-build has already claimed.
    #[cfg(feature = "cuda")]
    let convert_card_rr = Arc::new(AtomicUsize::new(0));
    #[cfg(feature = "cuda")]
    let prebuilt_cards: Arc<DashMap<usize, usize>> = Arc::new(DashMap::new());
    #[cfg(feature = "cuda")]
    let (convert_tx, convert_stage) = if !converts.is_empty() {
        let (convert_tx, convert_rx) = crossbeam::channel::unbounded::<(usize, MleProof)>();
        let num_preparers = preparer_pool("convert", "MLE_CONVERT_PREPARERS", 12, prover_count);
        let mut handles = Vec::new();
        for p in 0..num_preparers {
            let machines = converts.clone();
            let convert_rx = convert_rx.clone();
            let convert_ready_txs = convert_ready_txs.clone();
            let convert_card_rr = Arc::clone(&convert_card_rr);
            let prebuilt_cards = Arc::clone(&prebuilt_cards);
            handles.push(
                thread::Builder::new()
                    .name(format!("mle-convert-preparer-{p}"))
                    .spawn_watched(move || {
                        spans::bind_lane(LaneId::new(Role::ConvertPreparer, p));
                        while let Some((chunk_idx, riscv_proof)) =
                            recv_idle(&convert_rx, WorkKind::PrepareConvert)
                        {
                            if watch::failed() {
                                break;
                            }
                            // A keygen miss inside `prepare_one` opens its own span, which splits
                            // this one around it — see the span module on why that is automatic.
                            let _b = spans::busy(WorkKind::PrepareConvert, Some(chunk_idx as u32));
                            // Pick the card round-robin, NOT by `chunk_idx % cards`. The old form
                            // inherited the riscv stage's card for the chunk, but that stage no
                            // longer pins one, and the modulo had the same defect it did there: a
                            // machine in two-machine mode owns chunks 0-3, 8-11, 16-19..., all
                            // `% 8 < 4`, so convert work only ever reached half the cards
                            // (reth-239: 12 chunks each on cards 0-3, none on 4-7).
                            //
                            // Whatever card is chosen, prepare and prove agree on it, which is all
                            // the pk cache requires: `prepare_one` does GPU work on a keygen cache
                            // miss and the pk it caches must live on the card that proves with it,
                            // so this thread binds the card it is about to send to. Spreading the
                            // chunks warms the pk on all eight cards rather than four, which
                            // single-node already did by owning every index.
                            // The chunk's card, claimed by whichever of this thread and the
                            // pre-build asked first. A key warmed under
                            // `MLE_CONVERT_PREBUILD_PK` is on that card; if the pre-build has not
                            // finished, or never ran, this keygens here exactly as it did before.
                            let card = convert_card_for(
                                chunk_idx,
                                &prebuilt_cards,
                                &convert_card_rr,
                                machines.len(),
                            );
                            pico_vm::mle::cuda_mle::runtime::context::set_device(card as i32)
                                .unwrap_or_else(|e| {
                                    panic!("binding preparer to card {card} failed: {e:?}")
                                });
                            let prepared = machines[card].prepare_one(&riscv_proof);
                            info!("[mle-convert-preparer-{p}] chunk {chunk_idx} prepared");
                            // Built here, off the prover lane, so the prover never queues behind
                            // a ~10 ms build.
                            let work = ConvertWork(machines[card].build_convert_ctx(prepared));
                            // The bounded(1) send backpressures this preparer, which is fine —
                            // there is nowhere for more staged work to go anyway.
                            //
                            // That backpressure is `Wait`, not work: the lane is blocked because
                            // the prover has not drained the lane, which is downstream capacity.
                            // Left inside the `Busy` span it would report as this stage doing
                            // something, inflating exactly the figure someone would use to decide
                            // whether the host-side prepare is the constraint.
                            {
                                let _w =
                                    spans::wait(WorkKind::PrepareConvert, Some(chunk_idx as u32));
                                convert_ready_txs[card]
                                    .send((chunk_idx, work))
                                    .expect("prover hung up");
                            }
                        }
                    })
                    .expect("spawn mle-convert-preparer"),
            );
        }
        (Some(convert_tx), handles)
    } else {
        (None, Vec::new())
    };

    // Combine work reaches the prover the same way convert work does: a bounded(1) ready lane
    // carrying device-built prepares — each parked node holds a device ctx of its own (not free),
    // so the preparer count bounds how many. Per card; a node's card is assigned round-robin at
    // prepare time (combine children are host-side proofs, so any card can prove any node — the
    // assignment just has to match where its pk was keygen'd).
    let (combine_ready_txs, combine_ready_rxs): (Vec<_>, Vec<_>) = (0..prover_count)
        .map(|_| crossbeam::channel::bounded::<CombineWork>(1))
        .unzip();
    // The dispatcher's combine feed. Unbounded like the convert feed: tasks are Arc'd proof pairs
    // (KiB-scale, host-side), and bounding it would stall the dispatcher — which is also the riscv
    // task pump — on combine backpressure.
    #[cfg(feature = "cuda")]
    let (combine_task_tx, combine_task_rx) =
        crossbeam::channel::unbounded::<CombineTask<SchedulerProof>>();
    // Combine preparers: the CPU stage of each node (layout extraction, shape keygen, PV preflight,
    // recursion emulation) runs here, off the prover slot. What the slot keeps is the prove.
    // Round-robin card assignment for combine nodes, shared across the preparer pool.
    #[cfg(feature = "cuda")]
    let combine_card_seq = Arc::new(AtomicUsize::new(0));
    #[cfg(feature = "cuda")]
    let combine_stage = if !combines.is_empty() {
        let num_preparers = preparer_pool("combine", "MLE_COMBINE_PREPARERS", 7, prover_count);
        let mut handles = Vec::new();
        for p in 0..num_preparers {
            let machines = combines.clone();
            let scheduler = Arc::clone(&scheduler);
            let combine_task_rx = combine_task_rx.clone();
            let combine_ready_txs = combine_ready_txs.clone();
            let combine_card_seq = Arc::clone(&combine_card_seq);
            handles.push(
                thread::Builder::new()
                    .name(format!("mle-combine-preparer-{p}"))
                    .spawn_watched(move || {
                        spans::bind_lane(LaneId::new(Role::CombinePreparer, p));
                        while let Some(task) = recv_idle(&combine_task_rx, WorkKind::PrepareCombine)
                        {
                            if watch::failed() {
                                break;
                            }
                            let (start, end) = (task.left.start_chunk, task.right.end_chunk);
                            // A node spans a chunk range; the span is labelled with its first, which
                            // is what orders it against the riscv work.
                            let _b = spans::busy(WorkKind::PrepareCombine, Some(start as u32));
                            // Assign the node a card and bind to it: `prepare_node`'s keygen
                            // (cache miss) is GPU work, and the pk it caches must live where the
                            // node will be proven.
                            let card =
                                combine_card_seq.fetch_add(1, Ordering::Relaxed) % machines.len();
                            pico_vm::mle::cuda_mle::runtime::context::set_device(card as i32)
                                .unwrap_or_else(|e| {
                                    panic!("binding preparer to card {card} failed: {e:?}")
                                });
                            // `IndexedProof` hands out `Arc<P>`, but the witness builder needs
                            // owned `Proof`s. Recursion proofs are KiB-scale, so the clone is
                            // noise.
                            let children =
                                [(*task.left.inner).clone(), (*task.right.inner).clone()];
                            // Recomputed here rather than trusted from the task: the answer is
                            // monotonic (false -> true only), so a recompute can promote a node
                            // to the root but never demote one.
                            let is_final = scheduler
                                .is_final_combine(task.left.start_chunk, task.right.end_chunk);
                            let prepared = machines[card].prepare_node(&children, is_final);
                            info!(
                                "[mle-combine-preparer-{p}] node [{start},{end}] prepared \
                                 (is_final={is_final})"
                            );
                            // Built here, off the prover lane — same reasoning as the convert
                            // preparer above.
                            let work = CombineWork {
                                start_chunk: start,
                                end_chunk: end,
                                built: machines[card].build_node_ctx(prepared),
                            };
                            // Blocked on the prover draining its lane is downstream capacity, so
                            // `Wait` — see the convert preparer above for why leaving it inside
                            // `Busy` would misreport this stage as doing work.
                            {
                                let _w = spans::wait(WorkKind::PrepareCombine, Some(start as u32));
                                combine_ready_txs[card].send(work).expect("prover hung up");
                            }
                        }
                    })
                    .expect("spawn mle-combine-preparer"),
            );
        }
        handles
    } else {
        Vec::new()
    };
    #[cfg(feature = "cuda")]
    drop(combine_task_rx); // preparers hold the only receivers now

    // The clones above are the live ends now.
    drop(convert_ready_txs);
    drop(combine_ready_txs);

    // ---- Prover lanes (+ their dispatcher), per card. ----
    // The dispatcher forwards scheduler tasks as descriptors over bounded(1): the staged ctx lives
    // in the store either way, so this capacity is fairness, not VRAM — it keeps at most one
    // scheduler task in hand, letting convert work interleave instead of queueing behind a
    // 106-chunk riscv backlog. Waiter-based pull, so the 2 ms WaitForMore poll is gone.
    let t_prove = Instant::now();
    // ONE shared lane, drained by whichever card is free, rather than a per-card lane picked by
    // `chunk_idx % cards`. The per-card form assumed a chunk's record was card-resident, but the
    // riscv preparers are an unrouted pool and `prepare_chunk` allocates no device memory (:708),
    // so a prepared chunk is host-side and any card can prove it.
    //
    // Load-bearing under two-machine, and the reason 8+8 was no faster than 8: a machine proves
    // only the chunks it owns, and the static split hands the primary chunks 0-3, 8-11, 16-19...
    // — every one of them `% 8 < 4`. Half the cards were therefore unaddressable and sat idle for
    // the whole run (reth-239: provers 0-3 took 12 chunks each, provers 4-7 took none). Pulling
    // from a shared queue makes the mapping independent of which indices this machine owns.
    // It also drops the dispatcher's head-of-line stall: a full lane no longer blocks the chunk
    // behind it, because any idle card can take it.
    //
    // Capacity is `prover_count`, not 1: enough for every card to have work in hand without a
    // dispatcher round-trip each, and still far from the 106-chunk riscv backlog that capacity
    // was originally holding back so convert work could interleave.
    let (items_tx, items_rx) = crossbeam::channel::bounded::<ProverItem>(prover_count);
    // Closed by the dispatcher when no further chunk can be dispatched, which is long before the
    // run completes. A channel rather than a flag because the riscv lane is parked in a `select!`,
    // and only a channel can wake one.
    let (drain_tx, drain_rx) = crossbeam::channel::bounded::<()>(0);
    // Two prover lanes per card (riscv, recursion), or one when the recursion lane is off, plus
    // the dispatcher.
    let mut workers = Vec::with_capacity(lanes_per_card * prover_count + 1);

    {
        // No `Arc::clone(&scheduler)` here any more: the dispatcher reaches the scheduler through
        // the singleton, which is the whole point of this change.
        // Role-labelled, and load-bearing rather than cosmetic: `worker_index_for_id`
        // (`machine_role.rs`) picks the worker index by testing `worker_id.contains(label)` against
        // ["primary", "secondary"] and falls back to `unwrap_or(0)`. An unlabelled id therefore
        // makes EVERY worker on BOTH machines the leader — partitioning collapses and the root pin
        // in `try_acquire_combine_task` lapses. FRI avoids this by construction (its ids are
        // `format!("{}-gpu-prover", get_worker_label())`); MLE's did not. Single-node is unaffected
        // either way, since the label is "primary" and the index is 0.
        // The SCHEDULER's block number, not the ELF selector.
        //
        // `SchedulerService::acquire_task` gates on `block_num != scheduler.get_block_num()` and
        // returns `Wait` when they differ. MLE never sets a block number, so the scheduler's is 0 —
        // passing the reth selector (188) here meant the secondary long-polled, was told to wait
        // every time, and proved nothing while the primary sat on the four chunks reserved for it
        // until its 300s "system is broken" timeout. Reading it back off the scheduler keeps the
        // two in step by construction rather than by a matching constant.
        let block_num = get_mle_scheduler().get_block_num();
        // The dispatcher needs the store to evict records for chunks proved on the other machine
        // (see the acquire loop below), and the prover threads already took the original.
        let store = Arc::clone(&store);
        let dispatch_id: &'static str =
            Box::leak(format!("{}-mle-dispatch", get_worker_label()).into_boxed_str());
        #[cfg(feature = "cuda")]
        let combine_task_tx = combine_task_tx.clone();
        workers.push(
            thread::Builder::new()
                .name(dispatch_id.into())
                .spawn_watched(move || {
                    spans::bind_lane(LaneId::new(Role::Dispatch, 0));
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("dispatch runtime");
                    let sched = get_mle_scheduler();
                    let mut drain_tx = Some(drain_tx);
                    loop {
                        // Asked here because this is the thread that empties the queue, so the
                        // answer can only have changed as a result of the iteration just finished.
                        // A two-machine secondary never latches `emulation_done` locally, so this
                        // never fires there; its lane instead meets `drain` and `items` closing
                        // together when this thread exits, and by then there is nothing left to
                        // serve either way.
                        if drain_tx.is_some() && sched.chunk_feed_closed() {
                            drain_tx = None;
                        }
                        // Nothing to route yet: a shortage of input, so `Idle`.
                        let acquired = {
                            let _i = spans::idle(WorkKind::Dispatch);
                            let (acquired, proven_elsewhere) =
                                rt.block_on(mle_acquire_task_unified_async(dispatch_id, block_num));
                            // Drop prepared records for chunks somebody else already proved.
                            //
                            // Load-bearing under two-machine, not tidiness. Each machine emulates
                            // the whole block and stores every chunk, but proves only its share,
                            // and a pooled event buffer is released only when a worker finishes a
                            // chunk and drops its record. Without this the other machine's half is
                            // never dropped: the pool drains, `get_buffer` blocks, emulation stalls
                            // and stops registering, and both sides idle into the scheduler's 300s
                            // "system is broken" timeout. reth-239 stalled at 61 of 122 chunks
                            // against `MLE_EVENT_POOL_SIZE=64`. FRI does the same thing via
                            // `record_store::send_proven_chunks` on every acquire.
                            //
                            // A no-op in single-node: this machine already removed each chunk in
                            // `take_prepared_chunk` when it proved it.
                            for idx in &proven_elsewhere {
                                store.remove(idx);
                            }
                            acquired
                        };
                        match acquired {
                            MleAcquireResult::ChunkProof { chunk_idx } => {
                                // Blocking here means every card is saturated, not that one
                                // card's lane is full. Downstream capacity, so `Wait`, not `Idle`.
                                let _w = spans::wait(WorkKind::Dispatch, Some(chunk_idx as u32));
                                if items_tx.send(ProverItem::Riscv { chunk_idx }).is_err() {
                                    break;
                                }
                            }
                            // Combine tasks go to the preparer pool, not the prover: the
                            // prover only ever sees prepared nodes on the ready lane.
                            MleAcquireResult::Combine(task) => {
                                #[cfg(feature = "cuda")]
                                combine_task_tx
                                    .send(task)
                                    .expect("combine preparers hung up");
                                #[cfg(not(feature = "cuda"))]
                                {
                                    let _ = task;
                                    unreachable!(
                                        "CPU build: --step combine requires the `cuda` \
                                             feature"
                                    )
                                }
                            }
                            // The async path parks on a waiter; WaitForMore only leaks through
                            // on races. Back off a hair so a pathology cannot hot-spin.
                            MleAcquireResult::WaitForMore => {
                                thread::sleep(Duration::from_millis(1))
                            }
                            MleAcquireResult::Complete => break,
                        }
                    }
                    // items_tx drops here -> every prover knows the scheduler is drained.
                })
                .expect("spawn mle-dispatch"),
        );
    }

    let _vram = VramWatch::start(prover_count);

    // One pre-build pool for the whole process, shared by every card's riscv lane. Default ON:
    // `None` only when `MLE_CONVERT_PREBUILD` is set to an off-word or program sharing is off,
    // and then the lanes take the unhooked path (see [`ConvertPrebuild`]). Built here, after the
    // convert machines exist and before any riscv lane is handed out.
    #[cfg(feature = "cuda")]
    let convert_prebuild = (!converts.is_empty())
        .then(|| {
            ConvertPrebuild::new(
                converts.clone(),
                Arc::clone(&convert_card_rr),
                Arc::clone(&prebuilt_cards),
                // Past the preparer pool's own indices, so the two never share a lane.
                preparer_pool("convert", "MLE_CONVERT_PREPARERS", 12, prover_count),
            )
        })
        .flatten()
        .map(Arc::new);

    for k in 0..prover_count {
        // The riscv handles. Built per call site rather than once and moved, so that they and the
        // queue are handed out by the SAME conditional below: exactly one thread per card may hold
        // them, and it must be the one holding the queue. A lane with the queue and no handles
        // panics on its first chunk; a lane with the handles and no queue never releases the
        // `convert_tx` inside them, and the convert chain cannot drain (see [`RiscvLane`]).
        let riscv_lane = || RiscvLane {
            store: Arc::clone(&store),
            prover: Arc::clone(&provers[k]),
            convert_tx: convert_tx.clone(),
            prove_nanos: Arc::clone(&prove_nanos),
            prove_count: Arc::clone(&prove_count),
            verify,
            with_combine,
            #[cfg(feature = "cuda")]
            convert_prebuild: convert_prebuild.clone(),
        };

        // The default: riscv gets a thread of its own, told apart from the recursion lane by its
        // `Role` (the lane INDEX is the card, for both). Separate threads and not a wider
        // `select!`, because one thread can only be inside one prove at a time whatever it selects
        // on -- sharing the thread is exactly what kept a convert or combine node waiting behind
        // the chunk in front of it on the same card, and is what `MLE_RECURSION_LANE=0` goes back
        // to on the lane below.
        // One per card, shared: with the riscv lane joining the ready lanes once its feed is
        // drained, more than one thread proves this card's recursion work.
        #[cfg(feature = "cuda")]
        let card_rec = Arc::new(CardRecursion {
            convert: converts.get(k).cloned(),
            combine: combines.get(k).cloned(),
            root_slot: Arc::clone(&root_slot),
            convert_prove_nanos: Arc::clone(&convert_prove_nanos),
            convert_done: Arc::clone(&convert_done),
            combine_nanos: Arc::clone(&combine_nanos),
            combine_count: Arc::clone(&combine_count),
            verify,
            with_combine,
        });

        if rec_lane {
            // `Option`, and dropped the moment the feed closes: it owns this card's `convert_tx`
            // clone and this lane no longer ends there, so holding it would keep the convert
            // preparers' channel open past the last chunk and the final join would hang.
            let mut riscv = Some(riscv_lane());
            // Every card drains the one shared lane; the clone is this card's handle on it.
            let items = items_rx.clone();
            let drain = drain_rx.clone();
            #[cfg(feature = "cuda")]
            let rec = Arc::clone(&card_rec);
            // Held from the start although nothing is read from them until the drain: the arm
            // that attaches them runs inside the closure, so they have to be captured here. The
            // cost is that a live receiver keeps the preparers' `send` from erroring, so if the
            // recursion lane dies the preparer routed to this card blocks instead of panicking
            // with `prover hung up`. That diagnostic is not what reports a dead lane anyway --
            // the process-wide panic hook prints the real cause and exits first.
            let ready_src = convert_ready_rxs[k].clone();
            let combine_src = combine_ready_rxs[k].clone();
            // Role-labelled for the same reason as `dispatch_id` above.
            let worker_id = format!("{}-mle-prover-{k}", get_worker_label());
            workers.push(
                thread::Builder::new()
                    .name(worker_id.clone())
                    .spawn_watched(move || {
                        bind_prover_lane(k, Role::Prove);
                        let mut items = items;
                        let mut drain = drain;
                        // Not attached until the feed drains: while chunks can still arrive this
                        // lane's job is riscv alone, and a chunk queued behind a convert on its
                        // own card is exactly what splitting the lanes was for.
                        let mut ready = crossbeam::channel::never();
                        let mut combine_ready = crossbeam::channel::never();
                        let mut items_open = true;
                        let mut ready_open = false;
                        let mut combine_ready_open = false;
                        while items_open || ready_open || combine_ready_open {
                            // Nothing pushes to this slot, so it can only be idle for want of
                            // input, never blocked on capacity. Each arm's own `Busy` span splits
                            // this one.
                            let _i = spans::idle(WorkKind::Unattributed);
                            // Recursion only while no chunk is waiting. `select!` picks at random
                            // among ready arms, and when the feed drains there are still up to
                            // `prover_count` chunks on the lane -- the head of the tail's critical
                            // path, which must not lose a coin toss to a convert. Not
                            // `select_biased!`, which would also put convert ahead of combine, and
                            // that is a preference nobody has measured.
                            //
                            // The queue is shared by every card, so the chunk this saw may be
                            // taken by another lane; the retry is what stops that from parking
                            // this one on a queue that can never refill -- no chunk can arrive
                            // after the feed is drained, so it would sit out the whole tail.
                            let (rdy, comb, retry) = if items.is_empty() {
                                (
                                    ready.clone(),
                                    combine_ready.clone(),
                                    crossbeam::channel::never(),
                                )
                            } else {
                                (
                                    crossbeam::channel::never(),
                                    crossbeam::channel::never(),
                                    crossbeam::channel::after(Duration::from_millis(20)),
                                )
                            };
                            crossbeam::channel::select! {
                                recv(items) -> m => match m {
                                    // `items` and the handles travel together: the arm below
                                    // detaches the one as it drops the other, so a chunk cannot
                                    // arrive once they are gone.
                                    Ok(ProverItem::Riscv { chunk_idx }) => riscv
                                        .as_ref()
                                        .expect("a chunk arrived after the riscv handles went")
                                        .prove(chunk_idx, &worker_id),
                                    Err(_) => {
                                        items_open = false;
                                        items = crossbeam::channel::never();
                                        drain = crossbeam::channel::never();
                                        riscv = None;
                                    }
                                },
                                // Fires on close, the only thing that ever happens to it: the feed
                                // is finished, so start serving this card's recursion work.
                                // `items` stays attached -- chunks can still be on it when this
                                // arrives, so nothing may depend on the signal being exact.
                                recv(drain) -> _ => {
                                    drain = crossbeam::channel::never();
                                    ready = ready_src.clone();
                                    combine_ready = combine_src.clone();
                                    ready_open = true;
                                    combine_ready_open = true;
                                    info!("[{worker_id}] riscv feed drained: serving recursion");
                                },
                                recv(rdy) -> m => match m {
                                    Ok((chunk_idx, work)) => {
                                        #[cfg(feature = "cuda")]
                                        rec.prove_convert(chunk_idx, work, &worker_id);
                                        #[cfg(not(feature = "cuda"))]
                                        {
                                            let _ = chunk_idx;
                                            match work {}
                                        }
                                    }
                                    Err(_) => {
                                        ready_open = false;
                                        ready = crossbeam::channel::never();
                                    }
                                },
                                recv(comb) -> m => match m {
                                    Ok(work) => {
                                        #[cfg(feature = "cuda")]
                                        rec.prove_combine(work, &worker_id);
                                        #[cfg(not(feature = "cuda"))]
                                        {
                                            match work {}
                                        }
                                    }
                                    Err(_) => {
                                        combine_ready_open = false;
                                        combine_ready = crossbeam::channel::never();
                                    }
                                },
                                // Re-sample the queue; see above.
                                recv(retry) -> _ => {}
                            }
                        }
                    })
                    .expect("spawn mle-prover"),
            );
        }

        #[cfg(feature = "cuda")]
        let rec = Arc::clone(&card_rec);
        let convert_ready_rx = convert_ready_rxs[k].clone();
        let combine_ready_rx = combine_ready_rxs[k].clone();
        // The recursion lane by default; under `MLE_RECURSION_LANE=0` this is the card's ONLY
        // prover lane, and then it is the one that gets the riscv handles and the queue, making
        // its `select!` the pre-split three-armed loop exactly. One conditional for all of it, so
        // no two of these can disagree about which shape this lane is.
        //
        // The lane that does NOT serve riscv gets `never()` rather than a second clone of the real
        // receiver: a live receiver parked on a lane that never takes from it stops the
        // dispatcher's `send` from ever erroring, so if the riscv-serving lanes died it would
        // block on a full queue and the final join would hang.
        let (mut riscv, rec_items, role, worker_id, spawn_err) = if rec_lane {
            (
                None,
                crossbeam::channel::never(),
                Role::ProveRecursion,
                format!("{}-mle-prover-rec-{k}", get_worker_label()),
                "spawn mle-prover-rec",
            )
        } else {
            (
                Some(riscv_lane()),
                items_rx.clone(),
                Role::Prove,
                format!("{}-mle-prover-{k}", get_worker_label()),
                "spawn mle-prover",
            )
        };
        // What ends the run if this lane panics is the process-wide panic hook in
        // `bin/mle_single_node.rs`: it prints and exits, so the first panic is also the last line.
        //
        // The hook is load-bearing rather than a nicety, because the topology would report this
        // death in the wrong voice. This lane holds the only receivers for its card's convert and
        // combine ready lanes, so while prepares remain the next one routed to that card dies on
        // `.expect("prover hung up")` -- a preparer's panic, one stage downstream of the prover
        // that actually failed -- and once they are done the run instead hangs on the join with no
        // message at all. The hook is what keeps the real cause first in the log.
        workers.push(
            thread::Builder::new()
                .name(worker_id.clone())
                .spawn_watched(move || {
                    bind_prover_lane(k, role);
                    let mut items = rec_items;
                    let mut ready = convert_ready_rx;
                    let mut combine_ready = combine_ready_rx;
                    // Live only when this thread is the one serving riscv; otherwise `items` never
                    // fires and the flag would keep the loop from ever ending. The two travel
                    // together -- `riscv` is `Some` for exactly the lane that took the queue.
                    let mut items_open = riscv.is_some();
                    let mut ready_open = true;
                    let mut combine_ready_open = true;
                    while items_open || ready_open || combine_ready_open {
                        // Nothing pushes to this slot, so it can only be idle for want of input,
                        // never blocked on capacity. Each arm's own `Busy` span splits this one.
                        let _i = spans::idle(WorkKind::Unattributed);
                        crossbeam::channel::select! {
                            recv(items) -> m => match m {
                                Ok(ProverItem::Riscv { chunk_idx }) => riscv
                                    .as_ref()
                                    .expect("riscv work on a lane that does not serve riscv")
                                    .prove(chunk_idx, &worker_id),
                                Err(_) => {
                                    items_open = false;
                                    items = crossbeam::channel::never();
                                    // The scheduler is drained: no further riscv proofs can exist,
                                    // so release our convert feed and let that chain drain to a
                                    // close -- the ready lanes below are what we keep serving.
                                    riscv = None;
                                }
                            },
                            recv(ready) -> m => match m {
                                Ok((chunk_idx, work)) => {
                                    #[cfg(feature = "cuda")]
                                    rec.prove_convert(chunk_idx, work, &worker_id);
                                    #[cfg(not(feature = "cuda"))]
                                    {
                                        let _ = chunk_idx;
                                        match work {}
                                    }
                                }
                                Err(_) => {
                                    ready_open = false;
                                    ready = crossbeam::channel::never();
                                }
                            },
                            recv(combine_ready) -> m => match m {
                                Ok(work) => {
                                    #[cfg(feature = "cuda")]
                                    rec.prove_combine(work, &worker_id);
                                    #[cfg(not(feature = "cuda"))]
                                    {
                                        match work {}
                                    }
                                }
                                Err(_) => {
                                    combine_ready_open = false;
                                    combine_ready = crossbeam::channel::never();
                                }
                            },
                        }
                    }
                })
                .expect(spawn_err),
        );
    }
    // The provers hold their own clones; drop the originals so the convert chain can drain.
    // Same for the shared riscv queue, and there it is load-bearing rather than tidy: keeping a
    // receiver alive here leaves the channel connected after every riscv-serving lane has died, so
    // the dispatcher's blocking `send` waits forever on a full queue instead of erroring out. The
    // dispatcher is joined first, so that turns an all-lanes-dead panic into a silent hang.
    drop(items_rx);
    drop(convert_tx);
    drop(convert_ready_rxs);
    // Same for the combine chain: the dispatcher holds the live task sender (it drops it on
    // `Complete`), and the provers hold the live ready receivers.
    #[cfg(feature = "cuda")]
    drop(combine_task_tx);
    drop(combine_ready_rxs);

    let (emulate_wall, emulated_cycles, committed) = watch::join(emulate_handle, "emulate thread");
    vram_probe("emulate_joined", iteration.unwrap_or(0), prover_count);
    let (chunk_count, prepare_wall) = watch::join(preparer_handle, "preparer thread");
    vram_probe("after_preparer", iteration.unwrap_or(0), prover_count);
    info!(
        "MLE emulate done in {:.3}s, prepare in {:.3}s ({chunk_count} chunk(s))",
        emulate_wall.as_secs_f64(),
        prepare_wall.as_secs_f64(),
    );

    // Nothing to prove (degenerate empty program): the scheduler never completes with zero
    // chunks, so return without joining the workers — process exit reaps them.
    if chunk_count == 0 {
        info!("MLE single-node: no chunks emulated; nothing to prove");
        // The cycle count is real -- the emulator did run -- but there is no root. A caller that
        // has to report this block upstream must report it as unproved, and `root: None` is what
        // says so; handing back a default outcome here would also claim zero cycles.
        return BlockOutcome {
            cycles: emulated_cycles,
            committed,
            ..Default::default()
        };
    }

    // A single chunk cannot form a combine tree: `ProofTree` only pairs ADJACENT proofs, so a lone
    // proof never pairs, the tree never collapses, and the workers would poll forever — silently,
    // because the sync `acquire_task` returns `WaitForMore` rather than registering a waiter, so
    // there is no timeout to trip. Guard explicitly.
    //
    // Unreachable in practice: memory init/finalize events are deferred out of every CPU chunk
    // into their own record, so any real program emulates to >= 2 chunks. Kept because the failure
    // mode is a silent hang.
    assert!(
        !with_combine || chunk_count >= 2,
        "--step combine needs >= 2 chunks, got {chunk_count} \
         (a lone proof has no adjacent neighbour, so the tree never collapses)"
    );

    for h in workers {
        watch::join(h, "worker thread");
    }
    vram_probe("after_workers", iteration.unwrap_or(0), prover_count);
    // Every proof exists: each lane only exits once its own feeds are closed, so joining the
    // workers drains riscv, convert and combine alike.
    let prove_wall = t_prove.elapsed();

    // Cross-chunk memory consistency: each machine accumulates only its own chunks' terms, and
    // only the sum over ALL of them closes to zero — across cards, and under two-machine across
    // processes too. So the secondary ships its partial and the primary closes the sum.
    //
    // Summing partial sums is sound rather than merely convenient: `SepticDigest`'s `Sum` folds
    // each element as `(x - Z)` and adds a single `Z` back at the end, so
    // `sum([sum(a), sum(b)]) == sum(a ++ b)`. It is NOT plain addition — there is no `Add` impl —
    // which is why this collects into one iterator and sums once instead of accumulating pairwise.
    {
        let local = RiscvMachine::drain_cross_chunk_gcs_over(provers.iter().map(|p| p.as_ref()));
        if is_mle_secondary() {
            let bytes =
                bincode::serialize(&local).expect("serialising a septic digest cannot fail");
            info!(
                "secondary reporting its partial GCS digest ({} bytes)",
                bytes.len()
            );
            mle_report_gcs_digest(&get_worker_label(), bytes);
        } else {
            // Wait for the other machine(s) before reducing. The primary reaches this point as soon
            // as its own half is done, which is typically BEFORE the secondary has finished proving
            // and sent its partial — closing the sum then reduces over half the run and reports a
            // memory inconsistency that is not one.
            let expected = expected_remote_digests();
            if !crate::common::gcs_digest::wait_for_remote_digests(
                expected,
                Duration::from_secs(600),
            ) {
                panic!(
                    "timed out waiting for {expected} remote GCS digest(s); got {}. The sum cannot \
                     be closed without them, and closing it anyway would report a memory \
                     inconsistency that is really a missing report.",
                    crate::common::gcs_digest::remote_digest_count()
                );
            }
            let remote = take_remote_digests();
            let n_remote = remote.len();
            let mut parts = Vec::with_capacity(n_remote + 1);
            parts.push(local);
            for r in remote {
                parts.push(bincode::deserialize(&r.digest).unwrap_or_else(|e| {
                    panic!(
                        "partial GCS digest from {} did not deserialise: {e}",
                        r.worker_id
                    )
                }));
            }
            let total: SepticDigest<KoalaBear> = parts.into_iter().sum();
            assert!(
                total.is_zero(),
                "cross-chunk global cumulative sum is not zero (memory inconsistency); \
                 reduced this machine plus {n_remote} remote partial(s)"
            );
            info!("cross-chunk global cumulative sum == 0 ✓ ({n_remote} remote partial(s))");
        }
    }

    // The pre-build pool is speculative and unjoined by the channel alone — its `tx` lives in the
    // riscv lanes' hooks — so it is stopped here, before the resident machines serve another block.
    #[cfg(feature = "cuda")]
    if let Some(pb) = convert_prebuild.as_ref() {
        pb.shutdown();
    }

    // Convert stage drain: the workers' exits dropped the last `convert_tx` senders, so the
    // preparer/prover pools run dry and exit; joining them means every convert proof is done.
    #[cfg(feature = "cuda")]
    if !converts.is_empty() {
        for h in convert_stage {
            watch::join(h, "convert stage thread");
        }
        let done = convert_done.load(Ordering::SeqCst);
        // Single-node proves every chunk it emulated, so convert count == chunk count. Under
        // two-machine each side emulates the WHOLE block but proves only its share, so
        // the equality is the wrong invariant there — the secondary emulated 8 and converted 4, and
        // this assert fired on an otherwise correct run. What still holds on both is that every
        // chunk this machine proved got converted.
        if is_mle_secondary() || mle_two_machine_requested() {
            assert!(
                done <= chunk_count,
                "convert proofs ({done}) exceed the {chunk_count} chunks emulated"
            );
        } else {
            assert_eq!(
                done, chunk_count,
                "convert proofs ({done}) != riscv chunks ({chunk_count})"
            );
        }
        let convert_total = Duration::from_nanos(convert_prove_nanos.load(Ordering::SeqCst));
        let convert_note = if verify {
            "proved + verified"
        } else {
            "proved (verify skipped; set MLE_VERIFY=1 to enable)"
        };
        info!(
            "MLE convert complete: all {done} convert proof(s) {convert_note} ✓ | sum(convert)={:.3}s avg/chunk={:.3}s",
            convert_total.as_secs_f64(),
            convert_total.as_secs_f64() / (done.max(1) as f64),
        );
    }

    vram_probe("after_convert_report", iteration.unwrap_or(0), prover_count);
    // Combine preparer drain: the dispatcher's exit dropped the last task sender, so the pool
    // runs dry and exits; joining it propagates any preparer panic. An arity-2 reduction of N
    // leaves has exactly N-1 internal nodes, so the count check doubles as an engagement check —
    // a dead ready lane could not have produced them.
    #[cfg(feature = "cuda")]
    if !combines.is_empty() {
        for h in combine_stage {
            watch::join(h, "combine preparer thread");
        }
        let nodes = combine_count.load(Ordering::SeqCst);
        // A binary tree over N chunks has N-1 internal nodes, and single-node proves all of them.
        // Under two-machine the tree is one tree but its nodes are split across the machines --
        // measured 4 + 3 = 7 for an 8-chunk block -- so the per-machine count is a share, not the
        // total. Asserting equality locally failed on BOTH sides of a run whose tree was in fact
        // complete. The whole-run count is checked where it can be: the scheduler only reports the
        // run complete once its proof tree is (`is_proof_tree_complete`).
        if mle_two_machine_requested() {
            assert!(
                nodes < chunk_count,
                "combine nodes proved ({nodes}) exceeds the {} a {chunk_count}-chunk tree has",
                chunk_count - 1
            );
        } else {
            assert_eq!(
                nodes,
                chunk_count - 1,
                "combine nodes proved ({nodes}) != chunks - 1 ({})",
                chunk_count - 1
            );
        }
    }

    vram_probe("after_combine_check", iteration.unwrap_or(0), prover_count);
    // Window ends here: every proof exists and every stage has joined. Root acceptance below is CPU
    // work on a lane-less thread, so leaving it inside made the window outlast every lane and read as
    // device idleness.
    let e2e_wall = t_e2e.elapsed();
    // Starts where the window ended, so the two meet exactly and leave no unattributed sliver.
    #[cfg(feature = "cuda")]
    let t_accept = Instant::now();
    // Set at the end of the acceptance block; stays zero when there is none to do.
    #[cfg_attr(not(feature = "cuda"), allow(unused_mut))]
    let mut root_accept = Duration::ZERO;
    // Filled in the acceptance block below, i.e. only once the root has passed host-side
    // acceptance. A root this process has not itself verified must never reach a submission.
    #[cfg_attr(not(feature = "cuda"), allow(unused_mut))]
    let mut root_export: Option<RootProofExport> = None;

    // Combine stage: the tree collapsed (that is what let the workers exit), so the root is in the
    // slot. Acceptance runs on the CPU `CombineMachine` — deliberately, so the four-step host-side
    // check (honest-vk substitution, `flag_complete`, the exe anchor, PV-digest recompute) exists
    // in exactly one place instead of being transcribed onto the GPU machine. `register_shape`
    // first: `verify` checks against a VK this machine keygen'd itself, never the supplied one, so
    // the root's shape has to exist here (its documented CONTRACT). Rebuilding the root program
    // from the child layouts also catches a GPU-side program built with the wrong parameters —
    // a mismatch shows up as no matching complete shape.
    // The secondary never holds the root: `try_acquire_combine_task` refuses the final combine to
    // any non-leader worker, so the root is proved AND accepted on the primary by construction.
    // Without this guard the secondary would die on the `expect` below at the end of an otherwise
    // successful run — its slot is empty by design, not by failure.
    #[cfg(feature = "cuda")]
    if !combines.is_empty() && is_mle_secondary() {
        info!("secondary: run complete; the root is proved and accepted on the primary");
    }
    #[cfg(feature = "cuda")]
    if !combines.is_empty() && !is_mle_secondary() {
        let root = root_slot
            .lock()
            .expect("root slot mutex poisoned")
            .take()
            .expect("scheduler reported complete but no final combine node was recorded");
        let nodes = combine_count.load(Ordering::SeqCst);
        let combine_total = Duration::from_nanos(combine_nanos.load(Ordering::SeqCst));

        let t_verify = Instant::now();
        let vm_vk = riscv_vm_vk
            .clone()
            .expect("combine implies convert, which builds the exe identity");
        let mut cpu_combine = pico_vm::mle::machine::combine::CombineMachine::new(
            pico_vm::mle::recursion_params_with_100_bits_security(),
            vm_vk,
            vk_map.is_some(),
        );
        if let Some(map) = &vk_map {
            cpu_combine.set_vk_map(Arc::clone(map));
        }
        cpu_combine
            .register_shape(&root.child_layouts, /* is_complete = */ true)
            .unwrap_or_else(|e| panic!("{e}"));
        cpu_combine
            .verify(&root.proof)
            .expect("combine ROOT proof failed host-side acceptance");
        // Whitelist mode: the standalone apex re-accepts the root from artifacts only, against
        // the deployment's pinned root (`MLE_VK_ROOT`, else the artifact's own).
        if let Some(apex) = &apex {
            apex.verify(&root.proof)
                .expect("standalone apex verify failed");
            info!("standalone apex verify ✓");
        }
        // Asserted before the success line so a miscount cannot be preceded by a ✓.
        //
        // Per-machine under two-machine, for the same reason as the count above: the tree is one
        // tree but its nodes are shared out, so this machine proving fewer than `chunk_count - 1`
        // is the expected case, not a miscount. The root it just accepted is the whole tree's root
        // regardless — that is what `verify` above checks.
        if mle_two_machine_requested() {
            assert!(
                nodes < chunk_count,
                "combine nodes proved ({nodes}) exceeds the {} a {chunk_count}-leaf tree has",
                chunk_count - 1
            );
        } else {
            assert_eq!(
                nodes,
                chunk_count - 1,
                "a binary tree over {chunk_count} leaves has {} internal nodes, but {nodes} were proved",
                chunk_count - 1
            );
        }
        info!(
            "MLE combine complete: {nodes} node(s), root proved + verified ✓ \
             (n-1 expected for {chunk_count} chunks) | sum(combine)={:.3}s | verify={:.3}s",
            combine_total.as_secs_f64(),
            t_verify.elapsed().as_secs_f64(),
        );
        // What this run actually produced, in wire bytes, attributed per protocol part. Shared
        // with the CPU e2e example so the field list exists in one place; the number is
        // shape-dependent, so the CPU example's fib figure does not stand in for this one.
        pico_vm::mle::machine::recursion::log_proof_size("MLE combine root", &root.proof.0);

        // Package the root for whoever has to verify it elsewhere. Built here rather than at the
        // end of the function because `root` is moved-from by then, and built only on this side of
        // `verify` above so that what we hand out is what we ourselves accepted.
        // Whitelist mode ships the root's vk with the proof (see `RootProofExport::root_vk`).
        let root_vk = vk_map
            .as_ref()
            .map(|_| bincode::serialize(&*root.proof.1))
            .transpose();
        match (
            pico_vm::mle::machine::recursion::proof_wire_bytes(&root.proof.0),
            root_vk,
        ) {
            (Ok(bytes), Ok(root_vk)) => {
                root_export = Some(RootProofExport {
                    proof: bytes,
                    child_layouts: root.child_layouts.clone(),
                    riscv_vk_digest: riscv_vm_vk
                        .as_ref()
                        .expect("combine implies convert, which builds the exe identity")
                        .digest_hex(),
                    root_vk,
                });
            }
            // A run that has already produced a verified root must not die because the export
            // failed; the caller sees `root: None` and reports the block as unproved.
            (Err(e), _) => {
                tracing::warn!("MLE combine root: wire encode failed, not exported: {e:?}")
            }
            (_, Err(e)) => {
                tracing::warn!("MLE combine root: vk encode failed, not exported: {e:?}")
            }
        }

        // Shape summary: the sentinel for tree-shape jitter. The tree shape is a function of the
        // order convert proofs arrive in, and it decides which `(child layouts, is_complete)`
        // combinations occur — hence how many (expensive) keygens the run pays. That swing hides
        // inside the end-to-end figure, so it needs its own line. Counts and format both come
        // from `ShapeStats` so they cannot drift from what the machine actually recorded. One
        // line per card — each machine records only the nodes it proved.
        // Differenced against the block-start baseline, not read raw: the machines are resident, so
        // the raw figures are cumulative over every block this process has proved while `nodes` is
        // this block's alone. See `shape_baseline`.
        let mut shape_nodes = 0usize;
        let (mut blk_keygens, mut blk_hits, mut blk_evictions) = (0usize, 0usize, 0usize);
        for (card, machine) in combines.iter().enumerate() {
            let shapes = machine.shape_stats();
            let (base_k, base_h, base_e) = shape_baseline[card];
            let (dk, dh, de) = (
                shapes.keygens - base_k,
                shapes.hits - base_h,
                shapes.evictions - base_e,
            );
            shape_nodes += dk + dh;
            blk_keygens += dk;
            blk_hits += dh;
            blk_evictions += de;
            info!(
                target: "bench",
                "[bench] MLE combine shapes (card {card}): this block keygens={dk} hits={dh} \
                 evictions={de} | resident total {shapes}"
            );
        }
        info!(
            target: "bench",
            "[bench] MLE combine shapes: block keygens={blk_keygens} hits={blk_hits} evictions={blk_evictions}"
        );
        assert_eq!(
            shape_nodes, nodes,
            "every node either keygens a shape or hits a cached one"
        );
        // The whole block, not just `verify`: the root shape's CPU keygen inside `register_shape`, the
        // slot take and the two summary lines are on the same thread and outside the window just as
        // much. `t_verify` stays what the `verify=` field has always meant.
        root_accept = t_accept.elapsed();
    }

    // --- Benchmark report (throughput + end-to-end). ---
    let n = prove_count.load(Ordering::SeqCst);
    let sum_prove = Duration::from_nanos(prove_nanos.load(Ordering::SeqCst));
    let avg = sum_prove.as_secs_f64() / (n.max(1) as f64);
    let total = t_total.elapsed();
    let verified_note = if verify {
        "proved + per-chunk verified"
    } else {
        "proved (per-chunk verify skipped; set MLE_VERIFY=1 to enable)"
    };
    info!("MLE single-node: all {n} chunk(s) {verified_note}; cross-chunk GCS == 0 ✓");
    info!(
        // `e2e` excludes setup and root acceptance; `total` is the whole process. Keep each variable
        // named for the field it prints — the pair these replaced denoted each other's meaning.
        // `bench-scripts/sweep-csv.py` matches this line whole, so a field added or moved here
        // empties every timing column it extracts — on rows that still read rc=0.
        "MLE bench: chunks={n} prover_count={prover_count} lanes={lanes_per_card} | sum(prove)={:.3}s avg/chunk={:.3}s | prove(wall)={:.3}s | keygen={:.3}s | emulate={:.3}s cycles={emulated_cycles} prepare={:.3}s | e2e={:.3}s | root-accept={:.3}s | total={:.3}s",
        sum_prove.as_secs_f64(),
        avg,
        prove_wall.as_secs_f64(),
        keygen_wall.as_secs_f64(),
        emulate_wall.as_secs_f64(),
        prepare_wall.as_secs_f64(),
        e2e_wall.as_secs_f64(),
        root_accept.as_secs_f64(),
        total.as_secs_f64(),
    );
    // Where that window went, lane by lane — on its own lines, since the headline's field names are
    // what the harness extracts. The combine keygen total rides along to be cross-checked.
    #[cfg(feature = "cuda")]
    let combine_keygen_ms = (!combines.is_empty()).then(|| {
        combines
            .iter()
            .map(|m| m.shape_stats().keygen_total_ms)
            .sum::<u128>()
    });
    #[cfg(not(feature = "cuda"))]
    let combine_keygen_ms: Option<u128> = None;
    report_spans(e2e_wall, combine_keygen_ms, iteration);

    // Its own line rather than a field on the headline, whose field names benchmarks parse.
    // Absent in single-node: printing `0 MiB` there would invite comparing it against a
    // two-machine run's real figure as though the two measured the same thing.
    if let Some(line) = crate::common::transfer_stats::summary_line() {
        info!(target: "bench", "{line}");
    }
    vram_probe("exit", iteration.unwrap_or(0), prover_count);

    BlockOutcome {
        cycles: emulated_cycles,
        e2e_wall,
        root_accept,
        root: root_export,
        committed,
    }
}

/// The strip's label column, shared with the report layer via the strip's own header line so the two
/// cannot drift apart.
const STRIP_LABEL_WIDTH: usize = 14;

/// Emit the span-derived report, and the raw spans when `MLE_SPANS` names a path.
///
/// `window` is what every share is taken against — the headline's `e2e=`, which excludes setup.
/// `combine_keygen_ms` is the combine machines' own figure, cross-checked below against the spans'.
/// `iteration` names the `MLE_REPEAT` pass in the exported CSV's file name, and is `None` for a
/// single run, which keeps writing exactly the path it was given.
fn report_spans(window: Duration, combine_keygen_ms: Option<u128>, iteration: Option<usize>) {
    use pico_vm::mle::spans::report as rep;

    let recorded = spans::snapshot();
    if recorded.is_empty() {
        return; // nothing bound a lane: a CPU build, or a path that never reached the pipeline
    }
    let window_us = window.as_micros() as u64;

    // Validated before anything is derived from it. Every figure below is cross-lane, so a single
    // lane whose spans overlap leaves all of them untrustworthy rather than merely incomplete —
    // publishing the survivors would mean publishing plausible wrong numbers.
    let gaps = match spans::validate(&recorded) {
        Ok(g) => g,
        Err(v) => {
            tracing::warn!(
                "MLE spans: lane invariant violated ({v:?}) — per-lane figures withheld for this run"
            );
            return;
        }
    };

    let roles = rep::by_role(&recorded);
    for s in &roles {
        let occ = s
            .occ()
            .map(|o| format!("{:.1}%", o * 100.0))
            .unwrap_or_else(|| "n/a".into());
        // `idle` includes `wait`; the two are printed together because they are one quantity and its
        // contended part, and separating them into unrelated fields invites adding them up.
        info!(
            target: "bench",
            // `lane_time` is `occ`'s denominator and is not derivable from the other fields; it also
            // makes the lane's gap readable as `lane_time - busy - idle`.
            "MLE lane: {}x{} busy={:.3}s idle={:.3}s (wait={:.3}s) wall={:.3}s lane_time={:.3}s occ={occ}",
            s.role.as_str(),
            s.lanes,
            s.busy_us as f64 / 1e6,
            s.idle_us as f64 / 1e6,
            s.wait_us as f64 / 1e6,
            s.wall_us as f64 / 1e6,
            s.lane_time_us as f64 / 1e6,
        );
        if s.busy_by_work.len() > 1 {
            // The recursion lane, the emulate workers, and any preparer that took a keygen miss:
            // a pool taking several kinds of work in turn, where the split is the only way to see
            // one kind crowding out another (prove-convert against prove-combine; a batch's replay
            // against the recover before it; a keygen against the prepare it blocked).
            let parts: Vec<String> = s
                .busy_by_work
                .iter()
                .map(|(k, v)| format!("{k}={:.3}s", *v as f64 / 1e6))
                .collect();
            info!(target: "bench", "MLE lane: {} busy split: {}", s.role.as_str(), parts.join(" "));
        }
    }

    let gpu = rep::gpu_lane_figures(&recorded, window_us);
    let buckets: Vec<String> = (0..gpu.buckets.len())
        .map(|k| format!("k{k}={:.1}%", gpu.share(k) * 100.0))
        .collect();
    // Named for what it measures: lanes, not hardware. A lane counts as working while its thread is
    // inside GPU-related work, which is not the same as the device having kernels in flight.
    info!(
        target: "bench",
        "MLE gpu-lanes: dead={:.3}s ({:.1}% of window) concurrency {}",
        gpu.dead_us() as f64 / 1e6,
        gpu.share(0) * 100.0,
        buckets.join(" "),
    );

    // A fixed cell duration rather than window/N, so two runs' strips share a scale without either
    // having to know the other's window: identical cells mean columns correspond, and the shorter
    // run simply produces fewer of them, which is the difference made visible.
    let cell_ms = std::env::var("MLE_STRIP_CELL_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(350)
        .max(1);
    let cell_us = cell_ms * 1000;
    // Rounded up, so the last cell exists even when it is only partly inside the window; a strip that
    // stopped short would understate exactly the tail this is meant to show.
    let cells = window_us.div_ceil(cell_us).max(1) as usize;
    // `label_width` is stated rather than left implicit: the report layer blanks the label column of
    // the second arm's rows to pair them up, and it should read the width from here instead of both
    // sides hardcoding the same number and drifting apart.
    info!(
        target: "bench",
        "MLE strip: 1 cell = {cell_ms} ms, {cells} cells, window {:.3}s, label_width={} · {}",
        window_us as f64 / 1e6,
        STRIP_LABEL_WIDTH,
        rep::LEGEND,
    );
    info!(
        target: "bench",
        "MLE strip: a cell spans about one prove, so the strip shows occupancy and the mix of work \
         over time — not individual proves, and not a change of a few percent"
    );
    for row in rep::strip(&recorded, cell_us, cells, window_us) {
        let occ = row
            .occ
            .map(|o| format!("{:>3.0}%", o * 100.0))
            .unwrap_or_else(|| "    ".into());
        info!(
            target: "bench",
            "MLE strip: {:<width$}{occ} {}",
            row.label,
            row.cells,
            width = STRIP_LABEL_WIDTH,
        );
    }

    // Two independent measurements of the combine keygen total: the spans recorded on the combine
    // preparers, and what the combine machines report for themselves. They should agree; a mismatch
    // means a missed close or a keygen call site nobody bracketed, and it has no other symptom.
    if let Some(reported_ms) = combine_keygen_ms {
        let from_spans_ms =
            rep::keygen_us_on(&recorded, spans::Role::CombinePreparer) as f64 / 1000.0;
        // The two clocks start one statement apart, so exact equality is not the claim. 5 % or 10 ms,
        // whichever is larger, is far below any real discrepancy and far above the framing cost.
        let tol = (reported_ms as f64 * 0.05).max(10.0);
        if (from_spans_ms - reported_ms as f64).abs() > tol {
            tracing::warn!(
                "MLE spans: combine keygen disagrees — {:.3}s from spans against {:.3}s reported by \
                 the machine; a keygen call site is unbracketed or a span was left open",
                from_spans_ms / 1000.0,
                reported_ms as f64 / 1000.0,
            );
        } else {
            info!(
                target: "bench",
                "MLE spans: combine keygen cross-check ok ({:.3}s spans vs {:.3}s reported)",
                from_spans_ms / 1000.0,
                reported_ms as f64 / 1000.0,
            );
        }
    }

    // Unaccounted time inside a lane's life means a blocking call nobody bracketed. Small totals are
    // the loop overhead between one span closing and the next opening.
    for (lane, gap, frac) in gaps.significant(&rep::lane_lifetimes(&recorded), 0.05) {
        tracing::warn!(
            "MLE spans: lane {lane} has {:.3}s ({:.1}%) of unbracketed time — a blocking call is \
             missing instrumentation",
            gap as f64 / 1e6,
            frac * 100.0,
        );
    }

    if let Ok(path) = std::env::var("MLE_SPANS") {
        let path = match iteration {
            Some(n) => spans::csv_path_for_iteration(&path, n),
            None => path,
        };
        match spans::export_csv(&path, &recorded) {
            Ok(_) => info!("MLE spans: {} span(s) written to {path}", recorded.len()),
            Err(e) => tracing::warn!("MLE spans: could not write {path}: {e}"),
        }
    }
}
