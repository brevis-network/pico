use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Machine role in the two-machine distributed proof system
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum MachineRole {
    /// Primary machine: handles task units n=0,2,4...
    /// Receives sub_final_combine_proof from Secondary
    #[default]
    Primary,
    /// Secondary machine: handles task units n=1,3,5...
    /// Sends sub_final_combine_proof to Primary after completion
    Secondary,
}

impl FromStr for MachineRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "primary" | "0" => Ok(MachineRole::Primary),
            "secondary" | "1" => Ok(MachineRole::Secondary),
            _ => Err(format!(
                "Invalid machine role: {}. Expected 'primary' or 'secondary'",
                s
            )),
        }
    }
}

impl std::fmt::Display for MachineRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MachineRole::Primary => write!(f, "Primary"),
            MachineRole::Secondary => write!(f, "Secondary"),
        }
    }
}

/// Runtime mode derived from USECASE (+ optional MACHINE_ROLE fallback).
/// This is the scheduler-facing source of truth for deployment topology.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RuntimeMode {
    /// One-node deployment. A single scheduler/worker pool handles all chunks.
    #[default]
    SingleNode,
    /// Two-machine deployment, this process is Primary.
    TwoMachinePrimary,
    /// Two-machine deployment, this process is Secondary.
    TwoMachineSecondary,
}

impl RuntimeMode {
    pub fn is_single_node(&self) -> bool {
        matches!(self, RuntimeMode::SingleNode)
    }

    pub fn is_two_machine_secondary(&self) -> bool {
        matches!(self, RuntimeMode::TwoMachineSecondary)
    }

    /// Whether this process should acquire from local scheduler directly.
    /// Secondary must use scheduler_service client.
    pub fn uses_local_scheduler(&self) -> bool {
        !self.is_two_machine_secondary()
    }

    /// Parse scheduler topology labels from env or mode defaults.
    pub fn topology(&self) -> SchedulerTopology {
        SchedulerTopology::from_env_or_mode(*self)
    }

    /// Whether this worker is topology leader (index 0).
    pub fn is_leader_worker(&self, worker_id: &str) -> bool {
        self.topology().worker_index_for_id(worker_id) == 0
    }

    /// Whether this runtime mode should execute full trace for a chunk.
    pub fn should_full_trace_chunk(&self, chunk_idx: usize) -> bool {
        match self {
            RuntimeMode::SingleNode => true,
            RuntimeMode::TwoMachinePrimary => MachineRole::Primary.should_handle_chunk(chunk_idx),
            RuntimeMode::TwoMachineSecondary => {
                MachineRole::Secondary.should_handle_chunk(chunk_idx)
            }
        }
    }

    /// Chunk scheduling permission for pull-based workers.
    pub fn worker_can_handle_chunk_for_worker(&self, worker_id: &str, chunk_idx: usize) -> bool {
        let topology = self.topology();
        let worker_idx = topology.worker_index_for_id(worker_id);
        self.worker_can_handle_chunk_by_index(worker_idx, topology.worker_count(), chunk_idx)
    }

    /// Chunk scheduling permission using worker index in topology.
    pub fn worker_can_handle_chunk_by_index(
        &self,
        worker_idx: usize,
        worker_count: usize,
        chunk_idx: usize,
    ) -> bool {
        match self {
            RuntimeMode::SingleNode => true,
            RuntimeMode::TwoMachinePrimary | RuntimeMode::TwoMachineSecondary => {
                if chunk_idx >= dynamic_chunk_start() {
                    return true;
                }

                if worker_count <= 1 {
                    return true;
                }

                if worker_count == 2 {
                    if worker_idx == 0 {
                        MachineRole::Primary.can_handle_chunk(chunk_idx)
                    } else {
                        MachineRole::Secondary.can_handle_chunk(chunk_idx)
                    }
                } else {
                    // For N-worker topology, keep static chunks [0, dynamic_chunk_start())
                    // in deterministic round-robin assignment. Dynamic chunks are shared.
                    chunk_idx % worker_count == worker_idx
                }
            }
        }
    }
}

impl std::fmt::Display for RuntimeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimeMode::SingleNode => write!(f, "single-node"),
            RuntimeMode::TwoMachinePrimary => write!(f, "two-machine-primary"),
            RuntimeMode::TwoMachineSecondary => write!(f, "two-machine-secondary"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerTopology {
    workers: Vec<String>,
}

impl SchedulerTopology {
    pub fn from_env_or_mode(mode: RuntimeMode) -> Self {
        let workers = parse_scheduler_workers_env();
        if !workers.is_empty() {
            return Self { workers };
        }

        let defaults = match mode {
            RuntimeMode::SingleNode => vec![get_worker_label()],
            RuntimeMode::TwoMachinePrimary | RuntimeMode::TwoMachineSecondary => {
                vec!["primary".to_string(), "secondary".to_string()]
            }
        };

        Self { workers: defaults }
    }

    pub fn worker_count(&self) -> usize {
        self.workers.len().max(1)
    }

    pub fn worker_index_for_id(&self, worker_id: &str) -> usize {
        self.workers
            .iter()
            .position(|label| worker_id.contains(label))
            .unwrap_or(0)
    }
}

fn parse_scheduler_workers_env() -> Vec<String> {
    let raw = std::env::var("SCHED_WORKERS")
        .or_else(|_| std::env::var("SCHEDULER_WORKERS"))
        .unwrap_or_default();

    raw.replace([',', ';'], " ")
        .split_whitespace()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

// ============================================================================
// Chunk Assignment Configuration (compile-time feature selection)
// ============================================================================
// Default (one-round): Primary 0-7, Secondary 8-15, Dynamic 16+
// With `two-round-chunks`: Primary 0-7,16-23; Secondary 8-15,24-31; Dynamic 32+

/// Chunks each machine reserves per round, and the top of the static region. Runtime-resolved
/// rather than `const` because the right values depend on the workload, and the two stacks that
/// share this code have workloads an order of magnitude apart in chunk count:
///
/// - FRI @2^22 gives reth-188 21 chunks, which 8/16 splits into 16 static + 5 dynamic. Calibrated,
///   and unchanged here: the defaults are exactly the old constants.
/// - **MLE @2^23 gives reth-188 only 8 chunks — all inside the primary's reserved `0..8`, so the
///   secondary gets nothing at all**. Two-machine MLE is meaningless without this.
///
/// `CHUNKS_PER_ROUND` / `DYNAMIC_CHUNK_START` override both. See `mle_chunk_assignment_defaults`
/// for what MLE asks for and why.
const DEFAULT_CHUNKS_PER_ROUND: usize = 8;
#[cfg(feature = "two-round-chunks")]
const DEFAULT_DYNAMIC_CHUNK_START: usize = 32;
#[cfg(not(feature = "two-round-chunks"))]
const DEFAULT_DYNAMIC_CHUNK_START: usize = 16;

fn env_usize(key: &str, default: usize) -> usize {
    match std::env::var(key) {
        Ok(v) => match v.trim().parse::<usize>() {
            // A zero round size would make every chunk primary-reserved (integer division by zero
            // aside), which is the failure this exists to prevent -- refuse it loudly.
            Ok(n) if n > 0 => n,
            _ => panic!("{key}={v:?} is not a positive integer"),
        },
        Err(_) => default,
    }
}

/// Read once: these are consulted per chunk on the emulation path, and the values must not change
/// mid-run or the two machines would disagree about who owns what.
pub fn chunks_per_round() -> usize {
    static V: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *V.get_or_init(|| env_usize("CHUNKS_PER_ROUND", DEFAULT_CHUNKS_PER_ROUND))
}

/// Chunk-assignment defaults for MLE, applied before anything reads the two getters above.
///
/// MLE @2^23 produces roughly an order of magnitude fewer, much larger chunks than FRI @2^22, so
/// FRI's 8/16 leaves an 8-chunk block entirely inside the primary's reserved range. Rounds of 4
/// with the static region ending at 8 split that block evenly -- primary `0-3`, secondary `4-7` --
/// which is the smallest change that makes two-machine MLE mean anything.
///
/// Explicit env still wins, because this is a default and not a second nail: the whole point of
/// making these runtime values is that the right split is workload-dependent.
///
/// **Larger blocks fall into the dynamic region and are therefore full-traced by BOTH machines**
/// (that is what `should_handle_chunk` returning `true` above `dynamic_chunk_start()` means). For
/// reth-239's 122 chunks that is most of the block, so the redundant tracing is real and is exactly
/// the "double emulator" cost of the two-machine shape. Whether to widen the static region for
/// big blocks is a tuning question for measurements, not a guess here.
pub fn set_mle_chunk_assignment_defaults() {
    if std::env::var("CHUNKS_PER_ROUND").is_err() {
        std::env::set_var("CHUNKS_PER_ROUND", "4");
    }
    if std::env::var("DYNAMIC_CHUNK_START").is_err() {
        // Effectively "no dynamic region": the round alternation covers the whole block.
        //
        // This was 8, chosen so an 8-chunk reth-188 split 4/4. On any larger block that leaves
        // ~92% of chunks dynamic, and dynamic is first-come-first-served — which structurally
        // favours the primary, because it registers chunks locally and its dispatcher takes them
        // with no network hop while the secondary needs a gRPC round trip.
        //
        // Measured on two real machines, 95 chunks: the secondary won **0 of 87** dynamic chunks
        // and proved exactly 4,5,6,7 — its static allocation and nothing else. 91 vs 4.
        //
        // Alternating over the whole block instead gives a deterministic ~50/50 split at any size.
        // The cost is that a straggler cannot be helped: a machine that stalls strands its own
        // chunks rather than having them stolen. That is a real trade, taken because the dynamic
        // region was not providing balance — it was providing starvation. FRI sits between the two
        // (16 of 21 chunks static), which is closer to this end than to the old default.
        std::env::set_var("DYNAMIC_CHUNK_START", usize::MAX.to_string());
    }
}

pub fn dynamic_chunk_start() -> usize {
    static V: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *V.get_or_init(|| env_usize("DYNAMIC_CHUNK_START", DEFAULT_DYNAMIC_CHUNK_START))
}

impl MachineRole {
    /// Which role owns a chunk in the static region: rounds of `chunks_per_round()` alternate,
    /// primary first.
    ///
    /// This one formula replaces the two `#[cfg(feature = "two-round-chunks")]` pairs it grew out
    /// of, which were the same alternation written out by hand for one and two rounds -- at
    /// `R = 8` it reproduces both exactly (`0-7` primary, `8-15` secondary, and with the feature on,
    /// `16-23` primary, `24-31` secondary). The feature now only moves `DYNAMIC_CHUNK_START`.
    /// Pure form, so the split can be tested at several configurations in one process. The getters
    /// are `OnceLock`-cached (deliberately -- the values must not move mid-run), which makes any
    /// env-driven test order-dependent.
    pub(crate) fn is_primary_reserved_with(chunk_idx: usize, round: usize, dynamic: usize) -> bool {
        chunk_idx < dynamic && (chunk_idx / round).is_multiple_of(2)
    }

    fn is_primary_reserved(chunk_idx: usize) -> bool {
        Self::is_primary_reserved_with(chunk_idx, chunks_per_round(), dynamic_chunk_start())
    }

    fn is_secondary_reserved(chunk_idx: usize) -> bool {
        chunk_idx < dynamic_chunk_start() && !Self::is_primary_reserved(chunk_idx)
    }

    /// Check if this machine should handle the given chunk index during emulation.
    pub fn should_handle_chunk(&self, chunk_idx: usize) -> bool {
        if chunk_idx >= dynamic_chunk_start() {
            true
        } else if Self::is_primary_reserved(chunk_idx) {
            self.is_primary()
        } else {
            self.is_secondary()
        }
    }

    /// Check if a chunk is reserved for this role.
    pub fn is_reserved_for(&self, chunk_idx: usize) -> bool {
        match self {
            MachineRole::Primary => Self::is_primary_reserved(chunk_idx),
            MachineRole::Secondary => Self::is_secondary_reserved(chunk_idx),
        }
    }

    /// Check if a chunk can be assigned to this role (includes dynamic chunks).
    pub fn can_handle_chunk(&self, chunk_idx: usize) -> bool {
        chunk_idx >= dynamic_chunk_start() || self.is_reserved_for(chunk_idx)
    }

    // legacy code
    pub fn should_handle_task_unit(&self, task_unit: usize) -> bool {
        self.should_handle_chunk(task_unit * get_cpu_chunks_per_task_unit())
    }

    pub fn is_primary(&self) -> bool {
        matches!(self, MachineRole::Primary)
    }

    pub fn is_secondary(&self) -> bool {
        matches!(self, MachineRole::Secondary)
    }
}

/// Task unit configuration for distributed proof
#[derive(Clone, Debug)]
pub struct TaskUnitConfig {
    /// Number of CPU chunks per task unit
    pub cpu_chunks_per_unit: usize,
    /// Machine role
    pub role: MachineRole,
    /// Address of the peer machine for proof transfer
    pub peer_addr: Option<String>,
}

impl Default for TaskUnitConfig {
    fn default() -> Self {
        Self {
            cpu_chunks_per_unit: get_cpu_chunks_per_task_unit(),
            role: MachineRole::Primary,
            peer_addr: None,
        }
    }
}

impl TaskUnitConfig {
    pub fn new(role: MachineRole, peer_addr: Option<String>) -> Self {
        Self {
            cpu_chunks_per_unit: get_cpu_chunks_per_task_unit(),
            role,
            peer_addr,
        }
    }
}

/// Get chunks per task unit from environment variable
/// Default: 8
pub fn get_cpu_chunks_per_task_unit() -> usize {
    std::env::var("CPU_CHUNKS_PER_TASK_UNIT")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(8)
}

/// Get machine role from environment variable
/// Default: Primary
pub fn get_machine_role() -> MachineRole {
    std::env::var("MACHINE_ROLE")
        .ok()
        .and_then(|s| s.parse::<MachineRole>().ok())
        .unwrap_or(MachineRole::Primary)
}

/// Infer runtime mode from USECASE. Falls back to MACHINE_ROLE when USECASE is unknown.
/// This keeps legacy scripts usable while making single-node semantics explicit.
pub fn get_runtime_mode() -> RuntimeMode {
    match std::env::var("USECASE")
        .unwrap_or_else(|_| "local_single_node".to_string())
        .as_str()
    {
        "two_machine_primary" | "eth_proofs_two_machine_primary" => RuntimeMode::TwoMachinePrimary,
        "two_machine_secondary" | "eth_proofs_two_machine_secondary" => {
            RuntimeMode::TwoMachineSecondary
        }
        "local_single_node" | "eth_proofs_single_node" | "eth_proofs_agg_sub" => {
            RuntimeMode::SingleNode
        }
        _ => match std::env::var("MACHINE_ROLE")
            .ok()
            .and_then(|s| s.parse::<MachineRole>().ok())
        {
            Some(MachineRole::Secondary) => RuntimeMode::TwoMachineSecondary,
            _ => RuntimeMode::SingleNode,
        },
    }
}

/// Set when a worker belonging to the OTHER machine first polls this scheduler.
static PEER_WORKER_READY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Record that the peer machine's pipeline is up. Called from the `AcquireTask` handler.
pub fn note_peer_worker_ready() {
    PEER_WORKER_READY.store(true, std::sync::atomic::Ordering::Release);
}

pub fn peer_worker_ready() -> bool {
    PEER_WORKER_READY.load(std::sync::atomic::Ordering::Acquire)
}

/// Block until the peer machine's pipeline is up, or `timeout` elapses.
///
/// Two-machine had no rendezvous at all: each half began emulating whenever it personally finished
/// building, pre-sizing pools and running keygen, and those costs are neither equal nor stable
/// across two hosts. Measured on reth-24006677, the two halves pre-sized their pools 13.3s apart
/// with keygen within 0.3s of each other, so the skew is entirely pre-pipeline. The run's useful
/// work is only ~10s, so a 13s offset does not merely blur the overlap — it removes it: the primary
/// proved its chunks 08:04:00-08:04:06 and the secondary proved its own 08:04:13-08:04:19, with
/// **zero** overlap. 8+8 degenerated into "8, then 8 again", which is why it lost to a single
/// machine and why the GPUs sat at ~27% aggregate occupancy against single-node's 84%.
///
/// Returning `false` on timeout rather than panicking is deliberate: a missing peer should degrade
/// to "start anyway and let the existing acquire paths deal with it", which is the behaviour that
/// existed before this barrier. The barrier is an optimisation, not a correctness requirement.
pub fn wait_for_peer_worker(timeout: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if peer_worker_ready() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    false
}

/// Worker label used in prover ids. This allows N-worker deployments to
/// provide stable labels through `WORKER_LABEL`.
pub fn get_worker_label() -> String {
    if let Ok(label) = std::env::var("WORKER_LABEL") {
        let label = label.trim();
        if !label.is_empty() {
            return label.to_string();
        }
    }

    match get_runtime_mode() {
        RuntimeMode::SingleNode | RuntimeMode::TwoMachinePrimary => "primary".to_string(),
        RuntimeMode::TwoMachineSecondary => "secondary".to_string(),
    }
}

/// Get peer machine address from environment variable
pub fn get_peer_machine_addr() -> Option<String> {
    std::env::var("PEER_MACHINE_ADDR").ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn runtime_mode_maps_usecase() {
        let _guard = env_lock().lock().expect("env lock");
        let saved = std::env::var("USECASE").ok();

        std::env::set_var("USECASE", "eth_proofs_single_node");
        assert_eq!(get_runtime_mode(), RuntimeMode::SingleNode);

        std::env::set_var("USECASE", "two_machine_primary");
        assert_eq!(get_runtime_mode(), RuntimeMode::TwoMachinePrimary);

        std::env::set_var("USECASE", "two_machine_secondary");
        assert_eq!(get_runtime_mode(), RuntimeMode::TwoMachineSecondary);

        if let Some(v) = saved {
            std::env::set_var("USECASE", v);
        } else {
            std::env::remove_var("USECASE");
        }
    }

    #[test]
    fn single_node_accepts_all_chunks() {
        let mode = RuntimeMode::SingleNode;
        for i in 0..128 {
            assert!(mode.worker_can_handle_chunk_for_worker("primary-gpu-prover-0", i));
        }
    }

    #[test]
    fn n_worker_round_robin_static_region() {
        let _guard = env_lock().lock().expect("env lock");
        let saved_usecase = std::env::var("USECASE").ok();
        let saved_workers = std::env::var("SCHED_WORKERS").ok();

        std::env::set_var("USECASE", "two_machine_primary");
        std::env::set_var("SCHED_WORKERS", "worker0,worker1,worker2");

        let mode = get_runtime_mode();
        // Static chunks (< dynamic_chunk_start()) assigned by round-robin for N workers.
        assert!(mode.worker_can_handle_chunk_for_worker("worker0-gpu-prover-0", 0));
        assert!(mode.worker_can_handle_chunk_for_worker("worker1-gpu-prover-0", 1));
        assert!(mode.worker_can_handle_chunk_for_worker("worker2-gpu-prover-0", 2));
        assert!(!mode.worker_can_handle_chunk_for_worker("worker0-gpu-prover-0", 1));

        // Dynamic chunks are shared by all workers.
        assert!(
            mode.worker_can_handle_chunk_for_worker("worker0-gpu-prover-0", dynamic_chunk_start())
        );
        assert!(
            mode.worker_can_handle_chunk_for_worker("worker1-gpu-prover-0", dynamic_chunk_start())
        );
        assert!(
            mode.worker_can_handle_chunk_for_worker("worker2-gpu-prover-0", dynamic_chunk_start())
        );

        if let Some(v) = saved_usecase {
            std::env::set_var("USECASE", v);
        } else {
            std::env::remove_var("USECASE");
        }
        if let Some(v) = saved_workers {
            std::env::set_var("SCHED_WORKERS", v);
        } else {
            std::env::remove_var("SCHED_WORKERS");
        }
    }
}

#[cfg(test)]
mod chunk_assignment_tests {
    use super::MachineRole;

    /// Who owns each chunk of `0..n` at a given configuration: `P`/`S`/`d` (dynamic, both).
    fn split(n: usize, round: usize, dynamic: usize) -> String {
        (0..n)
            .map(|c| {
                if c >= dynamic {
                    'd'
                } else if MachineRole::is_primary_reserved_with(c, round, dynamic) {
                    'P'
                } else {
                    'S'
                }
            })
            .collect()
    }

    /// The defaults must reproduce the hand-written constants they replaced, or this refactor
    /// silently re-partitions FRI -- the existing user of this code.
    #[test]
    fn fri_defaults_are_unchanged() {
        // one-round: Primary 0-7, Secondary 8-15, Dynamic 16+
        assert_eq!(split(20, 8, 16), "PPPPPPPPSSSSSSSSdddd");
        // two-round-chunks: Primary 0-7 and 16-23, Secondary 8-15 and 24-31, Dynamic 32+
        assert_eq!(split(36, 8, 32), "PPPPPPPPSSSSSSSSPPPPPPPPSSSSSSSSdddd");
    }

    /// The case these defaults exist for: MLE @2^23 gives reth-188 8 chunks, and at FRI's defaults
    /// every one of them is the primary's, so the secondary idles.
    #[test]
    fn eight_chunks_starve_the_secondary_at_fri_defaults() {
        assert_eq!(split(8, 8, 16), "PPPPPPPP");
    }

    /// ...and with MLE's defaults the same block splits evenly.
    #[test]
    fn eight_chunks_split_evenly_at_mle_defaults() {
        assert_eq!(split(8, 4, 8), "PPPPSSSS");
        let s = split(8, 4, 8);
        assert_eq!(s.matches('P').count(), 4);
        assert_eq!(s.matches('S').count(), 4);
        assert_eq!(
            s.matches('d').count(),
            0,
            "an 8-chunk block needs no stealing"
        );
    }

    /// Above the static region both machines full-trace, which is what lets either steal. Recorded
    /// because it is the redundant-tracing cost, not an accident.
    #[test]
    fn larger_blocks_fall_into_the_shared_region() {
        assert_eq!(split(16, 4, 8), "PPPPSSSSdddddddd");
    }

    /// With the dynamic region removed, the alternation covers the whole block and the split stays
    /// even at any size. This is what MLE now defaults to.
    ///
    /// The old 4/8 default is the failure it replaces: on a 95-chunk block it made 87 chunks
    /// first-come-first-served, and the machine that registers them locally won every one — the
    /// secondary proved 4 of 95 on two real machines.
    #[test]
    fn alternation_over_the_whole_block_splits_evenly() {
        let s = split(96, 4, usize::MAX);
        assert_eq!(s.matches('P').count(), 48);
        assert_eq!(s.matches('S').count(), 48);
        assert_eq!(
            s.matches('d').count(),
            0,
            "no chunk is left first-come-first-served"
        );
        assert!(
            s.starts_with("PPPPSSSSPPPP"),
            "rounds of 4 alternate: {}",
            &s[..12]
        );
    }

    /// The trade this makes, stated as a test so it is not forgotten: with no dynamic region a
    /// machine's chunks are its own, so a straggler cannot be helped by the other side.
    #[test]
    fn no_chunk_is_stealable_without_a_dynamic_region() {
        let s = split(200, 4, usize::MAX);
        assert_eq!(s.matches('d').count(), 0);
    }
}
