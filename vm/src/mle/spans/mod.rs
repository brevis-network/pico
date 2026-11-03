//! Where the pipeline's wall clock went, lane by lane.
//!
//! [`record`] captures it while a run happens; [`report`] derives figures from what was captured. The
//! split is by direction, not by subject — hence one module with two halves rather than two modules.
//! The CSV `record` exports is what `perf/ledger/` and `bench-scripts/` read.
//!
//! A lane is in exactly one of three states at any instant: `Busy` (doing its own work), `Idle`
//! (blocked for want of input) or `Wait` (blocked on capacity someone else holds). The glossary
//! defines the rest of the vocabulary (lane, busy, idle, wait, occupancy); it is not restated here.
//!
//! Recording is behind the `stage-ledger` feature, which `pico-vm` leaves off. Without it `inert`
//! has the recorder's entry points as no-ops, so the threads that call them carry no `cfg`, and
//! `report` is absent with `record`, since it reads what only a recording leaves behind. The
//! vocabulary below is in both builds, since call sites name it either way.

#[cfg(feature = "stage-ledger")]
pub mod record;
#[cfg(feature = "stage-ledger")]
pub mod report;
// Re-exported so callers say `spans::busy(..)` and `spans::Role` rather than naming the half they came
// from: the recording API is the module's surface, and which file it lives in is not the caller's
// business. Glob rather than a list, so adding a function does not need an edit here to be reachable.
#[cfg(feature = "stage-ledger")]
pub use record::*;

#[cfg(not(feature = "stage-ledger"))]
mod inert;
#[cfg(not(feature = "stage-ledger"))]
pub use inert::*;

#[cfg(feature = "cuda")]
pub mod device;

/// What a lane was doing. See the module docs for why `Idle` and `Wait` are distinct.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Busy,
    Idle,
    Wait,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Busy => "busy",
            State::Idle => "idle",
            State::Wait => "wait",
        }
    }
}

/// The kind of work a span represents.
///
/// This is what lets two figures measured on the *same* lane stay distinct — the recursion lane
/// takes convert and combine proves in turn (and under `MLE_RECURSION_LANE=0` the one prover lane
/// takes riscv as well), and only the work kind separates them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WorkKind {
    /// The emulator's untraced forward pass, which produces the snapshot a worker then replays.
    /// AOT when the AOT factory is registered, the interpreter otherwise — one kind either way,
    /// because what matters here is that it is the serial pass, not which backend ran it.
    Snapshot,
    /// A worker's traced replay of one snapshot: the pass that actually produces records. Always the
    /// interpreter; there is no AOT replay path.
    Emulate,
    /// Restoring a worker's emulator from the snapshot, before the replay can start. Separate from
    /// [`WorkKind::Emulate`] because it is per-batch setup rather than the batch's own work, and the
    /// pipeline's head bubble is where the difference shows.
    EmulateRecover,
    /// The sequencer putting a finished chunk's records in order and splitting the deferred pool
    /// out of them, under the deferred-state lock the replay workers also take.
    Sequence,
    PrepareRiscv,
    PrepareConvert,
    PrepareCombine,
    /// Proving-key generation on a cache miss. Emitted from whichever preparer lane took the miss;
    /// it is GPU work inside an otherwise CPU-bound prepare, which is why it is a kind of its own
    /// rather than part of the prepare that contains it.
    Keygen,
    ProveRiscv,
    ProveConvert,
    ProveCombine,
    /// Routing. Its `Busy` is negligible by construction; what matters is its `Wait`, which is
    /// head-of-line blocking on a full downstream lane.
    Dispatch,
    /// No particular work: the lane was between items. Used for the blocked spans of a lane that
    /// serves several kinds — the recursion lane waits for convert *or* combine work (and for
    /// riscv too when it is the card's only lane), and labelling that wait with any one of them
    /// would assert something untrue about what it was waiting for.
    Unattributed,
}

impl WorkKind {
    /// Whether this work reaches the GPU. Exhaustive on purpose: adding a kind forces an answer
    /// here, where the knowledge is, rather than letting a table in a report layer default a new
    /// kind to "not GPU" and quietly overstate how idle the device-facing lanes were.
    pub fn touches_gpu(self) -> bool {
        match self {
            WorkKind::Keygen
            | WorkKind::ProveRiscv
            | WorkKind::ProveConvert
            | WorkKind::ProveCombine => true,
            WorkKind::PrepareRiscv
            | WorkKind::PrepareConvert
            | WorkKind::PrepareCombine
            | WorkKind::Dispatch
            | WorkKind::Snapshot
            | WorkKind::Emulate
            | WorkKind::EmulateRecover
            | WorkKind::Sequence
            | WorkKind::Unattributed => false,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            WorkKind::Snapshot => "snapshot",
            WorkKind::Emulate => "emulate",
            WorkKind::EmulateRecover => "emulate-recover",
            WorkKind::Sequence => "sequence",
            WorkKind::PrepareRiscv => "prepare-riscv",
            WorkKind::PrepareConvert => "prepare-convert",
            WorkKind::PrepareCombine => "prepare-combine",
            WorkKind::Keygen => "keygen",
            WorkKind::ProveRiscv => "prove-riscv",
            WorkKind::ProveConvert => "prove-convert",
            WorkKind::ProveCombine => "prove-combine",
            WorkKind::Dispatch => "dispatch",
            WorkKind::Unattributed => "-",
        }
    }
}

/// A lane's role. Lanes of the same role form a pool whose figures are reported together.
///
/// Adding one means editing the places outside this enum that no compiler checks, which a search
/// for the role names finds; `bench-scripts/draw-mle-timeline.py` is the one that fails loudly on
/// a name it does not know.
/// (`report.rs`'s `DRAWN` names variants, so that one the compiler does check.)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Role {
    // Declared upstream-first: `Role` is `Ord`, and every report that groups by role inherits this
    // order, so the emulate stage reads above the preparers it feeds.
    /// The emulator's single snapshot-taking thread.
    Snapshot,
    /// The emulator's traced-replay workers, `NUM_THREADS` of them.
    Emulate,
    /// The one thread that receives the workers' records and hands them on in chunk order.
    Sequencer,
    RiscvPreparer,
    ConvertPreparer,
    CombinePreparer,
    /// The per-card riscv prover lane — and the card's ONLY prover lane under
    /// `MLE_RECURSION_LANE=0`, where it takes convert and combine too.
    Prove,
    /// The per-card recursion prover lane, serving convert and combine. A second thread rather
    /// than a fourth `select!` arm on `Prove`: one thread can only be inside one prove at a time,
    /// whatever it selects on, so sharing the lane is what kept recursion behind riscv. Absent
    /// under `MLE_RECURSION_LANE=0` — no thread binds it, so no lane of this role exists.
    ProveRecursion,
    Dispatch,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Snapshot => "snapshot",
            Role::Emulate => "emulate",
            Role::Sequencer => "sequencer",
            Role::RiscvPreparer => "riscv-prep",
            Role::ConvertPreparer => "conv-prep",
            Role::CombinePreparer => "comb-prep",
            Role::Prove => "prove",
            Role::ProveRecursion => "prove-rec",
            Role::Dispatch => "dispatch",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct LaneId {
    pub role: Role,
    pub index: usize,
}

impl LaneId {
    pub fn new(role: Role, index: usize) -> Self {
        Self { role, index }
    }
}

impl std::fmt::Display for LaneId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.role.as_str(), self.index)
    }
}

/// One interval during which one lane was in one state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Span {
    pub lane: LaneId,
    pub state: State,
    pub work: WorkKind,
    /// The work item this span is about, or `None` where it is about none (an idle wait for the next
    /// one, say). Three key spaces, and they are not interchangeable, so anything joining them has to
    /// say which it means: chunks (the riscv/convert prepare, prove and dispatch lanes),
    /// snapshot batches (the emulate lanes, where one tail batch becomes several chunks), and a combine
    /// node's FIRST chunk, which every node up one side of the tree shares.
    pub item: Option<u32>,
    pub start_us: u64,
    pub end_us: u64,
}

impl Span {
    pub fn duration_us(&self) -> u64 {
        self.end_us.saturating_sub(self.start_us)
    }

    /// Whether this span occupied a GPU-touching lane: a `Busy` span whose work reaches the device.
    /// `Idle` and `Wait` never count, whatever the lane — a blocked thread occupies nothing.
    pub fn is_gpu_busy(&self) -> bool {
        self.state == State::Busy && self.work.touches_gpu()
    }
}
