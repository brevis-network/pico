//! Timers finer than a stage, which the rest of the ledger never is: a bracket around every
//! precompile a pipeline core runs, on the event-producing path a recording core takes or on the
//! compute-only copy a core with its sink off takes; around the CPU-window branch of the drain that
//! closes the memory words the event path touched; around each extend of the deferred record; and
//! around the phases of the final deferred split. Each is summed on the thread that ran it. A
//! bracket per event costs a clock pair per event, so the timers stay off unless
//! `MLE_LEDGER_PRECOMPILE_TIMERS=1` is set beside `MLE_LEDGER`.
//!
//! The sums go out as facts of the stage line that holds the work ([`take_timers`]):
//! - `role`, the core's own (`snapshot` or `worker`; `mixed` if the thread ran both in one stage),
//!   for the precompile and drain facts;
//! - per syscall kind, named as its `SyscallCode` lower-cased, `precompile.<kind>.count` and the
//!   microseconds on each path it took, `precompile.<kind>.event_path_us` and
//!   `precompile.<kind>.compute_us`. A pipeline core takes one path for its life: the snapshot
//!   thread's sink is off and a replay worker's is on;
//! - `drain.cpu_window_us`, one bracket per precompile call (`drain.calls`) around its words
//!   (`drain.words`);
//! - `deferred.extend_us` and `deferred.extends`, a record's precompile events joining the deferred
//!   record, and apart from them `deferred.memory_extend_us` and `deferred.memory_extends`, the
//!   run's memory initialize and finalize events joining it at the end;
//! - `split.last.<phase>_us` for `extract`, `sort`, `records`, `memory` and `wall`, and
//!   `split.last.splits`. The extract, the sort and part of the records run per precompile kind in
//!   parallel, so those are thread time summed over kinds; `wall` is the split's own.
//!
//! A bracket's own clock reads land in what it records, and in any bracket around it: the drain's
//! in the event path's. The window's envelope carries both per timer, as `timer_calibration`:
//! `timer.<name>.empty_pair_ns`, the median of what an empty bracket records, for a reader to take
//! out of each bracket's sum count times; and `timer.<name>.enclosed_pair_ns`, what one start and
//! stop cost a bracket or stage around them. The clock is `std::time::Instant`.

use std::{
    cell::RefCell,
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
    time::Instant,
};

use serde_json::{json, Map, Value};
use strum::IntoEnumIterator;

use crate::{
    emulator::riscv::syscalls::SyscallCode,
    mle::ledger::{CoreRole, SplitPhase},
};

/// Empty brackets timed for a timer's `empty_pair_ns`.
const CALIBRATION_PAIRS: usize = 4096;
/// Rounds of back-to-back brackets for a timer's `enclosed_pair_ns`, and the brackets in each: the
/// clock's own resolution is coarse on some hosts, so the cost is read off a round's wall.
const ENCLOSED_ROUNDS: usize = 33;
const ENCLOSED_PAIRS: usize = 256;

const CLOCK: &str = if cfg!(target_os = "linux") {
    "Instant (CLOCK_MONOTONIC)"
} else if cfg!(target_vendor = "apple") {
    "Instant (CLOCK_UPTIME_RAW)"
} else {
    "Instant"
};

/// `MLE_LEDGER_PRECOMPILE_TIMERS=1`, with the ledger writing somewhere. Read once.
#[inline]
pub(super) fn precompile_timers_on() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        super::enabled() && std::env::var("MLE_LEDGER_PRECOMPILE_TIMERS").is_ok_and(|v| v == "1")
    })
}

/// Where a bracket started: nothing with the timers off, and then its end reads no clock either.
#[derive(Clone, Copy, Debug)]
#[must_use]
pub struct TimerStart(Option<Instant>);

/// Starts the bracket around a run of `code`, when it is a precompile and the timers are on.
#[inline]
pub fn precompile_start(code: SyscallCode) -> TimerStart {
    TimerStart((code.should_send() != 0 && precompile_timers_on()).then(Instant::now))
}

/// Ends the bracket around a precompile's event-producing run on a core of `role`.
#[inline]
pub fn precompile_event_path(start: TimerStart, role: CoreRole, code: SyscallCode) {
    if let Some(ns) = lap(start) {
        add(Path::EventPath, role, code, ns);
    }
}

/// Ends the bracket around a precompile's compute-only run on a core of `role`.
#[inline]
pub fn precompile_compute(start: TimerStart, role: CoreRole, code: SyscallCode) {
    if let Some(ns) = lap(start) {
        add(Path::Compute, role, code, ns);
    }
}

/// Starts a bracket around the drain's CPU-window branch or a deferred extend, when the timers are
/// on.
#[inline]
pub fn timer_start() -> TimerStart {
    TimerStart(precompile_timers_on().then(Instant::now))
}

/// Ends the bracket around the CPU-window branch of one precompile call's drain, over its `words`
/// memory words, on a core of `role`.
#[inline]
pub fn drain_cpu_window(start: TimerStart, role: CoreRole, words: usize) {
    if let Some(ns) = lap(start) {
        TALLY.with(|tally| tally.borrow_mut().add_drain(role, ns, words as u64));
    }
}

/// Ends the bracket around one extend of the deferred record by a record's precompile events.
#[inline]
pub fn deferred_extend(start: TimerStart) {
    if let Some(ns) = lap(start) {
        TALLY.with(|tally| tally.borrow_mut().extend.add(ns));
    }
}

/// Ends the bracket around the extend of the deferred record by the run's memory initialize and
/// finalize events.
#[inline]
pub fn deferred_memory_extend(start: TimerStart) {
    if let Some(ns) = lap(start) {
        TALLY.with(|tally| tally.borrow_mut().memory_extend.add(ns));
    }
}

/// The final deferred split's phase sums, shared by the threads of its per-kind map.
pub struct SplitPhases(Option<[AtomicU64; SplitPhase::ALL.len()]>);

impl SplitPhases {
    /// Timed only for the last split, the one at the end of the run.
    pub fn start(last: bool) -> Self {
        Self((last && precompile_timers_on()).then(Default::default))
    }

    #[inline]
    pub fn mark(&self) -> TimerStart {
        TimerStart(self.0.as_ref().map(|_| Instant::now()))
    }

    #[inline]
    pub fn add(&self, phase: SplitPhase, start: TimerStart) {
        if let (Some(sums), Some(ns)) = (&self.0, lap(start)) {
            sums[phase as usize].fetch_add(ns, Ordering::Relaxed);
        }
    }

    /// Hands the sums to the calling thread's timers, for the stage line of the work that split.
    pub fn finish(self) {
        if let Some(sums) = self.0 {
            let ns = sums.map(AtomicU64::into_inner);
            TALLY.with(|tally| tally.borrow_mut().add_split(ns));
        }
    }

    fn sum(&self, phase: SplitPhase) -> u64 {
        self.0
            .as_ref()
            .map_or(0, |sums| sums[phase as usize].load(Ordering::Relaxed))
    }
}

#[inline(always)]
fn lap(start: TimerStart) -> Option<u64> {
    start.0.map(|t0| t0.elapsed().as_nanos() as u64)
}

/// A precompile's two paths: the interpreter's own implementation, writing its events, on a core
/// whose sink is on; the compute-only copy on one whose sink is off.
#[derive(Clone, Copy)]
enum Path {
    EventPath,
    Compute,
}

impl Path {
    const ALL: [Self; 2] = [Self::EventPath, Self::Compute];

    fn fact(self) -> &'static str {
        match self {
            Self::EventPath => "event_path_us",
            Self::Compute => "compute_us",
        }
    }
}

#[derive(Clone, Copy)]
struct Sum {
    count: u64,
    ns: u64,
}

impl Sum {
    const ZERO: Self = Self { count: 0, ns: 0 };

    fn add(&mut self, ns: u64) {
        self.count += 1;
        self.ns += ns;
    }
}

fn us(ns: u64) -> Value {
    json!(ns as f64 / 1e3)
}

/// What one thread's timers recorded since its last [`take_timers`]; the precompiles per path and
/// per syscall id (a syscall code's low byte, unique to it).
struct Tally {
    role: Option<CoreRole>,
    roles_mixed: bool,
    precompiles: [[Sum; 256]; 2],
    drain: Sum,
    drain_words: u64,
    extend: Sum,
    memory_extend: Sum,
    splits: u64,
    split_ns: [u64; SplitPhase::ALL.len()],
}

impl Tally {
    const EMPTY: Self = Self {
        role: None,
        roles_mixed: false,
        precompiles: [[Sum::ZERO; 256]; 2],
        drain: Sum::ZERO,
        drain_words: 0,
        extend: Sum::ZERO,
        memory_extend: Sum::ZERO,
        splits: 0,
        split_ns: [0; SplitPhase::ALL.len()],
    };

    fn is_empty(&self) -> bool {
        self.role.is_none()
            && self.extend.count == 0
            && self.memory_extend.count == 0
            && self.splits == 0
    }

    fn note_role(&mut self, role: CoreRole) {
        match self.role {
            None => self.role = Some(role),
            Some(seen) => self.roles_mixed |= seen != role,
        }
    }

    fn add(&mut self, path: Path, role: CoreRole, code: SyscallCode, ns: u64) {
        self.note_role(role);
        self.precompiles[path as usize][code.syscall_id() as usize].add(ns);
    }

    fn add_drain(&mut self, role: CoreRole, ns: u64, words: u64) {
        self.note_role(role);
        self.drain.add(ns);
        self.drain_words += words;
    }

    fn add_split(&mut self, ns: [u64; SplitPhase::ALL.len()]) {
        self.splits += 1;
        for (sum, ns) in self.split_ns.iter_mut().zip(ns) {
            *sum += ns;
        }
    }

    fn write(&self, facts: &mut Map<String, Value>) {
        let role = if self.roles_mixed {
            Some("mixed")
        } else {
            self.role.map(CoreRole::as_str)
        };
        if let Some(role) = role {
            facts.insert("role".into(), json!(role));
        }
        if self.drain.count > 0 {
            facts.insert("drain.cpu_window_us".into(), us(self.drain.ns));
            facts.insert("drain.calls".into(), json!(self.drain.count));
            facts.insert("drain.words".into(), json!(self.drain_words));
        }
        for (name, sum) in [
            ("deferred.extend", self.extend),
            ("deferred.memory_extend", self.memory_extend),
        ] {
            if sum.count > 0 {
                facts.insert(format!("{name}_us"), us(sum.ns));
                facts.insert(format!("{name}s"), json!(sum.count));
            }
        }
        if self.splits > 0 {
            for phase in SplitPhase::ALL {
                facts.insert(
                    format!("split.last.{}_us", phase.as_str()),
                    us(self.split_ns[phase as usize]),
                );
            }
            facts.insert("split.last.splits".into(), json!(self.splits));
        }
        for code in SyscallCode::iter() {
            let id = code.syscall_id() as usize;
            let sums = Path::ALL.map(|path| (path, self.precompiles[path as usize][id]));
            let count: u64 = sums.iter().map(|(_, sum)| sum.count).sum();
            if count == 0 {
                continue;
            }
            let kind = format!("{code:?}").to_ascii_lowercase();
            facts.insert(format!("precompile.{kind}.count"), json!(count));
            for (path, sum) in sums {
                if sum.count > 0 {
                    facts.insert(format!("precompile.{kind}.{}", path.fact()), us(sum.ns));
                }
            }
        }
    }
}

thread_local! {
    static TALLY: RefCell<Tally> = const { RefCell::new(Tally::EMPTY) };
}

fn add(path: Path, role: CoreRole, code: SyscallCode, ns: u64) {
    TALLY.with(|tally| tally.borrow_mut().add(path, role, code, ns));
}

fn take_tally() -> Option<Box<Tally>> {
    TALLY.with(|tally| {
        let mut tally = tally.borrow_mut();
        (!tally.is_empty()).then(|| Box::new(std::mem::replace(&mut *tally, Tally::EMPTY)))
    })
}

/// The sums one stage's work recorded, for its line.
#[must_use]
pub struct Timers(Option<Box<Tally>>);

impl Timers {
    /// Adds the sums to `facts`, a stage line's facts object; nothing when none was recorded.
    pub fn add_to(self, facts: &mut Value) {
        if let (Some(tally), Value::Object(facts)) = (self.0, facts) {
            tally.write(facts);
        }
    }
}

/// What this thread's timers recorded since the last call. Called after each piece of work whether
/// or not its line is written, so that the next piece starts from nothing.
pub fn take_timers() -> Timers {
    if !precompile_timers_on() {
        return Timers(None);
    }
    Timers(take_tally())
}

/// Each timer's own cost, for the envelope. Taken through the same calls a hook site makes, on the
/// calling thread, whose sums are then cleared.
pub(super) fn calibration() -> Value {
    const CODE: SyscallCode = SyscallCode::KECCAK_PERMUTE;
    let event_path = calibrate(
        || precompile_event_path(precompile_start(CODE), CoreRole::Worker, CODE),
        || recorded(Path::EventPath, CODE),
    );
    let compute = calibrate(
        || precompile_compute(precompile_start(CODE), CoreRole::Snapshot, CODE),
        || recorded(Path::Compute, CODE),
    );
    let drain = calibrate(
        || drain_cpu_window(timer_start(), CoreRole::Worker, 0),
        || TALLY.with(|tally| tally.borrow().drain.ns),
    );
    let extend = calibrate(
        || deferred_extend(timer_start()),
        || TALLY.with(|tally| tally.borrow().extend.ns),
    );
    let memory_extend = calibrate(
        || deferred_memory_extend(timer_start()),
        || TALLY.with(|tally| tally.borrow().memory_extend.ns),
    );
    let phases = SplitPhases::start(true);
    let split = calibrate(
        || phases.add(SplitPhase::Sort, phases.mark()),
        || phases.sum(SplitPhase::Sort),
    );
    drop(take_tally());
    let mut facts = Map::new();
    facts.insert("clock".into(), json!(CLOCK));
    facts.insert("pairs".into(), json!(CALIBRATION_PAIRS));
    for (name, (empty, enclosed)) in [
        ("precompile_event_path", event_path),
        ("precompile_compute", compute),
        ("drain_cpu_window", drain),
        ("deferred_extend", extend),
        ("deferred_memory_extend", memory_extend),
        ("split_last", split),
    ] {
        facts.insert(format!("timer.{name}.empty_pair_ns"), json!(empty));
        facts.insert(format!("timer.{name}.enclosed_pair_ns"), json!(enclosed));
    }
    Value::Object(facts)
}

fn recorded(path: Path, code: SyscallCode) -> u64 {
    TALLY.with(|tally| tally.borrow().precompiles[path as usize][code.syscall_id() as usize].ns)
}

/// What `pair`, one start and end of a timer around nothing, records, as the median of
/// [`CALIBRATION_PAIRS`] read through `recorded`, the timer's running sum; and what it costs a
/// bracket around it, as the median over rounds of a round's wall per pair.
fn calibrate(pair: impl Fn(), recorded: impl Fn() -> u64) -> (u64, f64) {
    let mut empty: Vec<u64> = (0..CALIBRATION_PAIRS)
        .map(|_| {
            let before = recorded();
            pair();
            recorded() - before
        })
        .collect();
    empty.sort_unstable();
    let mut enclosed: Vec<f64> = (0..ENCLOSED_ROUNDS)
        .map(|_| {
            let t0 = Instant::now();
            for _ in 0..ENCLOSED_PAIRS {
                pair();
            }
            t0.elapsed().as_nanos() as f64 / ENCLOSED_PAIRS as f64
        })
        .collect();
    enclosed.sort_by(f64::total_cmp);
    (empty[empty.len() / 2], enclosed[enclosed.len() / 2])
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        Path::{Compute, EventPath},
        *,
    };
    use crate::{
        emulator::riscv::syscalls::SyscallCode::{
            KECCAK_PERMUTE, SECP256K1_DOUBLE, SHA_EXTEND, UINT256_MUL,
        },
        mle::ledger::CoreRole::{Snapshot, Worker},
    };

    fn facts_of(timers: Timers) -> Map<String, Value> {
        let mut facts = json!({});
        timers.add_to(&mut facts);
        match facts {
            Value::Object(facts) => facts,
            _ => unreachable!("an object stays one"),
        }
    }

    #[test]
    fn a_line_gains_each_kind_with_its_count_and_its_time_on_the_path_it_took() {
        drop(take_tally());
        add(EventPath, Worker, KECCAK_PERMUTE, 1_500);
        add(EventPath, Worker, KECCAK_PERMUTE, 500);
        add(EventPath, Worker, SECP256K1_DOUBLE, 250);
        let facts = facts_of(Timers(take_tally()));
        assert_eq!(facts["role"], "worker");
        assert_eq!(facts["precompile.keccak_permute.count"], 2);
        assert_eq!(facts["precompile.keccak_permute.event_path_us"], 2.0);
        assert_eq!(facts["precompile.secp256k1_double.count"], 1);
        assert_eq!(facts["precompile.secp256k1_double.event_path_us"], 0.25);
        assert_eq!(facts.len(), 5, "{facts:?}");
        let left = take_tally();
        assert!(left.is_none(), "a take leaves the thread's sums empty");
    }

    #[test]
    fn a_thread_that_ran_both_kinds_of_core_says_so() {
        drop(take_tally());
        add(Compute, Snapshot, SHA_EXTEND, 10);
        add(EventPath, Worker, SHA_EXTEND, 30);
        let facts = facts_of(Timers(take_tally()));
        assert_eq!(facts["role"], "mixed");
        assert_eq!(facts["precompile.sha_extend.count"], 2);
        assert_eq!(facts["precompile.sha_extend.compute_us"], 0.01);
        assert_eq!(facts["precompile.sha_extend.event_path_us"], 0.03);
    }

    #[test]
    fn the_drain_the_extend_and_the_split_add_their_own_facts() {
        drop(take_tally());
        TALLY.with(|tally| {
            let mut tally = tally.borrow_mut();
            tally.add_drain(Worker, 40, 25);
            tally.add_drain(Worker, 60, 7);
            tally.extend.add(2_000);
            tally.memory_extend.add(3_000);
            tally.add_split([1_000, 2_000, 3_000, 4_000, 9_000]);
        });
        let facts = facts_of(Timers(take_tally()));
        assert_eq!(facts["role"], "worker");
        assert_eq!(facts["drain.calls"], 2);
        assert_eq!(facts["drain.words"], 32);
        assert_eq!(facts["drain.cpu_window_us"], 0.1);
        assert_eq!(facts["deferred.extends"], 1);
        assert_eq!(facts["deferred.extend_us"], 2.0);
        assert_eq!(facts["deferred.memory_extends"], 1);
        assert_eq!(facts["deferred.memory_extend_us"], 3.0);
        assert_eq!(facts["split.last.splits"], 1);
        assert_eq!(facts["split.last.extract_us"], 1.0);
        assert_eq!(facts["split.last.sort_us"], 2.0);
        assert_eq!(facts["split.last.records_us"], 3.0);
        assert_eq!(facts["split.last.memory_us"], 4.0);
        assert_eq!(facts["split.last.wall_us"], 9.0);
        assert_eq!(facts.len(), 14, "{facts:?}");
    }

    #[test]
    fn work_no_core_ran_carries_no_role() {
        drop(take_tally());
        TALLY.with(|tally| tally.borrow_mut().extend.add(500));
        let facts = facts_of(Timers(take_tally()));
        assert!(!facts.contains_key("role"), "{facts:?}");
        assert_eq!(facts["deferred.extend_us"], 0.5);
    }

    #[test]
    fn split_phases_off_record_nothing() {
        drop(take_tally());
        let phases = SplitPhases(None);
        phases.add(SplitPhase::Sort, phases.mark());
        phases.finish();
        assert!(take_tally().is_none());
    }

    #[test]
    fn nothing_recorded_adds_nothing() {
        assert!(facts_of(Timers(take_tally())).is_empty());
        assert!(facts_of(Timers(None)).is_empty());
    }

    #[test]
    fn calibration_reads_what_the_pair_records_and_what_it_costs_around_it() {
        drop(take_tally());
        let (empty, enclosed) = calibrate(
            || {
                if let Some(ns) = lap(TimerStart(Some(Instant::now()))) {
                    add(Compute, Snapshot, UINT256_MUL, ns);
                }
            },
            || recorded(Compute, UINT256_MUL),
        );
        let tally = take_tally().expect("the pairs were recorded");
        assert_eq!(
            tally.precompiles[Compute as usize][UINT256_MUL.syscall_id() as usize].count,
            (CALIBRATION_PAIRS + ENCLOSED_ROUNDS * ENCLOSED_PAIRS) as u64
        );
        assert!(empty < 1_000_000, "an empty bracket recorded {empty} ns");
        assert!(
            enclosed > 0.0 && enclosed < 1e6,
            "a bracket costs {enclosed} ns"
        );
    }

    #[test]
    fn every_syscall_sums_in_a_slot_of_its_own() {
        let ids: BTreeSet<u32> = SyscallCode::iter().map(SyscallCode::syscall_id).collect();
        assert_eq!(ids.len(), SyscallCode::iter().count());
    }
}
