//! The ledger with the `stage-ledger` feature off: each function the hook sites call, with its
//! twin's signature in `live` and nothing in its body. All are `#[inline(always)]`, so the call and
//! the closure that would build its facts leave no code behind in a release binary.
//!
//! A hook site that calls a function this file lacks does not build without the feature, which is
//! the reminder to add its twin here.

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use serde_json::Value;

use super::{At, Context, CoreRole, Driver, Lane, ProveSlot, Setup, SplitPhase};
use crate::emulator::riscv::{record::EmulationRecord, syscalls::SyscallCode};

#[must_use = "the window's emulation ends when this drops"]
pub struct EmulationWindow(());

/// Records nothing, and says so the first time either instrument is asked for, as the recording
/// build reads the two: an empty `MLE_SPANS` asks for nothing.
#[inline(always)]
pub fn open_window(
    _t: Instant,
    _snapshot_main: &str,
    _worker_kind: &str,
    _workers: usize,
) -> EmulationWindow {
    static TOLD: AtomicBool = AtomicBool::new(false);
    let asked = std::env::var_os("MLE_LEDGER").is_some()
        || std::env::var("MLE_SPANS").is_ok_and(|p| !p.is_empty());
    if asked && !TOLD.swap(true, Ordering::Relaxed) {
        // Not through `tracing`: its default filter is off, and this is for the run with no log.
        eprintln!(
            "MLE_LEDGER or MLE_SPANS is set, but this pico-vm was built without the `stage-ledger` \
             feature: no ledger or span file is written"
        );
    }
    EmulationWindow(())
}

#[inline(always)]
pub fn enabled() -> bool {
    false
}

#[inline(always)]
pub fn digests_enabled() -> bool {
    false
}

#[inline(always)]
pub fn set_driver(_driver: Driver) {}

#[inline(always)]
pub fn emulation_starts(_t: Instant) {}

#[inline(always)]
pub fn close_emulation(_t: Instant) {}

#[inline(always)]
pub(crate) fn close_window() {}

#[inline(always)]
pub fn finish() {}

#[inline(always)]
pub fn active() -> bool {
    false
}

#[inline(always)]
pub fn stage(
    _name: &str,
    _at: At,
    _lane: impl Into<Lane>,
    _t0: Instant,
    _t1: Instant,
    _facts: impl FnOnce() -> Value,
) {
}

#[inline(always)]
pub fn skipped(_name: &str, _at: At, _lane: impl Into<Lane>) {}

#[inline(always)]
pub fn current_prove_slot() -> Option<ProveSlot> {
    None
}

#[inline(always)]
pub fn with_prove_slot<R>(_slot: ProveSlot, f: impl FnOnce() -> R) -> R {
    f()
}

#[derive(Clone, Copy, Debug)]
pub struct ProveMark(());

impl ProveMark {
    #[inline(always)]
    pub fn now() -> Self {
        Self(())
    }
}

#[inline(always)]
pub fn prove_stage(_name: &str, _since: ProveMark, _facts: impl FnOnce() -> Value) {}

#[inline(always)]
pub fn prove_stage_until(
    _name: &str,
    _since: ProveMark,
    _until: ProveMark,
    _facts: impl FnOnce() -> Value,
) {
}

#[inline(always)]
pub fn in_prove_slot() -> bool {
    false
}

#[inline(always)]
pub fn with_context<R>(_context: Context, f: impl FnOnce() -> R) -> R {
    f()
}

#[inline(always)]
pub fn context_batch() -> Option<u32> {
    None
}

#[inline(always)]
pub fn pool_wait(_t0: Instant, _t1: Instant, _warned: bool) {}

/// The records are freed here and nowhere else: the prove path hands them over to be dropped.
#[inline(always)]
pub fn drop_records(records: Vec<EmulationRecord>) {
    drop(records);
}

#[inline(always)]
pub fn add_setup(_kind: Setup, _d: Duration) {}

#[derive(Clone, Copy, Debug)]
#[must_use]
pub struct TimerStart(());

#[inline(always)]
pub fn precompile_start(_code: SyscallCode) -> TimerStart {
    TimerStart(())
}

#[inline(always)]
pub fn precompile_event_path(_start: TimerStart, _role: CoreRole, _code: SyscallCode) {}

#[inline(always)]
pub fn precompile_compute(_start: TimerStart, _role: CoreRole, _code: SyscallCode) {}

#[inline(always)]
pub fn timer_start() -> TimerStart {
    TimerStart(())
}

#[inline(always)]
pub fn drain_cpu_window(_start: TimerStart, _role: CoreRole, _words: usize) {}

#[inline(always)]
pub fn deferred_extend(_start: TimerStart) {}

#[inline(always)]
pub fn deferred_memory_extend(_start: TimerStart) {}

#[inline(always)]
pub fn thread_page_faults() -> Option<(u64, u64)> {
    None
}

#[inline(always)]
pub fn record_slot_wait<T>(wait: impl FnOnce() -> T) -> T {
    wait()
}

#[inline(always)]
pub fn take_record_slot_waits() -> (u64, Duration) {
    (0, Duration::ZERO)
}

pub struct SplitPhases(());

impl SplitPhases {
    #[inline(always)]
    pub fn start(_last: bool) -> Self {
        Self(())
    }

    #[inline(always)]
    pub fn mark(&self) -> TimerStart {
        TimerStart(())
    }

    #[inline(always)]
    pub fn add(&self, _phase: SplitPhase, _start: TimerStart) {}

    #[inline(always)]
    pub fn finish(self) {}
}

#[must_use]
pub struct Timers(());

impl Timers {
    #[inline(always)]
    pub fn add_to(self, _facts: &mut Value) {}
}

#[inline(always)]
pub fn take_timers() -> Timers {
    Timers(())
}
