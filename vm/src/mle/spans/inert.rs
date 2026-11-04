//! The span recorder with the `stage-ledger` feature off: the entry points a pipeline thread calls,
//! with their twins' signatures in `record` and empty bodies. `set_origin` and `stop`, which only
//! the recording ledger calls, and `validate`, `export_csv` and the types they report in, which
//! read what a recording left behind, exist only with one. `snapshot` stays for the cost example's
//! count of what was recorded.

use std::marker::PhantomData;

use super::{LaneId, Span, State, WorkKind};

/// Neither `Send` nor `Sync`, as the recording guard is, so a call site that holds one across
/// threads fails to build on either configuration.
pub struct Guard(PhantomData<*const ()>);

// Empty, but it gives the type drop glue, so a `drop(guard)` at a hook site is not
// `clippy::drop_non_drop` on this build.
impl Drop for Guard {
    #[inline(always)]
    fn drop(&mut self) {}
}

#[inline(always)]
pub fn snapshot() -> Vec<Span> {
    Vec::new()
}

#[inline(always)]
pub fn bind_lane(_lane: LaneId) {}

#[inline(always)]
pub fn open(_state: State, _work: WorkKind, _item: Option<u32>) -> Guard {
    Guard(PhantomData)
}

#[inline(always)]
pub fn busy(work: WorkKind, item: Option<u32>) -> Guard {
    open(State::Busy, work, item)
}

#[inline(always)]
pub fn idle(work: WorkKind) -> Guard {
    open(State::Idle, work, None)
}

#[inline(always)]
pub fn wait(work: WorkKind, item: Option<u32>) -> Guard {
    open(State::Wait, work, item)
}
