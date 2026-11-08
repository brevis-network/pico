//! `MLE_INJECT_FAILURE`, a negative-test hook: one failure injected into a pipeline run, for the
//! tests that check a failed run leaves the process able to prove. Off unless set; read once per
//! process, and fires once per process unless stated otherwise.
//!
//! - `oom:<stage>:<n>` or `panic:<stage>:<n>`: the `n`-th item (1-based) `<stage>` takes panics.
//!   `oom` marks the thread out of device memory as the allocator does when it gives up, so only
//!   that mark tells it apart; `oom-text` carries the allocator's message instead and no mark, for
//!   the classifier's fallback; `panic` is any other panic. Stages: `emulate` (a record), `prove` (a
//!   RISC-V chunk), `convert` (a convert prepare), `combine` (a combine prepare), `keygen` (a
//!   recursion pk-cache miss on a pipeline thread, inside the cache's lock; the warmup keygen on
//!   the caller's thread, before the pipeline starts, is not counted).
//! - `refuse:<chunk>`: chunk `<chunk>` (1-based) is refused as if it selected the catch-all shape.
//! - `slow-finalize:<ms>`: every run finalizes its emulation `<ms>` late, as a slow emulation
//!   teardown does; this one fires on every run.

use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        OnceLock,
    },
    time::Duration,
};

/// The device allocator's panic on a failed allocation (`DeviceBuffer::with_capacity`); an
/// injected `oom-text` panic carries it too.
pub const DEVICE_ALLOC_FAILED: &str = "device allocation failed";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Emulate,
    Prove,
    Convert,
    Combine,
    Keygen,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// Out of device memory, told by the thread's mark alone.
    Oom,
    /// Out of device memory, told by the allocator's message alone.
    OomText,
    Other,
}

#[derive(Debug, PartialEq, Eq)]
enum Plan {
    Panic {
        stage: Stage,
        nth: usize,
        kind: Kind,
    },
    Refuse {
        chunk: usize,
    },
    SlowFinalize {
        ms: u64,
    },
}

fn parse(value: &str) -> Option<Plan> {
    let parts: Vec<&str> = value.split(':').collect();
    match parts.as_slice() {
        [kind @ ("oom" | "oom-text" | "panic"), stage, nth] => Some(Plan::Panic {
            stage: match *stage {
                "emulate" => Stage::Emulate,
                "prove" => Stage::Prove,
                "convert" => Stage::Convert,
                "combine" => Stage::Combine,
                "keygen" => Stage::Keygen,
                _ => return None,
            },
            nth: nth.parse().ok().filter(|&n| n > 0)?,
            kind: match *kind {
                "oom" => Kind::Oom,
                "oom-text" => Kind::OomText,
                _ => Kind::Other,
            },
        }),
        ["refuse", chunk] => Some(Plan::Refuse {
            chunk: chunk.parse().ok()?,
        }),
        ["slow-finalize", ms] => Some(Plan::SlowFinalize {
            ms: ms.parse().ok()?,
        }),
        _ => None,
    }
}

/// `MLE_INJECT_FAILURE` checked: unset is no plan, a value that does not parse an error.
pub fn validate() -> Result<(), String> {
    match std::env::var("MLE_INJECT_FAILURE") {
        Ok(value) if parse(&value).is_none() => Err(format!(
            "MLE_INJECT_FAILURE={value}: expected oom:<stage>:<n>, oom-text:<stage>:<n>, \
             panic:<stage>:<n>, refuse:<chunk> or slow-finalize:<ms>"
        )),
        _ => Ok(()),
    }
}

fn plan() -> Option<&'static Plan> {
    static PLAN: OnceLock<Option<Plan>> = OnceLock::new();
    PLAN.get_or_init(|| {
        if let Err(why) = validate() {
            panic!("{why}");
        }
        parse(&std::env::var("MLE_INJECT_FAILURE").ok()?)
    })
    .as_ref()
}

static SEEN: AtomicUsize = AtomicUsize::new(0);
static FIRED: AtomicBool = AtomicBool::new(false);

/// Panics if the plan fails this item of `stage`.
pub fn at(stage: Stage) {
    let Some(&Plan::Panic {
        stage: s,
        nth,
        kind,
    }) = plan()
    else {
        return;
    };
    if s != stage
        || stage == Stage::Keygen && !on_pipeline_thread()
        || SEEN.fetch_add(1, Ordering::SeqCst) + 1 != nth
        || FIRED.swap(true, Ordering::SeqCst)
    {
        return;
    }
    match kind {
        Kind::Oom => {
            #[cfg(feature = "cuda")]
            crate::mle::cuda_mle::runtime::memory_manager::mark_device_oom_raised();
            panic!("an out-of-memory injected by MLE_INJECT_FAILURE");
        }
        Kind::OomText => panic!(
            "{DEVICE_ALLOC_FAILED}: cudaErrorMemoryAllocation (injected by MLE_INJECT_FAILURE)"
        ),
        Kind::Other => panic!("a failure injected by MLE_INJECT_FAILURE"),
    }
}

/// The pipeline's threads are named `mle-*` or `<role>-mle-*`.
fn on_pipeline_thread() -> bool {
    std::thread::current()
        .name()
        .is_some_and(|name| name.contains("mle-"))
}

/// Whether the plan refuses chunk `chunk` (1-based).
pub fn refuses(chunk: usize) -> bool {
    matches!(plan(), Some(&Plan::Refuse { chunk: c }) if c == chunk)
        && !FIRED.swap(true, Ordering::SeqCst)
}

/// How late the plan finalizes every run's emulation.
pub fn finalize_delay() -> Option<Duration> {
    match plan() {
        Some(&Plan::SlowFinalize { ms }) => Some(Duration::from_millis(ms)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_plans_parse() {
        assert_eq!(
            parse("oom:prove:3"),
            Some(Plan::Panic {
                stage: Stage::Prove,
                nth: 3,
                kind: Kind::Oom
            })
        );
        assert_eq!(
            parse("panic:combine:1"),
            Some(Plan::Panic {
                stage: Stage::Combine,
                nth: 1,
                kind: Kind::Other
            })
        );
        assert_eq!(
            parse("oom:keygen:1"),
            Some(Plan::Panic {
                stage: Stage::Keygen,
                nth: 1,
                kind: Kind::Oom
            })
        );
        assert_eq!(
            parse("oom-text:convert:2"),
            Some(Plan::Panic {
                stage: Stage::Convert,
                nth: 2,
                kind: Kind::OomText
            })
        );
        assert_eq!(parse("refuse:12"), Some(Plan::Refuse { chunk: 12 }));
        assert_eq!(
            parse("slow-finalize:500"),
            Some(Plan::SlowFinalize { ms: 500 })
        );
        for bad in ["", "oom:prove", "oom:prove:0", "oom:nowhere:1", "refuse:x"] {
            assert_eq!(parse(bad), None, "{bad}");
        }
    }
}
