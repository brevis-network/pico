//! The run's first thread panic, so a failed run ends instead of hanging.
//!
//! A pipeline thread that dies leaves its neighbours blocked on channels and pooled buffers it
//! will never serve, and the run's joins wait on them forever. The CLI's panic hook exits the
//! process first; an embedded caller has no such hook, so the joins here give up as soon as any
//! watched thread has panicked, and the run fails with that thread's message.

use std::{
    any::Any,
    io,
    panic::{catch_unwind, resume_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, Ordering},
        Condvar, Mutex, MutexGuard,
    },
    thread::{Builder, JoinHandle},
    time::Duration,
};

static FAILURE: Mutex<Option<String>> = Mutex::new(None);
static FAILED: AtomicBool = AtomicBool::new(false);
static FAILURE_SET: Condvar = Condvar::new();

fn failure() -> MutexGuard<'static, Option<String>> {
    FAILURE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Starts a run with no failure recorded.
pub(crate) fn reset() {
    *failure() = None;
    FAILED.store(false, Ordering::Release);
}

/// Whether a watched thread of this run has panicked: stages poll it to stop early.
pub(crate) fn failed() -> bool {
    FAILED.load(Ordering::Acquire)
}

/// Records the run's failure; the first one wins.
pub(crate) fn fail(message: String) {
    let mut slot = failure();
    if slot.is_none() {
        *slot = Some(message);
    }
    FAILED.store(true, Ordering::Release);
    FAILURE_SET.notify_all();
}

pub(crate) fn panic_message(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|m| m.to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic with a non-string payload".into())
}

pub(crate) trait SpawnWatched {
    /// [`Builder::spawn`], recording a panic of the thread as the run's failure.
    fn spawn_watched<F, T>(self, f: F) -> io::Result<JoinHandle<T>>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static;
}

impl SpawnWatched for Builder {
    fn spawn_watched<F, T>(self, f: F) -> io::Result<JoinHandle<T>>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        self.spawn(move || match catch_unwind(AssertUnwindSafe(f)) {
            Ok(value) => value,
            Err(payload) => {
                let name = std::thread::current()
                    .name()
                    .unwrap_or("unnamed")
                    .to_owned();
                fail(format!("{name}: {}", panic_message(&*payload)));
                resume_unwind(payload)
            }
        })
    }
}

/// Joins `handle`, or panics with the run's failure as soon as any watched thread has panicked,
/// leaving `handle` behind: it may be blocked on a neighbour that is gone.
pub(crate) fn join<T>(handle: JoinHandle<T>, what: &str) -> T {
    let mut slot = failure();
    loop {
        if let Some(message) = slot.as_ref() {
            panic!("{what}: the pipeline failed: {message}");
        }
        if handle.is_finished() {
            drop(slot);
            return handle
                .join()
                .unwrap_or_else(|payload| panic!("{what}: {}", panic_message(&*payload)));
        }
        slot = FAILURE_SET
            .wait_timeout(slot, Duration::from_millis(50))
            .unwrap_or_else(|e| e.into_inner())
            .0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A panic in one watched thread ends the join on another that will now never finish.
    #[test]
    fn a_panic_ends_the_join_on_a_blocked_thread() {
        reset();
        let (release, blocked_on) = crossbeam::channel::bounded::<()>(0);
        let blocked = Builder::new()
            .name("blocked".into())
            .spawn_watched(move || {
                let _ = blocked_on.recv();
            })
            .unwrap();
        Builder::new()
            .name("dies".into())
            .spawn_watched(|| panic!("injected"))
            .unwrap();
        let payload = catch_unwind(AssertUnwindSafe(|| join(blocked, "blocked stage")))
            .expect_err("the join gives up");
        let message = panic_message(&*payload);
        assert!(message.contains("dies: injected"), "{message}");
        assert!(failed());
        drop(release);
        reset();
        assert!(!failed());
    }
}
