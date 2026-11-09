//! The run's first thread panic, so a failed run ends instead of hanging.
//!
//! The first panic aborts the scheduler, so every lane drains: a stage parked on the scheduler
//! wakes to `Complete`, and one parked on a channel sees it close as its neighbours exit. The CLI
//! still gives up on the joins at once ([`join`]), as its panic hook exits the process anyway; an
//! embedded run waits for every thread ([`join_draining`]) and reports the failure.

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

/// Every failure this run recorded, in the order they were recorded.
static FAILURES: Mutex<Vec<String>> = Mutex::new(Vec::new());
static FAILED: AtomicBool = AtomicBool::new(false);
static FAILURE_SET: Condvar = Condvar::new();

fn failures() -> MutexGuard<'static, Vec<String>> {
    FAILURES.lock().unwrap_or_else(|e| e.into_inner())
}

/// Starts a run with no failure recorded.
pub(crate) fn reset() {
    failures().clear();
    FAILED.store(false, Ordering::Release);
}

/// Whether a watched thread of this run has panicked: stages poll it to stop early.
pub(crate) fn failed() -> bool {
    FAILED.load(Ordering::Acquire)
}

/// Whether `message` is a stage failing only because a neighbour already did: its channel closed
/// under it, or it stopped on the run's failure. A neighbour's panic closes channels as it unwinds,
/// before it is recorded, so a symptom can be recorded first.
pub(crate) fn is_symptom(message: &str) -> bool {
    message.contains("hung up")
        || message.contains("the pipeline failed")
        || message.contains("riscv preparer panicked")
}

/// What a watched thread's failure starts with when its last device allocation gave up out of
/// memory, whatever the panic says.
#[cfg(any(feature = "cuda", test))]
const DEVICE_OOM_TAG: &str = "[device out of memory]";

/// Whether `message` (as [`fail`] records it, `<thread>: <panic>`) is a card running out of
/// memory: tagged so by the allocator, or failing for the CUDA out-of-memory status (a pool
/// allocation's `ErrorMemoryAllocation`, a kernel unit's `cudaErrorMemoryAllocation`, the device
/// allocator's message). Pinned host memory fails with that status too, so a panic naming the host
/// is not one.
#[cfg(any(feature = "cuda", test))]
pub(crate) fn is_device_oom(message: &str) -> bool {
    // `<thread>: `, a name with no space; a thread named for the host must not read as one.
    let panic = match message.split_once(": ") {
        Some((thread, panic)) if !thread.contains(' ') => panic,
        _ => message,
    };
    if panic.starts_with(DEVICE_OOM_TAG) {
        return true;
    }
    let host = ["host", "pinned", "Host"].iter().any(|h| panic.contains(h));
    !host
        && (panic.contains(pico_vm::mle::inject::DEVICE_ALLOC_FAILED)
            || panic.contains("ErrorMemoryAllocation"))
}

/// The run's failure: the first recorded one that is not a symptom of another, or the first one
/// if all are.
pub(crate) fn failure_message() -> Option<String> {
    primary(&failures())
}

fn primary(all: &[String]) -> Option<String> {
    all.iter()
        .find(|m| !is_symptom(m))
        .or_else(|| all.first())
        .cloned()
}

/// Every failure the run recorded.
#[cfg(any(feature = "cuda", test))]
pub(crate) fn all_failures() -> Vec<String> {
    failures().clone()
}

/// Records a failure of the run and aborts the scheduler so the run drains.
pub(crate) fn fail(message: String) {
    {
        failures().push(message);
        FAILED.store(true, Ordering::Release);
    }
    FAILURE_SET.notify_all();
    crate::common::mle_scheduler_singleton::mle_abort_run();
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
                #[cfg(feature = "cuda")]
                let tag =
                    if pico_vm::mle::cuda_mle::runtime::memory_manager::take_device_oom_raised() {
                        format!("{DEVICE_OOM_TAG} ")
                    } else {
                        String::new()
                    };
                #[cfg(not(feature = "cuda"))]
                let tag = "";
                fail(format!("{name}: {tag}{}", panic_message(&*payload)));
                resume_unwind(payload)
            }
        })
    }
}

/// Joins `handle`, or panics with the run's failure as soon as any watched thread has panicked,
/// leaving `handle` behind: it may be blocked on a neighbour that is gone.
pub(crate) fn join<T>(handle: JoinHandle<T>, what: &str) -> T {
    let mut slot = failures();
    loop {
        if let Some(message) = primary(&slot) {
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

/// Joins `handle` however long it takes, calling `tick` while it waits; `None` if the thread
/// panicked, whose panic is already the run's failure. Every stage exits once the run fails (see
/// the module header), so this ends.
pub(crate) fn join_draining<T>(handle: JoinHandle<T>, mut tick: impl FnMut()) -> Option<T> {
    while !handle.is_finished() {
        tick();
        std::thread::sleep(Duration::from_millis(20));
    }
    handle.join().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The failure is process-wide: one test at a time.
    static SERIAL: Mutex<()> = Mutex::new(());

    /// A panic in one watched thread ends the join on another that will now never finish.
    #[test]
    fn a_panic_ends_the_join_on_a_blocked_thread() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
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

    /// The draining join leaves no thread behind: a stage blocked on a dead neighbour's channel
    /// sees it close, exits, and is joined, while the dead one joins as `None`.
    #[test]
    fn a_draining_join_waits_for_every_thread() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let (feed, fed) = crossbeam::channel::bounded::<()>(0);
        let blocked = Builder::new()
            .name("blocked".into())
            .spawn_watched(move || fed.recv().is_err())
            .unwrap();
        let dies = Builder::new()
            .name("dies".into())
            .spawn_watched(move || {
                let _feed = feed;
                panic!("injected");
            })
            .unwrap();
        assert_eq!(join_draining(dies, || {}), None);
        assert_eq!(join_draining(blocked, || {}), Some(true));
        let message = failure_message().expect("the panic is recorded");
        assert!(message.contains("dies: injected"), "{message}");
        reset();
    }

    /// A neighbour's closed channel can be recorded before the panic that closed it: the run's
    /// failure is the first that is not such a symptom, and all of them stay readable.
    #[test]
    fn a_symptom_recorded_first_is_not_the_failure() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        fail("mle-convert-preparer-0: prover hung up".into());
        fail("primary-mle-prover-0: device allocation failed: cudaErrorMemoryAllocation".into());
        let primary = failure_message().expect("recorded");
        assert!(is_device_oom(&primary), "{primary}");
        assert_eq!(all_failures().len(), 2);
        reset();
        assert_eq!(failure_message(), None);
    }

    /// Device allocations that fail are a card out of memory; pinned host memory failing with the
    /// same CUDA status is not, nor is any other panic.
    #[test]
    fn only_device_allocations_are_out_of_memory() {
        assert!(is_device_oom(
            "primary-mle-prover-0: device allocation failed: Cuda(CudaError { code: 2 })"
        ));
        assert!(is_device_oom(
            "mle-convert-preparer-0: called `Result::unwrap()` on an `Err` value: \
             ErrorMemoryAllocation"
        ));
        assert!(!is_device_oom(
            "pinned host allocation failed: called `Result::unwrap()` on an `Err` value: \
             ErrorMemoryAllocation"
        ));
        assert!(!is_device_oom("an illegal memory access was encountered"));
        // A pool allocation's `expect`, and a kernel unit's CUDA check.
        assert!(is_device_oom(
            "mle-convert-preparer-0: weierstrass add events: ErrorMemoryAllocation"
        ));
        assert!(is_device_oom(
            "primary-mle-prover-0: out of memory (cudaErrorMemoryAllocation)"
        ));
        // The thread's name is not the panic: one named for the host still runs out of a card.
        assert!(is_device_oom(
            "worker-host-0: device allocation failed: cudaErrorMemoryAllocation"
        ));
        // The allocator's mark wins over a message that names nothing.
        assert!(is_device_oom(&format!(
            "primary-mle-prover-0: {DEVICE_OOM_TAG} called `Option::unwrap()` on a `None` value"
        )));
    }
}
