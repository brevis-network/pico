//! CUDA stream/event FFI: `CudaStream`/`CudaEvent` (record/wait/synchronize), the per-thread
//! default stream (`cudaStreamPerThread`) synced via `current_stream_sync`, and a thread-local
//! `CudaThreadCleanup` that drains a thread's default stream at exit. `mark_cuda_thread_used` arms
//! the cleanup; `error::CudaError::from_result` calls it on every mapped FFI return code, not only
//! calls routed through `error::check` — including the ~126 kernel bindings under `cuda/**`.
//!
//! `CudaStream`, `CudaEventStatus`'s ordering, and `gpu_metrics_span` are kept although unused
//! elsewhere in-tree; the tests below are their only exercise.
//! (`default_stream_wait` was dropped as unused — `CudaStream::wait` covers the same op.)
//! `current_stream_id` is likewise kept although it has no caller.
//!
//! `device_synchronize` lives here, not in `context.rs`, because this module is the crate's
//! synchronization-FFI surface, while `context.rs` covers device *lifecycle* instead.
//!
//! `CudaEventStatus` orders `Completed < NotReady < Error(_)`; `Ord` treats all `Error`s as equal,
//! so `PartialEq` must too, to keep the `Eq`/`Ord` contracts consistent.
//!
//! Drop policy: best-effort, never panic — a panicking destructor during unwinding aborts the
//! process. Destructors call the raw FFI entry directly, not `check`, to avoid re-entering TLS
//! tracking during teardown; `CudaStream`/`CudaEvent` log a nonzero code, `CudaThreadCleanup`
//! discards it silently.
//!
//! Counterpart: `mle-cpu` runs synchronously, so it has no stream/event abstraction to mirror.

use std::{borrow::Cow, cell::Cell, ffi::c_void};

use crate::runtime::error::{check, CudaError};

#[link(name = "cudart")]
extern "C" {
    fn cudaDeviceSynchronize() -> i32;
    fn cudaEventCreate(out: *mut cudaEvent_t) -> i32;
    fn cudaEventDestroy(ev: cudaEvent_t) -> i32;
    fn cudaEventElapsedTime(out_ms: *mut f32, from: cudaEvent_t, to: cudaEvent_t) -> i32;
    fn cudaEventQuery(ev: cudaEvent_t) -> i32;
    fn cudaEventRecord(ev: cudaEvent_t, on_stream: cudaStream_t) -> i32;
    fn cudaEventSynchronize(ev: cudaEvent_t) -> i32;
    fn cudaStreamCreate(out: *mut cudaStream_t) -> i32;
    fn cudaStreamDestroy(s: cudaStream_t) -> i32;
    fn cudaStreamGetId(s: cudaStream_t, out_id: *mut CudaStreamId) -> i32;
    fn cudaStreamSynchronize(s: cudaStream_t) -> i32;
    fn cudaStreamWaitEvent(s: cudaStream_t, ev: cudaEvent_t, flags: u32) -> i32;
}

pub fn device_synchronize() -> Result<(), CudaError> {
    // SAFETY: `cudaDeviceSynchronize` has no preconditions beyond a live CUDA context.
    check(unsafe { cudaDeviceSynchronize() })
}

#[allow(non_camel_case_types)]
pub type cudaStream_t = *mut c_void;

pub struct CudaStream {
    stream: cudaStream_t,
}

// SAFETY: `cudaStream_t` is a process-wide handle; the CUDA runtime API is thread-safe and
// permits recording/synchronizing a stream from any thread. The struct holds no host data.
unsafe impl Send for CudaStream {}
unsafe impl Sync for CudaStream {}

impl CudaStream {
    /// Creates a new non-blocking CUDA stream.
    pub fn new() -> Result<Self, CudaError> {
        let mut stream: cudaStream_t = std::ptr::null_mut();
        // SAFETY: `&mut stream` points to a live local for the duration of the call.
        check(unsafe { cudaStreamCreate(&mut stream) })?;
        Ok(Self { stream })
    }

    /// Returns the underlying `cudaStream_t`.
    #[inline]
    pub fn as_raw(&self) -> cudaStream_t {
        self.stream
    }

    /// Synchronize this stream.
    pub fn synchronize(&self) -> Result<(), CudaError> {
        // SAFETY: `self.stream` is live — created in `new`, destroyed only in `drop`.
        check(unsafe { cudaStreamSynchronize(self.stream) })
    }

    /// Wait for the given event.
    pub fn wait(&self, event: &CudaEvent) -> Result<(), CudaError> {
        // SAFETY: `self.stream` and `event.handle` are both live (same `new`/`drop` argument).
        check(unsafe { cudaStreamWaitEvent(self.stream, event.handle, 0) })
    }
}

impl Drop for CudaStream {
    fn drop(&mut self) {
        if !self.stream.is_null() {
            // Raw call, not `self.synchronize()`, to skip TLS tracking during drop; best-effort.
            // SAFETY (both calls below): `self.stream` is non-null (checked above) and live —
            // created in `new`, destroyed only here.
            let sync_code = unsafe { cudaStreamSynchronize(self.stream) };
            if sync_code != 0 {
                tracing::error!(code = sync_code, "CudaStream drop: synchronize failed");
            }
            let destroy_code = unsafe { cudaStreamDestroy(self.stream) };
            if destroy_code != 0 {
                tracing::error!(code = destroy_code, "CudaStream drop: destroy failed");
            }
            self.stream = std::ptr::null_mut();
        }
    }
}

// `(cudaStream_t)0x02` is CUDA's reserved sentinel for the per-thread default stream
// (`driver_types.h`'s `cudaStreamPerThread`) — always valid, no create/destroy needed.
#[allow(non_upper_case_globals)]
pub const cudaStreamPerThread: cudaStream_t = 0x02 as cudaStream_t;

pub type CudaStreamId = u64;

// Kept without a caller — see the module doc.
pub fn current_stream_id() -> Result<CudaStreamId, CudaError> {
    let mut id = 0;
    // SAFETY: `cudaStreamPerThread` is always valid (see above); `&mut id` is a live local.
    check(unsafe { cudaStreamGetId(cudaStreamPerThread, &mut id) })?;
    Ok(id)
}

pub fn current_stream_sync() -> Result<(), CudaError> {
    // SAFETY: `cudaStreamPerThread` is always valid (see above).
    check(unsafe { cudaStreamSynchronize(cudaStreamPerThread) })
}

struct CudaThreadCleanup {
    touched_cuda: Cell<bool>,
}

impl CudaThreadCleanup {
    const fn new() -> Self {
        Self {
            touched_cuda: Cell::new(false),
        }
    }

    fn mark_used(&self) {
        self.touched_cuda.set(true);
    }
}

impl Drop for CudaThreadCleanup {
    fn drop(&mut self) {
        if self.touched_cuda.get() {
            // Raw call (not `check`), per the Drop policy above: best-effort drain before TLS teardown.
            // SAFETY: `cudaStreamPerThread` is always valid (see above).
            let _ = unsafe { cudaStreamSynchronize(cudaStreamPerThread) };
        }
    }
}

thread_local! {
    static CUDA_THREAD_CLEANUP: CudaThreadCleanup = const { CudaThreadCleanup::new() };
}

pub(crate) fn mark_cuda_thread_used() {
    CUDA_THREAD_CLEANUP.with(|cleanup| cleanup.mark_used());
}

/// Opaque CUDA event handle (`cudaEvent_t`).
#[allow(non_camel_case_types)]
pub type cudaEvent_t = *mut c_void;

/// What `cudaEventQuery` reported. Ordered by progress: `Completed < NotReady < Error`, and any
/// two `Error`s compare equal so that `Eq` agrees with `Ord` (see module doc).
#[derive(Debug)]
pub enum CudaEventStatus {
    Completed,
    NotReady,
    Error(CudaError),
}

impl CudaEventStatus {
    fn rank(&self) -> u8 {
        match self {
            CudaEventStatus::Completed => 0,
            CudaEventStatus::NotReady => 1,
            CudaEventStatus::Error(_) => 2,
        }
    }
}

impl PartialEq for CudaEventStatus {
    fn eq(&self, other: &Self) -> bool {
        self.rank() == other.rank()
    }
}

impl Eq for CudaEventStatus {}

impl Ord for CudaEventStatus {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl PartialOrd for CudaEventStatus {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// `cudaSuccess`.
const CUDA_SUCCESS: i32 = 0;
/// `cudaErrorNotReady`: the work captured by the event has not finished yet.
const CUDA_ERROR_NOT_READY: i32 = 600;

#[derive(Debug)]
pub struct CudaEvent {
    handle: cudaEvent_t,
}

// SAFETY: `cudaEvent_t` is a process-wide handle; the CUDA runtime API is thread-safe and
// permits recording/querying/synchronizing an event from any thread. The struct holds no host
// data.
unsafe impl Send for CudaEvent {}
unsafe impl Sync for CudaEvent {}

impl CudaEvent {
    pub fn new() -> Result<Self, CudaError> {
        let mut handle: cudaEvent_t = std::ptr::null_mut();
        // SAFETY: `&mut handle` points to a live local for the duration of the call.
        check(unsafe { cudaEventCreate(&mut handle) })?;
        Ok(Self { handle })
    }

    /// # Safety
    /// `stream` must be a live CUDA stream handle.
    ///
    /// `pub(crate)`, not `pub`: its only caller is `record_and_wait` below, in this same file.
    pub(crate) unsafe fn record(&self, stream: cudaStream_t) -> Result<(), CudaError> {
        check(cudaEventRecord(self.handle, stream))
    }

    pub fn record_on_this(&self) -> Result<(), CudaError> {
        // SAFETY: `self.handle` is live (see `new`/`drop`); `cudaStreamPerThread` is always valid.
        check(unsafe { cudaEventRecord(self.handle, cudaStreamPerThread) })
    }

    pub fn synchronize(&self) -> Result<(), CudaError> {
        // SAFETY: `self.handle` is a live handle per `new`/`drop` above.
        check(unsafe { cudaEventSynchronize(self.handle) })
    }

    /// # Safety
    /// `stream` must be a live CUDA stream handle.
    pub unsafe fn record_and_wait(&self, stream: cudaStream_t) -> Result<(), CudaError> {
        self.record(stream)?;
        check(cudaEventSynchronize(self.handle))
    }

    pub fn status(&self) -> CudaEventStatus {
        // SAFETY: `self.handle` is a live handle per `new`/`drop` above.
        match unsafe { cudaEventQuery(self.handle) } {
            CUDA_SUCCESS => CudaEventStatus::Completed,
            CUDA_ERROR_NOT_READY => CudaEventStatus::NotReady,
            failure => CudaEventStatus::Error(CudaError::new(failure)),
        }
    }

    pub fn completed(&self) -> bool {
        self.status() == CudaEventStatus::Completed
    }
}

impl Drop for CudaEvent {
    fn drop(&mut self) {
        // Best-effort: a panic here would abort during unwinding.
        // SAFETY: `self.handle` is live — created in `new` (the only constructor), destroyed only
        // here.
        let code = unsafe { cudaEventDestroy(self.handle) };
        if code != 0 {
            tracing::error!(code, "CudaEvent drop: destroy failed");
        }
    }
}

/// A GPU-aware span that collects a gauge metric using CUDA events.
pub fn gpu_metrics_span<R, F: FnOnce() -> R>(
    name: impl Into<Cow<'static, str>>,
    f: F,
) -> Result<R, CudaError> {
    let start = CudaEvent::new()?;
    let stop = CudaEvent::new()?;
    // SAFETY: `start.handle` is live (see `new`/`drop`); `cudaStreamPerThread` is always valid.
    unsafe {
        check(cudaEventRecord(start.handle, cudaStreamPerThread))?;
    }
    let res = f();
    // SAFETY: `cudaStreamPerThread` is valid, satisfying `record_and_wait`'s safety contract.
    unsafe { stop.record_and_wait(cudaStreamPerThread)? };

    let mut elapsed_ms = 0f32;
    // SAFETY: `&mut elapsed_ms` is a live local; `start.handle`/`stop.handle` are live (see
    // `new`/`drop`).
    unsafe {
        check(cudaEventElapsedTime(
            &mut elapsed_ms,
            start.handle,
            stop.handle,
        ))?
    };

    metrics::gauge!(name.into()).set(elapsed_ms as f64);
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_lifecycle_reaches_completed() {
        let e = CudaEvent::new().unwrap();
        e.record_on_this().unwrap();
        e.synchronize().unwrap();
        assert!(e.completed());
        assert_eq!(e.status(), CudaEventStatus::Completed);
    }

    #[test]
    fn status_ordering_is_completed_lt_notready_lt_error() {
        use CudaEventStatus::*;
        assert!(Completed < NotReady);
        assert!(NotReady < Error(CudaError::new(1)));
        assert_eq!(Error(CudaError::new(1)), Error(CudaError::new(2))); // errors compare equal
    }

    #[test]
    fn stream_waits_on_event_and_drops_cleanly() {
        let s = CudaStream::new().unwrap();
        let e = CudaEvent::new().unwrap();
        e.record_on_this().unwrap();
        s.wait(&e).unwrap();
        s.synchronize().unwrap();
    } // Drop must not panic

    #[test]
    fn metrics_span_returns_closure_result() {
        let out = gpu_metrics_span("gpu2b_test_span", || 42u64).unwrap();
        assert_eq!(out, 42);
    }
}
