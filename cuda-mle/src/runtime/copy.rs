//! Host↔device memory copies on the per-thread default stream (`cudaStreamPerThread`).
//!
//! `cuda_memcpy` wraps `cudaMemcpyAsync`, selecting the `MemcpyKind` via an exhaustive match on
//! the `SRC_DEVICE`/`DST_DEVICE` const generics. `MemCopyH2D`/`MemCopyD2H`/`MemCopyD2D` are the
//! traits built on top of it.
//!
//! H2D and D2D copies (`copy_to`, `device_copy_to`) are async and return unsynchronized. D2H
//! copies (`to_host`) synchronize before returning, via a `CudaEvent` (`current_copy_event`)
//! recorded and waited on the calling thread's stream. The event is kept per thread *and* per
//! device: both dimensions are load-bearing, for the reasons at `COPY_EVENTS` below.
//!
//! D2H lands in a per-thread **pinned** bounce buffer rather than straight into the returned `Vec`:
//! a pageable destination sends the driver down a staging path that dominates the call, and a riscv
//! prove issues ~16.7k D2H reads with a median size of 32 bytes. `MLE_D2H_PINNED=0` opts out.

use std::{cell::Cell, ffi::c_void, sync::OnceLock};

use crate::runtime::{
    context::get_device,
    d_buffer::DeviceBuffer,
    error::{check, CudaError, MemCopyError},
    stream::{cudaStreamPerThread, cudaStream_t, CudaEvent},
};

/// Direction argument of `cudaMemcpyAsync`; the discriminants are the C enum's values.
#[repr(i32)]
#[non_exhaustive]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum MemcpyKind {
    HostToHost = 0,
    HostToDevice = 1,
    DeviceToHost = 2,
    DeviceToDevice = 3,
    Default = 4,
}

#[link(name = "cudart")]
extern "C" {
    fn cudaHostAlloc(out_ptr: *mut *mut c_void, bytes: usize, flags: u32) -> i32;
    fn cudaMemcpyAsync(
        to: *mut c_void,
        from: *const c_void,
        bytes: usize,
        direction: MemcpyKind,
        on_stream: cudaStream_t,
    ) -> i32;
}

/// `cudaHostAllocDefault`.
const CUDA_HOST_ALLOC_DEFAULT: u32 = 0;

/// Largest read routed through the pinned bounce. Past this the extra host-side copy costs more
/// than the pageable path it replaces, and the reservation stops being worth holding.
const D2H_STAGE_CAP: usize = 1 << 22;

/// Pinned bounce buffers whose thread has ended, as `(ptr, capacity)`; the pointer is carried as a
/// `usize` because a raw pointer is not `Send`.
///
/// Still never freed — `cudaFreeHost` from a TLS destructor races the CUDA runtime's own teardown,
/// which is why this was leaked outright. Handing it on keeps that property and drops the
/// consequence: with a fresh set of threads per block, "one per thread" was one per block.
/// Pinned memory belongs to the process, not to a card, so one list serves every device.
static FREE_D2H_STAGES: std::sync::Mutex<Vec<(usize, usize)>> = std::sync::Mutex::new(Vec::new());

/// Index of the SMALLEST waiting buffer that holds `size` bytes. Smallest, so a 4 KiB request does
/// not consume the 4 MiB one and leave the next large request to page-lock a fresh pin.
///
/// Split out from [`take_free_stage`] so the policy is testable without putting anything into the
/// process-wide list: an address parked there is one any `to_host` in the test binary can pick up
/// and copy into.
fn smallest_fit(free: &[(usize, usize)], size: usize) -> Option<usize> {
    free.iter()
        .enumerate()
        .filter(|(_, &(_, cap))| cap >= size)
        .min_by_key(|(_, &(_, cap))| cap)
        .map(|(i, _)| i)
}

/// Take the smallest waiting buffer that holds `size` bytes, or `None` when none does.
fn take_free_stage(size: usize) -> Option<(*mut c_void, usize)> {
    let mut free = FREE_D2H_STAGES.lock().ok()?;
    let idx = smallest_fit(&free, size)?;
    let (ptr, cap) = free.swap_remove(idx);
    Some((ptr as *mut c_void, cap))
}

fn put_free_stage(ptr: *mut c_void, cap: usize) {
    if ptr.is_null() {
        return;
    }
    if let Ok(mut free) = FREE_D2H_STAGES.lock() {
        free.push((ptr as usize, cap));
    }
}

/// This thread's pinned bounce buffer, handed back when the thread ends.
struct D2hStage(Cell<(*mut c_void, usize)>);

impl Drop for D2hStage {
    fn drop(&mut self) {
        let (ptr, cap) = self.0.get();
        if ptr.is_null() {
            return;
        }
        // Drained first. `to_host` normally waits on its own copy event before reading the buffer,
        // but an error return between enqueueing the copy and that wait leaves the copy landing in
        // a buffer this is about to hand to another thread.
        // Ignored per the Drop policy in `runtime::stream`'s module doc: best-effort, never
        // panic — a thread on its way out must not take the process with it.
        let _ = crate::runtime::stream::current_stream_sync();
        put_free_stage(ptr, cap);
    }
}

thread_local! {
    /// Per-thread pinned bounce buffer for D2H, as `(ptr, capacity)`. See [`FREE_D2H_STAGES`] for
    /// why it outlives the thread but not the thread's block.
    static D2H_STAGE: D2hStage = const { D2hStage(Cell::new((std::ptr::null_mut(), 0))) };
}

fn d2h_pinned_enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| !std::env::var("MLE_D2H_PINNED").is_ok_and(|v| v == "0"))
}

/// A pinned staging pointer with room for `size` bytes, or `None` to use the caller's own buffer.
/// `None` on allocation failure is not an error path: the pageable copy it falls back to is exactly
/// what this is trying to improve on.
fn d2h_stage(size: usize) -> Option<*mut c_void> {
    if size > D2H_STAGE_CAP || !d2h_pinned_enabled() {
        return None;
    }
    // `try_with`, not `with`: these thread-locals gained a `Drop`, so a call made while this
    // thread's TLS is being torn down would panic where it used to be infallible. Falling back to
    // the pageable path is exactly what `None` already means here.
    D2H_STAGE
        .try_with(|stage| {
            let (ptr, cap) = stage.0.get();
            if cap >= size {
                return Some(ptr);
            }
            let new_cap = size.next_power_of_two().max(4096);
            // An ended thread's buffer before a fresh pin: `cudaHostAlloc` page-locks, which is the
            // expensive half of this path.
            let (p, p_cap) = match take_free_stage(new_cap) {
                Some(reused) => reused,
                None => {
                    let mut p: *mut c_void = std::ptr::null_mut();
                    // SAFETY: `p` is a valid out-param; `cudaHostAlloc` either writes a pinned
                    // allocation of `new_cap` bytes or returns non-zero and leaves `p` untouched.
                    if unsafe { cudaHostAlloc(&mut p, new_cap, CUDA_HOST_ALLOC_DEFAULT) } != 0
                        || p.is_null()
                    {
                        return None;
                    }
                    (p, new_cap)
                }
            };
            // The outgrown one is still a perfectly good smaller buffer for someone else —
            // after the same drain, and for the same reason, as the hand-back in `Drop`.
            if !ptr.is_null() {
                let _ = crate::runtime::stream::current_stream_sync();
            }
            put_free_stage(ptr, cap);
            stage.0.set((p, p_cap));
            Some(p)
        })
        .ok()
        .flatten()
}

/// FFI binding for `cudaMemcpyAsync` on the default CUDA stream.
///
/// `copy_to`/`to_host`/`device_copy_to` bypass this generic; each has one fixed, known direction.
///
/// # Safety
/// `dst`, `src` and `size_bytes` must meet every precondition `cudaMemcpyAsync` documents.
pub unsafe fn cuda_memcpy<const SRC_DEVICE: bool, const DST_DEVICE: bool>(
    dst: *mut c_void,
    src: *const c_void,
    size_bytes: usize,
) -> Result<(), MemCopyError> {
    let kind = match (SRC_DEVICE, DST_DEVICE) {
        (false, false) => MemcpyKind::HostToHost,
        (false, true) => MemcpyKind::HostToDevice,
        (true, false) => MemcpyKind::DeviceToHost,
        (true, true) => MemcpyKind::DeviceToDevice,
    };
    check(unsafe { cudaMemcpyAsync(dst, src, size_bytes, kind, cudaStreamPerThread) })
        .map_err(MemCopyError::from)
}

// Host -> Device
pub trait MemCopyH2D<T> {
    /// Enqueue an async H2D copy on the per-thread default stream and return **without
    /// synchronizing**. The source slice is read asynchronously, so the caller must keep it
    /// alive and unmodified until the stream is synchronized (`current_stream_sync`).
    fn copy_to(&self, dst: &mut DeviceBuffer<T>) -> Result<(), MemCopyError>;
    fn to_device(&self) -> Result<DeviceBuffer<T>, MemCopyError>;
}

impl<T> MemCopyH2D<T> for [T] {
    fn copy_to(&self, dst: &mut DeviceBuffer<T>) -> Result<(), MemCopyError> {
        if self.len() > dst.len() {
            return Err(MemCopyError::SizeMismatch {
                operation: "copy_to_device",
                src_len: self.len(),
                dst_len: dst.len(),
            });
        }
        let size_bytes = std::mem::size_of_val(self);
        // SAFETY: `self.as_ptr()`/`dst.as_mut_raw_ptr()` are valid host/device pointers for
        // `size_bytes` bytes (length checked above); `cudaMemcpyHostToDevice` matches the
        // actual direction.
        check(unsafe {
            cudaMemcpyAsync(
                dst.as_mut_raw_ptr(),
                self.as_ptr() as *const c_void,
                size_bytes,
                MemcpyKind::HostToDevice,
                cudaStreamPerThread,
            )
        })
        .map_err(MemCopyError::from)
    }

    fn to_device(&self) -> Result<DeviceBuffer<T>, MemCopyError> {
        let mut dst = DeviceBuffer::with_capacity(self.len());
        self.copy_to(&mut dst)?;
        Ok(dst)
    }
}

// Device -> Host
pub trait MemCopyD2H<T> {
    fn to_host(&self) -> Result<Vec<T>, MemCopyError>;
}

/// Max CUDA devices for the per-thread, per-device copy-sync events.
const MAX_CUDA_DEVICES: usize = 16;

/// Copy-sync events whose thread has ended, per device. Same hand-back as [`FREE_D2H_STAGES`], and
/// per device because a CUDA event may only be recorded and waited on the device that created it.
static FREE_COPY_EVENTS: [std::sync::Mutex<Vec<&'static CudaEvent>>; MAX_CUDA_DEVICES] =
    [const { std::sync::Mutex::new(Vec::new()) }; MAX_CUDA_DEVICES];

/// A thread's copy events, and the hand-back that runs when it ends.
struct CopyEvents([Cell<Option<&'static CudaEvent>>; MAX_CUDA_DEVICES]);

impl Drop for CopyEvents {
    fn drop(&mut self) {
        for (device_id, slot) in self.0.iter().enumerate() {
            let Some(event) = slot.take() else { continue };
            // No wait needed: every use is `record_and_wait`, so nothing this thread recorded is
            // still outstanding once it can end.
            if let Ok(mut free) = FREE_COPY_EVENTS[device_id].lock() {
                free.push(event);
            }
        }
    }
}

thread_local! {
    /// CUDA copy-sync events, per thread and per device. Both dimensions are load-bearing: a CUDA
    /// event is **device-specific** (recording or waiting one on another device fails with
    /// `cudaErrorInvalidResourceHandle`), and one shared per device would put every thread's D2H
    /// wait behind whichever copy is already in flight on that card.
    ///
    /// Still never destroyed, for `D2H_STAGE`'s reason: `cudaEventDestroy` from a TLS destructor
    /// races the CUDA runtime's own teardown. Handed to the next thread instead — "one per thread
    /// per device" bounded nothing once the prover began starting a fresh set of threads per block.
    static COPY_EVENTS: CopyEvents =
        const { CopyEvents([const { Cell::new(None) }; MAX_CUDA_DEVICES]) };
}

fn current_copy_event() -> Result<&'static CudaEvent, CudaError> {
    let dev = get_device()? as usize;
    assert!(
        dev < MAX_CUDA_DEVICES,
        "CUDA device index {dev} exceeds MAX_CUDA_DEVICES ({MAX_CUDA_DEVICES}); raise the constant"
    );
    // `try_with` for `d2h_stage`'s reason; a thread tearing down gets a fresh leaked event rather
    // than a panic, which is what this did for every thread before it recycled them.
    COPY_EVENTS
        .try_with(|events| {
            if let Some(event) = events.0[dev].get() {
                return Ok(event);
            }
            // An ended thread's event before creating one.
            let event: &'static CudaEvent =
                match FREE_COPY_EVENTS[dev].lock().ok().and_then(|mut f| f.pop()) {
                    Some(event) => event,
                    None => Box::leak(Box::new(CudaEvent::new()?)),
                };
            events.0[dev].set(Some(event));
            Ok(event)
        })
        .unwrap_or_else(|_| Ok(Box::leak(Box::new(CudaEvent::new()?))))
}

impl<T> MemCopyD2H<T> for DeviceBuffer<T> {
    fn to_host(&self) -> Result<Vec<T>, MemCopyError> {
        let mut host_vec = Vec::with_capacity(self.len());
        let size_bytes = std::mem::size_of::<T>() * self.len();

        // Bounce through the thread's pinned buffer and memcpy on the host, where the scalar-sized
        // tail is free; see the module docs for why the pageable destination is the expensive part.
        let stage = d2h_stage(size_bytes);
        let dst = stage.unwrap_or(host_vec.as_mut_ptr() as *mut c_void);

        // SAFETY: `self.as_raw_ptr()`/`dst` are valid device/host pointers sized for `size_bytes`,
        // matching `cudaMemcpyDeviceToHost`; `dst` is unread until synced below.
        check(unsafe {
            cudaMemcpyAsync(
                dst,
                self.as_raw_ptr(),
                size_bytes,
                MemcpyKind::DeviceToHost,
                cudaStreamPerThread,
            )
        })?;
        unsafe {
            current_copy_event()?.record_and_wait(cudaStreamPerThread)?;

            // SAFETY: `record_and_wait` completed the copy, so `size_bytes` of the staging buffer
            // are initialized, and it is this thread's own allocation so it cannot alias the
            // freshly-reserved `host_vec`. Either way `host_vec`'s first `self.len()` elements are
            // initialized by the time `set_len` publishes them.
            if let Some(src) = stage {
                std::ptr::copy_nonoverlapping(
                    src as *const u8,
                    host_vec.as_mut_ptr() as *mut u8,
                    size_bytes,
                );
            }
            host_vec.set_len(self.len());
        }

        Ok(host_vec)
    }
}

pub trait MemCopyD2D<T> {
    fn device_copy(&self) -> Result<DeviceBuffer<T>, MemCopyError>;
    fn device_copy_to(&self, dst: &mut DeviceBuffer<T>) -> Result<(), MemCopyError>;
}

impl<T> MemCopyD2D<T> for DeviceBuffer<T> {
    fn device_copy(&self) -> Result<DeviceBuffer<T>, MemCopyError> {
        let mut dst = DeviceBuffer::<T>::with_capacity(self.len());
        self.device_copy_to(&mut dst)?;
        Ok(dst)
    }

    fn device_copy_to(&self, dst: &mut DeviceBuffer<T>) -> Result<(), MemCopyError> {
        if self.len() > dst.len() {
            return Err(MemCopyError::SizeMismatch {
                operation: "device_copy_to",
                src_len: self.len(),
                dst_len: dst.len(),
            });
        }
        let size_bytes = std::mem::size_of::<T>() * self.len();

        // SAFETY: `self.as_raw_ptr()`/`dst.as_mut_raw_ptr()` are valid device pointers for
        // `size_bytes` bytes (length checked above); `cudaMemcpyDeviceToDevice` matches the
        // actual direction.
        check(unsafe {
            cudaMemcpyAsync(
                dst.as_mut_raw_ptr(),
                self.as_raw_ptr(),
                size_bytes,
                MemcpyKind::DeviceToDevice,
                cudaStreamPerThread,
            )
        })
        .map_err(MemCopyError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::d_buffer::DeviceBuffer;

    /// These tests share one process-wide free list and `cargo test` runs them in parallel, so
    /// each takes this first. Sizes alone do not isolate them: `take_free_stage` hands out the
    /// smallest buffer that FITS, so a sibling asking for 4 KiB takes a 2 MiB entry whenever that
    /// is the only one waiting -- which it is, until some test has left a small one behind.
    static SERIALISE: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// `(address, capacity)` of every bounce waiting in the free list.
    fn waiting_stages() -> Vec<(usize, usize)> {
        FREE_D2H_STAGES
            .lock()
            .map_or_else(|_| Vec::new(), |v| v.clone())
    }

    /// Nothing legitimately returns `None` from [`d2h_stage`] except pinning being switched off.
    /// A failed `cudaHostAlloc` reaches the same `None`, and a test that passed on it would
    /// establish nothing on any box where page-locking is broken.
    fn skip_only_if_pinning_is_off(staged: Option<usize>) -> Option<usize> {
        if staged.is_none() {
            assert!(
                !d2h_pinned_enabled(),
                "pinning is enabled but no bounce was staged: cudaHostAlloc failed"
            );
        }
        staged
    }

    /// The pinned bounce a finished thread used has to be waiting for the next one, AT ITS FULL
    /// CAPACITY. The prover starts a fresh set of threads for every block it proves, so a buffer
    /// that dies with its thread is one page-locked pin per block.
    ///
    /// The capacity is asserted and not just the address, because a hand-back that files the
    /// buffer under a capacity below its own leaves it failing `take_free_stage`'s fit test for
    /// the rest of the process: the address is in the list, nothing can ever take it, and the leak
    /// is back with the test still green.
    #[test]
    fn an_exited_thread_hands_its_pinned_bounce_back() {
        let _serial = SERIALISE.lock();
        const BIG: usize = 1 << 21;
        let used = std::thread::spawn(|| d2h_stage(BIG).map(|p| p as usize))
            .join()
            .unwrap();
        let Some(used) = skip_only_if_pinning_is_off(used) else {
            return;
        };
        let Some((_, cap)) = waiting_stages().into_iter().find(|&(p, _)| p == used) else {
            panic!("the pinned bounce a finished thread used did not come back");
        };
        assert!(
            cap >= BIG,
            "handed back under capacity {cap}, below the {BIG} bytes it actually holds"
        );
    }

    /// The other half. A hand-back bounds nothing unless something takes it: the stream pool has
    /// both halves tested and this one had only the first.
    #[test]
    fn a_later_thread_takes_a_recycled_bounce() {
        let _serial = SERIALISE.lock();
        const BIG: usize = 1 << 21;
        let first = std::thread::spawn(|| d2h_stage(BIG).map(|p| p as usize))
            .join()
            .unwrap();
        let Some(first) = skip_only_if_pinning_is_off(first) else {
            return;
        };
        // Snapshot rather than assert on `first` alone: an equally-sized entry left by an earlier
        // test is an equally valid thing for the next thread to take.
        let waiting: Vec<usize> = waiting_stages().into_iter().map(|(p, _)| p).collect();
        assert!(
            waiting.contains(&first),
            "the first thread's bounce is not waiting"
        );
        let second = std::thread::spawn(|| d2h_stage(BIG).map(|p| p as usize))
            .join()
            .unwrap();
        assert!(
            second.is_some_and(|p| waiting.contains(&p)),
            "a later thread page-locked a fresh bounce while {} were waiting",
            waiting.len()
        );
    }

    /// The smallest buffer that fits is the one handed out, so a 4 KiB request does not consume a
    /// multi-megabyte pin and leave the next large request to page-lock a fresh one. Nothing else
    /// here would notice the policy inverting.
    ///
    /// Asserted on the pure selector, never through the process-wide list: an address parked there
    /// is one any `to_host` anywhere in this test binary can take and copy into, and none of those
    /// callers holds a lock of ours.
    #[test]
    fn the_smallest_fitting_bounce_is_the_one_taken() {
        let free = [(0x1000, 1 << 22), (0x2000, 4096), (0x3000, 1 << 21)];
        assert_eq!(
            smallest_fit(&free, 4096),
            Some(1),
            "a 4 KiB request did not take the 4 KiB bounce"
        );
        assert_eq!(
            smallest_fit(&free, 1 << 20),
            Some(2),
            "a 1 MiB request skipped the 2 MiB bounce for a larger one"
        );
        assert_eq!(
            smallest_fit(&free, 1 << 23),
            None,
            "an 8 MiB request was answered from buffers that cannot hold it"
        );
    }

    /// The copy-sync event a finished thread used has to be waiting for the next one, per device:
    /// a CUDA event may only be recorded and waited on the device that created it. Untested until
    /// now, and it is the same hand-back as the bounce above.
    #[test]
    fn an_exited_thread_hands_its_copy_event_back() {
        let _serial = SERIALISE.lock();
        let (dev, used) = std::thread::spawn(|| {
            let event = current_copy_event().expect("a copy event on this thread");
            let dev = get_device().expect("a bound device") as usize;
            (dev, event as *const CudaEvent as usize)
        })
        .join()
        .unwrap();
        let waiting: Vec<usize> = FREE_COPY_EVENTS[dev].lock().map_or_else(
            |_| Vec::new(),
            |v| v.iter().map(|e| *e as *const CudaEvent as usize).collect(),
        );
        assert!(
            waiting.contains(&used),
            "the copy event a finished thread used did not come back on card {dev}"
        );

        // And under card 1's index where a second device exists: an event may only be recorded on
        // the device that created it, so one filed under the wrong index hands the next thread an
        // event it cannot use. Gated on the visible device count rather than on `set_device`
        // failing, because the latter cannot tell a one-card box from a real failure on a two-card
        // one, and would delete the section silently -- the very thing this shape exists to avoid.
        if crate::runtime::memory_manager::visible_device_count() >= 2 {
            let (dev1, used1) = std::thread::spawn(|| {
                crate::runtime::context::set_device(1).expect("bind card 1");
                let event = current_copy_event().expect("a copy event on card 1");
                (
                    get_device().expect("a bound device") as usize,
                    event as *const CudaEvent as usize,
                )
            })
            .join()
            .unwrap();
            assert_eq!(
                dev1, 1,
                "set_device(1) succeeded but the thread reads card {dev1}"
            );
            let waiting1: Vec<usize> = FREE_COPY_EVENTS[dev1].lock().map_or_else(
                |_| Vec::new(),
                |v| v.iter().map(|e| *e as *const CudaEvent as usize).collect(),
            );
            assert!(
                waiting1.contains(&used1),
                "a card-1 copy event did not come back on card 1's list"
            );
        }
    }

    #[test]
    fn test_mem_copy() {
        // Our source data on the host
        let h = vec![1, 2, 3, 4, 5];

        // 1) Copy to a newly allocated device buffer
        let d1 = h.to_device().unwrap();

        // 2) Create another device buffer of the same size
        let mut d2 = DeviceBuffer::<i32>::with_capacity(h.len());

        // 3) Copy into that existing buffer
        h.copy_to(&mut d2).unwrap();

        // 4) Copy both buffers back to host
        let h1 = d1.to_host().unwrap();
        let h2 = d2.to_host().unwrap();

        assert_eq!(h, h1, "First device buffer mismatch");
        assert_eq!(h, h2, "Second device buffer mismatch");
    }

    #[test]
    fn copy_to_rejects_oversized_source() {
        let h = [1i32; 8];
        let mut d = DeviceBuffer::<i32>::with_capacity(4);
        match h.copy_to(&mut d) {
            Err(MemCopyError::SizeMismatch {
                src_len: 8,
                dst_len: 4,
                ..
            }) => {}
            other => panic!("expected SizeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn device_copy_round_trips_and_rejects_mismatch() {
        let h: Vec<u32> = (0..1024).collect();
        let d1 = h.to_device().unwrap();
        let d2 = d1.device_copy().unwrap();
        assert_eq!(d2.to_host().unwrap(), h);

        let mut small = DeviceBuffer::<u32>::with_capacity(16);
        match d1.device_copy_to(&mut small) {
            Err(MemCopyError::SizeMismatch {
                src_len: 1024,
                dst_len: 16,
                ..
            }) => {}
            other => panic!("expected SizeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn concurrent_round_trips_are_element_wise_isolated() {
        // Each thread's copies ride its own `cudaStreamPerThread` and are awaited on its own
        // copy-sync `CudaEvent`, so no thread waits on another's copy: 8 threads round-trip
        // distinct bit patterns concurrently, and a routing bug (e.g. waiting the wrong device's
        // event) or a premature `set_len` would surface as a mismatched element on some thread.
        // (Nothing serialises this module's tests globally, so a sibling may run alongside; one
        // test managing its own threads is still deterministic in pass/fail.)
        std::thread::scope(|s| {
            for t in 0..8u32 {
                s.spawn(move || {
                    for round in 0..16u32 {
                        let h: Vec<u32> = (0..4096).map(|i| i ^ (t << 16) ^ (round << 8)).collect();
                        let d = h.to_device().unwrap();
                        assert_eq!(d.to_host().unwrap(), h, "thread {t} round {round}");
                    }
                });
            }
        });
    }
}
