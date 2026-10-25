//! CUDA device-context management: current-device query, primary-context creation, device reset
//! and the reset epoch (used to invalidate cached device state). GPU-only process state — no
//! `mle-cpu` counterpart.

use std::{
    ffi::c_void,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::runtime::error::{check, CudaError};

#[link(name = "cudart")]
extern "C" {
    fn cudaFree(dev_ptr: *mut c_void) -> i32;
    fn cudaGetDevice(device: *mut i32) -> i32;
    fn cudaSetDevice(device: i32) -> i32;
    fn cudaDeviceReset() -> i32;
}

pub fn get_device() -> Result<i32, CudaError> {
    let mut device = 0;
    // SAFETY: `&mut device` points to a valid, uniquely-owned stack `i32`; `cudaGetDevice`
    // writes through it once and takes no other pointer.
    unsafe {
        check(cudaGetDevice(&mut device))?;
    }
    assert!(device >= 0);
    Ok(device)
}

/// Bind the calling thread to `device` (and force its primary context into existence).
///
/// Exists for in-process multi-card: every device-touching thread binds itself at spawn, so
/// `CUDA_VISIBLE_DEVICES` pinning no longer implies "device 0 is
/// the only target". (An earlier `set_device` was removed exactly because single-card
/// pinning made it a no-op; this is the case it exists for.) Threads that only ever run on the
/// process default keep using [`ensure_device_context`].
pub fn set_device(device: i32) -> Result<(), CudaError> {
    unsafe {
        check(cudaSetDevice(device))?;
        // Same no-op trick as `ensure_device_context`: force the primary context now, on this
        // thread, rather than inside the first kernel launch.
        check(cudaFree(std::ptr::null_mut()))?;
    }
    Ok(())
}

/// Ensure the calling thread has a live CUDA primary context and return the bound device id.
///
/// This does **not** change which device is current: it forces context creation via a no-op
/// `cudaFree(null)`, then re-binds the already-current device. (The earlier name `set_device`
/// implied a switch that never happened — [`set_device`] above is the explicit switch.)
pub fn ensure_device_context() -> Result<i32, CudaError> {
    let mut device = 0;
    unsafe {
        // SAFETY: `cudaFree(null)` is documented as a no-op that only forces primary-context
        // creation; passing null cannot free a live allocation.
        check(cudaFree(std::ptr::null_mut()))?;
        // SAFETY: same pointer invariant as `get_device`; `cudaSetDevice` then re-binds the
        // device value `cudaGetDevice` just returned, so it cannot switch devices.
        check(cudaGetDevice(&mut device))?;
        check(cudaSetDevice(device))?;
    }
    Ok(device)
}

static DEVICE_RESET_EPOCH: AtomicU64 = AtomicU64::new(0);

pub fn device_reset_epoch() -> u64 {
    DEVICE_RESET_EPOCH.load(Ordering::Acquire)
}

/// Resets the current CUDA device via `cudaDeviceReset()` and bumps the reset epoch that
/// `device_reset_epoch()` exposes.
///
/// Deliberately unwired (zero callers): `copy::COPY_EVENTS` is keyed by device index alone, not
/// `(device, epoch)` like the caches this epoch gates, so a live reset would dangle the cached
/// `CudaEvent` of every thread that has copied from that device. Do not wire this up without
/// first epoch-keying `COPY_EVENTS`.
pub fn reset_device() -> Result<(), CudaError> {
    // SAFETY: `cudaDeviceReset` takes no pointer arguments, so the call is unconditionally
    // memory-safe; the logical invariant (no un-epoch-keyed cached handle survives it) is why
    // this function stays unwired.
    check(unsafe { cudaDeviceReset() })?;
    DEVICE_RESET_EPOCH.fetch_add(1, Ordering::AcqRel);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_init_is_idempotent_and_matches_current_device() {
        let d1 = ensure_device_context().unwrap();
        let d2 = ensure_device_context().unwrap();
        assert_eq!(d1, d2);
        assert_eq!(get_device().unwrap(), d1);
        assert!(d1 >= 0);
    }
    // Deliberately NO test of `reset_device()`: it would invalidate every thread's cached
    // copy-sync events (`copy::COPY_EVENTS`) for every subsequent test in the same process.
}
