//! Thin per-device GPU allocator + usage tracker.
//!
//! # Design conclusion
//!
//! **The external-pool scheme is final. Keep it, keep the fallback, and do not resurrect a
//! self-managed pool.** Rationale and the limits of the design are recorded below, because the
//! choice constrains the runtime pool hookup.
//!
//! ## The scheme
//!
//! [`d_malloc`]/[`d_free`] wrap `cudaMallocFromPoolAsync`/`cudaFreeAsync`. Allocations are drawn
//! from an **external** `cudaMemPool_t` once one is registered via [`set_external_pool`] (pico's
//! global pool, so the MLE prover and pico's GPU trace-gen share one reservation), and from the
//! device's default pool via `cudaMallocAsync` otherwise. State is per CUDA device
//! ([`MAX_CUDA_DEVICES`] singletons keyed by the current device), so each card gets its own pool.
//! Per device, not per thread: however many prover lanes a card runs — two by default, one when
//! the prover's lane switch is off — they share one manager, and so share its peak and its metrics.
//!
//! Why the CUDA async-pool allocator rather than anything of our own: it already provides
//! stream-ordered reuse, an effectively infinite release threshold (so the steady state is
//! allocation-free), and — the point that matters for pico — a *shared* reservation, which is the
//! only way two subsystems in one process avoid each reserving a private slab of a 32 GB card.
//!
//! ## Keep the fallback
//!
//! Yes. The `cudaMallocAsync` path is what makes `cuda-mle` buildable and testable standalone:
//! the whole `cargo test -p cuda-mle` suite runs with no pool registered, and
//! `tests/from_pool.rs` covers the pool-routed path by registering the device's *default* pool.
//! It costs one branch in [`MemoryManager::raw_alloc`] and removes a hard dependency on pico's
//! initialization order. Callers that require the shared pool assert it via
//! [`external_pool_is_set`] instead of the allocator failing closed.
//!
//! ## Limit: `d_malloc` is NOT the crate's only allocation site
//!
//! Rust-side it is — every `DeviceBuffer` goes through it. But several `.cu` translation units
//! allocate device memory directly, which **bypasses both the registered pool and this tracker**.
//! Six files, 14 allocation sites, counted at this HEAD (`grep cudaMalloc cuda/**`, comment
//! lines excluded):
//!
//! - `src/prover/ntt/rs_ntt_fastpath.cu` (5): RS twiddle/Shoup/factor tables and `rs2_tile_scratch`
//!   use plain `cudaMalloc` (deliberately: the pointer is baked into captured CUDA graphs, so it
//!   must survive graph replay); `kb_rs_dense_scratch` uses `cudaMallocAsync`.
//! - `src/logup_zerocheck/batch_mle.cu` (4): packed-rule caches (`cudaMalloc`) and per-launch
//!   pointer arrays (`cudaMallocAsync`).
//! - `src/logup_zerocheck/batch_mle_monomial.cu` (2): a monomial table (`cudaMalloc`) and a
//!   per-launch ref array (`cudaMallocAsync`).
//! - `src/sumcheck.cu` (1): a small per-thread block-prefix scratch (`cudaMalloc`).
//! - `src/batch_ntt_small.cu` (1): `kb_rs_dense_scratch` (`cudaMallocAsync`).
//! - `src/logup_zerocheck/zerocheck_round0.cu` (1): a packed-rule cache (`cudaMalloc`).
//!
//! Consequences, and why this is acceptable rather than a blocker:
//!
//! 1. These are grow-once caches or bounded per-launch scratch, not per-round allocations, so they
//!    are a fixed overhead rather than a leak. The per-thread ones are bounded only because they
//!    are handed to the next thread on that card rather than left behind when a thread exits —
//!    without that, one process proving a list of blocks accumulates them per block.
//! 2. They are invisible to [`tracked_current_bytes`], so that figure is this crate's
//!    *Rust-side* working set, not a device budget. Budget against [`device_mem_info`], which is
//!    what the driver enforces — this is why the [`MemTracker`] lines and the `gpu_mem.device_*`
//!    gauges report device-wide numbers alongside the tracked ones.
//! 3. The `cudaMallocAsync` ones land in the device **default** pool, not the registered external
//!    pool. Through `oom_heal.cuh` the two whose failure is fatal retry once after
//!    [`mle_oom_trim_pools`]; the ones with a fallback only leave the thread's last-error slot
//!    clean and say so -- counted per card for the per-launch tables ([`mle_oom_note_fallback`]),
//!    every time for a grow-once cache, whose failed build is kept and leaves its AIR on the
//!    slower path ([`mle_oom_note_cache_fallback`]).
//!    That pool therefore needs the same retaining release threshold, per device — see
//!    [`ensure_default_pool_retains`], the process's **only** writer of that attribute, called
//!    from `init_mle_gpu_pool` per card and backstopped by `manager_for` before the first
//!    allocation lands. [`MemoryManager::trim_pool`] then trims both pools rather than only
//!    the external one — otherwise the OOM self-heal below would be weakest in exactly the
//!    configuration production runs in.
//!
//! Moving them behind `d_malloc` would mean plumbing a Rust-owned scratch allocator through the
//! FFI for buffers whose lifetime is inside a single launcher, and would break the graph-replay
//! requirement for `rs2_tile_scratch`. Not worth it; the accounting note above is the fix.
//!
//! ## Peak / fragmentation when sharing pico's reserve
//!
//! The pool never returns memory on its own, so a large request (e.g. the ~15 GiB RS codeword on
//! a reth chunk) can fail on fragmentation while the driver still has free memory. [`d_malloc`]
//! handles that in-band: on a failed allocation it synchronizes so in-flight `cudaFreeAsync`s
//! land, trims the pools back to the driver, and retries **once**; if the request is still out of
//! memory it waits, outside the manager lock, for another lane on the card to free some
//! (`MLE_OOM_WAIT_MS`, default 5 s) before failing. That converts the common fragmentation OOM, and
//! a collision with the other lane's peak, into a latency blip instead of a failed prove. The
//! large cross-round buffers that would otherwise thrash this path are cached by their owners
//! (see `logup_zerocheck`'s GKR-leaf and eq-buffer caches) rather than re-allocated per round.
//!
//! ## Rejected alternatives
//!
//! - **Self-managed VPMM pool** (CUDA VMM `cuMemCreate`/`cuMemMap` paging; the prototype's
//!   `vm_pool.rs` + `vpmm_shim.cu`, ~940 lines + a 701-line test module). Deleted, not refactored:
//!   it re-implemented what the driver's async pool already does, could not share a reservation
//!   with pico (the whole point of the external pool), and its defragmentation showed up as
//!   millisecond-scale stalls on the prove path. Nothing here needs the one thing VMM uniquely
//!   buys — a stable virtual address across remapping.
//! - **Pool-only, no fallback**: rejected, see "Keep the fallback".
//! - **A scratch cache in FRONT of the pool, keyed on (thread, exact size)**: built and
//!   **rejected** — it panics a four-card prove at every cap tried (512, 256, 64 MiB) where the
//!   control is clean. The binding resource is **arenas, not bytes**: `cudaMemPoolTrimTo` returns
//!   only a *wholly* free arena, so many small parked buffers each pin one. 64 MiB is 0.2 % of the
//!   card and still crashes, so it is not a tuning problem.
//! - **A custom sub-allocator on the pool**: no longer premature — the above is the argument *for*
//!   it. Anything holding pool memory must occupy **one** region, not be scattered. Unpriced.
//!
//! The free VRAM here is *working memory*: `d_malloc`'s OOM self-heal already fires ~14 times
//! per prove with no cache at all. **Gate a pool-holding change on trim-and-retry counts,
//! `succeeded after waiting` lines and panic counts, never on a peak watermark** — a watermark
//! passes a configuration that crashes.
//!
//! ## Per-call streams (recorded, not done here)
//!
//! Threading a per-call `cudaStream_t`/`GpuDeviceCtx` through the whole device surface is a
//! possible refactor that this crate has not done: everything runs on `cudaStreamPerThread`. The
//! root is [`crate::runtime::d_buffer`] (`with_capacity`/`to_host` would gain `_on(ctx)` variants),
//! and porting it touches every `extern "C"` declaration and safe wrapper under `src/cuda/` plus
//! their callers — a crate-wide contract change, not a memory-manager change. Left undone
//! deliberately; per-thread streams already give the isolation the prover needs.

use std::{
    collections::HashMap,
    ffi::c_void,
    ptr::NonNull,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bytesize::ByteSize;

use crate::runtime::{
    error::{check, MemoryError},
    stream::{cudaStreamPerThread, cudaStream_t, device_synchronize},
};

/// Opaque CUDA runtime memory-pool handle (`cudaMemPool_t`).
#[allow(non_camel_case_types)]
pub type cudaMemPool_t = *mut c_void;

#[link(name = "cudart")]
extern "C" {
    fn cudaMallocAsync(dev_ptr: *mut *mut c_void, size: usize, stream: cudaStream_t) -> i32;
    fn cudaMallocFromPoolAsync(
        dev_ptr: *mut *mut c_void,
        size: usize,
        pool: cudaMemPool_t,
        stream: cudaStream_t,
    ) -> i32;
    fn cudaFreeAsync(dev_ptr: *mut c_void, stream: cudaStream_t) -> i32;
    fn cudaMemGetInfo(free: *mut usize, total: *mut usize) -> i32;
    fn cudaDeviceGetMemPool(pool: *mut cudaMemPool_t, device: i32) -> i32;
    fn cudaMemPoolTrimTo(pool: cudaMemPool_t, min_bytes_to_keep: usize) -> i32;
    fn cudaMemPoolSetAttribute(pool: cudaMemPool_t, attr: i32, value: *mut c_void) -> i32;
    fn cudaMemPoolGetAttribute(pool: cudaMemPool_t, attr: i32, value: *mut c_void) -> i32;
    fn cudaGetDeviceCount(count: *mut i32) -> i32;
    fn cudaGetLastError() -> i32;
}

/// Maximum number of CUDA devices supported by the per-device state arrays (this manager, and
/// the other per-device singletons that mirror it).
pub const MAX_CUDA_DEVICES: usize = 16;

/// One [`MemoryManager`] **per CUDA device**, routed by the *current* device, so each device gets
/// isolated tracking (and can have its own external pool). Per device, not per thread: all of a
/// card's prover lanes share one.
static MEMORY_MANAGERS: [OnceLock<Mutex<MemoryManager>>; MAX_CUDA_DEVICES] =
    [const { OnceLock::new() }; MAX_CUDA_DEVICES];

/// `cudaMemPoolAttrReleaseThreshold`.
const CUDA_MEM_POOL_ATTR_RELEASE_THRESHOLD: i32 = 4;

/// Devices whose *default* pool has had its release threshold raised by
/// [`ensure_default_pool_retains`]. One slot per device: the threshold is a per-pool attribute
/// and every device has its own default pool.
static DEFAULT_POOL_RETAINS: [OnceLock<bool>; MAX_CUDA_DEVICES] =
    [const { OnceLock::new() }; MAX_CUDA_DEVICES];

fn pool_retain_enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| !std::env::var("MLE_POOL_RETAIN").is_ok_and(|v| v == "0"))
}

/// Raise `device_id`'s **default** pool release threshold so freed blocks are recycled instead of
/// being handed back to the driver at every stream sync.
///
/// The registered external pool already runs this way, but the `.cu` translation units listed in
/// the module header allocate with plain `cudaMallocAsync`, which always draws from the *default*
/// pool. At the driver's default threshold of 0 each of those alloc/free pairs unmaps and remaps
/// physical memory: measured at ~0.4 ms per call against ~1.5 us for the same call against a
/// retaining pool, and it is stream-ordered, so the device idles through it. Raising the
/// threshold is what [`MemoryManager::trim_pool`] already assumes has happened.
///
/// Idempotent and per device. `MLE_POOL_RETAIN=0` restores the driver default — this is the only
/// site that raises the threshold, so disabling it leaves every card as the driver left it.
///
/// A failure is cached like a success: the driver call is not retried, so the warning it logs is
/// the only notice that one card is still paying the un-retained cost.
pub fn ensure_default_pool_retains(device_id: usize) -> bool {
    if device_id >= MAX_CUDA_DEVICES || !pool_retain_enabled() {
        return false;
    }
    *DEFAULT_POOL_RETAINS[device_id].get_or_init(|| {
        let mut pool: cudaMemPool_t = std::ptr::null_mut();
        // SAFETY: `&mut pool` is a live out-param. Both the return code and the null check below
        // are load-bearing — CUDA does not promise the out-param is untouched on a failing call.
        let rc = unsafe { cudaDeviceGetMemPool(&mut pool, device_id as i32) };
        if rc != 0 || pool.is_null() {
            // Clear the sticky error, or the next `CHECK_KERNEL()` — a bare `cudaGetLastError`
            // in release builds — surfaces it as an unrelated kernel-launch failure.
            unsafe { cudaGetLastError() };
            tracing::warn!(
                "card {device_id}: cudaDeviceGetMemPool failed (rc={rc}); its default pool stays \
                 at the driver's release threshold of 0, so every `.cu` scratch alloc/free pair \
                 round-trips physical memory"
            );
            return false;
        }
        let mut threshold = u64::MAX;
        // SAFETY: `pool` is a valid handle from the call above; the release-threshold attribute
        // takes a `cuuint64_t`, which `threshold` is.
        let rc = unsafe {
            cudaMemPoolSetAttribute(
                pool,
                CUDA_MEM_POOL_ATTR_RELEASE_THRESHOLD,
                &mut threshold as *mut u64 as *mut c_void,
            )
        };
        if rc != 0 {
            // Clear the sticky error so the next real allocation is not blamed for it.
            unsafe { cudaGetLastError() };
            tracing::warn!(
                "card {device_id}: raising the default pool's release threshold failed \
                 (rc={rc}); it stays at 0 for the rest of the process"
            );
            return false;
        }
        true
    })
}

/// Number of CUDA devices the driver reports, clamped to [`MAX_CUDA_DEVICES`]. 0 if the driver
/// cannot be queried.
pub fn visible_device_count() -> usize {
    let mut count: i32 = 0;
    // SAFETY: `&mut count` is a live out-param; a failing call leaves it at 0, which we return.
    if unsafe { cudaGetDeviceCount(&mut count) } != 0 {
        unsafe { cudaGetLastError() };
        return 0;
    }
    (count.max(0) as usize).min(MAX_CUDA_DEVICES)
}

/// `device_id`'s default-pool release threshold, straight from the driver. The bytes the pool may
/// keep cached instead of returning; the driver's own default is 0.
pub fn default_pool_release_threshold(device_id: usize) -> Result<u64, MemoryError> {
    let mut pool: cudaMemPool_t = std::ptr::null_mut();
    check(unsafe { cudaDeviceGetMemPool(&mut pool, device_id as i32) })?;
    let mut value = 0u64;
    // SAFETY: `pool` is a valid handle; the release-threshold attribute reads a `cuuint64_t`.
    check(unsafe {
        cudaMemPoolGetAttribute(
            pool,
            CUDA_MEM_POOL_ATTR_RELEASE_THRESHOLD,
            &mut value as *mut u64 as *mut c_void,
        )
    })?;
    Ok(value)
}

/// The `cudaMemPoolAttr` byte counters (`driver_types.h`): current and high-water for the pool's
/// *backing* memory (what the driver has mapped for it) and for the part of that the application
/// is holding. The two high-water attributes are the only resettable ones, which is what makes a
/// per-window peak readable at all — write zero to reset, see [`reset_pool_high_water`].
const CUDA_MEM_POOL_ATTR_RESERVED_MEM_CURRENT: i32 = 5;
const CUDA_MEM_POOL_ATTR_RESERVED_MEM_HIGH: i32 = 6;
const CUDA_MEM_POOL_ATTR_USED_MEM_CURRENT: i32 = 7;
const CUDA_MEM_POOL_ATTR_USED_MEM_HIGH: i32 = 8;

/// One pool's four byte counters. `reserved - used` is what a trim could hand back right now.
#[derive(Debug, Clone, Copy, Default)]
pub struct PoolBytes {
    pub reserved: u64,
    pub reserved_high: u64,
    pub used: u64,
    pub used_high: u64,
}

/// A card's two pools. Both are needed to account for a device: every [`d_malloc`] lands in the
/// external one, and the `.cu` units' `cudaMallocAsync` scratch lands in the default one. Their
/// plain `cudaMalloc` sites land in neither, which is the whole point of subtracting these from
/// the device total (module header lists both kinds).
///
/// `external` is `None` when none is registered — and also when the registered pool IS the default
/// pool, which tests do deliberately, because a caller summing the two would otherwise count that
/// card's backing memory twice and conclude the device holds nothing outside its pools.
#[derive(Debug, Clone, Copy, Default)]
pub struct DevicePoolBytes {
    pub external: Option<PoolBytes>,
    pub default_pool: PoolBytes,
}

impl DevicePoolBytes {
    /// Backing memory the two pools hold between them. Subtract from the device's used bytes and
    /// what is left is everything allocated *outside* them: the plain `cudaMalloc` sites listed in
    /// the module header, loaded JIT modules, the CUDA context itself.
    pub fn reserved_total(&self) -> u64 {
        self.default_pool.reserved + self.external.map_or(0, |p| p.reserved)
    }

    /// Bytes the application currently holds from the two pools.
    pub fn used_total(&self) -> u64 {
        self.default_pool.used + self.external.map_or(0, |p| p.used)
    }

    /// The two marks summed. An upper bound on the joint peak rather than the peak itself — the
    /// pools need not reach their marks at the same instant — but a consistent one across blocks.
    pub fn used_high_total(&self) -> u64 {
        self.default_pool.used_high + self.external.map_or(0, |p| p.used_high)
    }

    /// As [`Self::used_high_total`], for backing memory.
    pub fn reserved_high_total(&self) -> u64 {
        self.default_pool.reserved_high + self.external.map_or(0, |p| p.reserved_high)
    }
}

/// Read one pool's counters. A failing attribute read leaves its field zero rather than failing
/// the whole census — a metrics path must not take a run down.
fn pool_bytes(pool: cudaMemPool_t) -> PoolBytes {
    let read = |attr: i32| -> u64 {
        let mut v = 0u64;
        // SAFETY: `pool` is a live handle and every attribute below reads a `cuuint64_t`.
        let rc = unsafe { cudaMemPoolGetAttribute(pool, attr, &mut v as *mut u64 as *mut c_void) };
        if rc != 0 {
            // Clear the sticky error, or the next `CHECK_KERNEL()` blames an unrelated launch.
            unsafe { cudaGetLastError() };
            return 0;
        }
        v
    };
    PoolBytes {
        reserved: read(CUDA_MEM_POOL_ATTR_RESERVED_MEM_CURRENT),
        reserved_high: read(CUDA_MEM_POOL_ATTR_RESERVED_MEM_HIGH),
        used: read(CUDA_MEM_POOL_ATTR_USED_MEM_CURRENT),
        used_high: read(CUDA_MEM_POOL_ATTR_USED_MEM_HIGH),
    }
}

/// `device_id`'s pool counters. Reads the manager without creating one, so asking about a card
/// this process never touched reports the default pool alone rather than initializing it.
pub fn pool_bytes_for(device_id: usize) -> DevicePoolBytes {
    if device_id >= MAX_CUDA_DEVICES {
        return DevicePoolBytes::default();
    }
    let default_handle = {
        let mut p: cudaMemPool_t = std::ptr::null_mut();
        // SAFETY: `&mut p` is a live out-param; the null check below covers a failing call.
        let rc = unsafe { cudaDeviceGetMemPool(&mut p, device_id as i32) };
        if rc != 0 || p.is_null() {
            unsafe { cudaGetLastError() };
            None
        } else {
            Some(p)
        }
    };
    let external_handle = MEMORY_MANAGERS[device_id]
        .get()
        .and_then(|m| m.lock().ok())
        .and_then(|m| m.external_pool)
        .filter(|ext| Some(*ext) != default_handle);
    DevicePoolBytes {
        external: external_handle.map(pool_bytes),
        default_pool: default_handle.map(pool_bytes).unwrap_or_default(),
    }
}

/// Reset both pools' high-water marks on `device_id`, so the next window's peak is that window's
/// own rather than the process's. Silent on failure for the same reason [`pool_bytes`] is.
pub fn reset_pool_high_water(device_id: usize) {
    let mut pools: Vec<cudaMemPool_t> = Vec::with_capacity(2);
    let mut p: cudaMemPool_t = std::ptr::null_mut();
    // SAFETY: `&mut p` is a live out-param, checked for null before use.
    if unsafe { cudaDeviceGetMemPool(&mut p, device_id as i32) } == 0 && !p.is_null() {
        pools.push(p);
    } else {
        unsafe { cudaGetLastError() };
    }
    if let Some(ext) = MEMORY_MANAGERS
        .get(device_id)
        .and_then(|m| m.get())
        .and_then(|m| m.lock().ok())
        .and_then(|m| m.external_pool)
    {
        if !pools.contains(&ext) {
            pools.push(ext);
        }
    }
    for pool in pools {
        for attr in [
            CUDA_MEM_POOL_ATTR_RESERVED_MEM_HIGH,
            CUDA_MEM_POOL_ATTR_USED_MEM_HIGH,
        ] {
            let mut zero = 0u64;
            // SAFETY: live handle; both attributes take a `cuuint64_t`, and zero is the only
            // value the driver accepts for them.
            let rc = unsafe {
                cudaMemPoolSetAttribute(pool, attr, &mut zero as *mut u64 as *mut c_void)
            };
            if rc != 0 {
                unsafe { cudaGetLastError() };
            }
        }
    }
}

#[inline]
fn current_device_index() -> usize {
    // Surfaced rather than defaulted to card 0: allocating against the wrong card's pool shows up
    // as an unrelated OOM much later. Note this catches a failed query, not a missed binding —
    // `cudaGetDevice` reads card 0 on a thread that never bound, and nothing here can tell the
    // difference.
    let idx = crate::runtime::context::get_device()
        .expect("cudaGetDevice failed in the memory manager") as usize;
    assert!(
        idx < MAX_CUDA_DEVICES,
        "CUDA device {idx} exceeds MAX_CUDA_DEVICES={MAX_CUDA_DEVICES}"
    );
    idx
}

/// The `.cu` units' `cudaMallocAsync` scratch lives in the device default pool, outside
/// `d_malloc` and its self-heal; `oom_heal.cuh` routes their OOM here for the same sync and trim
/// before its own retry. Called from a prover thread that holds no manager lock -- the call sites
/// are kernel-launch paths, not allocator internals -- so taking it here is safe.
#[no_mangle]
pub extern "C" fn mle_oom_trim_pools(device: i32, bytes: usize) {
    let Ok(device_id) = usize::try_from(device) else {
        return;
    };
    if device_id >= MAX_CUDA_DEVICES {
        return;
    }
    let _ = device_synchronize();
    if let Ok(m) = manager_for(device_id).lock() {
        m.trim_pool();
    }
    let (free, _) = device_mem_info();
    tracing::warn!(
        "default-pool allocation of {} failed on card {device_id}; trimmed the memory pools and \
         retrying (driver free: {})",
        ByteSize(bytes as u64),
        ByteSize(free as u64),
    );
}

/// The retry after [`mle_oom_trim_pools`] failed too; the caller now takes its fallback, and this
/// is the line that says so.
#[no_mangle]
pub extern "C" fn mle_oom_retry_failed(device: i32, bytes: usize) {
    let (free, _) = device_mem_info();
    tracing::warn!(
        "default-pool allocation of {} on card {device} still failed after the trim (driver free: \
         {}); falling back",
        ByteSize(bytes as u64),
        ByteSize(free as u64),
    );
}

/// A default-pool allocation failed and the caller took its fallback. Counted per card rather than
/// logged every time: the per-launch tables behind this fire dozens of times per block, and a card
/// that stays full would otherwise flood the log. Logged at the 1st, 10th, 100th, 1 000th and
/// 10 000th occurrence on that card.
#[no_mangle]
pub extern "C" fn mle_oom_note_fallback(device: i32, bytes: usize) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static SEEN: [AtomicUsize; MAX_CUDA_DEVICES] =
        [const { AtomicUsize::new(0) }; MAX_CUDA_DEVICES];
    let Ok(device_id) = usize::try_from(device) else {
        return;
    };
    if device_id >= MAX_CUDA_DEVICES {
        return;
    }
    let n = SEEN[device_id].fetch_add(1, Ordering::Relaxed) + 1;
    if matches!(n, 1 | 10 | 100 | 1_000 | 10_000) {
        let (free, _) = device_mem_info();
        tracing::warn!(
            "default-pool allocation of {} failed on card {device_id}; taking the fallback \
             (occurrence #{n} on this card, driver free: {})",
            ByteSize(bytes as u64),
            ByteSize(free as u64),
        );
    }
}

/// A grow-once cache failed to build with plain `cudaMalloc`. The failed build is kept like a
/// successful one, so the AIR runs its slower path for as long as its proving key lives -- logged
/// every time, since that is at most once per key.
#[no_mangle]
pub extern "C" fn mle_oom_note_cache_fallback(device: i32, bytes: usize) {
    let (free, _) = device_mem_info();
    tracing::warn!(
        "device allocation of {} for a cached table failed on card {device}; that AIR runs its \
         uncached path for as long as its proving key lives (driver free: {})",
        ByteSize(bytes as u64),
        ByteSize(free as u64),
    );
}

/// Get-or-create the memory manager for the given device index.
fn manager_for(device_id: usize) -> &'static Mutex<MemoryManager> {
    assert!(
        device_id < MAX_CUDA_DEVICES,
        "CUDA device {device_id} exceeds MAX_CUDA_DEVICES={MAX_CUDA_DEVICES}"
    );
    // Establish the retaining-default-pool invariant that `trim_pool` documents, on every
    // device this crate touches, before the first allocation lands on it.
    ensure_default_pool_retains(device_id);
    MEMORY_MANAGERS[device_id].get_or_init(|| Mutex::new(MemoryManager::new()))
}

/// Get-or-create the memory manager for the current CUDA device.
fn current_manager() -> &'static Mutex<MemoryManager> {
    manager_for(current_device_index())
}

/// The current device's memory manager if it has been initialized (read-only/metrics paths).
fn current_manager_opt() -> Option<&'static Mutex<MemoryManager>> {
    MEMORY_MANAGERS[current_device_index()].get()
}

/// Device-level memory info `(free, total)` in bytes, straight from `cudaMemGetInfo`. Unlike the
/// per-crate [`MemoryManager`] counters, this reflects the WHOLE device: CUDA context, JIT'd
/// cubins, the external pool's cached (freed-but-retained) reservation, and any other process —
/// i.e. the true figure the driver checks when an allocation OOMs.
pub fn device_mem_info() -> (usize, usize) {
    let mut free = 0usize;
    let mut total = 0usize;
    unsafe { cudaMemGetInfo(&mut free, &mut total) };
    (free, total)
}

pub fn device_memory_used() -> usize {
    let (free, total) = device_mem_info();
    total - free
}

pub struct MemoryManager {
    /// When set, all allocations are drawn from this pool via `cudaMallocFromPoolAsync`.
    external_pool: Option<cudaMemPool_t>,
    allocated_ptrs: HashMap<NonNull<c_void>, usize>,
    current_size: usize,
    max_used_size: usize,
}

/// # Safety
/// `MemoryManager` does no locking of its own; sharing it is sound only because every per-device
/// instance lives behind a `Mutex` in `MEMORY_MANAGERS`.
unsafe impl Send for MemoryManager {}
unsafe impl Sync for MemoryManager {}

impl MemoryManager {
    pub fn new() -> Self {
        Self {
            external_pool: None,
            allocated_ptrs: HashMap::new(),
            current_size: 0,
            max_used_size: 0,
        }
    }

    fn raw_alloc(&self, ptr: &mut *mut c_void, size: usize) -> i32 {
        match self.external_pool {
            Some(pool) => unsafe { cudaMallocFromPoolAsync(ptr, size, pool, cudaStreamPerThread) },
            None => unsafe { cudaMallocAsync(ptr, size, cudaStreamPerThread) },
        }
    }

    /// Return every pool's freed-but-retained reservation to the driver. The pools run with an
    /// effectively infinite release threshold (reuse is what makes the steady-state fast), so this
    /// is the only way their cached memory ever goes back.
    ///
    /// Trims **both** the registered external pool and the device default pool. Trimming only the
    /// external one would miss the C-side `cudaMallocAsync` scratch buffers (see the module
    /// header's "`d_malloc` is NOT the crate's only allocation site"), which always land in the
    /// default pool — i.e. the OOM self-heal would reclaim least in the production configuration.
    fn trim_pool(&self) {
        let default_pool = {
            let mut p: cudaMemPool_t = std::ptr::null_mut();
            let dev = crate::runtime::context::get_device().unwrap_or(0);
            (unsafe { cudaDeviceGetMemPool(&mut p, dev) } == 0 && !p.is_null()).then_some(p)
        };
        for pool in self.external_pool.into_iter().chain(default_pool) {
            // The external pool *may* be the default pool (tests register it deliberately);
            // trimming twice is harmless.
            let rc = unsafe { cudaMemPoolTrimTo(pool, 0) };
            if rc != 0 {
                tracing::warn!("cudaMemPoolTrimTo failed: rc={rc}");
            }
        }
    }

    fn d_malloc(&mut self, size: usize) -> Result<*mut c_void, MemoryError> {
        assert!(size != 0, "Requested size must be non-zero");
        let first = self.d_malloc_once(size);
        if first.is_ok() {
            return first;
        }
        // Self-heal before failing: the pool never returns memory on its own, so a large request
        // can OOM out of fragmentation alone. Sync so in-flight frees land, then trim and retry
        // under this lock, so the retry is guaranteed the memory the trim released. The sync is
        // device-wide on purpose -- the pool is shared by every lane on the card -- and it is
        // refused by, and invalidates, a capture another lane has open; an already-failing
        // allocation is the wrong place to fight over that. What this cannot do is wait for
        // another lane's frees: the public [`d_malloc`] does that once this returns and the lock
        // is gone.
        let _ = device_synchronize();
        self.trim_and_retry(size)
    }

    /// Trim both pools back to the driver and try once more: the pools' cached-but-free memory,
    /// and whatever a neighbour returned to the *default* pool, reaches a fresh request only
    /// after this.
    fn trim_and_retry(&mut self, size: usize) -> Result<*mut c_void, MemoryError> {
        self.trim_pool();
        // The sync or the trim may have recorded an error of their own; a retry that succeeds
        // must not hand it to the caller's next kernel check.
        unsafe { cudaGetLastError() };
        let (free, _) = device_mem_info();
        tracing::warn!(
            "GPU allocation of {} failed; trimmed the memory pool and retrying (driver free: {})",
            ByteSize(size as u64),
            ByteSize(free as u64),
        );
        let external_pool = self.external_pool.is_some();
        self.d_malloc_once(size).map_err(|e| {
            tracing::warn!(
                "GPU allocation of {} failed after the trim (external_pool={external_pool}): {e:?}",
                ByteSize(size as u64),
            );
            e
        })
    }

    /// One attempt at the pool, nothing else. A failure leaves the thread's last-error slot
    /// clean: in release `CHECK_KERNEL()` is `cudaGetLastError()`, and a stale OOM there would
    /// fail the caller's next kernel check after a later attempt had succeeded.
    fn d_malloc_once(&mut self, size: usize) -> Result<*mut c_void, MemoryError> {
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let result = self.raw_alloc(&mut ptr, size);
        if result != 0 {
            unsafe { cudaGetLastError() };
        }
        check(result)?;
        self.record_allocation(ptr, size);
        Ok(ptr)
    }

    fn record_allocation(&mut self, ptr: *mut c_void, size: usize) {
        self.allocated_ptrs.insert(
            NonNull::new(ptr).expect("BUG: CUDA allocation returned null"),
            size,
        );
        self.current_size += size;
        if self.current_size > self.max_used_size {
            self.max_used_size = self.current_size;
        }
    }

    /// # Safety
    /// `ptr` must come from this manager's allocator and not have been freed yet; it is dangling
    /// once this returns.
    unsafe fn d_free(&mut self, ptr: *mut c_void) -> Result<(), MemoryError> {
        let nn = NonNull::new(ptr).ok_or(MemoryError::NullPointer)?;

        // `cudaFreeAsync` handles both default-pool and `cudaMallocFromPoolAsync` allocations
        // (pool allocations are returned to their pool).
        let size = self
            .allocated_ptrs
            .remove(&nn)
            .ok_or(MemoryError::InvalidPointer)?;
        self.current_size -= size;
        check(unsafe { cudaFreeAsync(ptr, cudaStreamPerThread) }).map_err(|e| {
            tracing::error!("cudaFreeAsync failed: ptr={:p}: {:?}", ptr, e);
            MemoryError::from(e)
        })?;

        Ok(())
    }
}

impl Drop for MemoryManager {
    fn drop(&mut self) {
        device_synchronize().unwrap();
        let ptrs: Vec<*mut c_void> = self.allocated_ptrs.keys().map(|nn| nn.as_ptr()).collect();
        for &ptr in &ptrs {
            if let Err(e) = unsafe { self.d_free(ptr) } {
                tracing::error!("MemoryManager drop: failed to free {:p}: {:?}", ptr, e);
            }
        }
    }
}

impl Default for MemoryManager {
    fn default() -> Self {
        Self::new()
    }
}

/// How long a failed allocation waits for another lane on the card to free memory before it gives
/// up. `MLE_OOM_WAIT_MS`, default 5 s; 0 disables the wait.
fn oom_wait_budget() -> Duration {
    static V: OnceLock<Duration> = OnceLock::new();
    *V.get_or_init(|| {
        let default = Duration::from_millis(5_000);
        match std::env::var("MLE_OOM_WAIT_MS") {
            Ok(v) => v
                .trim()
                .parse::<u64>()
                .map(Duration::from_millis)
                .unwrap_or_else(|_| {
                    tracing::warn!(
                        "MLE_OOM_WAIT_MS={v:?} is not a number of milliseconds; using {} ms",
                        default.as_millis()
                    );
                    default
                }),
            Err(_) => default,
        }
    })
}

/// Allocate `size` bytes on the current device.
///
/// The manager's self-heal runs first, under its lock. If that still leaves the request out of
/// memory, this waits for another lane on the card to free some -- **outside** the lock, which
/// `d_free` needs -- retrying at the pool every few milliseconds up to [`oom_wait_budget`], then
/// trims once more and gives up as before. Any lock the waiting thread itself holds turns the
/// wait into that much delay for whoever needs it, and nothing worse: the wait is bounded.
pub fn d_malloc(size: usize) -> Result<*mut c_void, MemoryError> {
    let manager = current_manager();
    let lock = || manager.lock().map_err(|_| MemoryError::LockError);
    // Each guard below lives for its own statement only: nothing sleeps or logs under the lock.
    let first = lock()?.d_malloc(size);
    let first = match first {
        Ok(ptr) => return Ok(ptr),
        Err(e) => e,
    };
    let budget = oom_wait_budget();
    if !is_oom(&first) || budget.is_zero() {
        return Err(give_up(size, first, None));
    }
    const POLL: Duration = Duration::from_millis(5);
    let start = Instant::now();
    let mut attempts = 0u32;
    while start.elapsed() < budget {
        std::thread::sleep(POLL);
        attempts += 1;
        let once = lock()?.d_malloc_once(size);
        match once {
            Ok(ptr) => {
                tracing::warn!(
                    "GPU allocation of {} succeeded after waiting {} ms for memory freed on this \
                     card ({attempts} attempts)",
                    ByteSize(size as u64),
                    start.elapsed().as_millis()
                );
                return Ok(ptr);
            }
            Err(e) if !is_oom(&e) => return Err(give_up(size, e, Some(start.elapsed()))),
            Err(_) => {}
        }
    }
    // Frees that went back to the default pool, or to ours in pieces, reach a fresh request only
    // after a trim. Every free has long retired by now, so no device sync this time.
    let last = lock()?.trim_and_retry(size);
    last.map_err(|e| give_up(size, e, Some(start.elapsed())))
}

fn is_oom(e: &MemoryError) -> bool {
    matches!(e, MemoryError::Cuda(c) if c.is_out_of_memory())
}

/// The one error line an allocation that is not going to happen gets.
fn give_up(size: usize, e: MemoryError, waited: Option<Duration>) -> MemoryError {
    let waited = waited.map_or(String::new(), |w| {
        format!(" after waiting {} ms", w.as_millis())
    });
    tracing::error!(
        "GPU allocation of {} failed{waited}: {e:?}",
        ByteSize(size as u64)
    );
    e
}

/// # Safety
/// `ptr` must come from [`d_malloc`] and not have been freed yet; it is dangling once this
/// returns.
pub unsafe fn d_free(ptr: *mut c_void) -> Result<(), MemoryError> {
    // Fast path: the calling thread is bound to the owning device — true for every free on the
    // prove path (each card's threads free their own card's buffers).
    let cur = current_device_index();
    {
        let mut manager = manager_for(cur)
            .lock()
            .map_err(|_| MemoryError::LockError)?;
        if NonNull::new(ptr).is_some_and(|nn| manager.allocated_ptrs.contains_key(&nn)) {
            return manager.d_free(ptr);
        }
    }
    // Cross-device drop: at teardown the main thread (bound to one card) drops machines whose
    // buffers live on other cards. `cudaFreeAsync` must run with the owning device current (the
    // per-thread stream belongs to the current device), so find the owner, bind to it for the
    // free, and restore the binding.
    let nn = NonNull::new(ptr).ok_or(MemoryError::NullPointer)?;
    for dev in 0..MAX_CUDA_DEVICES {
        if dev == cur {
            continue;
        }
        let Some(mx) = MEMORY_MANAGERS[dev].get() else {
            continue;
        };
        let mut manager = mx.lock().map_err(|_| MemoryError::LockError)?;
        if !manager.allocated_ptrs.contains_key(&nn) {
            continue;
        }
        crate::runtime::context::set_device(dev as i32).map_err(MemoryError::from)?;
        let res = manager.d_free(ptr);
        // Best-effort restore; the free above already happened on the right device.
        let _ = crate::runtime::context::set_device(cur as i32);
        return res;
    }
    Err(MemoryError::InvalidPointer)
}

/// Route all subsequent `d_malloc` allocations on `device_id` to `pool` (e.g. pico's global
/// memory pool). Allocations made *before* this call are unaffected; `d_free` works for both
/// kinds. Pass a null pool to clear the routing (back to `cudaMallocAsync`).
///
/// # Safety
/// `pool` must be a valid `cudaMemPool_t` usable from `device_id`, and must outlive every
/// allocation drawn from it through this manager.
pub unsafe fn set_external_pool(device_id: usize, pool: cudaMemPool_t) -> Result<(), MemoryError> {
    let mut manager = manager_for(device_id)
        .lock()
        .map_err(|_| MemoryError::LockError)?;
    manager.external_pool = if pool.is_null() { None } else { Some(pool) };
    Ok(())
}

/// Live (allocated-and-not-freed) bytes tracked by this crate's manager on the current device.
///
/// This is the crate's **Rust-side** working set: pool-cached (freed-but-retained) blocks do not
/// count, and neither do the C-side scratch allocations listed in the module header. Budget a
/// device against [`device_mem_info`] instead; use this to attribute usage to this crate.
pub fn tracked_current_bytes() -> usize {
    current_manager_opt()
        .and_then(|m| m.lock().ok())
        .map_or(0, |m| m.current_size)
}

/// Live and peak tracked bytes for `device_id` as `(current, peak)`, `(0, 0)` when that card has
/// no manager yet. The per-device counterpart of [`tracked_current_bytes`]: a census thread reads
/// every card, not the one it happens to be bound to.
pub fn tracked_bytes_for(device_id: usize) -> (usize, usize) {
    MEMORY_MANAGERS
        .get(device_id)
        .and_then(|m| m.get())
        .and_then(|m| m.lock().ok())
        .map_or((0, 0), |m| (m.current_size, m.max_used_size))
}

/// Drop `device_id`'s tracked peak to its current live bytes, so the next window's peak belongs to
/// that window. The pool-side equivalent is [`reset_pool_high_water`].
pub fn reset_tracked_peak_for(device_id: usize) {
    if let Some(mut m) = MEMORY_MANAGERS
        .get(device_id)
        .and_then(|m| m.get())
        .and_then(|m| m.lock().ok())
    {
        m.max_used_size = m.current_size;
    }
}

/// Whether an external memory pool has been registered for `device_id` via [`set_external_pool`].
/// The MLE RISCV prover asserts this at construction so GPU proving draws from pico's shared pool
/// rather than the device default.
pub fn external_pool_is_set(device_id: usize) -> bool {
    device_id < MAX_CUDA_DEVICES
        && MEMORY_MANAGERS[device_id]
            .get()
            .and_then(|m| m.lock().ok())
            .is_some_and(|m| m.external_pool.is_some())
}

/// The device's *default* CUDA memory pool (`cudaDeviceGetMemPool`). Used by tests to exercise
/// the `cudaMallocFromPoolAsync` path without depending on an externally-created pool.
pub fn device_default_mem_pool(device_id: usize) -> Result<cudaMemPool_t, MemoryError> {
    let mut pool: cudaMemPool_t = std::ptr::null_mut();
    check(unsafe { cudaDeviceGetMemPool(&mut pool, device_id as i32) })?;
    Ok(pool)
}

#[derive(Debug, Clone)]
pub struct MemTracker {
    current: usize,
    /// Device-wide used bytes (`cudaMemGetInfo`) at `start`, so `tracing_info` can report how much
    /// the *whole device* grew across this step — not just this crate's tracked allocs. `None`
    /// when INFO was filtered out at `start` and the driver round-trip was skipped.
    dev_used_start: Option<usize>,
    label: &'static str,
}

impl MemTracker {
    pub fn start(label: &'static str) -> Self {
        let current = current_manager_opt()
            .and_then(|m| m.lock().ok())
            .map(|m| m.current_size)
            .unwrap_or_default();
        // The driver round-trip is only worth paying when `tracing_info` can actually print.
        let dev_used_start = tracing::enabled!(tracing::Level::INFO).then(device_memory_used);

        Self {
            current,
            dev_used_start,
            label,
        }
    }

    pub fn start_and_reset_peak(label: &'static str) -> Self {
        let mut mem = Self::start(label);
        mem.reset_peak();
        mem
    }

    pub fn emit_metrics(&self) {
        self.emit_metrics_with_label(self.label);
    }

    pub fn emit_metrics_with_label(&self, label: &'static str) {
        let Some(manager) = current_manager_opt().and_then(|m| m.lock().ok()) else {
            return;
        };

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
            * 1000.0;
        let current = manager.current_size;
        // Highest allocated total the manager has recorded since `reset_peak` last ran.
        let local_peak = manager.max_used_size;
        metrics::gauge!("gpu_mem.timestamp_ms", "module" => label).set(ts);
        metrics::gauge!("gpu_mem.current_bytes", "module" => label).set(current as f64);
        metrics::gauge!("gpu_mem.local_peak_bytes", "module" => label).set(local_peak as f64);
        // With the external-pool design the manager no longer owns a reservation; keep the
        // metric key alive (dashboards) reporting the currently allocated bytes.
        metrics::gauge!("gpu_mem.reserved_bytes", "module" => label).set(current as f64);
        // Device-wide gauges (cudaMemGetInfo) — the true driver-enforced figures, including the
        // allocations this crate's manager cannot see. Emitted alongside so a dashboard can chart
        // manager-tracked vs whole-device usage per step. Drop the lock first (not needed here).
        drop(manager);
        let (dev_free, dev_total) = device_mem_info();
        let dev_used = dev_total.saturating_sub(dev_free);
        metrics::gauge!("gpu_mem.device_used_bytes", "module" => label).set(dev_used as f64);
        metrics::gauge!("gpu_mem.device_free_bytes", "module" => label).set(dev_free as f64);
        metrics::gauge!("gpu_mem.device_total_bytes", "module" => label).set(dev_total as f64);
    }

    #[inline]
    pub fn tracing_info(&self, msg: impl Into<Option<&'static str>>) {
        let Some(manager) = current_manager_opt().and_then(|m| m.lock().ok()) else {
            tracing::error!("Memory manager not available");
            return;
        };
        // The info line below is filtered out on production runs; skip its driver round-trip
        // along with it (`start` gates its own the same way). Below the check above on purpose:
        // a missing manager is worth reporting whether or not INFO prints.
        if !tracing::enabled!(tracing::Level::INFO) {
            return;
        }
        let current = manager.current_size;
        let peak = manager.max_used_size;
        let used = current as isize - self.current as isize;
        let sign = if used >= 0 { "+" } else { "-" };
        // Drop the manager lock before the cudaMemGetInfo round-trip below (it does not need it).
        drop(manager);
        // Device-wide picture (see `device_mem_info`): true used/total the driver enforces, plus
        // how much the whole device grew across this step. `dev_used - current` is the "invisible"
        // overhead outside this crate's tracker (context, cubins, pool cache) — the slack that
        // decides whether a big single alloc (e.g. the 15 GiB RS codeword) fits.
        let (dev_free, dev_total) = device_mem_info();
        let dev_used = dev_total.saturating_sub(dev_free);
        // No baseline when INFO was off at `start`; say so rather than printing a Δ of zero.
        let dev_delta = self
            .dev_used_start
            .map(|start| dev_used as isize - start as isize);
        let dev_delta_str = dev_delta.map_or_else(
            || "?".to_string(),
            |d| {
                format!(
                    "{}{}",
                    if d >= 0 { "+" } else { "-" },
                    ByteSize::b(d.unsigned_abs() as u64)
                )
            },
        );
        tracing::info!(
            "GPU mem: used={}{}, current={}, peak={} | dev: used={}/{} free={} (Δ{}) ({})",
            sign,
            ByteSize::b(used.unsigned_abs() as u64),
            ByteSize::b(current as u64),
            ByteSize::b(peak as u64),
            ByteSize::b(dev_used as u64),
            ByteSize::b(dev_total as u64),
            ByteSize::b(dev_free as u64),
            dev_delta_str,
            msg.into()
                .map_or(self.label.to_string(), |m| format!("{}:{}", self.label, m))
        );
    }

    pub fn reset_peak(&mut self) {
        if let Some(mut manager) = current_manager_opt().and_then(|m| m.lock().ok()) {
            manager.max_used_size = manager.current_size;
        }
    }
}

impl Drop for MemTracker {
    fn drop(&mut self) {
        self.tracing_info(None);
    }
}
