//! A per-prove device scratch arena for this crate's small descriptor uploads.
//!
//! **What it removes.** Almost every kernel in the MLE prove path is driven by a descriptor array
//! — a handful of device pointers, per-window widths, per-AIR block contexts — that the host
//! builds as a `Vec` and ships with `[T]::to_device()`. That call allocates a fresh device buffer
//! and frees it a few lines later. An allocation census counted **147 735 such
//! uploads of ≤ 64 KiB per run** out of 320 232 Rust-side `d_malloc`s, and the driver
//! charges 2.01 µs for `cudaMallocFromPoolAsync` plus 1.76 µs for `cudaFreeAsync` — so the
//! *bookkeeping* around ~750 MB of payload costs more than the payload does.
//!
//! [`upload`] keeps the copy and drops the allocation: it bump-allocates out of a block the
//! current prove already owns and hands back a non-owning view.
//!
//! **Why this is not the allocator anti-pattern.** Generation 2026-09-05-001 built a bounded
//! per-thread, exact-size, keyed free list over the same memory pool and measured e2e
//! **+3.4 … +5.4 %**, growing monotonically in-process — progressive pool fragmentation
//! (`cuda-mle/src/runtime/memory_manager.rs`'s module header records the same rejection). The
//! property that failure needs is **retention**: blocks are handed back to a keyed cache and
//! re-issued at a different size later, so the pool's free list is churned by a second allocator
//! it cannot see.
//!
//! This arena has neither half of that. There is no key and no lookup — allocation is a bump
//! pointer. And nothing is retained: [`scope`] takes the blocks from the pool when a prove phase
//! opens and gives every one of them back when it closes, so between proves the pool is in
//! exactly the state it would have been in without this module. It is the same lifetime rule the
//! previous generation's caller-owned descriptor buffers used, generalised from one call site to
//! the crate.
use std::{
    cell::RefCell,
    marker::PhantomData,
    mem::{align_of, size_of_val, ManuallyDrop},
    ops::{Deref, DerefMut},
};

use crate::runtime::{copy::MemCopyH2D, d_buffer::DeviceBuffer, error::MemCopyError};

/// Uploads above this keep their own allocation. Descriptor arrays are 1–4 096 elements; the
/// buffers above the line are trace-sized, where one `d_malloc` per multi-MB payload is noise and
/// bump-allocating them would hold a prove's whole working set live at once.
const MAX_SCRATCH_BYTES: usize = 64 * 1024;

/// One `d_malloc` per block, so blocks want to be big relative to what they serve; the census
/// measured **4.9 MB of small uploads per prove**, so a 2 MiB block is a handful of allocations
/// per prove phase against the ~1 000 it replaces.
const BLOCK_BYTES: usize = 2 << 20;

/// Belt and braces: an arena is only ever as large as the phase that owns it, but a shape this
/// module has not seen must degrade to today's behaviour rather than to a VRAM cliff — peak
/// residency on this workload is 96.4 % of the card.
const MAX_SCOPE_BYTES: usize = 64 << 20;

/// A device buffer that may or may not own its allocation: `upload` returns an arena view when the
/// arena served it and a plain owning buffer otherwise, and either derefs to `DeviceBuffer<T>`.
pub struct Scratch<T> {
    buf: ManuallyDrop<DeviceBuffer<T>>,
    owned: bool,
}

impl<T> Scratch<T> {
    /// An owning buffer, for the call sites that keep one either way.
    pub fn owned(buf: DeviceBuffer<T>) -> Self {
        Self {
            buf: ManuallyDrop::new(buf),
            owned: true,
        }
    }
}

impl<T> Deref for Scratch<T> {
    type Target = DeviceBuffer<T>;
    #[inline]
    fn deref(&self) -> &DeviceBuffer<T> {
        &self.buf
    }
}

impl<T> DerefMut for Scratch<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut DeviceBuffer<T> {
        &mut self.buf
    }
}

impl<T> Drop for Scratch<T> {
    fn drop(&mut self) {
        if self.owned {
            // SAFETY: `owned` is only set for a buffer this type allocated and never handed out
            // elsewhere, and `drop` runs once.
            unsafe { ManuallyDrop::drop(&mut self.buf) }
        }
    }
}

struct Arena {
    blocks: Vec<DeviceBuffer<u8>>,
    /// Bump offset into `blocks.last()`.
    off: usize,
    /// Bytes reserved across all blocks of the open scope, against [`MAX_SCOPE_BYTES`].
    reserved: usize,
    /// Open [`ProveScope`]s. The arena is released when this returns to zero, so a nested scope
    /// (there is none today) would extend the outer one rather than free under it.
    depth: u32,
}

impl Arena {
    const fn new() -> Self {
        Self {
            blocks: Vec::new(),
            off: 0,
            reserved: 0,
            depth: 0,
        }
    }

    /// Reserve `bytes` at `align`, or `None` when the arena is closed or the scope cap is hit —
    /// in which case the caller falls back to a normal allocation.
    fn alloc(&mut self, bytes: usize, align: usize) -> Option<*mut u8> {
        if self.depth == 0 {
            return None;
        }
        if let Some(block) = self.blocks.last() {
            let start = (self.off + align - 1) & !(align - 1);
            if start + bytes <= block.len() {
                self.off = start + bytes;
                // SAFETY: `start + bytes <= block.len()`, so the range is inside the block.
                return Some(unsafe { block.as_mut_ptr().add(start) });
            }
        }
        let block_bytes = bytes.max(BLOCK_BYTES);
        if self.reserved + block_bytes > MAX_SCOPE_BYTES {
            return None;
        }
        let block = DeviceBuffer::<u8>::with_capacity(block_bytes);
        let ptr = block.as_mut_ptr();
        self.reserved += block_bytes;
        self.blocks.push(block);
        self.off = bytes;
        Some(ptr)
    }
}

thread_local! {
    static ARENA: RefCell<Arena> = const { RefCell::new(Arena::new()) };
}

/// Open the calling thread's arena for one prove phase. Every block it takes is freed when the
/// returned guard drops, which is what keeps this out of the retained-allocator anti-pattern.
///
/// The guard is `!Send` so the scope cannot be closed on a thread other than the one whose arena
/// it opened.
pub struct ProveScope {
    _not_send: PhantomData<*const ()>,
}

impl Drop for ProveScope {
    fn drop(&mut self) {
        ARENA.with(|a| {
            let mut a = a.borrow_mut();
            a.depth -= 1;
            if a.depth == 0 {
                // Freeing is stream-ordered on `cudaStreamPerThread`, exactly as the per-call
                // `to_device()` buffers this replaces were, and strictly later than they were —
                // so no kernel can outlive the descriptor it reads.
                a.blocks.clear();
                a.off = 0;
                a.reserved = 0;
            }
        });
    }
}

pub fn scope() -> ProveScope {
    ARENA.with(|a| a.borrow_mut().depth += 1);
    ProveScope {
        _not_send: PhantomData,
    }
}

/// Reserve `n` uninitialised elements of `T` on the device, out of the arena when one is open and
/// the request is small — the [`DeviceBuffer::with_capacity`] of this module.
///
/// Same lifetime contract as [`upload`]: the buffer must not outlive the [`ProveScope`].
pub fn alloc<T>(n: usize) -> Scratch<T> {
    let bytes = n * std::mem::size_of::<T>();
    // `touchemall` poisons every fresh allocation to catch reads of uninitialised device memory;
    // an arena block is poisoned once, not per hand-out, so that build takes the owning path and
    // keeps the check exact.
    if !cfg!(feature = "touchemall") && bytes > 0 && bytes <= MAX_SCRATCH_BYTES {
        let align = align_of::<T>().max(16);
        if let Some(ptr) = ARENA.with(|a| a.borrow_mut().alloc(bytes, align)) {
            // SAFETY: as in `upload`.
            return Scratch {
                buf: ManuallyDrop::new(unsafe { DeviceBuffer::from_raw_parts(ptr as *mut T, n) }),
                owned: false,
            };
        }
    }
    Scratch::owned(DeviceBuffer::with_capacity(n))
}

/// Upload `src` to the device, out of the arena when one is open and the payload is small.
///
/// The returned view must not outlive the [`ProveScope`] that served it. Every call site is inside
/// the prove phase that opened the scope, which is what makes that hold.
pub fn upload<T>(src: &[T]) -> Result<Scratch<T>, MemCopyError> {
    let bytes = size_of_val(src);
    if bytes > 0 && bytes <= MAX_SCRATCH_BYTES {
        // `align_of::<T>()` is what the type needs; 16 is what the widest element here (an
        // extension-field limb) wants, and keeps consecutive reservations from sharing a line.
        let align = align_of::<T>().max(16);
        if let Some(ptr) = ARENA.with(|a| a.borrow_mut().alloc(bytes, align)) {
            // SAFETY: the arena reserved `bytes` at `ptr` and will not hand the same range out
            // again before the scope closes; `ManuallyDrop` (via `owned: false`) keeps the view
            // from freeing a pointer the memory manager does not know.
            let mut view = ManuallyDrop::new(unsafe {
                DeviceBuffer::from_raw_parts(ptr as *mut T, src.len())
            });
            src.copy_to(&mut view)?;
            return Ok(Scratch {
                buf: view,
                owned: false,
            });
        }
    }
    Ok(Scratch::owned(src.to_device()?))
}
