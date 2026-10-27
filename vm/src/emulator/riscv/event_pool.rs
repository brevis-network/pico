use crossbeam::channel::{bounded, Receiver, Sender};
#[cfg(feature = "cuda")]
use cudart::{memory::HostAllocation, slice::CudaSlice};
use std::sync::atomic::{AtomicBool, Ordering};

/// Allocation flags for event buffers: CUDA's pinned-host flags in the GPU build, a placeholder
/// in the CPU build, where buffers are ordinary heap memory.
#[cfg(feature = "cuda")]
pub use cudart::memory::CudaHostAllocFlags as HostAllocFlags;

#[cfg(not(feature = "cuda"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostAllocFlags;

#[cfg(not(feature = "cuda"))]
impl HostAllocFlags {
    pub const DEFAULT: Self = Self;
}

/// Heap stand-in for `HostAllocation` in the CPU build: same uninitialized-slots contract.
#[cfg(not(feature = "cuda"))]
#[derive(Debug)]
struct HostAllocation<T>(Box<[std::mem::MaybeUninit<T>]>);

#[cfg(not(feature = "cuda"))]
impl<T> HostAllocation<T> {
    fn alloc(capacity: usize, _flags: HostAllocFlags) -> Result<Self, &'static str> {
        Ok(Self(Box::new_uninit_slice(capacity)))
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn as_ptr(&self) -> *const T {
        self.0.as_ptr() as *const T
    }

    fn as_mut_ptr(&mut self) -> *mut T {
        self.0.as_mut_ptr() as *mut T
    }
}

#[cfg(not(feature = "cuda"))]
impl<T> std::ops::Index<std::ops::RangeTo<usize>> for HostAllocation<T> {
    type Output = [T];

    /// Callers only index the initialized prefix `..len`.
    fn index(&self, range: std::ops::RangeTo<usize>) -> &[T] {
        assert!(range.end <= self.len());
        unsafe { std::slice::from_raw_parts(self.as_ptr(), range.end) }
    }
}

#[cfg(not(feature = "cuda"))]
impl<T> std::ops::IndexMut<std::ops::RangeTo<usize>> for HostAllocation<T> {
    fn index_mut(&mut self, range: std::ops::RangeTo<usize>) -> &mut [T] {
        assert!(range.end <= self.len());
        unsafe { std::slice::from_raw_parts_mut(self.as_mut_ptr(), range.end) }
    }
}

#[cfg(not(feature = "cuda"))]
impl<T> std::ops::Index<usize> for HostAllocation<T> {
    type Output = T;

    /// Callers only index the initialized prefix.
    fn index(&self, i: usize) -> &T {
        &self[..i + 1][i]
    }
}

#[cfg(not(feature = "cuda"))]
impl<T> std::ops::IndexMut<usize> for HostAllocation<T> {
    fn index_mut(&mut self, i: usize) -> &mut T {
        &mut self[..i + 1][i]
    }
}

/// When set, buffers do not come from the pools: each starts small and grows as events arrive, and
/// is freed when returned. For callers that hold every record of a run (the host prover): fixed
/// pools would block once every buffer is held, and full-size buffers would pin a chunk's worth of
/// memory per record however few events it has. Process-wide and never cleared, so a process that
/// sets it must not also run the GPU pipeline, which relies on the pools' blocking for backpressure.
static GROWABLE: AtomicBool = AtomicBool::new(false);

/// First capacity of a growable buffer.
const GROWABLE_INITIAL_CAPACITY: usize = 1 << 12;

/// Switch every event buffer in this process to growable, unpooled allocations. See [`GROWABLE`].
pub fn use_growable_event_buffers() {
    GROWABLE.store(true, Ordering::Relaxed);
}

/// Always on in the CPU build: without a GPU pipeline there is no backpressure to keep, and
/// fixed pools would reserve a chunk's worth of memory per buffer up front.
#[inline]
pub(crate) fn growable() -> bool {
    cfg!(not(feature = "cuda")) || GROWABLE.load(Ordering::Relaxed)
}

/// A generic pool of reusable event buffers (pinned memory in the GPU build).
#[derive(Debug)]
pub struct EventPool<T> {
    sender: Sender<PinnedEventBuffer<T>>,
    receiver: Receiver<PinnedEventBuffer<T>>,
    buffer_capacity: usize,
    flags: HostAllocFlags,
}

impl<T: std::fmt::Debug> EventPool<T> {
    pub fn new(pool_size: usize, buffer_capacity: usize, flags: HostAllocFlags) -> Self {
        // The CPU build's buffers never come from the pool, so there is nothing to preallocate.
        let pool_size = if cfg!(feature = "cuda") { pool_size } else { 0 };
        // Create a bounded channel with the same size as the pool
        let (sender, receiver) = bounded(pool_size);

        for _ in 0..pool_size {
            let mut buffer = PinnedEventBuffer::new(buffer_capacity, flags)
                .expect("Failed to create event buffer");
            buffer.pooled = true;
            // Fill the channel with initial buffers.
            // This is infallible as we are filling up to exact capacity.
            sender.send(buffer).unwrap();
        }

        Self {
            sender,
            receiver,
            buffer_capacity,
            flags,
        }
    }

    /// Blocks the current thread until a buffer becomes available, unless buffers are growable.
    /// Returns None only if the pool is disconnected/dropped.
    pub fn get(&self) -> Option<PinnedEventBuffer<T>> {
        if growable() {
            return Some(
                PinnedEventBuffer::new(GROWABLE_INITIAL_CAPACITY, self.flags)
                    .expect("Failed to allocate an event buffer"),
            );
        }
        // `recv()` blocks the thread if the channel is empty.
        // It waits until a buffer is returned via `return_buffer`.
        self.receiver.recv().ok()
    }

    pub fn return_buffer(&self, mut buffer: PinnedEventBuffer<T>) {
        if !buffer.pooled {
            // A growable buffer, not one of the pool's: dropping it frees the memory.
            return;
        }
        buffer.clear();
        // Send the buffer back to the channel.
        // If the channel is full (should not happen in correct usage), this might block,
        // but given we only return what we took, it's safe.
        let _ = self.sender.send(buffer);
    }

    pub fn buffer_capacity(&self) -> usize {
        self.buffer_capacity
    }

    /// Drain and drop all buffers currently in the pool.
    /// Outstanding buffers held by other threads will be dropped when they go out of scope.
    pub fn shutdown(&self) {
        // Use `try_recv` to drain the channel without blocking
        while let Ok(_buf) = self.receiver.try_recv() {
            // Dropping the buffer here frees the pinned memory
            // by running its Drop impl.
        }
    }
}

/// A pinned memory buffer for events. This is the "real" buffer implementation.
#[derive(Debug)]
pub struct PinnedEventBuffer<T> {
    host: HostAllocation<T>,
    len: usize,
    /// Made by a pool, and goes back to it; a growable buffer is freed instead.
    pooled: bool,
    flags: HostAllocFlags,
}

// SAFETY: The buffer contains elements of type T. It is only sound to move the
// buffer across threads if T is Send, and to share references if T is Sync.
unsafe impl<T: Send> Send for PinnedEventBuffer<T> {}
unsafe impl<T: Sync> Sync for PinnedEventBuffer<T> {}

impl<T> PinnedEventBuffer<T> {
    fn new(capacity: usize, flags: HostAllocFlags) -> Result<Self, String> {
        let host = HostAllocation::alloc(capacity, flags).map_err(|e| format!("{e:?}"))?;
        Ok(Self {
            host,
            len: 0,
            pooled: false,
            flags,
        })
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    #[inline]
    pub fn capacity(&self) -> usize {
        self.host.len()
    }
    #[inline]
    pub fn clear(&mut self) {
        // Drop initialized elements if they may have drop glue
        if std::mem::needs_drop::<T>() && self.len != 0 {
            unsafe {
                let ptr = self.host.as_mut_ptr();
                // Drop the initialized prefix in place
                std::ptr::drop_in_place(std::ptr::slice_from_raw_parts_mut(ptr, self.len));
            }
        }
        self.len = 0;
    }

    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.host[..self.len]
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.host[..self.len]
    }

    #[inline]
    pub fn get(&self, index: usize) -> Option<&T> {
        self.as_slice().get(index)
    }

    #[inline]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.as_mut_slice().get_mut(index)
    }

    /// Moves the events into a pinned allocation of at least `min_capacity`, doubling.
    fn grow(&mut self, min_capacity: usize) -> Result<(), &'static str> {
        let capacity = min_capacity.max(self.capacity() * 2);
        let mut host =
            HostAllocation::alloc(capacity, self.flags).map_err(|_| "Failed to grow buffer")?;
        unsafe {
            std::ptr::copy_nonoverlapping(self.host.as_ptr(), host.as_mut_ptr(), self.len);
        }
        // The events were moved bitwise; the old allocation is freed without dropping them.
        self.host = host;
        Ok(())
    }

    /// Makes room for `total` events: grows a growable buffer, refuses on a pooled one.
    pub fn reserve(&mut self, total: usize) -> Result<(), &'static str> {
        if total <= self.capacity() {
            return Ok(());
        }
        if !growable() {
            return Err("Not enough capacity");
        }
        self.grow(total)
    }

    pub fn push(&mut self, event: T) -> Result<(), &'static str> {
        if self.len >= self.capacity() {
            if !growable() {
                return Err("Buffer is full");
            }
            self.grow(self.len + 1)?;
        }
        unsafe {
            // Direct pointer manipulation for better performance
            // This avoids bounds checking overhead
            let ptr = self.host.as_mut_ptr().add(self.len);
            std::ptr::write(ptr, event);
        }
        self.len += 1;
        Ok(())
    }

    /// Unsafe push method for cases where capacity is guaranteed to be available
    /// # Safety
    /// Caller must ensure `self.len < self.capacity()` before calling
    pub unsafe fn push_unchecked(&mut self, event: T) {
        debug_assert!(self.len < self.capacity(), "push_unchecked overflow");
        let ptr = self.host.as_mut_ptr().add(self.len);
        std::ptr::write(ptr, event);
        self.len += 1;
    }

    pub fn extend_from_slice(&mut self, events: &[T]) -> Result<(), &'static str>
    where
        T: Copy,
    {
        if self.len + events.len() > self.capacity() {
            if !growable() {
                return Err("Not enough capacity to extend");
            }
            self.grow(self.len + events.len())?;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                events.as_ptr(),
                self.host.as_mut_ptr().add(self.len),
                events.len(),
            );
        }
        self.len += events.len();
        Ok(())
    }
}

impl<T> PinnedEventBuffer<T> {
    #[inline]
    pub fn remaining_capacity(&self) -> usize {
        self.capacity() - self.len()
    }
}

impl<T> Drop for PinnedEventBuffer<T> {
    fn drop(&mut self) {
        if std::mem::needs_drop::<T>() && self.len != 0 {
            unsafe {
                let ptr = self.host.as_mut_ptr();
                // Drop only the initialized elements
                std::ptr::drop_in_place(std::ptr::slice_from_raw_parts_mut(ptr, self.len));
            }
        }
    }
}

// Implement CudaSlice for PinnedEventBuffer to enable proper host->device transfer
#[cfg(feature = "cuda")]
impl<T> CudaSlice<T> for PinnedEventBuffer<T> {
    unsafe fn as_slice(&self) -> &[T] {
        std::slice::from_raw_parts(self.host.as_ptr(), self.len)
    }
}

#[derive(Debug, Default)]
pub enum EventBuffer<T> {
    Buffer(PinnedEventBuffer<T>),
    #[default]
    Empty,
}

impl<T> EventBuffer<T> {
    pub fn empty() -> Self {
        Self::Empty
    }

    #[inline]
    fn ensure_real<F>(&mut self, get_buffer: F) -> Result<(), &'static str>
    where
        F: FnOnce() -> Option<EventBuffer<T>>,
    {
        if let Self::Empty = self {
            *self = get_buffer().ok_or("Failed to get buffer from pool")?;
        }
        Ok(())
    }

    #[inline]
    pub fn push_generic<F>(&mut self, event: T, get_buffer: F) -> Result<(), &'static str>
    where
        F: FnOnce() -> Option<EventBuffer<T>>,
    {
        self.ensure_real(get_buffer)?;
        match self {
            Self::Buffer(b) => b.push(event),
            Self::Empty => unreachable!(),
        }
    }

    #[inline]
    pub fn extend_from_slice_generic<F>(
        &mut self,
        events: &[T],
        get_buffer: F,
    ) -> Result<(), &'static str>
    where
        T: Copy,
        F: FnOnce() -> Option<EventBuffer<T>>,
    {
        if events.is_empty() {
            return Ok(());
        }
        self.ensure_real(get_buffer)?;
        match self {
            Self::Buffer(b) => b.extend_from_slice(events),
            Self::Empty => unreachable!(),
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Buffer(b) => b.is_empty(),
            Self::Empty => true,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        match self {
            Self::Buffer(b) => b.len(),
            Self::Empty => 0,
        }
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        match self {
            Self::Buffer(b) => b.capacity(),
            Self::Empty => 0,
        }
    }

    #[inline]
    pub fn remaining_capacity(&self) -> usize {
        if growable() {
            return usize::MAX;
        }
        self.capacity().saturating_sub(self.len())
    }

    #[inline]
    pub fn as_slice(&self) -> &[T] {
        match self {
            Self::Buffer(b) => b.as_slice(),
            Self::Empty => &[],
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        if let Self::Buffer(b) = self {
            b.clear();
        }
    }

    #[inline]
    pub fn get(&self, index: usize) -> Option<&T> {
        match self {
            Self::Buffer(b) => b.get(index),
            Self::Empty => None,
        }
    }

    #[inline]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        match self {
            Self::Buffer(b) => b.get_mut(index),
            Self::Empty => None,
        }
    }

    #[inline]
    pub fn last(&self) -> Option<&T> {
        match self {
            Self::Buffer(b) => {
                if b.is_empty() {
                    None
                } else {
                    Some(&b.host[b.len - 1])
                }
            }
            Self::Empty => None,
        }
    }

    #[inline]
    pub fn last_mut(&mut self) -> Option<&mut T> {
        match self {
            Self::Buffer(b) => {
                if b.is_empty() {
                    None
                } else {
                    Some(&mut b.host[b.len - 1])
                }
            }
            Self::Empty => None,
        }
    }

    #[inline]
    pub fn first(&self) -> Option<&T> {
        match self {
            Self::Buffer(b) => {
                if b.is_empty() {
                    None
                } else {
                    Some(&b.host[0])
                }
            }
            Self::Empty => None,
        }
    }

    #[inline]
    pub fn first_mut(&mut self) -> Option<&mut T> {
        match self {
            Self::Buffer(b) => {
                if b.is_empty() {
                    None
                } else {
                    Some(&mut b.host[0])
                }
            }
            Self::Empty => None,
        }
    }
}

// Implement CudaSlice for EventBuffer to enable proper host->device transfer
#[cfg(feature = "cuda")]
impl<T> CudaSlice<T> for EventBuffer<T> {
    unsafe fn as_slice(&self) -> &[T] {
        match self {
            Self::Buffer(buffer) => CudaSlice::as_slice(buffer),
            Self::Empty => &[],
        }
    }
}

// Note: We don't implement Clone, Serialize, or Deserialize generically
// to avoid conflicts with specific implementations

/// A trait for managing global event pools
pub trait EventPoolManager<T> {
    fn init_pool(pool_size: usize, flags: HostAllocFlags);
    fn get_buffer() -> Option<EventBuffer<T>>;
    fn return_buffer(buffer: EventBuffer<T>);
    fn shutdown_pool();
    fn is_pool_initialized() -> bool;
}

/// Macro to create a specific event pool manager
#[macro_export]
macro_rules! create_event_pool_manager {
    ($name:ident, $event_type:ty, $pool_name:ident) => {
        $crate::create_event_pool_manager!(
            $name,
            $event_type,
            $pool_name,
            CPU_EVENT_BUFFER_CAPACITY
        );
    };
    ($name:ident, $event_type:ty, $pool_name:ident, $capacity:expr) => {
        use std::sync::OnceLock;
        use $crate::emulator::riscv::event_pool::EventPool;

        static $pool_name: OnceLock<EventPool<$event_type>> = OnceLock::new();

        pub struct $name;

        impl $crate::emulator::riscv::event_pool::EventPoolManager<$event_type> for $name {
            fn init_pool(
                pool_size: usize,
                flags: $crate::emulator::riscv::event_pool::HostAllocFlags,
            ) {
                let event_pool_capacity = *$capacity;
                tracing::info!(
                    "initializing event pool {} with capacity {event_pool_capacity}",
                    stringify!($pool_name)
                );
                let new_pool = EventPool::new(pool_size, event_pool_capacity, flags);
                // Idempotent on purpose: `set` fails only when another site initialised first, and
                // every site passes the same pool_size and flags, so the two pools are
                // interchangeable and dropping this one is correct. The previous `.expect` turned
                // that harmless race into a panic.
                if $pool_name.set(new_pool).is_err() {
                    tracing::debug!(
                        "event pool {} was already initialized; keeping the existing pool",
                        stringify!($pool_name)
                    );
                }
            }

            fn get_buffer() -> Option<$crate::emulator::riscv::event_pool::EventBuffer<$event_type>>
            {
                $pool_name
                    .get()
                    .and_then(|p| p.get())
                    .map($crate::emulator::riscv::event_pool::EventBuffer::Buffer)
            }

            fn return_buffer(
                buffer: $crate::emulator::riscv::event_pool::EventBuffer<$event_type>,
            ) {
                if let $crate::emulator::riscv::event_pool::EventBuffer::Buffer(real_buffer) =
                    buffer
                {
                    if let Some(pool) = $pool_name.get() {
                        pool.return_buffer(real_buffer);
                    }
                }
            }

            fn shutdown_pool() {
                if let Some(pool) = $pool_name.get() {
                    pool.shutdown();
                }
            }

            fn is_pool_initialized() -> bool {
                $pool_name.get().is_some()
            }
        }
    };
}

// ─── Packed-events staging additions (MLE_PACKED_EVENTS; additive, unused by default) ────────

impl<T> EventPool<T> {
    /// Non-blocking variant of [`EventPool::get`]: `None` when the pool is empty. The
    /// packed-events staging uses this so an exhausted pool degrades to the fat upload path
    /// instead of blocking (or deadlocking) the preparer thread.
    pub fn try_get(&self) -> Option<PinnedEventBuffer<T>> {
        self.receiver.try_recv().ok()
    }
}

impl<T> PinnedEventBuffer<T> {
    /// The full pinned allocation as uninitialized slots, for parallel one-shot initialization
    /// (packed-events staging). Combine with [`Self::set_len`] after filling a prefix.
    pub fn spare_full_mut(&mut self) -> &mut [std::mem::MaybeUninit<T>] {
        unsafe {
            std::slice::from_raw_parts_mut(
                self.host.as_mut_ptr() as *mut std::mem::MaybeUninit<T>,
                self.host.len(),
            )
        }
    }

    /// Declare the first `new_len` elements initialized.
    ///
    /// # Safety
    /// Caller must have initialized every element in `[0, new_len)`.
    pub unsafe fn set_len(&mut self, new_len: usize) {
        debug_assert!(new_len <= self.capacity());
        self.len = new_len;
    }
}
