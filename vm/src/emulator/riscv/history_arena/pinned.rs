//! A slot's pinned memory, and the device copies a slot waits for before it is reused. Without
//! `cuda` a slot is plain heap memory and nothing waits on a device.

#[cfg(not(feature = "cuda"))]
pub use heap::DeviceReadsDone;
#[cfg(not(feature = "cuda"))]
pub(super) use heap::{PinnedSlot, SlotFence};
#[cfg(feature = "cuda")]
pub use pinned::DeviceReadsDone;
#[cfg(feature = "cuda")]
pub(super) use pinned::{PinnedSlot, SlotFence};

#[cfg(feature = "cuda")]
mod pinned {
    use std::{ptr::NonNull, sync::Mutex};

    use cudart::{
        event::CudaEvent,
        memory::{CudaHostAllocFlags, HostAllocation},
    };

    pub(in super::super) struct PinnedSlot {
        /// In words, so the base is 8-aligned whatever the driver returns; `cudaHostAlloc` returns
        /// page-aligned memory in practice.
        host: HostAllocation<u64>,
    }

    // SAFETY: the allocation is plain pinned host memory, owned by one slot lease at a time, and a
    // shared reference reaches none of it.
    unsafe impl Send for PinnedSlot {}
    unsafe impl Sync for PinnedSlot {}

    impl PinnedSlot {
        pub(in super::super) fn alloc(bytes: usize) -> Result<Self, String> {
            HostAllocation::alloc(
                bytes.div_ceil(size_of::<u64>()).max(1),
                CudaHostAllocFlags::DEFAULT,
            )
            .map(|host| Self { host })
            .map_err(|e| format!("cannot pin {bytes} bytes for a history slot: {e}"))
        }

        pub(in super::super) fn base(&mut self) -> NonNull<u8> {
            NonNull::new(self.host.as_mut_ptr().cast()).expect("a pinned allocation at null")
        }
    }

    /// Recorded on a stream after its last copy out of a slot, so the slot goes back to the arena only
    /// once that copy has run: a pinned source is read by the copy engine after `cudaMemcpyAsync`
    /// returns, unlike a pageable one, which the driver stages before it does.
    pub struct DeviceReadsDone(CudaEvent);

    impl DeviceReadsDone {
        #[must_use]
        pub fn new(event: CudaEvent) -> Self {
            Self(event)
        }
    }

    // SAFETY: a CUDA event is a context object any host thread may synchronize on.
    unsafe impl Send for DeviceReadsDone {}

    #[derive(Default)]
    pub(in super::super) struct SlotFence(Mutex<Vec<DeviceReadsDone>>);

    impl SlotFence {
        pub(in super::super) fn hold(&self, done: DeviceReadsDone) {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(done);
        }

        /// Blocks until every held copy has run. A failed synchronisation leaves the slot unsafe to
        /// reuse, so it is a panic, not a skipped wait.
        pub(in super::super) fn wait(&self) {
            let held = std::mem::take(
                &mut *self
                    .0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
            for DeviceReadsDone(event) in held {
                event.synchronize().unwrap_or_else(|e| {
                    panic!("a copy out of a history slot did not complete: {e}")
                });
            }
        }
    }
}

#[cfg(not(feature = "cuda"))]
mod heap {
    use std::ptr::NonNull;

    pub(in super::super) struct PinnedSlot {
        host: Vec<u64>,
    }

    impl PinnedSlot {
        pub(in super::super) fn alloc(bytes: usize) -> Result<Self, String> {
            Ok(Self {
                host: vec![0; bytes.div_ceil(size_of::<u64>()).max(1)],
            })
        }

        pub(in super::super) fn base(&mut self) -> NonNull<u8> {
            NonNull::new(self.host.as_mut_ptr().cast()).expect("a heap allocation at null")
        }
    }

    /// No device reads a slot without `cuda`, so there is never one to wait for.
    pub enum DeviceReadsDone {}

    #[derive(Default)]
    pub(in super::super) struct SlotFence(());

    impl SlotFence {
        pub(in super::super) fn hold(&self, done: DeviceReadsDone) {
            match done {}
        }

        pub(in super::super) fn wait(&self) {}
    }
}
