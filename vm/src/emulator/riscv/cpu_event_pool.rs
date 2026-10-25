use crate::{
    chips::chips::riscv_cpu::event::CpuEvent,
    create_event_pool_manager,
    emulator::riscv::event_pool::{growable, EventBuffer, EventPoolManager},
};
use cudart::memory::CudaHostAllocFlags;
use once_cell::sync::Lazy;
use std::{env, fmt};

// default cpu event buffer size for rtx 5090
const DEFAULT_CPU_EVENT_BUFFER_CAPACITY: usize = 1 << 22;

// static variable of cpu event buffer size for avoiding duplicate initialization
pub(crate) static CPU_EVENT_BUFFER_CAPACITY: Lazy<usize> = Lazy::new(cpu_event_buffer_capacity);

// get the cpu event buffer size
fn cpu_event_buffer_capacity() -> usize {
    // set to CHUNK_SIZE if available
    env::var("CHUNK_SIZE")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(DEFAULT_CPU_EVENT_BUFFER_CAPACITY)
}

// Create the CPU event pool manager with larger buffer capacity (2^22 = 4,194,304 events)
create_event_pool_manager!(CpuEventPoolManager, CpuEvent, CPU_EVENT_POOL);

/// Initializes the global CPU event buffer pool.
/// This function should be called once at application startup.
/// It will panic if called more than once.
pub fn init_cpu_event_buffer_pool(pool_size: usize, flags: CudaHostAllocFlags) {
    CpuEventPoolManager::init_pool(pool_size, flags);
}

/// Gets a real buffer from the global pool, wrapped in `CpuEventBuffer::Real`.
pub fn get_cpu_event_buffer() -> Option<CpuEventBuffer> {
    CpuEventPoolManager::get_buffer()
}

/// Returns a buffer to the global pool. Empties are ignored.
pub fn return_cpu_event_buffer(buffer: CpuEventBuffer) {
    CpuEventPoolManager::return_buffer(buffer);
}

/// Releases all buffers in the global pool. Should be called after proving completes.
pub fn shutdown_cpu_event_buffer_pool() {
    CpuEventPoolManager::shutdown_pool();
}

/// Checks if the CPU event buffer pool has been initialized.
pub fn is_pool_initialized() -> bool {
    CpuEventPoolManager::is_pool_initialized()
}

/// Type alias for CPU event buffer
pub type CpuEventBuffer = EventBuffer<CpuEvent>;

// Re-export the generic buffer methods for convenience
impl CpuEventBuffer {
    /// Push a CPU event to the buffer
    #[inline]
    pub fn push(&mut self, event: CpuEvent) -> Result<(), &'static str> {
        self.push_generic(event, get_cpu_event_buffer)
    }

    /// Extend the buffer with CPU events from a slice
    pub fn extend_from_slice(&mut self, events: &[CpuEvent]) -> Result<(), &'static str> {
        self.extend_from_slice_generic(events, get_cpu_event_buffer)
    }
}

impl Clone for CpuEventBuffer {
    fn clone(&self) -> Self {
        match self {
            CpuEventBuffer::Buffer(b) => {
                let mut new_buffer = get_cpu_event_buffer()
                    .expect("Failed to get buffer from pool for clone operation");
                if !b.is_empty() {
                    new_buffer
                        .extend_from_slice_generic(b.as_slice(), get_cpu_event_buffer)
                        .expect("Clone extend failed");
                }
                new_buffer
            }
            CpuEventBuffer::Empty => CpuEventBuffer::Empty,
        }
    }
}

// Re-export the serialization traits
use serde::{
    de::{self, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

impl Serialize for CpuEventBuffer {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Zero-copy: delegate to slice serialization.
        serializer.collect_seq(self.as_slice())
    }
}

impl<'de> Deserialize<'de> for CpuEventBuffer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CpuEventBufferVisitor;

        impl<'de> Visitor<'de> for CpuEventBufferVisitor {
            type Value = CpuEventBuffer;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    f,
                    "a sequence of CpuEvent (up to capacity {})",
                    *CPU_EVENT_BUFFER_CAPACITY
                )
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                // If the format knows the exact length, we can early-reject.
                if let Some(n) = seq.size_hint() {
                    if n == 0 {
                        return Ok(CpuEventBuffer::Empty);
                    }
                    if n > *CPU_EVENT_BUFFER_CAPACITY && !growable() {
                        return Err(de::Error::custom("Data exceeds buffer capacity"));
                    }
                }

                let mut buf = get_cpu_event_buffer()
                    .ok_or_else(|| de::Error::custom("Failed to get buffer from pool"))?;

                match &mut buf {
                    CpuEventBuffer::Buffer(b) => {
                        // If we know it's <= capacity, we can use unchecked pushes.
                        if let Some(n) = seq.size_hint() {
                            b.reserve(n).map_err(de::Error::custom)?;
                            // Known-upper-bound path
                            for _ in 0..n {
                                let ev: CpuEvent = seq
                                    .next_element()?
                                    .ok_or_else(|| de::Error::custom("sequence ended early"))?;
                                unsafe { b.push_unchecked(ev) }
                            }
                            // For well-behaved formats with exact size, we're done.
                            // In case the format keeps yielding (shouldn't), guard capacity.
                            while let Some(ev) = seq.next_element::<CpuEvent>()? {
                                b.push(ev).map_err(de::Error::custom)?;
                            }
                        } else {
                            // Unknown length: check capacity per element.
                            while let Some(ev) = seq.next_element::<CpuEvent>()? {
                                b.push(ev).map_err(de::Error::custom)?;
                            }
                        }
                        Ok(buf)
                    }
                    CpuEventBuffer::Empty => unreachable!(),
                }
            }
        }

        deserializer.deserialize_seq(CpuEventBufferVisitor)
    }
}
