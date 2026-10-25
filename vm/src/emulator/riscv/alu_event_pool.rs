use crate::{
    chips::chips::alu::event::AluEvent,
    create_event_pool_manager,
    emulator::riscv::event_pool::{growable, EventBuffer, EventPoolManager},
};
use cudart::memory::CudaHostAllocFlags;
use once_cell::sync::Lazy;
use std::{env, fmt};

// default ALU event buffer size — same as CPU event default
const DEFAULT_ALU_EVENT_BUFFER_CAPACITY: usize = 1 << 22;

// static variable of ALU event buffer size for avoiding duplicate initialization
pub(crate) static ALU_EVENT_BUFFER_CAPACITY: Lazy<usize> = Lazy::new(alu_event_buffer_capacity);

// get the ALU event buffer size
fn alu_event_buffer_capacity() -> usize {
    // set to ALU_EVENT_BUFFER_SIZE if available, otherwise use CHUNK_SIZE, otherwise use default
    env::var("ALU_EVENT_BUFFER_SIZE")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .or_else(|| {
            env::var("CHUNK_SIZE")
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
        })
        .unwrap_or(DEFAULT_ALU_EVENT_BUFFER_CAPACITY)
}

// Create the ALU event pool manager
create_event_pool_manager!(
    AluEventPoolManager,
    AluEvent,
    ALU_EVENT_POOL,
    ALU_EVENT_BUFFER_CAPACITY
);

/// Initializes the global ALU event buffer pool.
/// This function should be called once at application startup.
/// It will panic if called more than once.
pub fn init_alu_event_buffer_pool(pool_size: usize, flags: CudaHostAllocFlags) {
    AluEventPoolManager::init_pool(pool_size, flags);
}

/// Gets a real buffer from the global pool, wrapped in `AluEventBuffer::Buffer`.
pub fn get_alu_event_buffer() -> Option<AluEventBuffer> {
    AluEventPoolManager::get_buffer()
}

/// Returns a buffer to the global pool. Empties are ignored.
pub fn return_alu_event_buffer(buffer: AluEventBuffer) {
    AluEventPoolManager::return_buffer(buffer);
}

/// Releases all buffers in the global pool.
pub fn shutdown_alu_event_buffer_pool() {
    AluEventPoolManager::shutdown_pool();
}

/// Checks if the ALU event buffer pool has been initialized.
pub fn is_alu_pool_initialized() -> bool {
    AluEventPoolManager::is_pool_initialized()
}

/// Type alias for ALU event buffer
pub type AluEventBuffer = EventBuffer<AluEvent>;

// Re-export the generic buffer methods for convenience
impl AluEventBuffer {
    /// Push an ALU event to the buffer
    #[inline]
    pub fn push_alu(&mut self, event: AluEvent) -> Result<(), &'static str> {
        self.push_generic(event, get_alu_event_buffer)
    }

    /// Extend the buffer with ALU events from a slice
    pub fn extend_from_alu_slice(&mut self, events: &[AluEvent]) -> Result<(), &'static str> {
        self.extend_from_slice_generic(events, get_alu_event_buffer)
    }

    /// Append all events from a Vec<AluEvent>, draining the source vec.
    /// Equivalent to Vec::append but for pinnned EventBuffer.
    pub fn append_vec(&mut self, source: &mut Vec<AluEvent>) -> Result<(), &'static str> {
        if source.is_empty() {
            return Ok(());
        }
        self.extend_from_slice_generic(source.as_slice(), get_alu_event_buffer)?;
        source.clear();
        Ok(())
    }

    /// Append all events from another AluEventBuffer, draining the source.
    pub fn append_from(&mut self, other: &mut AluEventBuffer) {
        match (&mut *self, &mut *other) {
            (EventBuffer::Empty, EventBuffer::Buffer(_)) => {
                // Self is empty, just take the other buffer
                let moved = std::mem::replace(other, EventBuffer::empty());
                *self = moved;
            }
            (EventBuffer::Buffer(dst), EventBuffer::Buffer(_)) if dst.is_empty() => {
                // Self has an empty buffer, swap to avoid copying
                std::mem::swap(self, other);
            }
            _ => {
                // Otherwise, copy as many as fit and clear the source
                let other_slice = other.as_slice();
                if !other_slice.is_empty() {
                    let _ = self.extend_from_slice_generic(other_slice, get_alu_event_buffer);
                }
                other.clear();
            }
        }
    }

    /// Convert to a Vec<AluEvent> by copying the contents.
    pub fn to_vec(&self) -> Vec<AluEvent> {
        self.as_slice().to_vec()
    }
}

impl Clone for AluEventBuffer {
    fn clone(&self) -> Self {
        match self {
            AluEventBuffer::Buffer(b) => {
                let mut new_buffer = get_alu_event_buffer()
                    .expect("Failed to get buffer from pool for clone operation");
                if !b.is_empty() {
                    new_buffer
                        .extend_from_slice_generic(b.as_slice(), get_alu_event_buffer)
                        .expect("Clone extend failed");
                }
                new_buffer
            }
            AluEventBuffer::Empty => AluEventBuffer::Empty,
        }
    }
}

// Serialization support
use serde::{
    de::{self, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

impl Serialize for AluEventBuffer {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(self.as_slice())
    }
}

impl<'de> Deserialize<'de> for AluEventBuffer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AluEventBufferVisitor;

        impl<'de> Visitor<'de> for AluEventBufferVisitor {
            type Value = AluEventBuffer;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    f,
                    "a sequence of AluEvent (up to capacity {})",
                    *ALU_EVENT_BUFFER_CAPACITY
                )
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                if let Some(n) = seq.size_hint() {
                    if n == 0 {
                        return Ok(AluEventBuffer::Empty);
                    }
                    if n > *ALU_EVENT_BUFFER_CAPACITY && !growable() {
                        return Err(de::Error::custom("Data exceeds buffer capacity"));
                    }
                }

                let mut buf = get_alu_event_buffer()
                    .ok_or_else(|| de::Error::custom("Failed to get buffer from pool"))?;

                match &mut buf {
                    AluEventBuffer::Buffer(b) => {
                        if let Some(n) = seq.size_hint() {
                            b.reserve(n).map_err(de::Error::custom)?;
                            for _ in 0..n {
                                let ev: AluEvent = seq
                                    .next_element()?
                                    .ok_or_else(|| de::Error::custom("sequence ended early"))?;
                                unsafe { b.push_unchecked(ev) }
                            }
                            while let Some(ev) = seq.next_element::<AluEvent>()? {
                                b.push(ev).map_err(de::Error::custom)?;
                            }
                        } else {
                            while let Some(ev) = seq.next_element::<AluEvent>()? {
                                b.push(ev).map_err(de::Error::custom)?;
                            }
                        }
                        Ok(buf)
                    }
                    AluEventBuffer::Empty => unreachable!(),
                }
            }
        }

        deserializer.deserialize_seq(AluEventBufferVisitor)
    }
}
