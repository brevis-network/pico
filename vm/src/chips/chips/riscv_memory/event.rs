use serde::{Deserialize, Serialize};

/// Memory Record.
///
/// This object encapsulates the information needed to prove a memory access operation. This
/// includes the chunk, timestamp, and value of the memory address.
#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize)]
pub struct MemoryRecord {
    /// The chunk number.
    pub chunk: u32,
    /// The timestamp.
    pub timestamp: u32,
    /// The value.
    pub value: u32,
}

/// Memory Access Position.
///
/// This enum represents the position of a memory access in a register. For example, if a memory
/// access is performed in the C register, it will have a position of C.
///
/// Note: The register positions require that they be read and written in the following order:
/// C, B, A.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum MemoryAccessPosition {
    /// Memory access position.
    Memory = 0,
    /// C register access position.
    C = 1,
    /// B register access position.
    B = 2,
    /// A register access position.
    A = 3,
}

/// Memory Read Record.
///
/// This object encapsulates the information needed to prove a memory read operation. This
/// includes the value, chunk, timestamp, and previous chunk and timestamp.
#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize)]
pub struct MemoryReadRecord {
    /// The value.
    pub value: u32,
    /// The chunk number.
    pub chunk: u32,
    /// The timestamp.
    pub timestamp: u32,
    /// The previous chunk number.
    pub prev_chunk: u32,
    /// The previous timestamp.
    pub prev_timestamp: u32,
}

/// Memory Write Record.
///
/// This object encapsulates the information needed to prove a memory write operation. This
/// includes the value, chunk, timestamp, previous value, previous chunk, and previous timestamp.
#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize)]
pub struct MemoryWriteRecord {
    /// The value.
    pub value: u32,
    /// The chunk number.
    pub chunk: u32,
    /// The timestamp.
    pub timestamp: u32,
    /// The previous value.
    pub prev_value: u32,
    /// The previous chunk number.
    pub prev_chunk: u32,
    /// The previous timestamp.
    pub prev_timestamp: u32,
}

/// Memory Record Enum.
///
/// This enum represents the different types of memory records that can be stored in the memory
/// event such as reads and writes.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum MemoryRecordEnum {
    /// Read.
    Read(MemoryReadRecord),
    /// Write.
    Write(MemoryWriteRecord),
}

/// Memory Initialize/Finalize Event.
///
/// This object encapsulates the information needed to prove a memory initialize or finalize
/// operation. This includes the address, value, chunk, timestamp, and whether the memory is
/// initialized or finalized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInitializeFinalizeEvent {
    /// The address.
    pub addr: u32,
    /// The value.
    pub value: u32,
    /// The chunk number.
    pub chunk: u32,
    /// The timestamp.
    pub timestamp: u32,
    /// The used flag.
    pub used: u32,
}

impl MemoryReadRecord {
    /// Creates a new [``MemoryReadRecord``].
    #[must_use]
    pub const fn new(
        value: u32,
        chunk: u32,
        timestamp: u32,
        prev_chunk: u32,
        prev_timestamp: u32,
    ) -> Self {
        assert!(chunk > prev_chunk || ((chunk == prev_chunk) && (timestamp > prev_timestamp)));
        Self {
            value,
            chunk,
            timestamp,
            prev_chunk,
            prev_timestamp,
        }
    }
}

impl MemoryWriteRecord {
    /// Creates a new [``MemoryWriteRecord``].
    #[must_use]
    pub const fn new(
        value: u32,
        chunk: u32,
        timestamp: u32,
        prev_value: u32,
        prev_chunk: u32,
        prev_timestamp: u32,
    ) -> Self {
        assert!(chunk > prev_chunk || ((chunk == prev_chunk) && (timestamp > prev_timestamp)),);
        Self {
            value,
            chunk,
            timestamp,
            prev_value,
            prev_chunk,
            prev_timestamp,
        }
    }
}

impl MemoryRecordEnum {
    /// Returns the value of the memory record.
    #[must_use]
    pub const fn value(&self) -> u32 {
        match self {
            MemoryRecordEnum::Read(record) => record.value,
            MemoryRecordEnum::Write(record) => record.value,
        }
    }
}

impl MemoryInitializeFinalizeEvent {
    /// Creates a new [``MemoryInitializeFinalizeEvent``] for an initialization.
    #[must_use]
    pub const fn initialize(addr: u32, value: u32, used: bool) -> Self {
        Self {
            addr,
            value,
            chunk: 1,
            timestamp: 1,
            used: if used { 1 } else { 0 },
        }
    }

    /// Creates a new [``MemoryInitializeFinalizeEvent``] for a finalization.
    #[must_use]
    pub const fn finalize_from_record(addr: u32, record: &MemoryRecord) -> Self {
        Self {
            addr,
            value: record.value,
            chunk: record.chunk,
            timestamp: record.timestamp,
            used: 1,
        }
    }
}

impl From<MemoryReadRecord> for MemoryRecordEnum {
    fn from(read_record: MemoryReadRecord) -> Self {
        MemoryRecordEnum::Read(read_record)
    }
}

impl From<MemoryWriteRecord> for MemoryRecordEnum {
    fn from(write_record: MemoryWriteRecord) -> Self {
        MemoryRecordEnum::Write(write_record)
    }
}
