use serde::{Deserialize, Serialize};

use crate::emulator::riscv::event_types::{RvAddr, RvChunk, RvTimestamp, RvValue};

/// Memory Record.
///
/// This object encapsulates the information needed to prove a memory access operation. This
/// includes the chunk, timestamp, and value of the memory address.
#[derive(Debug, Copy, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MemoryRecord {
    /// The chunk number.
    pub chunk: RvChunk,
    /// The timestamp.
    pub timestamp: RvTimestamp,
    /// The value.
    pub value: RvValue,
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
    pub value: RvValue,
    /// The chunk number.
    pub chunk: RvChunk,
    /// The timestamp.
    pub timestamp: RvTimestamp,
    /// The previous chunk number.
    pub prev_chunk: RvChunk,
    /// The previous timestamp.
    pub prev_timestamp: RvTimestamp,
}

/// Memory Write Record.
///
/// This object encapsulates the information needed to prove a memory write operation. This
/// includes the value, chunk, timestamp, previous value, previous chunk, and previous timestamp.
#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize)]
pub struct MemoryWriteRecord {
    /// The value.
    pub value: RvValue,
    /// The chunk number.
    pub chunk: RvChunk,
    /// The timestamp.
    pub timestamp: RvTimestamp,
    /// The previous value.
    pub prev_value: RvValue,
    /// The previous chunk number.
    pub prev_chunk: RvChunk,
    /// The previous timestamp.
    pub prev_timestamp: RvTimestamp,
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
    pub addr: RvAddr,
    /// The value.
    pub value: RvValue,
    /// The chunk number.
    pub chunk: RvChunk,
    /// The timestamp.
    pub timestamp: RvTimestamp,
    /// The used flag.
    pub used: u32,
}

impl MemoryReadRecord {
    /// Creates a new [``MemoryReadRecord``].
    #[must_use]
    pub const fn new(
        value: RvValue,
        chunk: RvChunk,
        timestamp: RvTimestamp,
        prev_chunk: RvChunk,
        prev_timestamp: RvTimestamp,
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
        value: RvValue,
        chunk: RvChunk,
        timestamp: RvTimestamp,
        prev_value: RvValue,
        prev_chunk: RvChunk,
        prev_timestamp: RvTimestamp,
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
    pub const fn value(&self) -> RvValue {
        match self {
            MemoryRecordEnum::Read(record) => record.value,
            MemoryRecordEnum::Write(record) => record.value,
        }
    }
}

impl MemoryInitializeFinalizeEvent {
    /// Creates a new [``MemoryInitializeFinalizeEvent``] for an initialization.
    #[must_use]
    pub const fn initialize(addr: RvAddr, value: RvValue, used: bool) -> Self {
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
    pub const fn finalize_from_record(addr: RvAddr, record: &MemoryRecord) -> Self {
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

/// Memory Local Event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryLocalEvent {
    /// The address
    pub addr: RvAddr,
    /// The initial memory access
    pub initial_mem_access: MemoryRecord,
    /// The final memory access
    pub final_mem_access: MemoryRecord,
}

#[cfg(test)]
mod tests {
    use super::{
        MemoryInitializeFinalizeEvent, MemoryLocalEvent, MemoryReadRecord, MemoryRecord,
        MemoryRecordEnum, MemoryWriteRecord,
    };

    #[test]
    fn serde_roundtrip_preserves_memory_event_fields() {
        let read = MemoryReadRecord::new(0xABCD_EF01_2345_6789, 3, u32::MAX - 1, 2, u32::MAX - 9);
        let write = MemoryWriteRecord::new(
            0x7FFF_FFFF_0000_0001,
            4,
            u32::MAX - 3,
            0x8000_0000_0000_0002,
            3,
            u32::MAX - 4,
        );
        let init_finalize = MemoryInitializeFinalizeEvent {
            addr: 0x1_0000_0000,
            value: 0x1234_5678_9ABC_DEF0,
            chunk: 5,
            timestamp: u32::MAX - 123,
            used: 1,
        };
        let local = MemoryLocalEvent {
            addr: 0x1_0000_0000,
            initial_mem_access: MemoryRecord {
                chunk: 1,
                timestamp: u32::MAX - 17,
                value: 0x1111_2222_3333_4444,
            },
            final_mem_access: MemoryRecord {
                chunk: 2,
                timestamp: u32::MAX - 16,
                value: 0x5555_6666_7777_8888,
            },
        };
        let enum_read = MemoryRecordEnum::Read(read);
        let enum_write = MemoryRecordEnum::Write(write);

        let encoded =
            serde_json::to_string(&(enum_read, enum_write, init_finalize.clone(), local.clone()))
                .expect("serialize");
        let decoded: (
            MemoryRecordEnum,
            MemoryRecordEnum,
            MemoryInitializeFinalizeEvent,
            MemoryLocalEvent,
        ) = serde_json::from_str(&encoded).expect("deserialize");

        assert_eq!(decoded.0.value(), enum_read.value());
        assert_eq!(decoded.1.value(), enum_write.value());
        assert_eq!(decoded.2.timestamp, init_finalize.timestamp);
        assert_eq!(decoded.2.addr, init_finalize.addr);
        assert_eq!(
            decoded.3.initial_mem_access.timestamp,
            local.initial_mem_access.timestamp
        );
        assert_eq!(
            decoded.3.final_mem_access.timestamp,
            local.final_mem_access.timestamp
        );
    }
}
