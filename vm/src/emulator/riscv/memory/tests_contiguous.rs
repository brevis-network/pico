use crate::chips::chips::riscv_memory::event::MemoryRecord;

use super::{ContiguousRiscvMemory, VALUES_SIZE};

#[test]
fn contiguous_memory_serialization_round_trip() {
    let mut memory = ContiguousRiscvMemory::new();
    memory.insert(
        0x100,
        MemoryRecord {
            value: 42,
            chunk: 1,
            timestamp: 2,
        },
    );
    memory.insert(
        64,
        MemoryRecord {
            value: 999,
            chunk: 5,
            timestamp: 6,
        },
    );

    let serialized = bincode::serialize(&memory).unwrap();
    assert!(serialized.len() < 1000);

    let deserialized: ContiguousRiscvMemory = bincode::deserialize(&serialized).unwrap();
    assert_eq!(
        deserialized.get(0x100),
        MemoryRecord {
            value: 42,
            chunk: 1,
            timestamp: 2
        }
    );
    assert_eq!(
        deserialized.get(64),
        MemoryRecord {
            value: 999,
            chunk: 5,
            timestamp: 6
        }
    );
}

#[test]
fn mark_accessed_behavior_matches_contract() {
    let mut memory = ContiguousRiscvMemory::new();
    memory.insert(
        0x1000,
        MemoryRecord {
            value: 0,
            chunk: 0,
            timestamp: 0,
        },
    );
    assert!(memory.has_accessed(0x1000));

    let _ = memory.get(0x2000);
    assert!(!memory.has_accessed(0x2000));

    let _ = memory.get_mut_or_create(0x3000);
    assert!(memory.has_accessed(0x3000));
}

#[test]
fn par_restore_preserves_timestamp() {
    let mut src = ContiguousRiscvMemory::new();
    let mut dst = ContiguousRiscvMemory::new();
    let addr = 0x4000u64;
    let ts = u32::MAX - 777;

    src.insert(
        addr,
        MemoryRecord {
            value: 0xDEAD_BEEF,
            chunk: 9,
            timestamp: ts,
        },
    );
    dst.par_restore_from(&src);

    assert_eq!(dst.get(addr).timestamp, ts);
    assert_eq!(dst.get(addr).chunk, 9);
    assert_eq!(dst.get(addr).value, 0xDEAD_BEEF);
}

#[test]
#[should_panic(expected = "dword address out of range")]
fn dword_access_out_of_range_panics() {
    let mut memory = ContiguousRiscvMemory::new();
    memory.write_dword(VALUES_SIZE as u64, 1, 0, 0);
}

/// The bitmap-only clear and `reset` both reach every marked word: the first and last word of a
/// cache line of the bitmap, and its last word. `reset` zeroes the cells under them; the bitmap-only
/// clear leaves them as they were.
#[test]
fn the_sparse_clears_reach_every_marked_word() {
    let addrs = [0x100, 0xff8, 0x1000, VALUES_SIZE as u64 - 8];
    let record = MemoryRecord {
        value: 0xdead_beef,
        chunk: 3,
        timestamp: 5,
    };
    let mark = |memory: &mut ContiguousRiscvMemory| {
        for addr in addrs {
            memory.insert_u64(addr, record);
        }
    };
    let mut memory = ContiguousRiscvMemory::new();

    mark(&mut memory);
    memory.clear_accessed_bitmap();
    for addr in addrs {
        assert!(!memory.has_accessed(addr), "{addr:#x} is still marked");
        assert_eq!(memory.get(addr), record, "{addr:#x} lost its cell");
    }

    mark(&mut memory);
    memory.reset();
    for addr in addrs {
        assert!(
            !memory.has_accessed(addr),
            "{addr:#x} is still marked after reset"
        );
        assert_eq!(
            memory.get(addr),
            MemoryRecord::default(),
            "{addr:#x} was not zeroed"
        );
    }
}
