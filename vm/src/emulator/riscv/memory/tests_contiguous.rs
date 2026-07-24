use crate::chips::chips::riscv_memory::event::MemoryRecord;

use super::{ContiguousRiscvMemory, VALUES_SIZE};

#[test]
fn cow_checkpoint_support_matches_feature() {
    let regular_memory = ContiguousRiscvMemory::new();
    assert!(!regular_memory.supports_cow_checkpoint());

    let checkpointable_memory = ContiguousRiscvMemory::new_checkpointable();
    assert_eq!(
        checkpointable_memory.supports_cow_checkpoint(),
        cfg!(feature = "mmap-memory")
    );
}

#[cfg(feature = "mmap-memory")]
#[test]
fn cow_checkpoint_restores_values_and_metadata() {
    let mut memory = ContiguousRiscvMemory::new_checkpointable();
    memory.insert(
        0x100,
        MemoryRecord {
            value: 0x1111_2222_3333_4444,
            chunk: 7,
            timestamp: 9,
        },
    );
    memory.insert(
        0x108,
        MemoryRecord {
            value: 0xAAAA_BBBB_CCCC_DDDD,
            chunk: 3,
            timestamp: 5,
        },
    );

    let checkpoint = memory
        .fork_cow_checkpoint()
        .expect("checkpoint should exist");
    memory.insert(
        0x100,
        MemoryRecord {
            value: 0x9999_8888_7777_6666,
            chunk: 1,
            timestamp: 2,
        },
    );
    memory.insert(
        0x108,
        MemoryRecord {
            value: 0x5555_4444_3333_2222,
            chunk: 4,
            timestamp: 6,
        },
    );

    memory.restore_from_checkpoint(checkpoint);

    assert_eq!(memory.get(0x100).value, 0x1111_2222_3333_4444);
    assert_eq!(memory.get(0x100).chunk, 7);
    assert_eq!(memory.get(0x100).timestamp, 9);
    assert_eq!(memory.get(0x108).value, 0xAAAA_BBBB_CCCC_DDDD);
    assert_eq!(memory.get(0x108).chunk, 3);
    assert_eq!(memory.get(0x108).timestamp, 5);
}

#[cfg(feature = "mmap-memory")]
#[test]
fn cow_checkpoint_preserves_untouched_initialized_pages() {
    let mut memory = ContiguousRiscvMemory::new_checkpointable();
    memory.write_dword(0x200, 0x1234_5678_9ABC_DEF0, 11, 17);

    let checkpoint = memory
        .fork_cow_checkpoint()
        .expect("checkpoint should exist");
    memory.write_dword(0x100, 0xAAAA_AAAA_BBBB_BBBB, 1, 2);

    memory.restore_from_checkpoint(checkpoint);

    assert_eq!(memory.get(0x200).value, 0x1234_5678_9ABC_DEF0);
    assert_eq!(memory.get(0x200).chunk, 11);
    assert_eq!(memory.get(0x200).timestamp, 17);
}

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
