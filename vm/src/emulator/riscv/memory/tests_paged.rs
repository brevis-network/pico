use super::{Memory, Memory32, Memory64, PagedMemory64};

#[test]
fn memory32_parity_insert_get() {
    let mut memory: Memory32<u32> = Memory::new_preallocated();
    memory.insert(0, 11);
    memory.insert(4, 22);
    assert_eq!(memory.get(0), Some(&11));
    assert_eq!(memory.get(4), Some(&22));
}

#[test]
fn memory64_high_address_path() {
    let mut memory: Memory64<u32> = Memory::new_preallocated();

    let high_addr = 0x1_0000_0000u64;
    memory.insert(high_addr, 0xCAFE_BABE);
    memory.insert(high_addr + 0x1000, 0xDEAD_BEEF);

    assert_eq!(memory.get(high_addr), Some(&0xCAFE_BABE));
    assert_eq!(memory.get(high_addr + 0x1000), Some(&0xDEAD_BEEF));
}

#[test]
fn memory64_register_path_uses_low_addresses() {
    let mut memory: Memory64<u32> = Memory::new_preallocated();
    memory.insert(5, 0x1234_5678);
    assert_eq!(memory.get(5), Some(&0x1234_5678));
}

#[test]
fn paged_memory_from_iter_round_trip() {
    let paged: PagedMemory64<u32> = [(0x1000_u64, 7_u32), (0x2000_u64, 9_u32)]
        .into_iter()
        .collect();

    assert_eq!(paged.get(0x1000), Some(&7));
    assert_eq!(paged.get(0x2000), Some(&9));

    let collected: std::collections::BTreeMap<_, _> = paged.into_iter().collect();
    assert_eq!(collected.get(&0x1000), Some(&7));
    assert_eq!(collected.get(&0x2000), Some(&9));
}
