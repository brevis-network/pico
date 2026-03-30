pub mod edwards;
pub mod fptower;
pub mod keccak256;
pub mod poseidon2;
pub mod sha256;
pub mod uint256;
pub mod weierstrass;

use crate::chips::chips::riscv_memory::event::{MemoryReadRecord, MemoryWriteRecord};

/// Checked u64 -> u32 narrowing at proof/FFI boundaries.
/// Panics if value exceeds u32::MAX.
#[inline(always)]
pub fn checked_u64_to_u32(value: u64, context: &str) -> u32 {
    u32::try_from(value)
        .unwrap_or_else(|_| panic!("{context}: 0x{value:016x} exceeds u32 boundary"))
}

#[inline(always)]
fn low_u32_word(value: u64) -> u32 {
    // Intentionally split a dword into legacy little-endian u32 words for retained chip/FFI
    // layouts that still operate on 32-bit limbs.
    u32::try_from(value & 0xFFFF_FFFF)
        .unwrap_or_else(|_| panic!("low word split failed for 0x{value:016x}"))
}

#[inline(always)]
fn high_u32_word(value: u64) -> u32 {
    // Intentionally split a dword into legacy little-endian u32 words for retained chip/FFI
    // layouts that still operate on 32-bit limbs.
    u32::try_from(value >> 32)
        .unwrap_or_else(|_| panic!("high word split failed for 0x{value:016x}"))
}

pub fn split_dword_words_to_legacy_u32_words(words: &[u64]) -> Vec<u32> {
    words
        .iter()
        .flat_map(|&word| [low_u32_word(word), high_u32_word(word)])
        .collect()
}

pub fn checked_word_values_to_legacy_u32_words(words: &[u64], context: &str) -> Vec<u32> {
    // Some chips still model algorithm-native payload words as exact u32 values. Keep this as an
    // explicit checked boundary rather than an unlabeled compatibility shim.
    words
        .iter()
        .map(|&word| checked_u64_to_u32(word, context))
        .collect()
}

pub fn split_dword_read_records_to_word_records(
    records: &[MemoryReadRecord],
) -> Vec<MemoryReadRecord> {
    records
        .iter()
        .flat_map(|record| {
            [
                MemoryReadRecord {
                    value: u64::from(low_u32_word(record.value)),
                    chunk: record.chunk,
                    timestamp: record.timestamp,
                    prev_chunk: record.prev_chunk,
                    prev_timestamp: record.prev_timestamp,
                },
                MemoryReadRecord {
                    value: u64::from(high_u32_word(record.value)),
                    chunk: record.chunk,
                    timestamp: record.timestamp,
                    prev_chunk: record.prev_chunk,
                    prev_timestamp: record.prev_timestamp,
                },
            ]
        })
        .collect()
}

pub fn split_dword_write_records_to_word_records(
    records: &[MemoryWriteRecord],
) -> Vec<MemoryWriteRecord> {
    records
        .iter()
        .flat_map(|record| {
            [
                MemoryWriteRecord {
                    value: u64::from(low_u32_word(record.value)),
                    chunk: record.chunk,
                    timestamp: record.timestamp,
                    prev_value: u64::from(low_u32_word(record.prev_value)),
                    prev_chunk: record.prev_chunk,
                    prev_timestamp: record.prev_timestamp,
                },
                MemoryWriteRecord {
                    value: u64::from(high_u32_word(record.value)),
                    chunk: record.chunk,
                    timestamp: record.timestamp,
                    prev_value: u64::from(high_u32_word(record.prev_value)),
                    prev_chunk: record.prev_chunk,
                    prev_timestamp: record.prev_timestamp,
                },
            ]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        checked_u64_to_u32, checked_word_values_to_legacy_u32_words,
        split_dword_read_records_to_word_records, split_dword_words_to_legacy_u32_words,
        split_dword_write_records_to_word_records,
    };
    use crate::chips::chips::riscv_memory::event::{MemoryReadRecord, MemoryWriteRecord};

    #[test]
    fn dword_words_split_to_legacy_u32_words_little_endian() {
        let words = [0xBBBB_BBBB_AAAA_AAAAu64, 0xDDDD_DDDD_CCCC_CCCCu64];
        assert_eq!(
            split_dword_words_to_legacy_u32_words(&words),
            vec![0xAAAA_AAAA, 0xBBBB_BBBB, 0xCCCC_CCCC, 0xDDDD_DDDD]
        );
    }

    #[test]
    fn checked_word_values_preserve_u32_words() {
        let words = [1u64, u64::from(u32::MAX), 7];
        assert_eq!(
            checked_word_values_to_legacy_u32_words(&words, "test"),
            vec![1, u32::MAX, 7]
        );
    }

    #[test]
    fn dword_read_record_expansion_splits_values() {
        let records = [MemoryReadRecord {
            value: 0xBBBB_BBBB_AAAA_AAAAu64,
            chunk: 3,
            timestamp: 11,
            prev_chunk: 2,
            prev_timestamp: 10,
        }];
        let expanded = split_dword_read_records_to_word_records(&records);
        assert_eq!(expanded.len(), 2);
        assert_eq!(expanded[0].value, 0xAAAA_AAAA);
        assert_eq!(expanded[1].value, 0xBBBB_BBBB);
        assert_eq!(expanded[0].timestamp, 11);
        assert_eq!(expanded[1].prev_timestamp, 10);
    }

    #[test]
    fn dword_write_record_expansion_splits_values_and_prev_values() {
        let records = [MemoryWriteRecord {
            value: 0xBBBB_BBBB_AAAA_AAAAu64,
            chunk: 3,
            timestamp: 11,
            prev_value: 0xDDDD_DDDD_CCCC_CCCCu64,
            prev_chunk: 2,
            prev_timestamp: 10,
        }];
        let expanded = split_dword_write_records_to_word_records(&records);
        assert_eq!(expanded.len(), 2);
        assert_eq!(expanded[0].value, 0xAAAA_AAAA);
        assert_eq!(expanded[1].value, 0xBBBB_BBBB);
        assert_eq!(expanded[0].prev_value, 0xCCCC_CCCC);
        assert_eq!(expanded[1].prev_value, 0xDDDD_DDDD);
    }

    #[test]
    #[should_panic(expected = "test overflow: 0x0000000100000000 exceeds u32 boundary")]
    fn checked_u64_to_u32_rejects_overflow() {
        let _ = checked_u64_to_u32(0x1_0000_0000, "test overflow");
    }

    #[test]
    fn checked_u64_to_u32_accepts_max_u32() {
        assert_eq!(checked_u64_to_u32(u64::from(u32::MAX), "test"), u32::MAX);
    }
}
