// todo: further cleanup since these might be repetitive
/*
For word and bytes
 */
use crate::{compiler::word::Word, emulator::riscv::public_values::PublicValues};
use std::mem::size_of;
// todo: further cleanup since these might be repetitive
/*
For word and bytes
 */
use crate::recursion::air::RecursionPublicValues;

/// The size of a byte in bits.
pub const BYTE_SIZE: usize = 8;

/// The size of a word in bytes.
pub const WORD_SIZE: usize = 4;

/// The size of a long word in bytes.
pub const LONG_WORD_SIZE: usize = 2 * WORD_SIZE;

/*
For public values
 */

pub const MAX_NUM_PVS: usize = 370;

pub const RISCV_NUM_PVS: usize = size_of::<PublicValues<Word<u8>, u8>>();

pub const RECURSION_NUM_PVS: usize = size_of::<RecursionPublicValues<u8>>();

/*
For Extensions
 */

pub const EXTENSION_DEGREE: usize = 4;

/*
For digests
 */

pub const DIGEST_SIZE: usize = 8;

pub const PV_DIGEST_NUM_WORDS: usize = 8;

/// The number of field elements in the poseidon2 digest.
pub const POSEIDON_NUM_WORDS: usize = 8;

/*
For chunks
 */

pub const MAX_LOG_CHUNK_SIZE: i32 = 22;

pub const DEFAULT_CHUNK_SIZE: usize = 1 << MAX_LOG_CHUNK_SIZE;

pub const DEFAULT_CHUNK_BATCH_SIZE: usize = 16;
/// The threshold for splitting deferred events.
pub const DEFERRED_SPLIT_THRESHOLD: usize = 1 << 19;

pub const TEST_CHUNK_SIZE: usize = 1 << 16;

pub const TEST_CHUNK_BATCH_SIZE: usize = 2;

pub const TEST_DEFERRED_SPLIT_THRESHOLD: usize = 1 << 5;
