use crate::{
    compiler::word::Word,
    configs::config::Poseidon2Config,
    emulator::{
        recursion::public_values::RecursionPublicValues, riscv::public_values::PublicValues,
    },
};
use p3_field::Field;
use p3_koala_bear::KoalaBear;
use std::mem::size_of;

/*
For address, byte and word
 */

/// The size of an address
pub const ADDR_SIZE: usize = 3;

/// The size of a byte in bits.
pub const BYTE_SIZE: usize = 8;

/// The size of a word in bytes.
pub const WORD_SIZE: usize = 4;

/// The size of a long word in bytes.
pub const LONG_WORD_SIZE: usize = 2 * WORD_SIZE;

/// The size of a word in bytes.
pub const WORD_BYTE_SIZE: usize = 2 * WORD_SIZE;

/// The number of bytes necessary to represent a 128-bit integer.
pub const LONG_WORD_BYTE_SIZE: usize = 2 * WORD_BYTE_SIZE;

/*
For public values
 */

pub const RISCV_NUM_PVS: usize = size_of::<PublicValues<Word<u8>, u8>>();
pub const RECURSION_NUM_PVS: usize = size_of::<RecursionPublicValues<u8>>();
pub const MAX_NUM_PVS: usize = RECURSION_NUM_PVS;

/*
For Extensions
 */

pub const EXTENSION_DEGREE: usize = 4;

/*
For digests
 */

pub const DIGEST_SIZE: usize = 8;

pub const PV_DIGEST_NUM_WORDS: usize = 8;

/*
For options
 */

pub const MAX_LOG_CHUNK_SIZE: usize = 23;

/// The `clk` value of every chunk's first CPU row.
///
/// Not zero: the memory bus needs one timestamp below every real access, so that
/// `MemoryLocalChip` can label the state a chunk inherits from an earlier one. A memory access
/// is stamped `clk + MemoryAccessPosition`, and the four positions are all in use, so the room
/// has to come from the start of the counter. One would do; 4 is the per-instruction clk
/// increment, so the counter starts where an instruction boundary would put it. `CHUNK_CLK_START`
/// is charged to the chunk-split threshold
/// (`ChunkSplitConfig::for_chunk_size`), so the absolute clk ceiling is unchanged and
/// CHUNK_SIZE=2^23 stays valid -- it is the shipping operating point and its log2 is in the VK.
pub const CHUNK_CLK_START: u32 = 4;

// for test
pub const TEST_CHUNK_SIZE: u32 = 1 << 16;
// One, not two: the deferred split's committed-chunk filter is only valid at one chunk per
// batch (see `chunk_batch_size`).
pub const TEST_CHUNK_BATCH_SIZE: u32 = 1;
pub const TEST_DEFERRED_SPLIT_THRESHOLD: usize = 1 << 7;

// for benchmark
// Unlocked by the 25-bit chunk-clk widening (which makes this size sound), the slimmed AIR
// (a narrower RS-code matrix) and the streaming RS/WHIR commit (which caps its peak
// allocation). Was 2^22, the old 24-bit chunk-clk cap.
pub const BENCH_MAX_CHUNK_SIZE: u32 = 1 << 23;
pub const BENCH_MAX_DEFERRED_SPLIT_THRESHOLD: usize = 1 << 20;
// One chunk per batch, for the same reason as `TEST_CHUNK_BATCH_SIZE`.
pub const BENCH_MAX_CHUNK_BATCH_SIZE: u32 = 1;
pub const BENCH_RECURSION_MAX_CHUNK_SIZE: u32 = 1 << 22;

/*
For RiscV
 */
pub const MAX_LOG_NUMBER_OF_CHUNKS: usize = 16;

/*
For recursion
 */

pub const COMBINE_SIZE: usize = 2;

pub const EMPTY: usize = 0x_1111_1111;

pub const ADDR_NUM_LIMBS: usize = 3;

pub const EMULATOR_POSEIDON2_LEN: usize = 7_100_000;

/// Converts a slice of words to a slice of bytes in little endian.
pub fn words_to_bytes_le<const B: usize>(words: &[u32]) -> [u8; B] {
    debug_assert_eq!(words.len() * 4, B);
    words
        .iter()
        .flat_map(|word| word.to_le_bytes().to_vec())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// Converts a byte array in little endian to a slice of words.
pub fn bytes_to_words_le<const W: usize>(bytes: &[u8]) -> [u32; W] {
    debug_assert_eq!(bytes.len(), W * 4);
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|chunk| u32::from_le_bytes(*chunk))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// Converts a 64-bit integer to four 16-bit limbs (little endian).
pub fn u64_to_u16_limbs(value: u64) -> [u16; 4] {
    [
        (value & 0xFFFF) as u16,
        (value >> 16) as u16,
        (value >> 32) as u16,
        (value >> 48) as u16,
    ]
}

/// Converts a 32-bit integer to a pair of 16-bit integers.
pub fn u32_to_u16_limbs(value: u32) -> [u16; 2] {
    [(value & 0xFFFF) as u16, (value >> 16) as u16]
}

/// Converts a 32-bit integer to a pair of field elements (half words).
pub fn u32_to_half_word<F: Field>(value: u32) -> [F; 2] {
    [
        F::from_u16((value & 0xFFFF) as u16),
        F::from_u16((value >> 16) as u16),
    ]
}

/*
KoalaBear consts
 */

pub const KOALABEAR_MONTY_INVERSE: KoalaBear = KoalaBear::new(1);
pub const KOALABEAR_W: u32 = 3;

/*
Poseidon2
 */

pub const PERMUTATION_WIDTH: usize = 16;
pub const PERMUTATION_RATE: usize = 8;

// The BN254 sponge the wrap circuit runs its challenger on -- the outer, on-chain half, not the
// riscv stage above.
pub const MULTI_FIELD_CHALLENGER_WIDTH: usize = 3;
pub const MULTI_FIELD_CHALLENGER_RATE: usize = 2;

#[derive(Clone, Copy, Default)]
pub struct KoalaBearConfig;
impl Poseidon2Config for KoalaBearConfig {
    type FullRounds = typenum::U8;
    type HalfFullRounds = typenum::U4;
    type HalfFullRoundsM1 = typenum::U3;
    type PartialRounds = typenum::U20;
    type PartialRoundsM1 = typenum::U19;
    type SBoxRegisters = typenum::U0;
}
pub const KOALABEAR_S_BOX_DEGREE: u64 = 3;
pub const KOALABEAR_NUM_EXTERNAL_ROUNDS: usize = 8;
pub const KOALABEAR_NUM_INTERNAL_ROUNDS: usize = 20;

pub const BN254_S_BOX_DEGREE: u64 = 5;

/*
Chip Data Parallelism
 */
pub const ADD_DATAPAR: usize = 1;
pub const SUB_DATAPAR: usize = 1;
pub const MUL_DATAPAR: usize = 1;
pub const DIVREM_DATAPAR: usize = 1;
pub const LT_DATAPAR: usize = 1;
pub const SLL_DATAPAR: usize = 1;
pub const SR_DATAPAR: usize = 1;
pub const BITWISE_DATAPAR: usize = 1;
pub const MEMORY_RW_DATAPAR: usize = 1;
pub const LOCAL_MEMORY_DATAPAR: usize = 4;
pub const RISCV_POSEIDON2_DATAPAR: usize = 4;

pub const BASE_ALU_DATAPAR: usize = 2;
pub const EXT_ALU_DATAPAR: usize = 4;
pub const VAR_MEM_DATAPAR: usize = 4;
pub const CONST_MEM_DATAPAR: usize = 1;
pub const SELECT_DATAPAR: usize = 2;
/// Elements per ExtDotProduct trace row (MLE recursion precompile).
pub const EXT_DOT_PRODUCT_DATAPAR: usize = 8;
/// Packed value groups per ExtDotProduct trace row: each group reads ONE packed
/// value block (EXTENSION_DEGREE base values in its lanes) and EXTENSION_DEGREE
/// mu values, contributing `sum_k val.lane_k * mu_k` to the accumulator.
pub const EXT_DOT_PRODUCT_GROUPS: usize = EXT_DOT_PRODUCT_DATAPAR / EXTENSION_DEGREE;
/// Coefficients per HornerEval trace row (MLE recursion precompile).
pub const HORNER_EVAL_DATAPAR: usize = 4;
/// Pack operations per PackBlock trace row (MLE recursion precompile).
pub const PACK_BLOCK_DATAPAR: usize = 4;
/// Select operations per DigestSelect trace row (MLE recursion precompile).
pub const DIGEST_SELECT_DATAPAR: usize = 2;
pub const POSEIDON2_DATAPAR: usize = 1;

pub const NUM_BITS: usize = 31;
