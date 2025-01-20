// todo: further cleanup since these might be repetitive
/*
For word and bytes
 */
use crate::{
    compiler::word::Word,
    configs::config::Poseidon2Config,
    emulator::{
        recursion::public_values::RecursionPublicValues, riscv::public_values::PublicValues,
    },
};
use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;
use std::mem::size_of;

// todo: further cleanup since these might be repetitive
/*
For word and bytes
 */

/// The size of a byte in bits.
pub const BYTE_SIZE: usize = 8;

/// The size of a word in bytes.
pub const WORD_SIZE: usize = 4;

/// The size of a long word in bytes.
pub const LONG_WORD_SIZE: usize = 2 * WORD_SIZE;

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

/// The number of field elements in the poseidon2 digest.
pub const POSEIDON_NUM_WORDS: usize = 8;

/*
For chunks
 */

pub const MAX_LOG_CHUNK_SIZE: usize = 22;

pub const DEFAULT_CHUNK_SIZE: u32 = 1 << MAX_LOG_CHUNK_SIZE;

pub const DEFAULT_CHUNK_BATCH_SIZE: u32 = 16;
/// The threshold for splitting deferred events.
pub const DEFERRED_SPLIT_THRESHOLD: usize = 1 << 19;

pub const TEST_CHUNK_SIZE: u32 = 1 << 16;

pub const TEST_CHUNK_BATCH_SIZE: u32 = 2;

pub const TEST_DEFERRED_SPLIT_THRESHOLD: usize = 1 << 7;

// for benchmark
pub const BENCH_MAX_DEFERRED_SPLIT_THRESHOLD: usize = 1 << 18;

pub const BENCH_MAX_CHUNK_SIZE: u32 = 1 << 21;

pub const BENCH_MAX_CHUNK_BATCH_SIZE: u32 = 8;

pub const BENCH_RECURSION_MAX_CHUNK_SIZE: u32 = 1 << 22;

/*
For RiscV
 */
pub const MAX_LOG_NUMBER_OF_CHUNKS: usize = 16;
pub const MAX_NUMBER_OF_CHUNKS: usize = 1 << MAX_LOG_NUMBER_OF_CHUNKS;

/*
For recursion
 */

pub const COMBINE_SIZE: usize = 2;

pub const EMPTY: usize = 0x_1111_1111;

pub const ADDR_NUM_BITS: usize = 32;

/*
For recursion chip degrees
 */
pub const RISCV_SIMPLE_DEGREE: usize = 3;
pub const CONVERT_DEGREE: usize = 3;
pub const COMBINE_DEGREE: usize = 3;
pub const COMPRESS_DEGREE: usize = 3;
pub const EMBED_DEGREE: usize = 9;

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
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/*
BabyBear consts
 */

pub const MONTY_INVERSE: BabyBear = BabyBear::new(1);

// <https://github.com/Plonky3/Plonky3/blob/e61ed4aed488f8cef5618914042d8eb515b74ebb/baby-bear/src/poseidon2.rs#L66>
pub const POSEIDON2_INTERNAL_MATRIX_DIAG_16_BABYBEAR_MONTY: [BabyBear; 16] = BabyBear::new_array([
    BabyBear::ORDER_U32 - 2,
    1,
    2,
    (BabyBear::ORDER_U32 + 1) >> 1,
    3,
    4,
    (BabyBear::ORDER_U32 - 1) >> 1,
    BabyBear::ORDER_U32 - 3,
    BabyBear::ORDER_U32 - 4,
    BabyBear::ORDER_U32 - ((BabyBear::ORDER_U32 - 1) >> 8),
    BabyBear::ORDER_U32 - ((BabyBear::ORDER_U32 - 1) >> 2),
    BabyBear::ORDER_U32 - ((BabyBear::ORDER_U32 - 1) >> 3),
    BabyBear::ORDER_U32 - 15,
    (BabyBear::ORDER_U32 - 1) >> 8,
    (BabyBear::ORDER_U32 - 1) >> 4,
    15,
]);

pub const POSEIDON2_INTERNAL_MATRIX_DIAG_16_KOALABEAR_MONTY: [KoalaBear; 16] =
    KoalaBear::new_array([
        KoalaBear::ORDER_U32 - 2,
        1,
        2,
        (KoalaBear::ORDER_U32 + 1) >> 1,
        3,
        4,
        (KoalaBear::ORDER_U32 - 1) >> 1,
        KoalaBear::ORDER_U32 - 3,
        KoalaBear::ORDER_U32 - 4,
        KoalaBear::ORDER_U32 - ((KoalaBear::ORDER_U32 - 1) >> 8),
        KoalaBear::ORDER_U32 - ((KoalaBear::ORDER_U32 - 1) >> 3),
        KoalaBear::ORDER_U32 - 127,
        (KoalaBear::ORDER_U32 - 1) >> 8,
        (KoalaBear::ORDER_U32 - 1) >> 3,
        (KoalaBear::ORDER_U32 - 1) >> 4,
        127,
    ]);

/*
Poseidon2
 */

pub const PERMUTATION_WIDTH: usize = 16;

pub const PERMUTATION_RATE: usize = 8;

pub const MULTI_FIELD_CHALLENGER_WIDTH: usize = 3;

pub const MULTI_FIELD_CHALLENGER_RATE: usize = 2;

pub const MULTI_FIELD_CHALLENGER_DIGEST_SIZE: usize = 1;

#[derive(Clone, Copy, Default)]
pub struct BabyBearConfig;
impl Poseidon2Config for BabyBearConfig {
    type ExternalRounds = typenum::U8;
    type HalfExternalRounds = typenum::U4;
    type InternalRounds = typenum::U13;
    type InternalRoundsM1 = typenum::U12;
}
pub const BABYBEAR_S_BOX_DEGREE: u64 = 7;
pub const BABYBEAR_NUM_EXTERNAL_ROUNDS: usize = 8;
pub const BABYBEAR_NUM_INTERNAL_ROUNDS: usize = 13;
pub const BABYBEAR_NUM_ROUNDS: usize = BABYBEAR_NUM_EXTERNAL_ROUNDS + BABYBEAR_NUM_INTERNAL_ROUNDS;

#[derive(Clone, Copy, Default)]
pub struct KoalaBearConfig;
impl Poseidon2Config for KoalaBearConfig {
    type ExternalRounds = typenum::U8;
    type HalfExternalRounds = typenum::U4;
    type InternalRounds = typenum::U20;
    type InternalRoundsM1 = typenum::U19;
}
pub const KOALABEAR_S_BOX_DEGREE: u64 = 3;
pub const KOALABEAR_NUM_EXTERNAL_ROUNDS: usize = 8;
pub const KOALABEAR_NUM_INTERNAL_ROUNDS: usize = 20;
pub const KOALABEAR_NUM_ROUNDS: usize =
    KOALABEAR_NUM_EXTERNAL_ROUNDS + KOALABEAR_NUM_INTERNAL_ROUNDS;

#[derive(Clone, Copy, Default)]
pub struct Mersenne31Config;
impl Poseidon2Config for Mersenne31Config {
    type ExternalRounds = typenum::U8;
    type HalfExternalRounds = typenum::U4;
    type InternalRounds = typenum::U14;
    type InternalRoundsM1 = typenum::U13;
}
pub const MERSENNE31_S_BOX_DEGREE: u64 = 5;
pub const MERSENNE31_NUM_EXTERNAL_ROUNDS: usize = 8;
pub const MERSENNE31_NUM_INTERNAL_ROUNDS: usize = 14;
pub const MERSENNE31_NUM_ROUNDS: usize =
    MERSENNE31_NUM_EXTERNAL_ROUNDS + MERSENNE31_NUM_INTERNAL_ROUNDS;

pub const BN254_S_BOX_DEGREE: u64 = 5;

pub const BABYBEAR_W: u32 = 11;
pub const KOALABEAR_W: u32 = 3;

/*
Chip Data Parallelism
 */
pub const ADD_SUB_DATAPAR: usize = 8; // optimized
pub const MUL_DATAPAR: usize = 2; // optimized
pub const DIVREM_DATAPAR: usize = 2; // optimized
pub const LT_DATAPAR: usize = 2; // optimized
pub const SLL_DATAPAR: usize = 4; // optimized
pub const SR_DATAPAR: usize = 2; // optimized
pub const BITWISE_DATAPAR: usize = 2; // optimized
pub const MEMORY_RW_DATAPAR: usize = 1; // optimized
pub const LOCAL_MEMORY_DATAPAR: usize = 4; // fixed

pub const BASE_ALU_DATAPAR: usize = 2; // optimized
pub const EXT_ALU_DATAPAR: usize = 4; // optimized
pub const VAR_MEM_DATAPAR: usize = 4; // optimized
pub const CONST_MEM_DATAPAR: usize = 1; // optimized
pub const SELECT_DATAPAR: usize = 2; // optimized
pub const POSEIDON2_DATAPAR: usize = 1; // tbd

/// The width of the Poseidon2 permutation.
pub const NUM_BITS: usize = 31;
