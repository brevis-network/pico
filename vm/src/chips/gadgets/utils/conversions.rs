use crate::chips::{
    chips::riscv_memory::read_write::columns::MemoryCols, gadgets::utils::limbs::Limbs,
};
use hybrid_array::ArraySize;
use num::BigUint;

/// Converts a slice of words to a byte vector in little endian.
pub fn words_to_bytes_le_vec(words: &[u32]) -> Vec<u8> {
    words
        .iter()
        .flat_map(|word| word.to_le_bytes().to_vec())
        .collect::<Vec<_>>()
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

/// Converts a byte array in little endian to a vector of words.
pub fn bytes_to_words_le_vec(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>()
}

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

pub fn limbs_from_prev_access<T: Copy, N: ArraySize, M: MemoryCols<T>>(cols: &[M]) -> Limbs<T, N> {
    let vec = cols
        .iter()
        .flat_map(|access| access.prev_value().0)
        .collect::<Vec<T>>();

    let sized = (&*vec)
        .try_into()
        .unwrap_or_else(|_| panic!("failed to convert to limbs"));
    Limbs(sized)
}

pub fn limbs_from_access<T: Copy, N: ArraySize, M: MemoryCols<T>>(cols: &[M]) -> Limbs<T, N> {
    let vec = cols
        .iter()
        .flat_map(|access| access.value().0)
        .collect::<Vec<T>>();

    let sized = (&*vec)
        .try_into()
        .unwrap_or_else(|_| panic!("failed to convert to limbs"));
    Limbs(sized)
}

use crate::{
    chips::{
        chips::riscv_memory::read_write::columns::{MemoryReadColsU8, MemoryWriteColsU8},
        gadgets::u16_to_u8::U16ToU8Gadget,
    },
    compiler::word::Word,
    machine::builder::ChipLookupBuilder,
    primitives::consts::{u64_to_u16_limbs, WORD_SIZE},
};
use p3_field::{Field, PrimeField32};

/// Extract byte limbs from `MemoryReadColsU8` slices via U16→U8 conversion with range checks.
///
/// For each `MemoryReadColsU8`, takes the `prev_value` (4×u16) and produces 8 u8 limbs
/// using the `U16ToU8Gadget`. Returns all limbs concatenated.
pub fn generate_limbs_from_read_cols_u8<F: Field, CB: ChipLookupBuilder<F>>(
    builder: &mut CB,
    cols: &[MemoryReadColsU8<CB::Var>],
    is_real: CB::Expr,
) -> Vec<CB::Expr> {
    cols.iter()
        .flat_map(|access| {
            let u16_values = access.inner.access.value.0.map(|x| x.into());
            U16ToU8Gadget::<CB::F>::eval_u16_to_u8_safe(
                builder,
                u16_values,
                access.prev_value_u8,
                is_real.clone(),
            )
        })
        .collect()
}

/// Extract byte limbs from `MemoryWriteColsU8` slices via U16→U8 conversion with range checks.
///
/// Same as `generate_limbs_from_read_cols_u8` but for write columns (uses `prev_value`).
pub fn generate_limbs_from_write_cols_u8<F: Field, CB: ChipLookupBuilder<F>>(
    builder: &mut CB,
    cols: &[MemoryWriteColsU8<CB::Var>],
    is_real: CB::Expr,
) -> Vec<CB::Expr> {
    cols.iter()
        .flat_map(|access| {
            let u16_values = access.inner.prev_value.0.map(|x| x.into());
            U16ToU8Gadget::<CB::F>::eval_u16_to_u8_safe(
                builder,
                u16_values,
                access.prev_value_u8,
                is_real.clone(),
            )
        })
        .collect()
}

/// Convert a u64 address to 3×u16 limbs as field elements.
#[inline(always)]
pub fn addr_to_u16_limbs<F: PrimeField32>(addr: u64) -> [F; 3] {
    let limbs = u64_to_u16_limbs(addr);
    [
        F::from_canonical_u16(limbs[0]),
        F::from_canonical_u16(limbs[1]),
        F::from_canonical_u16(limbs[2]),
    ]
}

/// Reconvert byte limbs (u8 values) into Words (4×u16 each).
///
/// Groups every 8 consecutive byte limbs into pairs, then packs each pair as
/// `low + high * 256` to form a u16 limb. Every 4 such u16 limbs form one Word.
pub fn limbs_to_words<E: Clone + std::ops::Add<Output = E> + std::ops::Mul<Output = E>>(
    limbs: &[E],
    multiplier_256: E,
) -> Vec<Word<E>> {
    limbs
        .chunks(WORD_SIZE * 2) // 8 bytes per Word
        .map(|chunk| {
            let mut word_limbs = Vec::with_capacity(WORD_SIZE);
            for pair in chunk.chunks(2) {
                let low = pair[0].clone();
                let high = pair[1].clone();
                word_limbs.push(low + high * multiplier_256.clone());
            }
            Word(
                word_limbs
                    .try_into()
                    .unwrap_or_else(|_| panic!("limbs_to_words: wrong size")),
            )
        })
        .collect()
}

pub fn biguint_to_bits_le(integer: &BigUint, num_bits: usize) -> Vec<bool> {
    let byte_vec = integer.to_bytes_le();
    let mut bits = Vec::new();
    for byte in byte_vec {
        for i in 0..8 {
            bits.push(byte & (1 << i) != 0);
        }
    }
    debug_assert!(
        bits.len() <= num_bits,
        "Number too large to fit in {num_bits} digits"
    );
    bits.resize(num_bits, false);
    bits
}

pub fn biguint_to_limbs<const N: usize>(integer: &BigUint) -> [u8; N] {
    let mut bytes = integer.to_bytes_le();
    debug_assert!(bytes.len() <= N, "Number too large to fit in {N} limbs");
    bytes.resize(N, 0u8);
    let mut limbs = [0u8; N];
    limbs.copy_from_slice(&bytes);
    limbs
}

#[inline]
pub fn biguint_from_limbs(limbs: &[u8]) -> BigUint {
    BigUint::from_bytes_le(limbs)
}

cfg_if::cfg_if! {
    if #[cfg(feature = "bigint-rug")] {
        pub fn biguint_to_rug(integer: &BigUint) -> rug::Integer {
            let mut int = rug::Integer::new();
            unsafe {
                int.assign_bytes_radix_unchecked(integer.to_bytes_be().as_slice(), 256, false);
            }
            int
        }

        pub fn rug_to_biguint(integer: &rug::Integer) -> BigUint {
            let be_bytes = integer.to_digits::<u8>(rug::integer::Order::MsfBe);
            BigUint::from_bytes_be(&be_bytes)
        }
    }
}
