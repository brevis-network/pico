use crate::chips::{
    chips::riscv_memory::read_write::columns::MemoryCols, gadgets::utils::limbs::Limbs,
};
use generic_array::ArrayLength;
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

pub fn limbs_from_prev_access<T: Copy, N: ArrayLength, M: MemoryCols<T>>(
    cols: &[M],
) -> Limbs<T, N> {
    let vec = cols
        .iter()
        .flat_map(|access| access.prev_value().0)
        .collect::<Vec<T>>();

    let sized = vec
        .try_into()
        .unwrap_or_else(|_| panic!("failed to convert to limbs"));
    Limbs(sized)
}

pub fn limbs_from_access<T: Copy, N: ArrayLength, M: MemoryCols<T>>(cols: &[M]) -> Limbs<T, N> {
    let vec = cols
        .iter()
        .flat_map(|access| access.value().0)
        .collect::<Vec<T>>();

    let sized = vec
        .try_into()
        .unwrap_or_else(|_| panic!("failed to convert to limbs"));
    Limbs(sized)
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
