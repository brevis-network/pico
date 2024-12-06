pub mod fp;
pub mod fp2_addsub;
pub mod fp2_mul;

use crate::chips::{
    chips::riscv_memory::read_write::columns::MemoryCols, gadgets::utils::limbs::Limbs,
};
use hybrid_array::ArraySize;

pub fn limbs_from_prev_access<T: Copy, N: ArraySize, M: MemoryCols<T>>(cols: &[M]) -> Limbs<T, N> {
    let vec = cols
        .iter()
        .flat_map(|access| access.prev_value().0)
        .collect::<Box<[T]>>();

    let sized = (&*vec)
        .try_into()
        .unwrap_or_else(|_| panic!("failed to convert to limbs"));
    Limbs(sized)
}

/// Converts a slice of words to a byte slice in little endian.
pub fn words_to_bytes_le_slice(words: &[u32]) -> Box<[u8]> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}
