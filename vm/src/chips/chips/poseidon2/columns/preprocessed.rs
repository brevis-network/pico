use crate::{
    chips::chips::recursion_memory_v2::MemoryAccessCols, primitives::consts::PERMUTATION_WIDTH,
    recursion_v2::types::Address,
};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

pub const PREPROCESSED_POSEIDON2_WIDTH: usize = size_of::<Poseidon2PreprocessedCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2PreprocessedCols<T: Copy> {
    pub input: [Address<T>; PERMUTATION_WIDTH],
    pub output: [MemoryAccessCols<T>; PERMUTATION_WIDTH],
    pub is_real_neg: T,
}
