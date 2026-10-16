use crate::{
    chips::chips::recursion_memory::MemoryAccessCols, compiler::recursion::types::Address,
};
use pico_derive::AlignedBorrow;

pub const NUM_POSEIDON2_PACKED_PREPROCESSED_COLS: usize =
    core::mem::size_of::<Poseidon2PackedPreprocessedCols<u8>>();

/// Preprocessed columns: 4 packed input Block addresses + liveness flag +
/// 4 packed output Block accesses. The main columns are the shared gadget's
/// [`crate::chips::gadgets::poseidon2::columns::Poseidon2ValueCols`] (one
/// permutation per row).
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2PackedPreprocessedCols<F: Copy> {
    pub is_real: F,
    pub input: [Address<F>; 4],
    pub output: [MemoryAccessCols<F>; 4],
}
