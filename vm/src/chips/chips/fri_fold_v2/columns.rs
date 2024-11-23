use crate::{chips::chips::recursion_memory_v2::MemoryAccessCols, recursion_v2::air::Block};
use pico_derive::AlignedBorrow;

pub const NUM_FRI_FOLD_PREPROCESSED_COLS: usize =
    core::mem::size_of::<FriFoldPreprocessedCols<u8>>();
pub const NUM_FRI_FOLD_MAIN_COLS: usize = core::mem::size_of::<FriFoldMainCols<u8>>();

/// The preprocessed columns for a FRI fold invocation.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct FriFoldPreprocessedCols<T: Copy> {
    pub is_first: T,

    // Memory accesses for the single fields.
    pub z_mem: MemoryAccessCols<T>,
    pub alpha_mem: MemoryAccessCols<T>,
    pub x_mem: MemoryAccessCols<T>,

    // Memory accesses for the vector field inputs.
    pub alpha_pow_input_mem: MemoryAccessCols<T>,
    pub ro_input_mem: MemoryAccessCols<T>,
    pub p_at_x_mem: MemoryAccessCols<T>,
    pub p_at_z_mem: MemoryAccessCols<T>,

    // Memory accesses for the vector field outputs.
    pub ro_output_mem: MemoryAccessCols<T>,
    pub alpha_pow_output_mem: MemoryAccessCols<T>,

    pub is_real: T,
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct FriFoldMainCols<T: Copy> {
    pub z: Block<T>,
    pub alpha: Block<T>,
    pub x: T,

    pub p_at_x: Block<T>,
    pub p_at_z: Block<T>,
    pub alpha_pow_input: Block<T>,
    pub ro_input: Block<T>,

    pub alpha_pow_output: Block<T>,
    pub ro_output: Block<T>,
}
