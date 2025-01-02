use crate::recursion_v2::{air::Block, types::Address};
use pico_derive::AlignedBorrow;

pub const NUM_BATCH_FRI_COLS: usize = core::mem::size_of::<BatchFRICols<u8>>();
pub const NUM_BATCH_FRI_PREPROCESSED_COLS: usize =
    core::mem::size_of::<BatchFRIPreprocessedCols<u8>>();

#[derive(Clone, Debug, Copy, Default)]
pub struct BatchFRIChip<const DEGREE: usize>;

/// The preprocessed columns for a batch FRI invocation.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BatchFRIPreprocessedCols<F: Copy> {
    pub is_real: F,
    pub is_end: F,
    pub acc_addr: Address<F>,
    pub alpha_pow_addr: Address<F>,
    pub p_at_z_addr: Address<F>,
    pub p_at_x_addr: Address<F>,
}

/// The main columns for a batch FRI invocation.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BatchFRICols<F: Copy> {
    pub acc: Block<F>,
    pub alpha_pow: Block<F>,
    pub p_at_z: Block<F>,
    pub p_at_x: F,
}
