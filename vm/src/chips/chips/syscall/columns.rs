use crate::chips::gadgets::{
    global_accumulation::GlobalAccumulationOperation,
    global_interaction::GlobalInteractionOperation,
};
use pico_derive::AlignedBorrow;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct SyscallCols<T> {
    /// The chunk number of the syscall.
    pub chunk: T,

    /// The bottom 16 bits of clk of the syscall.
    pub clk_16: T,

    /// The top 8 bits of clk of the syscall.
    pub clk_8: T,

    pub nonce: T,

    /// The syscall_id of the syscall.
    pub syscall_id: T,

    /// The arg1.
    pub arg1: T,

    /// The arg2.
    pub arg2: T,

    pub is_real: T,

    /// The global interaction columns.
    pub global_interaction_cols: GlobalInteractionOperation<T>,

    /// The columns for accumulating the elliptic curve digests.
    pub global_accumulation_cols: GlobalAccumulationOperation<T, 1>,
}
