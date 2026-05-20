use pico_derive::AlignedBorrow;
use std::mem::size_of;

pub const NUM_JUMP_COLS: usize = size_of::<JumpCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct JumpCols<T> {
    /// Bit 0 of (rs1 + imm) for JALR. Witnesses that next_pc = (rs1 + imm) & !1.
    pub jalr_lsb: T,
}
