use crate::{
    chips::chips::riscv_cpu::{
        instruction::columns::InstructionCols, opcode_selector::columns::OpcodeSelectorCols,
    },
    compiler::addr::Pc,
};
use core::mem::size_of;
use pico_derive::AlignedBorrow;

/// The number of preprocessed program columns.
pub const NUM_PROGRAM_PREPROCESSED_COLS: usize = size_of::<ProgramPreprocessedCols<u8>>();

// Pinned on both sides. The CUDA kernel reinterpret_casts a host-allocated row straight onto
// `ProgramPreprocessedColsU64` using a width handed over from here, so drift on either side
// writes past or short of the row with no diagnostic. Pc(2) + InstructionCols(9) +
// OpcodeSelectorCols(13) + pc_carry(1) = 25.
const _: () = assert!(NUM_PROGRAM_PREPROCESSED_COLS == 25);

/// The number of columns for the program multiplicities.
pub const NUM_PROGRAM_MULT_COLS: usize = size_of::<ProgramMultiplicityCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy, Default, Eq, PartialEq)]
#[repr(C)]
pub struct ProgramPreprocessedCols<T> {
    pub pc: Pc<T>,
    pub instruction: InstructionCols<T>,
    pub selectors: OpcodeSelectorCols<T>,
    /// `[pc[0] >= 0xFFFC]`: the carry out of limb 0 in `pc + 4`, a function of the row's pc.
    ///
    /// The Program message carries it, so every real Cpu row's `pc_carry` is pinned to this
    /// value; that is what makes a jump row's return address `pc + 4 = op_a` canonical without
    /// a range check (`riscv_cpu/register/constraints.rs`). A table pc is 4-aligned, so the
    /// predicate is `pc[0] == 0xFFFC`.
    pub pc_carry: T,
}

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy, Default, Eq, PartialEq)]
#[repr(C)]
pub struct ProgramMultiplicityCols<T> {
    pub multiplicity: T,
}
