use crate::{
    chips::gadgets::{
        field_range_check::word_range::FieldWordRangeChecker, is_zero::IsZeroGadget,
        u16_to_u8::U16ToU8Gadget,
    },
    compiler::word::Word,
    primitives::consts::PV_DIGEST_NUM_WORDS,
};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

pub const NUM_ECALL_COLS: usize = size_of::<EcallCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct EcallCols<T> {
    /// u16 → u8 decomposition of op_a prev_value (syscall code).
    /// Produces 8 bytes from the 4 u16 limbs of the Word.
    pub syscall_code_bytes: U16ToU8Gadget<T>,

    /// Whether the current ecall is ENTER_UNCONSTRAINED.
    pub is_enter_unconstrained: IsZeroGadget<T>,

    /// Whether the current ecall is HINT_LEN.
    pub is_hint_len: IsZeroGadget<T>,

    /// Whether the current ecall is HALT.
    pub is_halt: IsZeroGadget<T>,

    /// Whether the current ecall is a COMMIT.
    pub is_commit: IsZeroGadget<T>,

    /// Whether the current ecall is a COMMIT.
    pub is_commit_deferred_proofs: IsZeroGadget<T>,

    /// Field to store the word index passed into the COMMIT ecall.  index_bitmap[word index]
    /// should be set to 1 and everything else set to 0.
    pub index_bitmap: [T; PV_DIGEST_NUM_WORDS],

    // TODO: check if operand is u32 for halt and commit_deferred_proofs
    /// Columns to range check the halt/commit_deferred_proofs operand.
    pub operand_range_check_cols: FieldWordRangeChecker<T>,

    // TODO: check if operand is u32 for halt and commit_deferred_proofs
    /// The operand value to range check.
    pub operand_to_check: Word<T>,
}
