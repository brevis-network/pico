use crate::{
    chips::gadgets::{is_equal_word::IsEqualWordGadget, is_zero_word::IsZeroWordGadget},
    compiler::word::Word,
    primitives::consts::{DIVREM_DATAPAR, LONG_WORD_SIZE},
};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

/// The number of main trace columns for `DivRemChip`.
pub const NUM_DIVREM_COLS: usize = size_of::<DivRemCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct DivRemCols<F> {
    pub values: [DivRemValueCols<F>; DIVREM_DATAPAR],
}

pub const NUM_DIVREM_VALUE_COLS: usize = size_of::<DivRemValueCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct DivRemValueCols<F> {
    /// The output operand.
    pub a: Word<F>,

    /// The first input operand.
    pub b: Word<F>,

    /// The second input operand.
    pub c: Word<F>,

    /// Results of dividing `b` by `c`.
    pub quotient: Word<F>,

    /// Remainder when dividing `b` by `c`.
    pub remainder: Word<F>,

    /// `abs(remainder)`, used to check `abs(remainder) < abs(c)`.
    pub abs_remainder: Word<F>,

    /// `abs(c)`, used to check `abs(remainder) < abs(c)`.
    pub abs_c: Word<F>,

    /// `max(abs(c), 1)`, used to check `abs(remainder) < abs(c)`.
    pub max_abs_c_or_1: Word<F>,

    /// The result of `c * quotient`.
    pub c_times_quotient: [F; LONG_WORD_SIZE],

    /// Carry propagated when adding `remainder` by `c * quotient`.
    pub carry: [F; LONG_WORD_SIZE],

    /// Flag to indicate division by 0.
    pub is_c_0: IsZeroWordGadget<F>,

    /// Flag to indicate whether the opcode is DIV.
    pub is_div: F,

    /// Flag to indicate whether the opcode is DIVU.
    pub is_divu: F,

    /// Flag to indicate whether the opcode is REM.
    pub is_rem: F,

    /// Flag to indicate whether the opcode is REMU.
    pub is_remu: F,

    /// Flag to indicate whether the division operation overflows.
    ///
    /// Overflow occurs in a specific case of signed 32-bit integer division: when `b` is the
    /// minimum representable value (`-2^31`, the smallest negative number) and `c` is `-1`. In
    /// this case, the division result exceeds the maximum positive value representable by a
    /// 32-bit signed integer.
    pub is_overflow: F,

    /// Flag for whether the value of `b` matches the unique overflow case `b = -2^31` and `c =
    /// -1`.
    pub is_overflow_b: IsEqualWordGadget<F>,

    /// Flag for whether the value of `c` matches the unique overflow case `b = -2^31` and `c =
    /// -1`.
    pub is_overflow_c: IsEqualWordGadget<F>,

    /// The most significant bit of `b`.
    pub b_msb: F,

    /// The most significant bit of remainder.
    pub rem_msb: F,

    /// The most significant bit of `c`.
    pub c_msb: F,

    /// Flag to indicate whether `b` is negative.
    pub b_neg: F,

    /// Flag to indicate whether `rem_neg` is negative.
    pub rem_neg: F,

    /// Flag to indicate whether `c` is negative.
    pub c_neg: F,

    /// Selector to determine whether an ALU Event is sent for absolute value computation of `c`.
    pub abs_c_alu_event: F,

    /// Selector to determine whether an ALU Event is sent for absolute value computation of `rem`.
    pub abs_rem_alu_event: F,

    /// Selector to know whether this row is enabled.
    pub is_real: F,

    /// Column to modify multiplicity for remainder range check event.
    pub remainder_check_multiplicity: F,
}
