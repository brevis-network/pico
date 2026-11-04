use crate::compiler::riscv::opcode::Opcode;

/// Returns `true` if the given `opcode` is a signed 64bit operation.
#[must_use]
pub fn is_signed_64bit_operation(opcode: Opcode) -> bool {
    opcode == Opcode::DIV || opcode == Opcode::REM
}

/// Returns `true` if the given `opcode` is an unsigned 64bit operation.
#[must_use]
pub fn is_unsigned_64bit_operation(opcode: Opcode) -> bool {
    opcode == Opcode::DIVU || opcode == Opcode::REMU
}

/// Returns `true` if the given `opcode` is a 64bit operation.
#[must_use]
pub fn is_64bit_operation(opcode: Opcode) -> bool {
    opcode == Opcode::DIV
        || opcode == Opcode::DIVU
        || opcode == Opcode::REM
        || opcode == Opcode::REMU
}

/// Returns `true` if the given `opcode` is a word operation.
#[must_use]
pub fn is_word_operation(opcode: Opcode) -> bool {
    opcode == Opcode::DIVW
        || opcode == Opcode::DIVUW
        || opcode == Opcode::REMW
        || opcode == Opcode::REMUW
}

/// Returns `true` if the given `opcode` is a signed word operation.
#[must_use]
#[allow(dead_code)]
pub fn is_signed_word_operation(opcode: Opcode) -> bool {
    opcode == Opcode::DIVW || opcode == Opcode::REMW
}

/// Returns `true` if the given `opcode` is an unsigned word operation.
#[must_use]
pub fn is_unsigned_word_operation(opcode: Opcode) -> bool {
    opcode == Opcode::DIVUW || opcode == Opcode::REMUW
}

/// Returns `true` if the given `opcode` is NOT a word operation (i.e., 64-bit operation).
#[allow(dead_code)]
pub fn is_not_word_operation(opcode: Opcode) -> bool {
    !is_word_operation(opcode)
}

/// Returns `true` if the given `opcode` is a signed operation (for backwards compatibility).
#[must_use]
pub fn is_signed_operation(opcode: Opcode) -> bool {
    is_signed_64bit_operation(opcode) || is_signed_word_operation(opcode)
}

/// Calculate the correct `quotient` and `remainder` for the given `b` and `c` per RISC-V spec.
#[must_use]
pub fn get_quotient_and_remainder(b: u64, c: u64, opcode: Opcode) -> (u64, u64) {
    if c == 0 && is_64bit_operation(opcode) {
        (u64::MAX, b)
    } else if (c as i32 == 0) && is_word_operation(opcode) {
        (u64::MAX, (b as i32) as u64)
    } else if is_signed_64bit_operation(opcode) {
        (
            (b as i64).wrapping_div(c as i64) as u64,
            (b as i64).wrapping_rem(c as i64) as u64,
        )
    } else if is_signed_word_operation(opcode) {
        (
            (b as i32).wrapping_div(c as i32) as i64 as u64,
            (b as i32).wrapping_rem(c as i32) as i64 as u64,
        )
    } else if is_unsigned_word_operation(opcode) {
        (
            (b as u32).wrapping_div(c as u32) as i32 as i64 as u64,
            (b as u32).wrapping_rem(c as u32) as i32 as i64 as u64,
        )
    } else {
        (b.wrapping_div(c), b.wrapping_rem(c))
    }
}

/// Calculate the most significant bit of the given 64-bit integer `a`, and returns it as a u8.
/// For u64, the MSB is bit 63 (the highest bit of the upper u16 limb at index 3).
pub const fn get_msb(a: u64) -> u8 {
    ((a >> 63) & 1) as u8
}

/// ALU events one DivRem event adds. Shared with the GPU kernels, which index the ALU buffers
/// by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DivremExtraEventIndices {
    pub add: usize,
    pub lt: usize,
}

/// The ADD rows a div/rem of `opcode` on `b` and `c` appends to the add chip: one for each of the
/// divisor and the remainder that a signed operation finds negative, so none, one or two.
#[must_use]
pub fn derived_add_rows(opcode: Opcode, b: u64, c: u64) -> usize {
    let (_, remainder) = get_quotient_and_remainder(b, c, opcode);
    let (c_neg, rem_neg) = if is_signed_64bit_operation(opcode) {
        (get_msb(c), get_msb(remainder))
    } else if is_signed_word_operation(opcode) {
        (
            get_msb((c as i32) as i64 as u64),
            get_msb((remainder as i32) as i64 as u64),
        )
    } else {
        (0, 0)
    };
    usize::from(c_neg) + usize::from(rem_neg)
}
