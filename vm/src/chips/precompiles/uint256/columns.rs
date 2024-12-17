use crate::{
    chips::{
        chips::riscv_memory::read_write::columns::{MemoryReadCols, MemoryWriteCols},
        gadgets::{
            field::{field_lt::FieldLtCols, field_op::FieldOpCols},
            uint256::U256Field,
        },
        precompiles::uint256::Uint256NumWords,
    },
    recursion_v2::air::IsZeroOperation,
};
use hybrid_array::Array;
use pico_derive::AlignedBorrow;
use std::mem::size_of;

/// The number of columns in the Uint256MulCols.
pub const NUM_UINT256_MUL_COLS: usize = size_of::<Uint256MulCols<u8>>();

/// A set of columns for the Uint256Mul operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Uint256MulCols<T> {
    /// The chunk number of the syscall.
    pub chunk: T,

    /// The clock cycle of the syscall.
    pub clk: T,

    /// The nonce of the operation.
    pub nonce: T,

    /// The pointer to the first input.
    pub x_ptr: T,

    /// The pointer to the second input, which contains the y value and the modulus.
    pub y_ptr: T,

    // Memory columns.
    // x_memory is written to with the result, which is why it is of type MemoryWriteCols.
    pub x_memory: Array<MemoryWriteCols<T>, Uint256NumWords>,
    pub y_memory: Array<MemoryReadCols<T>, Uint256NumWords>,
    pub modulus_memory: Array<MemoryReadCols<T>, Uint256NumWords>,

    /// Columns for checking if modulus is zero. If it's zero, then use 2^256 as the effective
    /// modulus.
    pub modulus_is_zero: IsZeroOperation<T>,

    /// Column that is equal to is_real * (1 - modulus_is_zero.result).
    pub modulus_is_not_zero: T,

    // Output values. We compute (x * y) % modulus.
    pub output: FieldOpCols<T, U256Field>,

    pub output_range_check: FieldLtCols<T, U256Field>,

    pub is_real: T,
}
