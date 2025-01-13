use super::{
    instruction::columns::InstructionCols, opcode_selector::columns::OpcodeSelectorCols,
    opcode_specific::columns::OpcodeSpecificCols, utils::make_col_map,
};
use crate::{
    chips::chips::riscv_memory::read_write::columns::{
        MemoryCols, MemoryReadCols, MemoryReadWriteCols,
    },
    compiler::word::Word,
};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

pub const NUM_CPU_COLS: usize = size_of::<CpuCols<u8>>();

pub const CPU_COL_MAP: CpuCols<usize> = make_col_map();

/// The whole column layout for the CPU.
#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct CpuCols<T: Copy> {
    /// The current chunk.
    pub chunk: T,

    /// The clock cycle value.  This should be within 24 bits.
    pub clk: T,
    /// The least significant 16 bit limb of clk.
    pub clk_16bit_limb: T,
    /// The most significant 8 bit limb of clk.
    pub clk_8bit_limb: T,

    /// The program counter value.
    pub pc: T,

    /// The expected next program counter value.
    pub next_pc: T,

    /// Columns related to the instruction.
    pub instruction: InstructionCols<T>,

    /// Selectors for the opcode.
    pub opcode_selector: OpcodeSelectorCols<T>,

    /// Operand values, either from registers or immediate values.
    pub op_a_access: MemoryReadWriteCols<T>,
    pub op_b_access: MemoryReadCols<T>,
    pub op_c_access: MemoryReadCols<T>,

    pub opcode_specific: OpcodeSpecificCols<T>,

    /// Selector to label whether this row is a non padded row.
    pub is_real: T,

    /// The branching column is equal to:
    ///
    /// > is_beq & a_eq_b ||
    /// > is_bne & (a_lt_b | a_gt_b) ||
    /// > (is_blt | is_bltu) & a_lt_b ||
    /// > (is_bge | is_bgeu) & (a_eq_b | a_gt_b)
    pub branching: T,

    /// The not branching column is equal to:
    ///
    /// > is_beq & !a_eq_b ||
    /// > is_bne & !(a_lt_b | a_gt_b) ||
    /// > (is_blt | is_bltu) & !a_lt_b ||
    /// > (is_bge | is_bgeu) & !(a_eq_b | a_gt_b)
    pub not_branching: T,

    /// The result of selectors.is_ecall * the send_to_table column for the ECALL opcode.
    pub ecall_mul_send_to_table: T,

    /// The result of selectors.is_ecall * (is_halt || is_commit_deferred_proofs)
    pub ecall_range_check_operand: T,

    /// This is true for all instructions that are not jumps, branches, and halt.  Those
    /// instructions may move the program counter to a non sequential instruction.
    pub is_sequential_instr: T,
}

impl<T: Copy> CpuCols<T> {
    /// Gets the value of the first operand.
    pub fn op_a_val(&self) -> Word<T> {
        *self.op_a_access.value()
    }

    /// Gets the value of the second operand.
    pub fn op_b_val(&self) -> Word<T> {
        *self.op_b_access.value()
    }

    /// Gets the value of the third operand.
    pub fn op_c_val(&self) -> Word<T> {
        *self.op_c_access.value()
    }
}
