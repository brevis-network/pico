use super::{
    instruction::columns::InstructionCols, opcode_selector::columns::OpcodeSelectorCols,
    opcode_specific::columns::OpcodeSpecificCols, utils::make_col_map,
};
use crate::{
    chips::chips::riscv_memory::read_write::columns::{
        MemoryCols, MemoryReadCols, MemoryReadWriteCols,
    },
    compiler::{addr::Addr, word::Word},
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

    /// Number of extra clock cycles for ecall instructions (stored in syscall code).
    pub num_extra_clk: T,

    /// The program counter value.
    pub pc: Addr<T>,

    /// The expected next program counter value.
    pub next_pc: Addr<T>,

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

    /// The result of selectors.is_ecall * (is_halt)
    pub ecall_range_check_operand: T,

    /// This is true for all instructions that are not jumps, branches, and halt.  Those
    /// instructions may move the program counter to a non sequential instruction.
    pub is_sequential_instr: T,

    /// `is_alu_instruction * (1 - op_a_0)` — multiplicity of the ALU dispatch.
    ///
    /// Precomputed because a lookup multiplicity must have degree ≤ 1
    /// (`machine/lookup.rs:117` panics otherwise), and the product of the selector sum
    /// with `1 - op_a_0` is degree 2.
    pub is_alu_not_x0: T,

    /// `is_auipc * (1 - op_a_0)` — multiplicity of the AUIPC dispatch.
    pub is_auipc_not_x0: T,

    /// Bit 0 of the *unmasked* JALR target `rs1 + imm`.
    ///
    /// RISC-V clears the low bit of a JALR target. The emulator does so
    /// (`instruction.rs`: `next_pc = b.wrapping_add(c) & !1`), so `next_pc` is the masked
    /// value, while `populate_jump` supplies the Add chip with the *unmasked* sum. The AIR
    /// therefore has to reconstruct the unmasked sum as `next_pc + lsb` when it dispatches.
    ///
    /// `add_operation` computes the unmasked sum and the CPU state advances to
    /// `next_pc[0] - lsb`.
    pub jalr_lsb: T,

    /// Carry columns for cross-row PC constraints (`pc + 4 = next_row.pc`).
    /// Used by: sequential transition (#1), branch not-taken transition (#3),
    /// and jump return address `pc + 4 = op_a` (#5).
    /// These are mutually exclusive, so the columns are shared.
    /// Addr constraints use [0..4]; Word (jump) uses all [0..5].
    pub pc_carry_a: [T; 5],

    /// Carry columns for same-row PC constraints (`pc + 4 = local.next_pc`).
    /// Used by: sequential (#2) and branch not-taken (#4).
    /// These are mutually exclusive, so the columns are shared.
    pub pc_carry_b: [T; 4],
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
