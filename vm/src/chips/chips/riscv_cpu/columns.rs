use super::{
    instruction::columns::InstructionCols, opcode_selector::columns::OpcodeSelectorCols,
    utils::make_col_map,
};
use crate::{
    chips::chips::riscv_memory::read_write::columns::{
        MemoryLiteCols, MemoryReadLiteCols, MemoryReadWriteLiteCols,
    },
    compiler::{addr::Pc, word::Word},
};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

pub const NUM_CPU_COLS: usize = size_of::<CpuCols<u8>>();

// Pinned on both sides: the CUDA mirror asserts the same width (pico-gpu's
// `src/tracegen/riscv/cpu.cuh`, and the second hand-written mirror in
// `src/tracegen/riscv/packed_tracegen.cuh`), and the host writes
// `is_last` into the GPU trace by column index after the kernels run, so a silent width change on
// either side would put that write in the wrong column.
const _: () = assert!(NUM_CPU_COLS == 58);

pub const CPU_COL_MAP: CpuCols<usize> = make_col_map();

/// The whole column layout for the CPU.
#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct CpuCols<T: Copy> {
    // There is no committed `chunk` column: every lookup message that names the chunk carries
    // the proof's `execution_chunk` public value itself (`eval_registers`, the memory dispatch,
    // `eval_ecall`). The recursion chain bounds that value (`execution_chunk <= chunk`, with
    // `chunk` range-checked by the convert circuit), so nothing is lost by not committing a copy
    // of it per row.
    /// The row's clk, one column.
    ///
    /// Not range-checked: the row chain bounds `clk` as an integer
    /// (`chunk_clk/constraints.rs`), so the column is one free witness. The 25-bit shape is the
    /// completeness budget (`chunk_split`), not a constraint. Read through `CpuChip::clk_expr`.
    pub clk: T,

    /// Number of extra clock cycles for ecall instructions (stored in syscall code).
    pub num_extra_clk: T,

    /// The program counter value, two u16 limbs (a guest address fits in 32 bits).
    pub pc: Pc<T>,

    /// The expected next program counter value.
    pub next_pc: Pc<T>,

    /// Columns related to the instruction.
    pub instruction: InstructionCols<T>,

    /// Selectors for the opcode.
    pub opcode_selector: OpcodeSelectorCols<T>,

    /// Operand values, either from registers or immediate values.
    ///
    /// Lite access layout: no committed `prev_clk`, the AIR defines it from the two difference
    /// limbs (see `MemoryAccessLiteCols`).
    pub op_a_access: MemoryReadWriteLiteCols<T>,
    pub op_b_access: MemoryReadLiteCols<T>,
    pub op_c_access: MemoryReadLiteCols<T>,

    /// Branch comparison flags (formerly the `BranchCols` view of the opcode_specific union).
    /// Only meaningful on branch rows; zero elsewhere.
    ///
    /// The former `a_eq_b` column is derived as `1 - a_lt_b - a_gt_b`. One tagged CMP lookup
    /// to the Lt chip proves `a_lt_b`/`a_gt_b` are the (mutually exclusive) strict-comparison
    /// bits of a single Lt row, so their trichotomy complement is exactly the equality indicator.
    ///
    /// Whether a is greater than b.
    pub a_gt_b: T,
    /// Whether a is less than b.
    pub a_lt_b: T,

    /// Committed flag for "this row is an ECALL executing HALT".
    /// Constrained to 0 on non-ecall rows; on ecall rows its correctness is enforced by the
    /// Ecall-chip lookup (the Ecall chip re-derives the halt bit from the syscall code and
    /// receives this column in the message).
    pub is_halt: T,

    /// Selector to label whether this row is a non padded row.
    ///
    /// The real rows are a physical prefix, and the AIR constrains that shape: row 0 is real
    /// (`eval_is_real`) and `is_real` never comes back on across a transition (`eval_row_chain`,
    /// N3), so `is_real = [i < m]` for some `m >= 1`. A constraint may rely on the prefix shape.
    pub is_real: T,

    /// The last real row of the chunk, defined by the row chain rather than pinned by
    /// constraints of its own: on a transition row `is_last = is_real - next.is_real`, on the
    /// last physical row `is_last = is_real` (`eval_row_chain`, N4 / N5). With the prefix shape
    /// that makes it 1 on row `m - 1` and 0 everywhere else -- boolean, zero off real rows and
    /// unique -- so none of the three is asserted separately. The public-value hand-off and the
    /// halt rule read it; trace generation writes it on the last real row (host and GPU).
    ///
    /// It replaces the former `branching` column, whose value is a degree-2 expression of the
    /// opcode selectors and the comparison bits (`branch_taken_expr`) and so never needed to be
    /// committed.
    pub is_last: T,

    /// `is_alu_instruction * (1 - op_a_0)` — multiplicity of the ALU dispatch.
    ///
    /// Precomputed to keep the multiplicity degree 1. Nothing enforces that any more -- the FRI
    /// lowering that used to panic on a higher-degree multiplicity is gone -- but the degree
    /// still feeds `nc_lg`, so a degree-2 multiplicity doubles this chip's round-zero logUp cost.
    ///
    /// Since X12 this also covers what used to be AUIPC rows: the transpiler re-encodes
    /// `AUIPC rd, imm` as the two-immediate `ADD rd, imm, pc`, so those rows are ordinary ALU
    /// rows and the separate `is_auipc_not_x0` multiplicity is gone.
    pub is_alu_not_x0: T,

    /// Bit 0 of the *unmasked* JALR target `rs1 + imm`.
    ///
    /// RISC-V clears the low bit of a JALR target. The emulator does so
    /// (`instruction.rs`: `next_pc = b.wrapping_add(c) & !1`), so `next_pc` is the masked
    /// value, and the AIR proves `b + c = (next_pc[0] + lsb, next_pc[1], 0, 0)` limb by limb
    /// with boolean carry expressions (`jump/constraints.rs`). Membership pins the bit: a
    /// table pc is 4-aligned, so of `(lsb = 0, S)` and `(lsb = 1, S - 1)` at most one is a
    /// Program-table pc.
    pub jalr_lsb: T,

    /// `[pc[0] >= 0xFFFC]`: the carry out of limb 0 in `pc + 4`, written on every real row.
    ///
    /// The column travels in the Program message, so the lookup pins it to the preprocessed
    /// table's value for the row's pc (`riscv_program/columns.rs`); nothing asserts it boolean.
    /// Its one reader is a **jump row**'s return address `pc + 4 = op_a` via
    /// `Pc::add_limb_with_carry`, gated on `is_jump * (1 - op_a_0)`; padding rows leave it at 0
    /// and the gate is zero there.
    ///
    /// Sequential and branch-not-taken rows do not use it: both sides of their
    /// `pc + 4 = next_pc` are pcs, which fit in two limbs (the guest's address space is
    /// 1.875 GiB), so the addition stays inside `[0, p)` and one degree-1 field equation
    /// suffices. `op_a` is a register `Word` whose recombination can reach past `p`, so the jump
    /// case keeps the limb arithmetic.
    ///
    /// One witness, not three: a guest address stays below `0x7800_0000`, so limb 1 is at most
    /// `0x77FF` and absorbing the carry out of limb 0 cannot make it overflow, while the pc has
    /// no limb 2 and `op_a`'s must be zero. Those two limbs are plain equalities in
    /// `Pc::add_limb_with_carry`, which also leaves the prover no witness there to lie with.
    pub pc_carry: T,
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
