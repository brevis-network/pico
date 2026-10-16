//! Cpu-side remains of the ECALL logic after the hoist to the dedicated Ecall chip.
//!
//! The syscall decode gadgets (U16ToU8 + IsZero), the syscall-table send, the operand range
//! check and the ecall-driven public-value constraints (exit_code, commit digests) now live in
//! the dedicated [`EcallChip`](crate::chips::chips::riscv_ecall::EcallChip). The Cpu chip keeps
//! three committed scalars — `is_ecall` (selector), `num_extra_clk` and `is_halt` — and sends
//! one fat lookup message per ecall row to the Ecall chip, which re-derives the decode and
//! thereby certifies `num_extra_clk`/`is_halt`.

use super::super::{columns::CpuCols, opcode_selector::columns::OpcodeSelectorCols, CpuChip};
use crate::{
    chips::chips::riscv_memory::read_write::columns::MemoryLiteCols,
    machine::{
        builder::{ChipBuilder, ChipWordBuilder},
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
};
use p3_air::AirBuilder;
use p3_field::Field;

impl<F: Field> CpuChip<F> {
    /// Whether the instruction is an ECALL instruction.
    pub(crate) fn is_ecall_instruction<CB: ChipBuilder<F>>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<CB::Var>,
    ) -> CB::Expr {
        opcode_selectors.is_ecall.into()
    }

    /// Constraints related to the ECALL opcode (slim version).
    ///
    /// 1. Force `is_halt` and `num_extra_clk` to zero on non-ecall rows (padding rows are
    ///    covered because all selectors are forced to zero there), so the pc-advance and
    ///    clk-transition constraints stay sound.
    /// 2. Send the fat message to the Ecall chip with multiplicity `is_ecall`. The Ecall chip
    ///    re-derives the syscall decode from `op_a` prev_value and constrains that the
    ///    `num_extra_clk` and `is_halt` values in the message are correct, which makes the two
    ///    committed columns sound on ecall rows.
    pub(crate) fn eval_ecall<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
        chunk: CB::Expr,
    ) {
        let is_ecall_instruction = self.is_ecall_instruction::<CB>(&local.opcode_selector);

        // `is_halt` and `num_extra_clk` may only be set on ecall rows; their values there are
        // pinned by the lookup. Pinning `num_extra_clk` to zero off ecall rows lets the clk
        // transition (`chunk_clk/constraints.rs`) read it directly instead of multiplying by the
        // ecall selector, which is what keeps that constraint at degree 3.
        builder
            .when_not(is_ecall_instruction.clone())
            .assert_zero(local.is_halt);
        builder
            .when_not(is_ecall_instruction.clone())
            .assert_zero(local.num_extra_clk);

        // Fat message: [chunk, clk, op_a_prev(4), op_a_val(4), op_b_val(4), op_c_val(4),
        // num_extra_clk, is_halt] -- 20 elements. The chunk element is the `execution_chunk`
        // public value, not a committed column; the `clk` element is the committed `clk` column
        // (`clk_expr`). Positions and values are those the Ecall chip expects.
        let clk = Self::clk_expr::<CB>(local);
        let mut values: Vec<CB::Expr> = Vec::with_capacity(20);
        values.push(chunk);
        values.push(clk);
        values.extend(
            (*local.op_a_access.prev_value())
                .into_iter()
                .map(Into::into),
        );
        values.extend(local.op_a_val().into_iter().map(Into::into));
        values.extend(local.op_b_val().into_iter().map(Into::into));
        values.extend(local.op_c_val().into_iter().map(Into::into));
        values.push(local.num_extra_clk.into());
        values.push(local.is_halt.into());

        builder.looking(SymbolicLookup::new(
            values,
            is_ecall_instruction,
            LookupType::Ecall,
            LookupScope::Regional,
        ));
    }

    /// Constraints related to the halt ecall. (UNIMP / EBREAK need none: a trap pc has no
    /// Program-table row, see `eval`.)
    ///
    /// Uses the committed `is_halt` column (backed by the Ecall-chip lookup). The exit_code
    /// public-value constraint moved to the Ecall chip.
    pub(crate) fn eval_halt_unimpl<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
    ) {
        // A halting row ends the chunk, so it is the chain's last row. Stated on the row itself
        // instead of on its successor's `is_real`: the old form was vacuous when the halt landed
        // on the physically last row, this one is not.
        // (There is no `is_unimpl` selector: a trap pc has no Program-table row, see `eval`.)
        builder.when(local.is_halt).assert_one(local.is_last);

        builder.when(local.is_halt).assert_pc_zero(local.next_pc);
    }

    /// Returns the number of extra cycles from an ECALL instruction.
    ///
    /// Degree 1: `num_extra_clk` is asserted zero off ecall rows in `eval_ecall`, so no
    /// multiplication by the ecall selector is needed here.
    pub(crate) fn get_num_extra_ecall_cycles<CB: ChipBuilder<F>>(
        &self,
        local: &CpuCols<CB::Var>,
    ) -> CB::Expr {
        local.num_extra_clk.into()
    }
}
