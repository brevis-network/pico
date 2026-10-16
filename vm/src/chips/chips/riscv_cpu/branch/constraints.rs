use super::super::{columns::CpuCols, opcode_selector::columns::OpcodeSelectorCols, CpuChip};
use crate::{
    chips::chips::alu::lt::LT_CMP_OPCODE_TAG,
    compiler::{riscv::opcode::Opcode, word::Word},
    machine::builder::{ChipBuilder, ChipLookupBuilder},
};
use p3_air::AirBuilder;
use p3_field::{Field, PrimeCharacteristicRing};

impl<F: Field> CpuChip<F> {
    /// Computes whether the opcode is a branch instruction.
    pub(crate) fn is_branch_instruction<CB: ChipBuilder<F>>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<CB::Var>,
    ) -> CB::Expr {
        opcode_selectors.is_beq
            + opcode_selectors.is_bne
            + opcode_selectors.is_blt
            + opcode_selectors.is_bge
            + opcode_selectors.is_bltu
            + opcode_selectors.is_bgeu
    }

    /// Verifies the branch rows: the target equation and the comparison bits `a_lt_b`/`a_gt_b`.
    /// (There is no `branching` column any more; the taken predicate is `branch_taken_expr`.)
    ///
    /// It does this in few parts:
    /// 1. It verifies the branch target `next_pc = pc + c` on taken rows; the not-taken `pc + 4`
    ///    step is folded into the sequential-row equation in `eval_pc`.
    /// 2. It requires every branch row to be an immediate-c row, so the Program table's sign bit
    ///    describes the operand the target equation reads.
    /// 3. It verifies the helper comparison bits against op_a and op_b via one tagged CMP lookup
    ///    to the Lt chip, whose row carries both strict bits (`a = [a_lt_b, a_gt_b, 0, 0]`).
    pub(crate) fn eval_branch_ops<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        is_branch_instruction: CB::Expr,
        local: &CpuCols<CB::Var>,
    ) {
        // `a_eq_b` is derived, not committed. On branch rows the single CMP lookup below
        // proves `a_lt_b` and `a_gt_b` are the (mutually exclusive) strict-comparison bits of
        // one Lt row, so `1 - a_lt_b - a_gt_b` is exactly the equality indicator (trichotomy).

        // Evaluate program counter constraints. The hand-off to the successor's `pc` is not
        // repeated here: the row chain pins it limb by limb (`eval_row_chain`, N1).
        {
            // When we are branching, calculate local.next_pc <==> local.pc + c.
            //
            // `op_c` is the offset sign-extended to 64 bits (the emulator does
            // `pc.wrapping_add(c)`), so a backward branch has every limb above the offset set:
            // for `c = -d` the word is `2^64 - d`, i.e. `op_c[2] == op_c[3] == 0xFFFF`. The
            // Program table carries that sign as `op_c.sign`, and the 64-bit wrap collapses to
            // one field equation:
            //
            //     next_pc = pc + (op_c[0] + op_c[1]*2^16) - sign*2^32
            //
            // which is the integer identity `pc - d` for a backward branch and `pc + d` for a
            // forward one. Both sides land in `[0, 2^31) ⊂ [0, p)`, so the field arithmetic is
            // exact -- no carry witnesses and no ALU dispatch.
            //
            // Soundness: this drops the Add chip's output range check as the anchor for
            // `next_pc`'s canonicity, so membership carries it instead -- the row chain (N1)
            // makes this row's `next_pc` the successor's `pc`, which the Program table pins, and
            // the last real row's becomes PV.next_pc, which the recursion chain pins. `reduce()`
            // is exact because a pc fits in two limbs (guest space is 1.875 GiB).
            let op_c = local.op_c_val();
            // The sign is preprocessed, not read off the operand word: on an immediate-c row
            // `register/constraints.rs` pins `op_c_val()`'s limbs 2 and 3 to `0xFFFF * sign`, so
            // the fill needs no separate shape constraints here. Fail-closed:
            // every branch row must be an immediate-c row for that to hold. The decoder builds
            // every branch with `imm_c = true` (`compiler/riscv/disassembler/rrs.rs`); a
            // hand-built Program with a register-operand branch is rejected here rather than
            // proven with a sign that describes nothing.
            builder
                .when(is_branch_instruction.clone())
                .assert_zero(CB::Expr::ONE - local.opcode_selector.imm_c);
            let sign: CB::Expr = local.instruction.op_c.sign.into();
            builder
                .when(Self::branch_taken_expr::<CB>(local))
                .assert_eq(
                    local.next_pc.reduce::<CB>(),
                    local.pc.reduce::<CB>()
                        + op_c[0]
                        + Into::<CB::Expr>::into(op_c[1]) * CB::Expr::from_u32(1 << 16)
                        - sign * CB::Expr::from_u64(1u64 << 32),
                );
        }

        // The taken predicate is no longer committed: `branch_taken_expr` builds it from the
        // opcode selectors and the comparison bits wherever it is needed, and the column it used
        // to occupy became `is_last`. The former definitional constraint disappears with it.
        //
        // The `is_branch * a_eq_b => op_a == op_b` check is gone too: it was already implied by
        // the CMP lookup below. That lookup pins `a[1] = is_cmp * (sum_flags - bit)` on the Lt
        // row, so `1 - a_lt_b - a_gt_b = 1 - sum_flags`, and a zero flag sum makes the gadget
        // assert every limb of the two operands equal -- which is exactly what this said.

        // One merged CMP lookup pins both comparison bits (using appropriate signedness): the
        // Lt row's `a[0]` is `[op_a < op_b]` and its `a[1]` is `[op_a > op_b]`, boolean and
        // mutually exclusive on that single row, so `a_eq_b = 1 - a_lt_b - a_gt_b` is exact
        // without a second dispatch. The opcode carries `LT_CMP_OPCODE_TAG`, so this message can
        // only pair with a merged Lt row (`is_cmp = 1`), never with a plain SLT/SLTU result.
        let use_signed_comparison = local.opcode_selector.is_blt + local.opcode_selector.is_bge;
        builder.looking_alu(
            use_signed_comparison.clone() * Opcode::SLT.as_field::<CB::F>()
                + (CB::Expr::ONE - use_signed_comparison) * Opcode::SLTU.as_field::<CB::F>()
                + CB::F::from_u32(LT_CMP_OPCODE_TAG),
            Word([
                local.a_lt_b.into(),
                local.a_gt_b.into(),
                CB::Expr::ZERO,
                CB::Expr::ZERO,
            ]),
            local.op_a_val(),
            local.op_b_val(),
            is_branch_instruction,
        );
    }
}
