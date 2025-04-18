use super::super::{columns::CpuCols, opcode_selector::columns::OpcodeSelectorCols, CpuChip};
use crate::{
    chips::gadgets::field_range_check::word_range::FieldWordRangeChecker,
    compiler::{riscv::opcode::Opcode, word::Word},
    machine::builder::{ChipBaseBuilder, ChipBuilder, ChipLookupBuilder, ChipWordBuilder},
};
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};

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

    /// Verifies all the branching related columns.
    ///
    /// It does this in few parts:
    /// 1. It verifies that the next pc is correct based on the branching column.  That column is a
    ///    boolean that indicates whether the branch condition is true.
    /// 2. It verifies the correct value of branching based on the helper bool columns (a_eq_b,
    ///    a_gt_b, a_lt_b).
    /// 3. It verifier the correct values of the helper bool columns based on op_a and op_b.
    pub(crate) fn eval_branch_ops<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        is_branch_instruction: CB::Expr,
        local: &CpuCols<CB::Var>,
        next: &CpuCols<CB::Var>,
    ) {
        // Get the branch specific columns.
        let branch_cols = local.opcode_specific.branch();

        // Evaluate program counter constraints.
        {
            // When we are branching, assert local.pc <==> branch_cols.pc as Word.
            builder
                .when(local.branching)
                .assert_eq(branch_cols.pc.reduce::<CB>(), local.pc);

            // When we are branching, assert that next.pc <==> branch_columns.next_pc as Word.
            builder
                .when_transition()
                .when(next.is_real)
                .when(local.branching)
                .assert_eq(branch_cols.next_pc.reduce::<CB>(), next.pc);

            // When the current row is real and local.branching, assert that local.next_pc <==>
            // branch_columns.next_pc as Word.
            builder
                .when(local.is_real)
                .when(local.branching)
                .assert_eq(branch_cols.next_pc.reduce::<CB>(), local.next_pc);

            // Range check branch_cols.pc and branch_cols.next_pc.
            // println!("marking field type: {:?}", CB::F::field_type());

            FieldWordRangeChecker::<CB::F>::range_check(
                builder,
                branch_cols.pc,
                branch_cols.pc_range_checker,
                is_branch_instruction.clone(),
            );
            FieldWordRangeChecker::<CB::F>::range_check(
                builder,
                branch_cols.next_pc,
                branch_cols.next_pc_range_checker,
                is_branch_instruction.clone(),
            );

            // When we are branching, calculate branch_cols.next_pc <==> branch_cols.pc + c.
            builder.looking_alu(
                Opcode::ADD.as_field::<CB::F>(),
                branch_cols.next_pc,
                branch_cols.pc,
                local.op_c_val(),
                local.branching,
            );

            // When we are not branching, assert that local.pc + 4 <==> next.pc.
            builder
                .when_transition()
                .when(next.is_real)
                .when(local.not_branching)
                .assert_eq(local.pc + CB::Expr::from_canonical_u8(4), next.pc);

            // When local.not_branching is true, assert that local.is_real is true.
            builder.when(local.not_branching).assert_one(local.is_real);

            // When the last row is real and local.not_branching, assert that local.pc + 4 <==>
            // local.next_pc.
            builder
                .when(local.is_real)
                .when(local.not_branching)
                .assert_eq(local.pc + CB::Expr::from_canonical_u8(4), local.next_pc);

            // Assert that either we are branching or not branching when the instruction is a
            // branch.
            builder
                .when(is_branch_instruction.clone())
                .assert_one(local.branching + local.not_branching);
            builder
                .when(is_branch_instruction.clone())
                .assert_bool(local.branching);
            builder
                .when(is_branch_instruction.clone())
                .assert_bool(local.not_branching);
        }

        // Evaluate branching value constraints.
        {
            // When the opcode is BEQ and we are branching, assert that a_eq_b is true.
            builder
                .when(local.opcode_selector.is_beq * local.branching)
                .assert_one(branch_cols.a_eq_b);

            // When the opcode is BEQ and we are not branching, assert that either a_gt_b or a_lt_b
            // is true.
            builder
                .when(local.opcode_selector.is_beq)
                .when_not(local.branching)
                .assert_one(branch_cols.a_gt_b + branch_cols.a_lt_b);

            // When the opcode is BNE and we are branching, assert that either a_gt_b or a_lt_b is
            // true.
            builder
                .when(local.opcode_selector.is_bne * local.branching)
                .assert_one(branch_cols.a_gt_b + branch_cols.a_lt_b);

            // When the opcode is BNE and we are not branching, assert that a_eq_b is true.
            builder
                .when(local.opcode_selector.is_bne)
                .when_not(local.branching)
                .assert_one(branch_cols.a_eq_b);

            // When the opcode is BLT or BLTU and we are branching, assert that a_lt_b is true.
            builder
                .when(
                    (local.opcode_selector.is_blt + local.opcode_selector.is_bltu)
                        * local.branching,
                )
                .assert_one(branch_cols.a_lt_b);

            // When the opcode is BLT or BLTU and we are not branching, assert that either a_eq_b
            // or a_gt_b is true.
            builder
                .when(local.opcode_selector.is_blt + local.opcode_selector.is_bltu)
                .when_not(local.branching)
                .assert_one(branch_cols.a_eq_b + branch_cols.a_gt_b);

            // When the opcode is BGE or BGEU and we are branching, assert that a_gt_b is true.
            builder
                .when(
                    (local.opcode_selector.is_bge + local.opcode_selector.is_bgeu)
                        * local.branching,
                )
                .assert_one(branch_cols.a_gt_b + branch_cols.a_eq_b);

            // When the opcode is BGE or BGEU and we are not branching, assert that either a_eq_b
            // or a_lt_b is true.
            builder
                .when(local.opcode_selector.is_bge + local.opcode_selector.is_bgeu)
                .when_not(local.branching)
                .assert_one(branch_cols.a_lt_b);
        }

        // When it's a branch instruction and a_eq_b, assert that a == b.
        builder
            .when(is_branch_instruction.clone() * branch_cols.a_eq_b)
            .assert_word_eq(local.op_a_val(), local.op_b_val());

        //  To prevent this ALU send to be arbitrarily large when is_branch_instruction is false.
        builder
            .when_not(is_branch_instruction.clone())
            .assert_zero(local.branching);

        // Calculate a_lt_b <==> a < b (using appropriate signedness).
        let use_signed_comparison = local.opcode_selector.is_blt + local.opcode_selector.is_bge;
        builder.looking_alu(
            use_signed_comparison.clone() * Opcode::SLT.as_field::<CB::F>()
                + (CB::Expr::ONE - use_signed_comparison.clone())
                    * Opcode::SLTU.as_field::<CB::F>(),
            Word::extend_var::<CB>(branch_cols.a_lt_b),
            local.op_a_val(),
            local.op_b_val(),
            is_branch_instruction.clone(),
        );

        // Calculate a_gt_b <==> a > b (using appropriate signedness).
        builder.looking_alu(
            use_signed_comparison.clone() * Opcode::SLT.as_field::<CB::F>()
                + (CB::Expr::ONE - use_signed_comparison) * Opcode::SLTU.as_field::<CB::F>(),
            Word::extend_var::<CB>(branch_cols.a_gt_b),
            local.op_b_val(),
            local.op_a_val(),
            is_branch_instruction.clone(),
        );
    }
}
