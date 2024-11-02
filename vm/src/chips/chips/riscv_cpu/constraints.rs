use super::{
    channel_selector::constraints::eval_channel_selector,
    columns::CpuCols,
    instruction::columns::InstructionCols,
    opcode_selector::columns::{OpcodeSelectorCols, OPCODE_SELECTORS_COL_MAP},
    CpuChip,
};
use crate::{
    compiler::word::Word,
    emulator::riscv::public_values::PublicValues,
    machine::{
        builder::{ChipBaseBuilder, ChipBuilder, ChipLookupBuilder},
        lookup::{LookupType, SymbolicLookup},
    },
    primitives::consts::RISCV_NUM_PVS,
};
use p3_air::{Air, AirBuilder};
use p3_field::{AbstractField, Field, PrimeField32};
use p3_matrix::Matrix;
use std::{array, borrow::Borrow, iter::once};

impl<F: PrimeField32, CB: ChipBuilder<F>> Air<CB> for CpuChip<F>
where
    CB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &CpuCols<CB::Var> = (*local).borrow();
        let next: &CpuCols<CB::Var> = (*next).borrow();

        let public_values_slice: [CB::Expr; RISCV_NUM_PVS] =
            array::from_fn(|i| builder.public_values()[i].into());
        let public_values: &PublicValues<Word<CB::Expr>, CB::Expr> =
            public_values_slice.as_slice().borrow();

        // Contrain the interaction with program table.
        self.looking_program(
            builder,
            local.pc,
            local.instruction,
            local.opcode_selector,
            local.chunk,
            local.is_real,
        );

        // Compute some flags for which type of instruction we are dealing with.
        let is_memory_instruction: CB::Expr =
            self.is_memory_instruction::<CB>(&local.opcode_selector);
        let is_branch_instruction: CB::Expr =
            self.is_branch_instruction::<CB>(&local.opcode_selector);
        let is_alu_instruction: CB::Expr = self.is_alu_instruction::<CB>(&local.opcode_selector);

        // Register constraints.
        self.eval_registers::<CB>(builder, local, is_branch_instruction.clone());

        // Memory instructions.
        builder.looking_instruction(
            local.instruction.opcode,
            local.op_a_val(),
            local.op_b_val(),
            local.op_c_val(),
            local.chunk,
            local.channel,
            CB::Expr::zero(), // local.nonce,
            is_memory_instruction,
        );

        // Channel constraints.
        eval_channel_selector(
            builder,
            &local.channel_selector,
            &next.channel_selector,
            local.channel,
            local.is_real,
            next.is_real,
        );

        // ALU instructions.
        builder.looking_alu(
            local.instruction.opcode,
            local.op_a_val(),
            local.op_b_val(),
            local.op_c_val(),
            local.chunk,
            local.channel,
            CB::Expr::zero(), // local.nonce,
            is_alu_instruction,
        );

        // Branch instructions.
        self.eval_branch_ops::<CB>(builder, is_branch_instruction.clone(), local, next);

        // Jump instructions.
        self.eval_jump_ops::<CB>(builder, local, next);

        // AUIPC instruction.
        self.eval_auipc(builder, local);

        // ECALL instruction.
        self.eval_ecall(builder, local);

        // COMMIT/COMMIT_DEFERRED_PROOFS ecall instruction.
        self.eval_commit(
            builder,
            local,
            public_values.committed_value_digest.clone(),
            public_values.deferred_proofs_digest.clone(),
        );

        // HALT ecall and UNIMPL instruction.
        self.eval_halt_unimpl(builder, local, next, public_values);

        // Check that the chunk and clk is updated correctly.
        self.eval_chunk_clk(builder, local, next);

        // Check that the pc is updated correctly.
        self.eval_pc(builder, local, next, is_branch_instruction.clone());

        // Check public values constraints.
        self.eval_public_values(builder, local, next, public_values);

        // Check that the is_real flag is correct.
        self.eval_is_real(builder, local, next);

        // Check that when `is_real=0` that all flags that send interactions are zero.
        local
            .opcode_selector
            .into_iter()
            .enumerate()
            .for_each(|(i, selector)| {
                if i == OPCODE_SELECTORS_COL_MAP.imm_b {
                    builder
                        .when(CB::Expr::one() - local.is_real)
                        .assert_one(local.opcode_selector.imm_b);
                } else if i == OPCODE_SELECTORS_COL_MAP.imm_c {
                    builder
                        .when(CB::Expr::one() - local.is_real)
                        .assert_one(local.opcode_selector.imm_c);
                } else {
                    builder
                        .when(CB::Expr::one() - local.is_real)
                        .assert_zero(selector);
                }
            });
    }
}

impl<F: Field> CpuChip<F> {
    /// Whether the instruction is an ALU instruction.
    pub(crate) fn is_alu_instruction<CB: ChipBuilder<F>>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<CB::Var>,
    ) -> CB::Expr {
        opcode_selectors.is_alu.into()
    }

    /// Computes whether the opcode is a memory instruction.
    pub(crate) fn is_memory_instruction<CB: ChipBuilder<F>>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<CB::Var>,
    ) -> CB::Expr {
        opcode_selectors.is_lb
            + opcode_selectors.is_lbu
            + opcode_selectors.is_lh
            + opcode_selectors.is_lhu
            + opcode_selectors.is_lw
            + opcode_selectors.is_sb
            + opcode_selectors.is_sh
            + opcode_selectors.is_sw
    }

    /// Computes whether the opcode is a store instruction.
    pub(crate) fn is_store_instruction<CB: ChipBuilder<F>>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<CB::Var>,
    ) -> CB::Expr {
        opcode_selectors.is_sb + opcode_selectors.is_sh + opcode_selectors.is_sw
    }

    /// Constraints related to the pc for non jump, branch, and halt instructions.
    ///
    /// The function will verify that the pc increments by 4 for all instructions except branch,
    /// jump and halt instructions. Also, it ensures that the pc is carried down to the last row
    /// for non-real rows.
    pub(crate) fn eval_pc<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
        next: &CpuCols<CB::Var>,
        is_branch_instruction: CB::Expr,
    ) {
        // When is_sequential_instr is true, assert that instruction is not branch, jump, or halt.
        // Note that the condition `when(local_is_real)` is implied from the previous constraint.
        let is_halt = self.get_is_halt_syscall::<CB>(builder, local);
        builder.when(local.is_real).assert_eq(
            local.is_sequential_instr,
            CB::Expr::one()
                - (is_branch_instruction
                    + local.opcode_selector.is_jal
                    + local.opcode_selector.is_jalr
                    + is_halt),
        );

        // Verify that the pc increments by 4 for all instructions except branch, jump and halt
        // instructions. The other case is handled by eval_jump, eval_branch and eval_ecall
        // (for halt).
        builder
            .when_transition()
            .when(next.is_real)
            .when(local.is_sequential_instr)
            .assert_eq(local.pc + CB::Expr::from_canonical_u8(4), next.pc);

        // When the last row is real and it's a sequential instruction, assert that local.next_pc
        // <==> local.pc + 4
        builder
            .when(local.is_real)
            .when(local.is_sequential_instr)
            .assert_eq(local.pc + CB::Expr::from_canonical_u8(4), local.next_pc);
    }

    /// Constraints related to the is_real column.
    ///
    /// This method checks that the is_real column is a boolean.  It also checks that the first row
    /// is 1 and once its 0, it never changes value.
    pub(crate) fn eval_is_real<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
        next: &CpuCols<CB::Var>,
    ) {
        // Check the is_real flag.  It should be 1 for the first row.  Once its 0, it should never
        // change value.
        builder.assert_bool(local.is_real);
        builder.when_first_row().assert_one(local.is_real);
        builder
            .when_transition()
            .when_not(local.is_real)
            .assert_zero(next.is_real);
    }

    fn looking_program<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        pc: impl Into<CB::Expr>,
        instruction: InstructionCols<impl Into<CB::Expr> + Copy>,
        selectors: OpcodeSelectorCols<impl Into<CB::Expr> + Copy>,
        chunk: impl Into<CB::Expr> + Copy,
        multiplicity: impl Into<CB::Expr>,
    ) {
        let values = once(pc.into())
            .chain(once(instruction.opcode.into()))
            .chain(instruction.into_iter().map(|x| x.into()))
            .chain(selectors.into_iter().map(|x| x.into()))
            .chain(once(chunk.into()))
            .collect();

        builder.looking(SymbolicLookup::new(
            values,
            multiplicity.into(),
            LookupType::Program,
        ));
    }
}
