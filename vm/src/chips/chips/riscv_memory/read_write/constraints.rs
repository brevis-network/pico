use super::{
    super::event::MemoryAccessPosition,
    columns::{MemoryChipCols, MemoryInstructionCols, NUM_MEMORY_CHIP_COLS},
    MemoryReadWriteChip,
};
use crate::{
    chips::{
        chips::riscv_memory::read_write::columns::{MemoryChipValueCols, MemoryCols},
        gadgets::field_range_check::word_range::FieldWordRangeChecker,
    },
    compiler::{riscv::opcode::Opcode, word::Word},
    machine::builder::{
        ChipBuilder, ChipLookupBuilder, ChipRangeBuilder, ChipWordBuilder, RiscVMemoryBuilder,
    },
};
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, FieldAlgebra};
use p3_matrix::Matrix;

impl<F: Field> BaseAir<F> for MemoryReadWriteChip<F> {
    fn width(&self) -> usize {
        NUM_MEMORY_CHIP_COLS
    }
}

impl<F: Field, CB: ChipBuilder<F>> Air<CB> for MemoryReadWriteChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryChipCols<CB::Var> = (*local).borrow();

        for local_memory_chip_value_cols in local.values {
            // The clock cycle value for memory offset
            let is_memory_instruction: CB::Expr =
                self.is_memory_instruction::<CB>(&local_memory_chip_value_cols.instruction);

            builder.looked_instruction(
                local_memory_chip_value_cols.instruction.opcode,
                local_memory_chip_value_cols.op_a_val(),
                local_memory_chip_value_cols.op_b_val(),
                local_memory_chip_value_cols.op_c_val(),
                is_memory_instruction.clone(),
            );

            self.eval_memory_address_and_access::<CB>(
                builder,
                &local_memory_chip_value_cols,
                is_memory_instruction.clone(),
            );
            self.eval_memory_load::<CB>(builder, &local_memory_chip_value_cols);
            self.eval_memory_store::<CB>(builder, &local_memory_chip_value_cols);
        }
    }
}

impl<F: Field> MemoryReadWriteChip<F> {
    /// Computes whether the opcode is a load instruction.
    pub(crate) fn is_load_instruction<CB: ChipBuilder<F>>(
        &self,
        instruction: &MemoryInstructionCols<CB::Var>,
    ) -> CB::Expr {
        instruction.is_lb
            + instruction.is_lbu
            + instruction.is_lh
            + instruction.is_lhu
            + instruction.is_lw
    }

    /// Computes whether the opcode is a memory instruction.
    pub(crate) fn is_memory_instruction<CB: ChipBuilder<F>>(
        &self,
        instruction: &MemoryInstructionCols<CB::Var>,
    ) -> CB::Expr {
        instruction.is_lb
            + instruction.is_lbu
            + instruction.is_lh
            + instruction.is_lhu
            + instruction.is_lw
            + instruction.is_sb
            + instruction.is_sh
            + instruction.is_sw
    }

    /// Constrains the addr_aligned, addr_offset, and addr_word memory columns.
    ///
    /// This method will do the following:
    /// 1. Calculate that the unaligned address is correctly computed to be op_b.value + op_c.value.
    /// 2. Calculate that the address offset is address % 4.
    /// 3. Assert the validity of the aligned address given the address offset and the unaligned
    ///    address.
    pub(crate) fn eval_memory_address_and_access<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &MemoryChipValueCols<CB::Var>,
        is_memory_instruction: CB::Expr,
    ) {
        // Send to the ALU table to verify correct calculation of addr_word.
        builder.looking_alu(
            CB::Expr::from_canonical_u32(Opcode::ADD as u32),
            local.addr_word,
            local.op_b_val(),
            local.op_c_val(),
            is_memory_instruction.clone(),
        );

        // Range check the addr_word to be a valid field word.
        FieldWordRangeChecker::<CB::F>::range_check(
            builder,
            local.addr_word,
            local.addr_word_range_checker,
            is_memory_instruction.clone(),
        );

        // Check that each addr_word element is a byte.
        builder.slice_range_check_u8(&local.addr_word.0, is_memory_instruction.clone());

        // Evaluate the addr_offset column and offset flags.
        self.eval_offset_value_flags(builder, local);

        // Assert that reduce(addr_word) == addr_aligned + addr_offset.
        builder
            .when(is_memory_instruction.clone())
            .assert_eq::<CB::Expr, CB::Expr>(
                local.addr_aligned + local.addr_offset,
                local.addr_word.reduce::<CB>(),
            );

        // Verify that the least significant byte of addr_word - addr_offset is divisible by 4.
        let offset = [
            local.offset_is_one,
            local.offset_is_two,
            local.offset_is_three,
        ]
        .iter()
        .enumerate()
        .fold(CB::Expr::ZERO, |acc, (index, &value)| {
            acc + CB::Expr::from_canonical_usize(index + 1) * value
        });
        let mut recomposed_byte = CB::Expr::ZERO;
        local
            .aa_least_sig_byte_decomp
            .iter()
            .enumerate()
            .for_each(|(i, value)| {
                builder
                    .when(is_memory_instruction.clone())
                    .assert_bool(*value);

                recomposed_byte =
                    recomposed_byte.clone() + CB::Expr::from_canonical_usize(1 << (i + 2)) * *value;
            });

        builder
            .when(is_memory_instruction.clone())
            .assert_eq(local.addr_word[0] - offset, recomposed_byte);

        // For operations that require reading from memory (not registers), we need to read the
        // value into the memory columns.
        builder.eval_memory_access(
            local.chunk,
            local.clk + CB::F::from_canonical_u32(MemoryAccessPosition::Memory as u32),
            local.addr_aligned,
            &local.memory_access,
            is_memory_instruction.clone(),
        );

        // On memory load instructions, make sure that the memory value is not changed.
        builder
            .when(self.is_load_instruction::<CB>(&local.instruction))
            .assert_word_eq(
                *local.memory_access.value(),
                *local.memory_access.prev_value(),
            );
    }

    /// Evaluates constraints related to loading from memory.
    pub(crate) fn eval_memory_load<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &MemoryChipValueCols<CB::Var>,
    ) {
        // Verify the unsigned_mem_value column.
        self.eval_unsigned_mem_value(builder, local);

        // If it's a signed operation (such as LB or LH), then we need verify the bit decomposition
        // of the most significant byte to get it's sign.
        self.eval_most_sig_byte_bit_decomp(builder, local, &local.unsigned_mem_val);

        // sanity check op_a_0
        builder.assert_bool(local.instruction.op_a_0);

        // Assert that correct value of `mem_value_is_neg_not_x0`.
        builder.assert_eq(
            local.mem_value_is_neg_not_x0,
            (local.instruction.is_lb + local.instruction.is_lh)
                * local.most_sig_byte_decomp[7]
                * (CB::Expr::ONE - local.instruction.op_a_0),
        );

        // When the memory value is negative and not writing to x0, use the SUB opcode to compute
        // the signed value of the memory value and verify that the op_a value is correct.
        let signed_value = Word([
            CB::Expr::ZERO,
            CB::Expr::ONE * local.instruction.is_lb,
            CB::Expr::ONE * local.instruction.is_lh,
            CB::Expr::ZERO,
        ]);

        builder.looking_alu(
            Opcode::SUB.as_field::<CB::F>(),
            local.op_a_val(),
            local.unsigned_mem_val,
            signed_value,
            local.mem_value_is_neg_not_x0,
        );

        // Assert that correct value of `mem_value_is_pos_not_x0`.
        let mem_value_is_pos = (local.instruction.is_lb + local.instruction.is_lh)
            * (CB::Expr::ONE - local.most_sig_byte_decomp[7])
            + local.instruction.is_lbu
            + local.instruction.is_lhu
            + local.instruction.is_lw;
        builder.assert_eq(
            local.mem_value_is_pos_not_x0,
            mem_value_is_pos * (CB::Expr::ONE - local.instruction.op_a_0),
        );

        // When the memory value is not positive and not writing to x0, assert that op_a value is
        // equal to the unsigned memory value.
        builder
            .when(local.mem_value_is_pos_not_x0)
            .assert_word_eq(local.unsigned_mem_val, local.op_a_val());
    }

    /// Evaluates constraints related to storing to memory.
    pub(crate) fn eval_memory_store<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &MemoryChipValueCols<CB::Var>,
    ) {
        // Get the memory offset flags.
        self.eval_offset_value_flags(builder, local);
        // Compute the offset_is_zero flag.  The other offset flags are already contrained by the
        // method `eval_memory_address_and_access`, which is called in
        // `eval_memory_address_and_access`.
        let offset_is_zero =
            CB::Expr::ONE - local.offset_is_one - local.offset_is_two - local.offset_is_three;

        // Compute the expected stored value for a SB instruction.
        let one = CB::Expr::ONE;
        let a_val = local.op_a_val();
        let mem_val = *local.memory_access.value();
        let prev_mem_val = *local.memory_access.prev_value();
        let sb_expected_stored_value = Word([
            a_val[0] * offset_is_zero.clone()
                + (one.clone() - offset_is_zero.clone()) * prev_mem_val[0],
            a_val[0] * local.offset_is_one + (one.clone() - local.offset_is_one) * prev_mem_val[1],
            a_val[0] * local.offset_is_two + (one.clone() - local.offset_is_two) * prev_mem_val[2],
            a_val[0] * local.offset_is_three
                + (one.clone() - local.offset_is_three) * prev_mem_val[3],
        ]);

        builder
            .when(local.instruction.is_sb)
            .assert_word_eq(mem_val.map(|x| x.into()), sb_expected_stored_value);

        // When the instruction is SH, make sure both offset one and three are off.
        builder
            .when(local.instruction.is_sh)
            .assert_zero(local.offset_is_one + local.offset_is_three);

        // When the instruction is SW, ensure that the offset is 0.
        builder
            .when(local.instruction.is_sw)
            .assert_one(offset_is_zero.clone());

        // Compute the expected stored value for a SH instruction.
        let a_is_lower_half = offset_is_zero;
        let a_is_upper_half = local.offset_is_two;
        let sh_expected_stored_value = Word([
            a_val[0] * a_is_lower_half.clone()
                + (one.clone() - a_is_lower_half.clone()) * prev_mem_val[0],
            a_val[1] * a_is_lower_half.clone() + (one.clone() - a_is_lower_half) * prev_mem_val[1],
            a_val[0] * a_is_upper_half + (one.clone() - a_is_upper_half) * prev_mem_val[2],
            a_val[1] * a_is_upper_half + (one.clone() - a_is_upper_half) * prev_mem_val[3],
        ]);

        builder
            .when(local.instruction.is_sh)
            .assert_word_eq(mem_val.map(|x| x.into()), sh_expected_stored_value);

        // When the instruction is SW, just use the word without masking.
        builder
            .when(local.instruction.is_sw)
            .assert_word_eq(mem_val.map(|x| x.into()), a_val.map(|x| x.into()));
    }

    /// This function is used to evaluate the unsigned memory value for the load memory
    /// instructions.
    fn eval_unsigned_mem_value<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &MemoryChipValueCols<CB::Var>,
    ) {
        let mem_val = *local.memory_access.value();

        // Compute the offset_is_zero flag.  The other offset flags are already contrained by the
        // method `eval_memory_address_and_access`, which is called in
        // `eval_memory_address_and_access`.
        let offset_is_zero =
            CB::Expr::ONE - local.offset_is_one - local.offset_is_two - local.offset_is_three;

        // Compute the byte value.
        let mem_byte = mem_val[0] * offset_is_zero.clone()
            + mem_val[1] * local.offset_is_one
            + mem_val[2] * local.offset_is_two
            + mem_val[3] * local.offset_is_three;
        let byte_value = Word::extend_expr::<CB>(mem_byte.clone());

        // When the instruction is LB or LBU, just use the lower byte.
        builder
            .when(local.instruction.is_lb + local.instruction.is_lbu)
            .assert_word_eq(byte_value, local.unsigned_mem_val.map(|x| x.into()));

        // When the instruction is LH or LHU, use the lower half.
        builder
            .when(local.instruction.is_lh + local.instruction.is_lhu)
            .assert_zero(local.offset_is_one + local.offset_is_three);

        // When the instruction is LW, ensure that the offset is zero.
        builder
            .when(local.instruction.is_lw)
            .assert_one(offset_is_zero.clone());

        let use_lower_half = offset_is_zero;
        let use_upper_half = local.offset_is_two;
        let half_value = Word([
            use_lower_half.clone() * mem_val[0] + use_upper_half * mem_val[2],
            use_lower_half * mem_val[1] + use_upper_half * mem_val[3],
            CB::Expr::ZERO,
            CB::Expr::ZERO,
        ]);

        builder
            .when(local.instruction.is_lh + local.instruction.is_lhu)
            .assert_word_eq(half_value, local.unsigned_mem_val.map(|x| x.into()));

        // When the instruction is LW, just use the word.
        builder
            .when(local.instruction.is_lw)
            .assert_word_eq(mem_val, local.unsigned_mem_val);
    }

    /// Evaluates the decomposition of the most significant byte of the memory value.
    fn eval_most_sig_byte_bit_decomp<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &MemoryChipValueCols<CB::Var>,
        unsigned_mem_val: &Word<CB::Var>,
    ) {
        let is_mem = self.is_memory_instruction::<CB>(&local.instruction);
        let mut recomposed_byte = CB::Expr::ZERO;
        for i in 0..8 {
            builder
                .when(is_mem.clone())
                .assert_bool(local.most_sig_byte_decomp[i]);
            recomposed_byte += local.most_sig_byte_decomp[i] * CB::Expr::from_canonical_u8(1 << i);
        }
        builder
            .when(local.instruction.is_lb)
            .assert_eq(recomposed_byte.clone(), unsigned_mem_val[0]);
        builder
            .when(local.instruction.is_lh)
            .assert_eq(recomposed_byte, unsigned_mem_val[1]);
    }

    /// Evaluates the offset value flags.
    fn eval_offset_value_flags<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &MemoryChipValueCols<CB::Var>,
    ) {
        let is_mem_op = self.is_memory_instruction::<CB>(&local.instruction);
        let offset_is_zero =
            CB::Expr::ONE - local.offset_is_one - local.offset_is_two - local.offset_is_three;

        let mut filtered_builder = builder.when(is_mem_op);

        // Assert that the value flags are boolean
        filtered_builder.assert_bool(local.offset_is_one);
        filtered_builder.assert_bool(local.offset_is_two);
        filtered_builder.assert_bool(local.offset_is_three);

        // Assert that only one of the value flags is true
        filtered_builder.assert_one(
            offset_is_zero.clone()
                + local.offset_is_one
                + local.offset_is_two
                + local.offset_is_three,
        );

        // Assert that the correct value flag is set
        filtered_builder
            .when(offset_is_zero)
            .assert_zero(local.addr_offset);
        filtered_builder
            .when(local.offset_is_one)
            .assert_one(local.addr_offset);
        filtered_builder
            .when(local.offset_is_two)
            .assert_eq(local.addr_offset, CB::Expr::TWO);
        filtered_builder
            .when(local.offset_is_three)
            .assert_eq(local.addr_offset, CB::Expr::from_canonical_u8(3));
    }
}
