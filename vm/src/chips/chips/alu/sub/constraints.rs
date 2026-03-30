use crate::{
    chips::{
        chips::alu::sub::{
            columns::{SubCols, SubValueCols, NUM_SUB_COLS},
            SubChip,
        },
        gadgets::sub::SubGadget,
    },
    compiler::riscv::opcode::Opcode,
    machine::builder::{ChipBuilder, ChipLookupBuilder, ScopedBuilder},
};
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::Matrix;
use std::borrow::Borrow;

impl<F: Field> BaseAir<F> for SubChip<F> {
    fn width(&self) -> usize {
        NUM_SUB_COLS
    }
}

impl<F: Field, CB: ChipBuilder<F> + ScopedBuilder> Air<CB> for SubChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &SubCols<CB::Var> = (*local).borrow();

        for (
            i,
            SubValueCols {
                sub_operation,
                operand_1,
                operand_2,
                is_sub,
            },
        ) in local.values.into_iter().enumerate()
        {
            let scope = format!("SubValueCols[{}]", i);
            builder.with_scope(scope, |builder| {
                // Evaluate the 64-bit subtraction gadget.
                // Sub64Gadget computes: sub_operation.value = operand_1 - operand_2
                SubGadget::<CB::F>::eval(
                    builder,
                    operand_1,
                    operand_2,
                    sub_operation,
                    is_sub.into(),
                );

                // Receive the SUB lookup: a = b - c, multiplicity = is_sub.
                // In standard ALU convention: a is the result, b is the minuend, c is the subtrahend.
                builder.looked_alu(
                    Opcode::SUB.as_field::<CB::F>(),
                    sub_operation.value,
                    operand_1,
                    operand_2,
                    is_sub,
                );

                builder.assert_bool(is_sub);
            });
        }
    }
}
