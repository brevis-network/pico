use crate::{
    chips::{
        chips::alu::add_sub::{
            columns::{AddSubCols, AddSubValueCols, NUM_ADD_SUB_COLS},
            AddSubChip,
        },
        gadgets::add::AddGadget,
    },
    compiler::riscv::opcode::Opcode,
    machine::builder::{ChipBuilder, ChipLookupBuilder, ScopedBuilder},
};
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::Matrix;
use std::borrow::Borrow;

impl<F: Field> BaseAir<F> for AddSubChip<F> {
    fn width(&self) -> usize {
        NUM_ADD_SUB_COLS
    }
}

impl<F: Field, CB: ChipBuilder<F> + ScopedBuilder> Air<CB> for AddSubChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &AddSubCols<CB::Var> = (*local).borrow();

        for (
            i,
            AddSubValueCols {
                add_operation,
                operand_1,
                operand_2,
                is_add,
                is_sub,
            },
        ) in local.values.into_iter().enumerate()
        {
            let scope = format!("AddSubValueCols[{}]", i);
            builder.with_scope(scope, |builder| {
                // Evaluate the addition operation.
                AddGadget::<CB::F>::eval(
                    builder,
                    operand_1,
                    operand_2,
                    add_operation,
                    is_add + is_sub,
                );

                let opcode = is_add * Opcode::ADD.as_field::<CB::F>()
                    + is_sub * Opcode::SUB.as_field::<CB::F>();

                // Receive the arguments.  There are seperate receives for ADD and SUB.
                // For add, `add_operation.value` is `a`, `operand_1` is `b`, and `operand_2` is `c`.
                builder.looked_alu(
                    opcode.clone(),
                    add_operation.value,
                    operand_1,
                    operand_2,
                    is_add,
                );
                // For sub, `operand_1` is `a`, `add_operation.value` is `b`, and `operand_2` is `c`.
                builder.looked_alu(opcode, operand_1, add_operation.value, operand_2, is_sub);

                let is_real = is_add + is_sub;
                builder.assert_bool(is_add);
                builder.assert_bool(is_sub);
                builder.with_scope("is_real", |builder| builder.assert_bool(is_real));
            });
        }
    }
}
