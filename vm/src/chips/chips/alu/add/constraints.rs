use crate::{
    chips::{
        chips::alu::add::{
            columns::{AddCols, AddValueCols, NUM_ADD_COLS},
            AddChip,
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

impl<F: Field> BaseAir<F> for AddChip<F> {
    fn width(&self) -> usize {
        NUM_ADD_COLS
    }
}

impl<F: Field, CB: ChipBuilder<F> + ScopedBuilder> Air<CB> for AddChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &AddCols<CB::Var> = (*local).borrow();

        for (
            i,
            AddValueCols {
                add_operation,
                operand_1,
                operand_2,
                is_add,
            },
        ) in local.values.into_iter().enumerate()
        {
            let scope = format!("AddValueCols[{}]", i);
            builder.with_scope(scope, |builder| {
                // Evaluate the 64-bit addition gadget.
                AddGadget::<CB::F>::eval(builder, operand_1, operand_2, add_operation, is_add);

                // Receive the ADD lookup: a = b + c, multiplicity = is_add.
                builder.looked_alu(
                    Opcode::ADD.as_field::<CB::F>(),
                    add_operation.value,
                    operand_1,
                    operand_2,
                    is_add,
                );

                builder.assert_bool(is_add);
            });
        }
    }
}
