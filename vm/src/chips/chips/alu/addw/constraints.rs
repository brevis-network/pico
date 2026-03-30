use crate::{
    chips::{
        chips::alu::addw::{
            columns::{AddwCols, AddwValueCols, NUM_ADDW_COLS},
            AddwChip,
        },
        gadgets::addw::AddwGadget,
    },
    compiler::{riscv::opcode::Opcode, word::Word},
    machine::builder::{ChipBuilder, ChipLookupBuilder, ScopedBuilder},
};
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::Matrix;
use std::borrow::Borrow;

impl<F: Field> BaseAir<F> for AddwChip<F> {
    fn width(&self) -> usize {
        NUM_ADDW_COLS
    }
}

impl<F: Field, CB: ChipBuilder<F> + ScopedBuilder> Air<CB> for AddwChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &AddwCols<CB::Var> = (*local).borrow();

        for (
            i,
            AddwValueCols {
                addw_operation,
                operand_1,
                operand_2,
                is_addw,
            },
        ) in local.values.into_iter().enumerate()
        {
            let scope = format!("AddwValueCols[{}]", i);
            builder.with_scope(scope, |builder| {
                // Evaluate the ADDW gadget: constrains lower 32 bits of (operand_1 + operand_2)
                // and the MSB of the result (needed for sign extension).
                AddwGadget::<CB::F>::eval(
                    builder,
                    operand_1.map(Into::into),
                    operand_2.map(Into::into),
                    addw_operation,
                    is_addw.into(),
                );

                // Sign-extend the 32-bit result to 64 bits by filling upper two u16 limbs with
                // 0x0000 (positive) or 0xFFFF (negative) according to the MSB.
                let max_u16 = CB::F::from_canonical_u32((1 << 16) - 1);
                let a_val = Word([
                    addw_operation.value[0].into(),
                    addw_operation.value[1].into(),
                    addw_operation.msb.msb * max_u16,
                    addw_operation.msb.msb * max_u16,
                ]);

                // Receive the ADDW lookup: a = sign_extend_32(b + c), multiplicity = is_addw.
                builder.looked_alu(
                    Opcode::ADDW.as_field::<CB::F>(),
                    a_val,
                    operand_1,
                    operand_2,
                    is_addw,
                );

                builder.assert_bool(is_addw);
            });
        }
    }
}
