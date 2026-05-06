use crate::{
    chips::{
        chips::alu::subw::{
            columns::{SubwCols, SubwValueCols, NUM_SUBW_COLS},
            SubwChip,
        },
        gadgets::subw::SubwGadget,
    },
    compiler::{riscv::opcode::Opcode, word::Word},
    machine::builder::{ChipBuilder, ChipLookupBuilder, ScopedBuilder},
};
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::Matrix;
use std::borrow::Borrow;

impl<F: Field> BaseAir<F> for SubwChip<F> {
    fn width(&self) -> usize {
        NUM_SUBW_COLS
    }
}

impl<F: Field, CB: ChipBuilder<F> + ScopedBuilder> Air<CB> for SubwChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &SubwCols<CB::Var> = (*local).borrow();

        for (
            i,
            SubwValueCols {
                subw_operation,
                operand_1,
                operand_2,
                is_subw,
            },
        ) in local.values.into_iter().enumerate()
        {
            let scope = format!("SubwValueCols[{}]", i);
            builder.with_scope(scope, |builder| {
                // Evaluate the SUBW gadget: constrains lower 32 bits of (operand_1 - operand_2)
                // and the MSB of the result (needed for sign extension).
                // Subw64Gadget takes Word<AB::Var>, so pass directly.
                SubwGadget::<CB::F>::eval(
                    builder,
                    operand_1,
                    operand_2,
                    subw_operation,
                    is_subw.into(),
                );

                // Sign-extend the 32-bit result to 64 bits by filling upper two u16 limbs with
                // 0x0000 (positive) or 0xFFFF (negative) according to the MSB.
                let max_u16 = CB::F::from_canonical_u32((1 << 16) - 1);
                let a_val = Word([
                    subw_operation.value[0].into(),
                    subw_operation.value[1].into(),
                    subw_operation.msb.msb * max_u16,
                    subw_operation.msb.msb * max_u16,
                ]);

                // Receive the SUBW lookup: a = sign_extend_32(b - c), multiplicity = is_subw.
                builder.looked_alu(
                    Opcode::SUBW.as_field::<CB::F>(),
                    a_val,
                    operand_1,
                    operand_2,
                    is_subw,
                );

                builder.assert_bool(is_subw);
            });
        }
    }
}
