use super::{
    columns::{BitwiseCols, NUM_BITWISE_COLS},
    BitwiseChip,
};
use crate::{
    chips::{
        chips::alu::bitwise::columns::BitwiseValueCols, gadgets::bitwise_u16::BitWiseU16Gadget,
    },
    compiler::riscv::opcode::{ByteOpcode, Opcode},
    machine::builder::{ChipBuilder, ChipLookupBuilder},
};
use core::borrow::Borrow;
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::Matrix;

impl<F: Field> BaseAir<F> for BitwiseChip<F> {
    fn width(&self) -> usize {
        NUM_BITWISE_COLS
    }
}

impl<F: Field, CB: ChipBuilder<F>> Air<CB> for BitwiseChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &BitwiseCols<CB::Var> = (*local).borrow();

        for BitwiseValueCols {
            b,
            c,
            bitwise,
            is_xor,
            is_or,
            is_and,
        } in local.values
        {
            let is_real = is_xor + is_or + is_and;

            // Get the opcode for the operation.
            let opcode = is_xor * ByteOpcode::XOR.as_field::<CB::F>()
                + is_or * ByteOpcode::OR.as_field::<CB::F>()
                + is_and * ByteOpcode::AND.as_field::<CB::F>();

            // Use BitWiseGadget to evaluate the bitwise operation
            let a = BitWiseU16Gadget::<F>::eval(
                builder,
                b.map(Into::into),
                c.map(Into::into),
                bitwise,
                opcode.clone(),
                is_real.clone(),
            );

            // Get the cpu opcode, which corresponds to the opcode being sent in the CPU table.
            let cpu_opcode = is_xor * Opcode::XOR.as_field::<CB::F>()
                + is_or * Opcode::OR.as_field::<CB::F>()
                + is_and * Opcode::AND.as_field::<CB::F>();

            builder.looked_alu(cpu_opcode, a, b, c, is_real.clone());

            builder.assert_bool(is_xor);
            builder.assert_bool(is_or);
            builder.assert_bool(is_and);
            builder.assert_bool(is_real);
        }
    }
}
