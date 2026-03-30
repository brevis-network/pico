//! Implementation to check that b * c = product.
//!
//! This chip uses the MulGadget to verify multiplication operations.

use std::borrow::Borrow;

use crate::{
    chips::{chips::alu::mul::columns::MulValueCols, gadgets::mul::MulGadget},
    compiler::riscv::opcode::Opcode,
    machine::builder::{ChipBuilder, ChipLookupBuilder},
};

use super::{columns::MulCols, MulChip};
use p3_air::{Air, AirBuilder};
use p3_field::Field;
use p3_matrix::Matrix;

impl<F: Field, CB> Air<CB> for MulChip<F>
where
    CB: ChipBuilder<F> + ChipLookupBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MulCols<CB::Var> = (*local).borrow();

        for MulValueCols {
            a: local_a,
            b: local_b,
            c: local_c,
            mul_gadget,
            is_mul: local_is_mul,
            is_mulh: local_is_mulh,
            is_mulhu: local_is_mulhu,
            is_mulhsu: local_is_mulhsu,
            is_mulw: local_is_mulw,
        } in local.values
        {
            // Convert flags to expressions
            let is_mul: CB::Expr = local_is_mul.into();
            let is_mulh: CB::Expr = local_is_mulh.into();
            let is_mulhu: CB::Expr = local_is_mulhu.into();
            let is_mulhsu: CB::Expr = local_is_mulhsu.into();
            let is_mulw: CB::Expr = local_is_mulw.into();

            // Use MulGadget to evaluate multiplication constraints
            // is_real is true when any mul operation is being executed
            let is_real = is_mul.clone()
                + is_mulh.clone()
                + is_mulhu.clone()
                + is_mulhsu.clone()
                + is_mulw.clone();
            MulGadget::eval(
                builder,
                local_a,
                local_b,
                local_c,
                mul_gadget,
                is_real.clone(),
                is_mul.clone(),
                is_mulh.clone(),
                is_mulw.clone(),
                is_mulhu.clone(),
                is_mulhsu.clone(),
            );

            // Calculate the opcode.
            let opcode = {
                // Check that the boolean values are indeed boolean values.
                {
                    [
                        local_is_mul,
                        local_is_mulh,
                        local_is_mulhu,
                        local_is_mulhsu,
                        local_is_mulw,
                    ]
                    .iter()
                    .for_each(|flag| builder.assert_bool(*flag));
                }

                // Exactly one of the op codes must be on.
                builder.when(is_real.clone()).assert_one(
                    is_mul.clone()
                        + is_mulh.clone()
                        + is_mulhu.clone()
                        + is_mulhsu.clone()
                        + is_mulw.clone(),
                );

                let mul: CB::Expr = CB::F::from_canonical_u32(Opcode::MUL as u32).into();
                let mulh: CB::Expr = CB::F::from_canonical_u32(Opcode::MULH as u32).into();
                let mulhu: CB::Expr = CB::F::from_canonical_u32(Opcode::MULHU as u32).into();
                let mulhsu: CB::Expr = CB::F::from_canonical_u32(Opcode::MULHSU as u32).into();
                let mulw: CB::Expr = CB::F::from_canonical_u32(Opcode::MULW as u32).into();
                is_mul * mul
                    + is_mulh * mulh
                    + is_mulhu * mulhu
                    + is_mulhsu * mulhsu
                    + is_mulw * mulw
            };

            // Receive the arguments.
            builder.looked_alu(opcode, local_a, local_b, local_c, is_real);
        }
    }
}
