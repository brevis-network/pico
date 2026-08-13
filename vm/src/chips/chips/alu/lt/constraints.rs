#![allow(clippy::assign_op_pattern)]

use super::{columns::LtCols, traces::LtChip, LtValueCols};
use crate::{
    chips::gadgets::lt_signed::LtSignedGadget,
    compiler::riscv::opcode::Opcode,
    machine::builder::{ChipBuilder, ChipLookupBuilder},
};
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder};
use p3_field::Field;
use p3_matrix::Matrix;

impl<F: Field, CB> Air<CB> for LtChip<F>
where
    CB: ChipBuilder<F> + ChipLookupBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &LtCols<CB::Var> = (*local).borrow();

        for values in &local.values {
            let LtValueCols {
                is_slt,
                is_slt_u,
                a,
                b,
                c,
                lt_signed,
            } = values;

            let is_real = *is_slt + *is_slt_u;

            // Assert that the operation flags are boolean.
            builder.assert_bool(*is_slt);
            builder.assert_bool(*is_slt_u);
            builder.assert_bool(is_real.clone());

            // Evaluate the lt_signed gadget
            // This handles MSB extraction, XOR with (1 << 63) for signed comparison,
            // and the unsigned less-than check
            LtSignedGadget::<CB::F>::eval(builder, *b, *c, *lt_signed, *is_slt, is_real.clone());

            // Result should only be in a[0]
            builder.assert_zero(a[1]);
            builder.assert_zero(a[2]);
            builder.assert_zero(a[3]);

            // Bind a[0] to the comparison the gadget actually computed.
            //
            // Without this, `a` was pinned only in its upper three limbs while the outcome sat
            // unused in `lt_signed.result.bit`, so a prover could put any u16 in `a[0]` and the
            // ALU bus would carry it as the result of the comparison.
            //
            // Gated by `is_real`. The ungated form is equivalent here, not stronger: on a
            // padding row the bus multiplicity is `is_real = 0` so
            // nothing is emitted, and `result.bit` is itself a free column there (the gadget's
            // own eval is gated), so an ungated equality would only tie two free columns together.
            builder
                .when(is_real.clone())
                .assert_eq(a[0], lt_signed.result.bit);

            // SLT looked
            let lt_op_code = *is_slt * CB::F::from_canonical_u32(Opcode::SLT as u32)
                + *is_slt_u * CB::F::from_canonical_u32(Opcode::SLTU as u32);
            builder.looked_alu(lt_op_code, *a, *b, *c, is_real)
        }
    }
}
