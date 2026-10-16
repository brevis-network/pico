#![allow(clippy::assign_op_pattern)]

use super::{columns::LtCols, traces::LtChip, LtValueCols, LT_CMP_OPCODE_TAG};
use crate::{
    chips::gadgets::lt_signed::LtSignedGadget,
    compiler::riscv::opcode::Opcode,
    machine::builder::{ChipBuilder, ChipLookupBuilder},
};
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, WindowAccess};
use p3_field::Field;

impl<F: Field, CB> Air<CB> for LtChip<F>
where
    CB: ChipBuilder<F> + ChipLookupBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &LtCols<CB::Var> = (*local).borrow();

        for values in &local.values {
            let LtValueCols {
                is_slt,
                is_slt_u,
                a,
                b,
                c,
                lt_signed,
                is_cmp,
            } = values;

            let is_real = *is_slt + *is_slt_u;

            // Assert that the operation flags are boolean.
            builder.assert_bool(*is_slt);
            builder.assert_bool(*is_slt_u);
            builder.assert_bool(is_real.clone());

            // `is_cmp` marks a merged branch-comparison row: one row pins both `[b < c]` and
            // `[b > c]` for the Cpu. Its booleanity is a soundness constraint, not a convention.
            // The bus message below carries `is_cmp * LT_CMP_OPCODE_TAG` in the opcode field, and
            // over the field a non-boolean `is_cmp = (d - 8) * 256^-1` would move that field onto
            // any other ALU opcode `d`, letting this row pay for a foreign dispatch.
            builder.assert_bool(*is_cmp);
            // Padding rows keep the flag at zero (convention, same as the gadget's `is_signed`).
            builder.when_not(is_real.clone()).assert_zero(*is_cmp);

            // Evaluate the lt_signed gadget
            // This handles MSB extraction, XOR with (1 << 63) for signed comparison,
            // and the unsigned less-than check
            LtSignedGadget::<CB::F>::eval(builder, *b, *c, *lt_signed, *is_slt, is_real.clone());

            // `a[1]` is the strict "greater than" bit on merged rows and zero elsewhere.
            //
            // On a real row the gadget pins `bit = [b' < c']` and `sum_flags = [b' != c']` (on the
            // sign-adjusted operands; the adjustment is an order-preserving bijection), and a zero
            // flag sum forces every limb equal so the U16Range on `bit * 2^16` forces `bit = 0`:
            // `bit = 1 => sum_flags = 1`. Hence `sum_flags - bit` is exactly the boolean
            // `[b > c]`, and `a[0] * a[1] = 0` / `1 - a[0] - a[1] = [b = c]` hold on one row.
            // Ungated: padding rows are all-zero, so both sides vanish there.
            let sum_flags = lt_signed.result.u16_flags[0]
                + lt_signed.result.u16_flags[1]
                + lt_signed.result.u16_flags[2]
                + lt_signed.result.u16_flags[3];
            builder.assert_eq(a[1], *is_cmp * (sum_flags - lt_signed.result.bit));
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

            // SLT looked. Merged rows add `LT_CMP_OPCODE_TAG`, so their message can only pair
            // with the Cpu's single branch-comparison dispatch, never with a plain SLT/SLTU one.
            let lt_op_code = *is_slt * CB::F::from_u32(Opcode::SLT as u32)
                + *is_slt_u * CB::F::from_u32(Opcode::SLTU as u32)
                + *is_cmp * CB::F::from_u32(LT_CMP_OPCODE_TAG);
            builder.looked_alu(lt_op_code, *a, *b, *c, is_real)
        }
    }
}
