use super::{columns::LtCols, traces::LtChip, LtValueCols};
use crate::{
    compiler::{
        riscv::opcode::{ByteOpcode, Opcode},
        word::Word,
    },
    machine::builder::{ChipBaseBuilder, ChipBuilder, ChipLookupBuilder},
};
use core::borrow::Borrow;
use itertools::izip;
use p3_air::{Air, AirBuilder};
use p3_field::{Field, FieldAlgebra};
use p3_matrix::Matrix;

impl<F: Field, CB> Air<CB> for LtChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &LtCols<CB::Var> = (*local).borrow();

        for LtValueCols {
            is_slt,
            is_slt_u,
            a,
            b,
            c,
            byte_flags,
            b_masked,
            c_masked,
            bit_b,
            bit_c,
            not_eq_inv,
            msb_b,
            msb_c,
            slt_u,
            is_cmp_eq,
            is_sign_bit_same,
            cmp_bytes,
        } in local.values
        {
            let is_real = is_slt + is_slt_u;
            let mut b_cmp: Word<CB::Expr> = b.map(|x| x.into());
            let mut c_cmp: Word<CB::Expr> = c.map(|x| x.into());

            b_cmp[3] = b[3] * is_slt_u + b_masked * is_slt;
            c_cmp[3] = c[3] * is_slt_u + c_masked * is_slt;

            // msb = b - b_masked * msb_inverse
            let inv_128 = F::from_canonical_u32(128).inverse();
            builder.assert_eq(msb_b, (b[3] - b_masked) * inv_128);
            builder.assert_eq(msb_c, (c[3] - c_masked) * inv_128);

            builder.assert_bool(is_sign_bit_same);

            builder.assert_eq(bit_b, msb_b * is_slt);
            builder.assert_eq(bit_c, msb_c * is_slt);

            // assert same sign
            builder.when(is_sign_bit_same).assert_eq(bit_b, bit_c);

            // assert 1 when b and c signs are not same
            builder
                .when(is_real.clone())
                .when_not(is_sign_bit_same)
                .assert_one(bit_b + bit_c);

            // when case msb_b = 0; msb_c = 1(negative), a0 = 0;
            // when case msb_b = 1(negative); msg_c = 0, a0 = 1;
            // when case msb_b and msb_c both is 0 or 1, a0 depends on SLTU.
            builder.assert_eq(
                a[0],
                bit_b * (CB::Expr::ONE - bit_c) + is_sign_bit_same * slt_u,
            );

            // just keeping the b < c result to a0
            builder.assert_zero(a[1]);
            builder.assert_zero(a[2]);
            builder.assert_zero(a[3]);

            builder.assert_bool(is_cmp_eq);

            let sum_flags = byte_flags[0] + byte_flags[1] + byte_flags[2] + byte_flags[3];
            builder.assert_bool(byte_flags[0]);
            builder.assert_bool(byte_flags[1]);
            builder.assert_bool(byte_flags[2]);
            builder.assert_bool(byte_flags[3]);
            builder.assert_bool(sum_flags.clone());
            builder
                .when(is_real.clone())
                .assert_eq(CB::Expr::ONE - is_cmp_eq, sum_flags);

            let mut is_not_equal = CB::Expr::ZERO;

            // Expressions for computing the comparison bytes.
            let mut b_cmp_byte = CB::Expr::ZERO;
            let mut c_cmp_byte = CB::Expr::ZERO;
            // Iterate over the bytes in reverse order and select the differing bytes using the byte
            // flag columns values.
            for (b_byte, c_byte, &flag) in izip!(
                b_cmp.0.iter().rev(),
                c_cmp.0.iter().rev(),
                byte_flags.iter().rev()
            ) {
                // Once the byte flag was set to one, we turn off the quality check flag.
                // We can do this by calculating the sum of the flags since only `1` is set to `1`.
                is_not_equal += flag.into();

                b_cmp_byte += b_byte.clone() * flag;
                c_cmp_byte += c_byte.clone() * flag;

                // If inequality is not visited, assert that the bytes are equal.
                builder
                    .when_not(is_not_equal.clone())
                    .assert_eq(b_byte.clone(), c_byte.clone());
                // If the numbers are assumed equal, inequality should not be visited.
                builder.when(is_cmp_eq).assert_zero(is_not_equal.clone());
            }

            let (b_comp_byte, c_comp_byte) = (cmp_bytes[0], cmp_bytes[1]);
            builder.assert_eq(b_comp_byte, b_cmp_byte);
            builder.assert_eq(c_comp_byte, c_cmp_byte);

            // Using the values above, we can constrain the `local.is_comp_eq` flag. We already asserted
            // in the loop that when `local.is_comp_eq == 1` then all bytes are equal. It is left to
            // verify that when `local.is_comp_eq == 0` the comparison bytes are indeed not equal.
            // This is done using the inverse hint `not_eq_inv`.
            builder
                .when_not(is_cmp_eq)
                .assert_eq(not_eq_inv * (b_comp_byte - c_comp_byte), is_real.clone());

            // Check that the operation flags are boolean.
            builder.assert_bool(is_slt);
            builder.assert_bool(is_slt_u);

            builder.assert_bool(is_slt + is_slt_u);

            // constraint b_masked
            builder.looking_byte(
                ByteOpcode::AND.as_field::<CB::F>(),
                b_masked,
                b[3],
                CB::F::from_canonical_u8(0x7f),
                is_real.clone(),
            );

            // constraint c_masked
            builder.looking_byte(
                ByteOpcode::AND.as_field::<CB::F>(),
                c_masked,
                c[3],
                CB::F::from_canonical_u8(0x7f),
                is_real.clone(),
            );

            // constraint unsigned b and C LTU
            builder.looking_byte(
                ByteOpcode::LTU.as_field::<CB::F>(),
                slt_u,
                b_comp_byte,
                c_comp_byte,
                is_real.clone(),
            );

            // SLT looked
            let lt_op_code = is_slt * CB::F::from_canonical_u32(Opcode::SLT as u32)
                + is_slt_u * CB::F::from_canonical_u32(Opcode::SLTU as u32);
            builder.looked_alu(lt_op_code, a, b, c, is_real)
        }
    }
}
