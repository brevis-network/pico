use super::{columns::LtCols, traces::LtChip};
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

        let is_real = local.is_slt + local.is_slt_u;
        let mut b_cmp: Word<CB::Expr> = local.b.map(|x| x.into());
        let mut c_cmp: Word<CB::Expr> = local.c.map(|x| x.into());

        b_cmp[3] = local.b[3] * local.is_slt_u + local.b_masked * local.is_slt;
        c_cmp[3] = local.c[3] * local.is_slt_u + local.c_masked * local.is_slt;

        // msb = b - b_masked * msb_inverse
        let inv_128 = F::from_canonical_u32(128).inverse();
        builder.assert_eq(local.msb_b, (local.b[3] - local.b_masked) * inv_128);
        builder.assert_eq(local.msb_c, (local.c[3] - local.c_masked) * inv_128);

        builder.assert_bool(local.is_sign_bit_same);

        builder.assert_eq(local.bit_b, local.msb_b * local.is_slt);
        builder.assert_eq(local.bit_c, local.msb_c * local.is_slt);

        // assert same sign
        builder
            .when(local.is_sign_bit_same)
            .assert_eq(local.bit_b, local.bit_c);

        // assert 1 when b and c signs are not same
        builder
            .when(is_real.clone())
            .when_not(local.is_sign_bit_same)
            .assert_one(local.bit_b + local.bit_c);

        // when case msb_b = 0; msb_c = 1(negative), a0 = 0;
        // when case msb_b = 1(negative); msg_c = 0, a0 = 1;
        // when case msb_b and msb_c both is 0 or 1, a0 depends on SLTU.
        builder.assert_eq(
            local.a[0],
            local.bit_b * (CB::Expr::ONE - local.bit_c) + local.is_sign_bit_same * local.slt_u,
        );

        // just keeping the b < c result to a0
        builder.assert_zero(local.a[1]);
        builder.assert_zero(local.a[2]);
        builder.assert_zero(local.a[3]);

        builder.assert_bool(local.is_cmp_eq);

        let sum_flags =
            local.byte_flags[0] + local.byte_flags[1] + local.byte_flags[2] + local.byte_flags[3];
        builder.assert_bool(local.byte_flags[0]);
        builder.assert_bool(local.byte_flags[1]);
        builder.assert_bool(local.byte_flags[2]);
        builder.assert_bool(local.byte_flags[3]);
        builder.assert_bool(sum_flags.clone());
        builder
            .when(is_real.clone())
            .assert_eq(CB::Expr::ONE - local.is_cmp_eq, sum_flags);

        let mut is_not_equal = CB::Expr::ZERO;

        // Expressions for computing the comparison bytes.
        let mut b_cmp_byte = CB::Expr::ZERO;
        let mut c_cmp_byte = CB::Expr::ZERO;
        // Iterate over the bytes in reverse order and select the differing bytes using the byte
        // flag columns values.
        for (b_byte, c_byte, &flag) in izip!(
            b_cmp.0.iter().rev(),
            c_cmp.0.iter().rev(),
            local.byte_flags.iter().rev()
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
            builder
                .when(local.is_cmp_eq)
                .assert_zero(is_not_equal.clone());
        }

        let (b_comp_byte, c_comp_byte) = (local.cmp_bytes[0], local.cmp_bytes[1]);
        builder.assert_eq(b_comp_byte, b_cmp_byte);
        builder.assert_eq(c_comp_byte, c_cmp_byte);

        // Using the values above, we can constrain the `local.is_comp_eq` flag. We already asserted
        // in the loop that when `local.is_comp_eq == 1` then all bytes are equal. It is left to
        // verify that when `local.is_comp_eq == 0` the comparison bytes are indeed not equal.
        // This is done using the inverse hint `not_eq_inv`.
        builder.when_not(local.is_cmp_eq).assert_eq(
            local.not_eq_inv * (b_comp_byte - c_comp_byte),
            is_real.clone(),
        );

        // Check that the operation flags are boolean.
        builder.assert_bool(local.is_slt);
        builder.assert_bool(local.is_slt_u);

        builder.assert_bool(local.is_slt + local.is_slt_u);

        // constraint b_masked
        builder.looking_byte(
            ByteOpcode::AND.as_field::<CB::F>(),
            local.b_masked,
            local.b[3],
            CB::F::from_canonical_u8(0x7f),
            is_real.clone(),
        );

        // constraint c_masked
        builder.looking_byte(
            ByteOpcode::AND.as_field::<CB::F>(),
            local.c_masked,
            local.c[3],
            CB::F::from_canonical_u8(0x7f),
            is_real.clone(),
        );

        // constraint unsigned b and C LTU
        builder.looking_byte(
            ByteOpcode::LTU.as_field::<CB::F>(),
            local.slt_u,
            b_comp_byte,
            c_comp_byte,
            is_real.clone(),
        );

        // SLT looked
        let lt_op_code = local.is_slt * CB::F::from_canonical_u32(Opcode::SLT as u32)
            + local.is_slt_u * CB::F::from_canonical_u32(Opcode::SLTU as u32);
        builder.looked_alu(lt_op_code, local.a, local.b, local.c, is_real)
    }
}
