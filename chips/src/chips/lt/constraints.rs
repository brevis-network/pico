use crate::chips::lt::{columns::LtCols, traces::LtChip};
use core::borrow::Borrow;
use itertools::izip;
use p3_air::{Air, AirBuilder};
use p3_field::{AbstractField, Field};
use p3_matrix::Matrix;
use pico_compiler::{
    opcode::{ByteOpcode, Opcode},
    word::Word,
};
use pico_machine::{
    builder::ChipBuilder,
    lookup::{LookupType, SymbolicLookup},
};
use std::iter::once;

impl<F, CB> Air<CB> for LtChip<F>
where
    F: Field,
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &LtCols<CB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &LtCols<CB::Var> = (*next).borrow();

        let is_real = local.is_slt + local.is_slt_u;
        let mut b_cmp: Word<CB::Expr> = local.b.map(|x| x.into());
        let mut c_cmp: Word<CB::Expr> = local.c.map(|x| x.into());

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder
            .when_transition()
            .assert_eq(local.nonce + CB::Expr::one(), next.nonce);

        b_cmp[3] = local.b[3] * local.is_slt_u + local.b_masked * local.is_slt;
        c_cmp[3] = local.c[3] * local.is_slt_u + local.c_masked * local.is_slt;

        // msb = b - b_masked * msb_inverse
        let inv_128 = F::from_canonical_u32(128).inverse();
        builder.assert_eq(local.msb_b, (local.b[3] - local.b_masked) * inv_128);
        builder.assert_eq(local.msb_c, (local.c[3] - local.c_masked) * inv_128);

        builder.assert_bool(local.is_sign_bit_same);

        let sign_b = local.msb_b * local.is_slt;
        let sign_c = local.msb_c * local.is_slt;
        // assert same sign
        builder
            .when(local.is_sign_bit_same)
            .assert_eq(sign_b.clone(), sign_c.clone());

        // assert 1 when b and c signs are not same
        builder
            .when(is_real.clone())
            .when_not(local.is_sign_bit_same)
            .assert_one(sign_b.clone() + sign_c.clone());

        // when case msb_b = 0; msb_c = 1(negative), a0 = 0;
        // when case msb_b = 1(negative); msg_c = 0, a0 = 1;
        // when case msb_b and msb_c both is 0 or 1, a0 depends on SLTU.
        builder.assert_eq(
            local.a[0],
            sign_b * (CB::Expr::one() - sign_c) + local.is_sign_bit_same * local.slt_u,
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
            .assert_eq(CB::Expr::one() - local.is_cmp_eq, sum_flags);

        let mut is_not_equal = CB::Expr::zero();

        // Expressions for computing the comparison bytes.
        let mut b_cmp_byte = CB::Expr::zero();
        let mut c_cmp_byte = CB::Expr::zero();
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
            local.shard,
            local.channel,
            is_real.clone(),
        );

        // constraint c_masked
        builder.looking_byte(
            ByteOpcode::AND.as_field::<CB::F>(),
            local.c_masked,
            local.c[3],
            CB::F::from_canonical_u8(0x7f),
            local.shard,
            local.channel,
            is_real.clone(),
        );

        // constraint unsigned b and C LTU
        builder.looking_byte(
            ByteOpcode::LTU.as_field::<CB::F>(),
            local.slt_u,
            b_comp_byte,
            c_comp_byte,
            local.shard,
            local.channel,
            is_real.clone(),
        );

        // SLT looked
        let lt_op_code = local.is_slt * CB::F::from_canonical_u32(Opcode::SLT as u32)
            + local.is_slt_u * CB::F::from_canonical_u32(Opcode::SLTU as u32);
        self.looked_lt(
            builder,
            lt_op_code,
            local.a,
            local.b,
            local.c,
            local.shard,
            local.channel,
            local.nonce,
            is_real,
        )
    }
}

#[allow(clippy::too_many_arguments)]
impl<F: Field> LtChip<F> {
    pub fn looked_lt<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        opcode: impl Into<CB::Expr>,
        a: Word<impl Into<CB::Expr>>,
        b: Word<impl Into<CB::Expr>>,
        c: Word<impl Into<CB::Expr>>,
        shard: impl Into<CB::Expr>,
        channel: impl Into<CB::Expr>,
        nonce: impl Into<CB::Expr>,
        multiplicity: impl Into<CB::Expr>,
    ) {
        let values = once(opcode.into())
            .chain(a.0.into_iter().map(Into::into))
            .chain(b.0.into_iter().map(Into::into))
            .chain(c.0.into_iter().map(Into::into))
            .chain(once(shard.into()))
            .chain(once(channel.into()))
            .chain(once(nonce.into()))
            .collect();

        builder.looked(SymbolicLookup::new(
            values,
            multiplicity.into(),
            LookupType::Alu,
        ))
    }
}
