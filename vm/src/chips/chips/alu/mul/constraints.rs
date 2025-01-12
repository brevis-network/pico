//! Implementation to check that b * c = product.
//!
//! We first extend the operands to 64 bits. We sign-extend them if the op code is signed. Then we
//! calculate the un-carried product and propagate the carry. Finally, we check that the appropriate
//! bits of the product match the result.
//!
//! b_64 = sign_extend(b) if signed operation else b
//! c_64 = sign_extend(c) if signed operation else c
//!
//! m = []
//! # 64-bit integers have 8 limbs.
//! # Calculate un-carried product.
//! for i in 0..8:
//!     for j in 0..8:
//!         if i + j < 8:
//!             m[i + j] += b_64[i] * c_64[j]
//!
//! # Propagate carry
//! for i in 0..8:
//!     x = m[i]
//!     if i > 0:
//!         x += carry[i - 1]
//!     carry[i] = x / 256
//!     m[i] = x % 256
//!
//! if upper_half:
//!     assert_eq(a, m[4..8])
//! if lower_half:
//!     assert_eq(a, m[0..4])

use std::borrow::Borrow;

use super::{columns::MulCols, MulChip, BYTE_MASK, PRODUCT_SIZE};
use crate::{
    compiler::riscv::opcode::{ByteOpcode, Opcode},
    machine::builder::{ChipBuilder, ChipLookupBuilder, ChipRangeBuilder},
    primitives::consts::WORD_SIZE,
};
use p3_air::{Air, AirBuilder};
use p3_field::Field;
use p3_matrix::Matrix;

impl<F: Field, CB> Air<CB> for MulChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MulCols<CB::Var> = (*local).borrow();
        let base = CB::F::from_canonical_u32(1 << 8);

        let zero: CB::Expr = CB::F::ZERO.into();
        let one: CB::Expr = CB::F::ONE.into();
        let byte_mask = CB::F::from_canonical_u8(BYTE_MASK);

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);

        // Calculate the MSBs.
        let (b_msb, c_msb) = {
            let msb_pairs = [
                (local.b_msb, local.b[WORD_SIZE - 1]),
                (local.c_msb, local.c[WORD_SIZE - 1]),
            ];
            let opcode = CB::F::from_canonical_u32(ByteOpcode::MSB as u32);
            for msb_pair in msb_pairs.iter() {
                let msb = msb_pair.0;
                let byte = msb_pair.1;
                builder.looking_byte(opcode, msb, byte, zero.clone(), local.is_real);
            }
            (local.b_msb, local.c_msb)
        };

        // Calculate whether to extend b and c's sign.
        let (b_sign_extend, c_sign_extend) = {
            // MULH or MULHSU
            let is_b_i32 = local.is_mulh + local.is_mulhsu - local.is_mulh * local.is_mulhsu;

            let is_c_i32 = local.is_mulh;

            builder.assert_eq(local.b_sign_extend, is_b_i32 * b_msb);
            builder.assert_eq(local.c_sign_extend, is_c_i32 * c_msb);
            (local.b_sign_extend, local.c_sign_extend)
        };

        // Sign extend local.b and local.c whenever appropriate.
        let (b, c) = {
            let mut b: Vec<CB::Expr> = vec![CB::F::ZERO.into(); PRODUCT_SIZE];
            let mut c: Vec<CB::Expr> = vec![CB::F::ZERO.into(); PRODUCT_SIZE];
            for i in 0..PRODUCT_SIZE {
                if i < WORD_SIZE {
                    b[i] = local.b[i].into();
                    c[i] = local.c[i].into();
                } else {
                    b[i] = b_sign_extend * byte_mask;
                    c[i] = c_sign_extend * byte_mask;
                }
            }
            (b, c)
        };

        // Compute the uncarried product b(x) * c(x) = m(x).
        let mut m: Vec<CB::Expr> = vec![CB::F::ZERO.into(); PRODUCT_SIZE];
        for i in 0..PRODUCT_SIZE {
            for j in 0..PRODUCT_SIZE {
                if i + j < PRODUCT_SIZE {
                    m[i + j] += b[i].clone() * c[j].clone();
                }
            }
        }

        // Propagate carry.
        let product = {
            for i in 0..PRODUCT_SIZE {
                if i == 0 {
                    builder.assert_eq(local.product[i], m[i].clone() - local.carry[i] * base);
                } else {
                    builder.assert_eq(
                        local.product[i],
                        m[i].clone() + local.carry[i - 1] - local.carry[i] * base,
                    );
                }
            }
            local.product
        };

        // Compare the product's appropriate bytes with that of the result.
        {
            let is_lower = local.is_mul;
            let is_upper = local.is_mulh + local.is_mulhu + local.is_mulhsu;
            for i in 0..WORD_SIZE {
                builder.when(is_lower).assert_eq(product[i], local.a[i]);
                builder
                    .when(is_upper.clone())
                    .assert_eq(product[i + WORD_SIZE], local.a[i]);
            }
        }

        // Check that the boolean values are indeed boolean values.
        {
            [
                local.b_msb,
                local.c_msb,
                local.b_sign_extend,
                local.c_sign_extend,
                local.is_mul,
                local.is_mulh,
                local.is_mulhu,
                local.is_mulhsu,
                local.is_real,
            ]
            .iter()
            .for_each(|flag| builder.assert_bool(*flag));
        }

        // If signed extended, the MSB better be 1.
        builder
            .when(local.b_sign_extend)
            .assert_eq(local.b_msb, one.clone());
        builder
            .when(local.c_sign_extend)
            .assert_eq(local.c_msb, one.clone());

        // Calculate the opcode.
        let opcode = {
            // Exactly one of the op codes must be on.
            builder
                .when(local.is_real)
                .assert_one(local.is_mul + local.is_mulh + local.is_mulhu + local.is_mulhsu);

            let mul: CB::Expr = CB::F::from_canonical_u32(Opcode::MUL as u32).into();
            let mulh: CB::Expr = CB::F::from_canonical_u32(Opcode::MULH as u32).into();
            let mulhu: CB::Expr = CB::F::from_canonical_u32(Opcode::MULHU as u32).into();
            let mulhsu: CB::Expr = CB::F::from_canonical_u32(Opcode::MULHSU as u32).into();
            local.is_mul * mul
                + local.is_mulh * mulh
                + local.is_mulhu * mulhu
                + local.is_mulhsu * mulhsu
        };

        // Range check.
        {
            // Ensure that the carry is at most 2^16. This ensures that
            // product_before_carry_propagation - carry * base + last_carry never overflows or
            // underflows enough to "wrap" around to create a second solution.
            builder.slice_range_check_u16(&local.carry, local.chunk, local.is_real);

            builder.slice_range_check_u8(&local.product, local.chunk, local.is_real);
        }

        // Receive the arguments.
        builder.looked_alu(
            opcode,
            local.a,
            local.b,
            local.c,
            local.chunk,
            local.nonce,
            local.is_real,
        );
    }
}
