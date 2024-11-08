//! Division and remainder verification.
//!
//! This module implements the verification logic for division and remainder operations. It ensures
//! that for any given inputs b and c and outputs quotient and remainder, the equation
//!
//! b = c * quotient + remainder
//!
//! holds true, while also ensuring that the signs of `b` and `remainder` match.
//!
//! A critical aspect of this implementation is the use of 64-bit arithmetic for result calculation.
//! This choice is driven by the need to make the solution unique: in 32-bit arithmetic,
//! `c * quotient + remainder` could overflow, leading to results that are congruent modulo 2^{32}
//! and thus not uniquely defined. The 64-bit approach avoids this overflow, ensuring that each
//! valid input combination maps to a unique result.
//!
//! Implementation:
//!
//! # Use the multiplication ALU table. result is 64 bits.
//! result = quotient * c.
//!
//! # Add sign-extended remainder to result. Propagate carry to handle overflow within bytes.
//! base = pow(2, 8)
//! carry = 0
//! for i in range(8):
//!     x = result[i] + remainder[i] + carry
//!     result[i] = x % base
//!     carry = x // base
//!
//! # The number represented by c * quotient + remainder in 64 bits must equal b in 32 bits.
//!
//! # Assert the lower 32 bits of result match b.
//! assert result[0..4] == b[0..4]
//!
//! # Assert the upper 32 bits of result match the sign of b.
//! if (b == -2^{31}) and (c == -1):
//!     # This is the only exception as this is the only case where it overflows.
//!     assert result[4..8] == [0, 0, 0, 0]
//! elif b < 0:
//!     assert result[4..8] == [0xff, 0xff, 0xff, 0xff]
//! else:
//!     assert result[4..8] == [0, 0, 0, 0]
//!
//! # Check a = quotient or remainder.
//! assert a == (quotient if opcode == division else remainder)
//!
//! # remainder and b must have the same sign.
//! if remainder < 0:
//!     assert b <= 0
//! if remainder > 0:
//!     assert b >= 0
//!
//! # abs(remainder) < abs(c)
//! if c < 0:
//!    assert c < remainder <= 0
//! elif c > 0:
//!    assert 0 <= remainder < c
//!
//! if is_c_0:
//!    # if division by 0, then quotient = 0xffffffff per RISC-V spec. This needs special care since
//!    # b = 0 * quotient + b is satisfied by any quotient.
//!    assert quotient = 0xffffffff

use crate::{
    chips::{
        chips::alu::divrem::{columns::DivRemCols, DivRemChip},
        gadgets::{is_equal_word::IsEqualWordGadget, is_zero_word::IsZeroWordGadget},
    },
    compiler::{
        riscv::opcode::{ByteOpcode, Opcode},
        word::Word,
    },
    machine::builder::{ChipBuilder, ChipLookupBuilder, ChipRangeBuilder},
    primitives::consts::{LONG_WORD_SIZE, WORD_SIZE},
};
use p3_air::{Air, AirBuilder};
use p3_field::{AbstractField, Field};
use p3_matrix::Matrix;
use std::borrow::Borrow;

impl<F: Field, CB: ChipBuilder<F>> Air<CB> for DivRemChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &DivRemCols<CB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &DivRemCols<CB::Var> = (*next).borrow();
        let base = CB::F::from_canonical_u32(1 << 8);
        let one: CB::Expr = CB::F::one().into();
        let zero: CB::Expr = CB::F::zero().into();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder
            .when_transition()
            .assert_eq(local.nonce + CB::Expr::one(), next.nonce);

        // Calculate whether b, remainder, and c are negative.
        {
            // Negative if and only if op code is signed & MSB = 1.
            let is_signed_type = local.is_div + local.is_rem;
            let msb_sign_pairs = [
                (local.b_msb, local.b_neg),
                (local.rem_msb, local.rem_neg),
                (local.c_msb, local.c_neg),
            ];

            for msb_sign_pair in msb_sign_pairs.iter() {
                let msb = msb_sign_pair.0;
                let is_negative = msb_sign_pair.1;
                builder.assert_eq(msb * is_signed_type.clone(), is_negative);
            }
        }

        // Use the mul table to compute c * quotient and compare it to local.c_times_quotient.
        {
            let lower_half: [CB::Expr; 4] = [
                local.c_times_quotient[0].into(),
                local.c_times_quotient[1].into(),
                local.c_times_quotient[2].into(),
                local.c_times_quotient[3].into(),
            ];

            // The lower 4 bytes of c_times_quotient must match the lower 4 bytes of (c * quotient).
            builder.looking_alu(
                CB::Expr::from_canonical_u32(Opcode::MUL as u32),
                Word(lower_half),
                local.quotient,
                local.c,
                local.chunk,
                local.channel,
                local.lower_nonce,
                local.is_real,
            );

            let opcode_for_upper_half = {
                let mulh = CB::Expr::from_canonical_u32(Opcode::MULH as u32);
                let mulhu = CB::Expr::from_canonical_u32(Opcode::MULHU as u32);
                let is_signed = local.is_div + local.is_rem;
                let is_unsigned = local.is_divu + local.is_remu;
                is_signed * mulh + is_unsigned * mulhu
            };

            let upper_half: [CB::Expr; 4] = [
                local.c_times_quotient[4].into(),
                local.c_times_quotient[5].into(),
                local.c_times_quotient[6].into(),
                local.c_times_quotient[7].into(),
            ];

            builder.looking_alu(
                opcode_for_upper_half,
                Word(upper_half),
                local.quotient,
                local.c,
                local.chunk,
                local.channel,
                local.upper_nonce,
                local.is_real,
            );
        }

        // Calculate is_overflow. is_overflow = is_equal(b, -2^{31}) * is_equal(c, -1) * is_signed
        {
            IsEqualWordGadget::<CB::F>::eval(
                builder,
                local.b.map(|x| x.into()),
                Word::from(i32::MIN as u32).map(|x: CB::F| x.into()),
                local.is_overflow_b,
                local.is_real.into(),
            );

            IsEqualWordGadget::<CB::F>::eval(
                builder,
                local.c.map(|x| x.into()),
                Word::from(-1i32 as u32).map(|x: CB::F| x.into()),
                local.is_overflow_c,
                local.is_real.into(),
            );

            let is_signed = local.is_div + local.is_rem;

            builder.assert_eq(
                local.is_overflow,
                local.is_overflow_b.is_diff_zero.result
                    * local.is_overflow_c.is_diff_zero.result
                    * is_signed,
            );
        }

        // Add remainder to product c * quotient, and compare it to b.
        {
            let sign_extension = local.rem_neg * CB::F::from_canonical_u8(u8::MAX);
            let mut c_times_quotient_plus_remainder: Vec<CB::Expr> =
                vec![CB::F::zero().into(); LONG_WORD_SIZE];

            c_times_quotient_plus_remainder
                .iter_mut()
                .enumerate()
                .for_each(|(i, quotient_plus_remainder_times)| {
                    // Add remainder to c_times_quotient and propagate carry.
                    {
                        *quotient_plus_remainder_times = local.c_times_quotient[i].into();

                        // Add remainder.
                        if i < WORD_SIZE {
                            *quotient_plus_remainder_times += local.remainder[i].into();
                        } else {
                            // If rem is negative, add 0xff to the upper 4 bytes.
                            *quotient_plus_remainder_times += sign_extension.clone();
                        }

                        // Propagate carry.
                        *quotient_plus_remainder_times -= local.carry[i] * base;
                        if i > 0 {
                            *quotient_plus_remainder_times += local.carry[i - 1].into();
                        }
                    }

                    // Compare c_times_quotient_plus_remainder to b by checking each limb.
                    {
                        if i < WORD_SIZE {
                            // The lower 4 bytes of the result must match the corresponding bytes in b.
                            builder.assert_eq(local.b[i], quotient_plus_remainder_times.clone());
                        } else {
                            // The upper 4 bytes must reflect the sign of b in two's complement:
                            // - All 1s (0xff) for negative b.
                            // - All 0s for non-negative b.
                            let not_overflow = one.clone() - local.is_overflow;
                            builder
                                .when(not_overflow.clone())
                                .when(local.b_neg)
                                .assert_eq(
                                    quotient_plus_remainder_times.clone(),
                                    CB::F::from_canonical_u8(u8::MAX),
                                );
                            builder
                                .when(not_overflow.clone())
                                .when_ne(one.clone(), local.b_neg)
                                .assert_zero(quotient_plus_remainder_times.clone());

                            // The only exception to the upper-4-byte check is the overflow case.
                            builder
                                .when(local.is_overflow)
                                .assert_zero(quotient_plus_remainder_times.clone());
                        }
                    }
                });
        }

        // a must equal remainder or quotient depending on the opcode.
        for i in 0..WORD_SIZE {
            builder
                .when(local.is_divu + local.is_div)
                .assert_eq(local.quotient[i], local.a[i]);
            builder
                .when(local.is_remu + local.is_rem)
                .assert_eq(local.remainder[i], local.a[i]);
        }

        // remainder and b must have the same sign. Due to the intricate nature of sign logic in ZK,
        // we will check a slightly stronger condition:
        //
        // 1. If remainder < 0, then b < 0.
        // 2. If remainder > 0, then b >= 0.
        {
            // A number is 0 if and only if the sum of the 4 limbs equals to 0.
            let mut rem_byte_sum = zero.clone();
            let mut b_byte_sum = zero.clone();
            for i in 0..WORD_SIZE {
                rem_byte_sum += local.remainder[i].into();
                b_byte_sum += local.b[i].into();
            }

            // 1. If remainder < 0, then b < 0.
            builder
                .when(local.rem_neg) // rem is negative.
                .assert_one(local.b_neg); // b is negative.

            // 2. If remainder > 0, then b >= 0.
            builder
                .when(rem_byte_sum.clone()) // remainder is nonzero.
                .when(one.clone() - local.rem_neg) // rem is not negative.
                .assert_zero(local.b_neg); // b is not negative.
        }

        // When division by 0, quotient must be 0xffffffff per RISC-V spec.
        {
            // Calculate whether c is 0.
            IsZeroWordGadget::<CB::F>::eval(
                builder,
                local.c.map(|x| x.into()),
                local.is_c_0,
                local.is_real.into(),
            );

            // If is_c_0 is true, then quotient must be 0xffffffff = u32::MAX.
            for i in 0..WORD_SIZE {
                builder
                    .when(local.is_c_0.result)
                    .when(local.is_divu + local.is_div)
                    .assert_eq(local.quotient[i], CB::F::from_canonical_u8(u8::MAX));
            }
        }

        // Range check remainder. (i.e., |remainder| < |c| when not is_c_0)
        {
            // For each of `c` and `rem`, assert that the absolute value is equal to the original
            // value, if the original value is non-negative or the minimum i32.
            for i in 0..WORD_SIZE {
                builder
                    .when_not(local.c_neg)
                    .assert_eq(local.c[i], local.abs_c[i]);
                builder
                    .when_not(local.rem_neg)
                    .assert_eq(local.remainder[i], local.abs_remainder[i]);
            }
            // In the case that `c` or `rem` is negative, instead check that their sum is zero by
            // sending an AddEvent.
            builder.looking_alu(
                CB::Expr::from_canonical_u32(Opcode::ADD as u32),
                Word([zero.clone(), zero.clone(), zero.clone(), zero.clone()]),
                local.c,
                local.abs_c,
                local.chunk,
                local.channel,
                local.abs_c_alu_event_nonce,
                local.abs_c_alu_event,
            );
            builder.looking_alu(
                CB::Expr::from_canonical_u32(Opcode::ADD as u32),
                Word([zero.clone(), zero.clone(), zero.clone(), zero.clone()]),
                local.remainder,
                local.abs_remainder,
                local.chunk,
                local.channel,
                local.abs_rem_alu_event_nonce,
                local.abs_rem_alu_event,
            );

            // max(abs(c), 1) = abs(c) * (1 - is_c_0) + 1 * is_c_0
            let max_abs_c_or_1: Word<CB::Expr> = {
                let mut v = vec![zero.clone(); WORD_SIZE];

                // Set the least significant byte to 1 if is_c_0 is true.
                v[0] = local.is_c_0.result * one.clone()
                    + (one.clone() - local.is_c_0.result) * local.abs_c[0];

                // Set the remaining bytes to 0 if is_c_0 is true.
                for i in 1..WORD_SIZE {
                    v[i] = (one.clone() - local.is_c_0.result) * local.abs_c[i];
                }
                Word(v.try_into().unwrap_or_else(|_| panic!("Incorrect length")))
            };
            for i in 0..WORD_SIZE {
                builder.assert_eq(local.max_abs_c_or_1[i], max_abs_c_or_1[i].clone());
            }

            // Handle cases:
            // - If is_real == 0 then remainder_check_multiplicity == 0 is forced.
            // - If is_real == 1 then is_c_0_result must be the expected one, so
            //   remainder_check_multiplicity = (1 - is_c_0_result) * is_real.
            builder.assert_eq(
                (CB::Expr::one() - local.is_c_0.result) * local.is_real,
                local.remainder_check_multiplicity,
            );

            // the cleaner idea is simply remainder_check_multiplicity == (1 - is_c_0_result) *
            // is_real

            // Check that the absolute value selector columns are computed correctly.
            builder.assert_eq(local.abs_c_alu_event, local.c_neg * local.is_real);
            builder.assert_eq(local.abs_rem_alu_event, local.rem_neg * local.is_real);

            // Dispatch abs(remainder) < max(abs(c), 1), this is equivalent to abs(remainder) <
            // abs(c) if not division by 0.
            builder.looking_alu(
                CB::Expr::from_canonical_u32(Opcode::SLTU as u32),
                Word([one.clone(), zero.clone(), zero.clone(), zero.clone()]),
                local.abs_remainder,
                local.max_abs_c_or_1,
                local.chunk,
                local.channel,
                local.abs_nonce,
                local.remainder_check_multiplicity,
            );
        }

        // Check that the MSBs are correct.
        {
            let msb_pairs = [
                (local.b_msb, local.b[WORD_SIZE - 1]),
                (local.c_msb, local.c[WORD_SIZE - 1]),
                (local.rem_msb, local.remainder[WORD_SIZE - 1]),
            ];
            let opcode = CB::F::from_canonical_u32(ByteOpcode::MSB as u32);
            for msb_pair in msb_pairs.iter() {
                let msb = msb_pair.0;
                let byte = msb_pair.1;
                builder.looking_byte(
                    opcode,
                    msb,
                    byte,
                    zero.clone(),
                    local.chunk,
                    local.channel,
                    local.is_real,
                );
            }
        }

        // Range check all the bytes.
        {
            builder.slice_range_check_u8(&local.quotient.0, local.chunk, local.is_real);
            builder.slice_range_check_u8(&local.remainder.0, local.chunk, local.is_real);

            local.carry.iter().for_each(|carry| {
                builder.assert_bool(*carry);
            });

            builder.slice_range_check_u8(&local.c_times_quotient, local.chunk, local.is_real);
        }

        // Check that the flags are boolean.
        {
            [
                local.is_div,
                local.is_divu,
                local.is_rem,
                local.is_remu,
                local.is_overflow,
                local.b_msb,
                local.rem_msb,
                local.c_msb,
                local.b_neg,
                local.rem_neg,
                local.c_neg,
                local.is_real,
                local.abs_c_alu_event,
                local.abs_rem_alu_event,
            ]
            .iter()
            .for_each(|flag| builder.assert_bool(*flag));
        }

        // Receive the arguments.
        {
            // Exactly one of the opcode flags must be on.
            builder.assert_eq(
                one.clone(),
                local.is_divu + local.is_remu + local.is_div + local.is_rem,
            );

            let opcode = {
                let divu: CB::Expr = CB::F::from_canonical_u32(Opcode::DIVU as u32).into();
                let remu: CB::Expr = CB::F::from_canonical_u32(Opcode::REMU as u32).into();
                let div: CB::Expr = CB::F::from_canonical_u32(Opcode::DIV as u32).into();
                let rem: CB::Expr = CB::F::from_canonical_u32(Opcode::REM as u32).into();

                local.is_divu * divu
                    + local.is_remu * remu
                    + local.is_div * div
                    + local.is_rem * rem
            };

            builder.looked_alu(
                opcode,
                local.a,
                local.b,
                local.c,
                local.chunk,
                local.channel,
                local.nonce,
                local.is_real,
            );
        }
    }
}
