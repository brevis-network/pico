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
        chips::alu::divrem::{
            columns::{DivRemCols, DivRemValueCols},
            DivRemChip,
        },
        gadgets::{
            add::AddGadget, is_equal_word::IsEqualWordGadget, is_zero_word::IsZeroWordGadget,
            lt_word_u16::LtWordU16Gadget, msb::U16MSBGadget, mul::MulGadget,
        },
    },
    compiler::{riscv::opcode::Opcode, word::Word},
    machine::builder::{ChipBuilder, ChipLookupBuilder, ChipRangeBuilder, ChipWordBuilder},
    primitives::consts::{LONG_WORD_SIZE, WORD_SIZE},
};
use p3_air::{Air, AirBuilder};
use p3_field::{Field, FieldAlgebra};
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
        let base = CB::F::from_canonical_u32(1 << 16);
        let one: CB::Expr = CB::F::ONE.into();
        let zero: CB::Expr = CB::F::ZERO.into();

        for DivRemValueCols {
            a: local_a,
            b: local_b,
            c: local_c,
            quotient: local_quotient,
            quotient_comp: local_quotient_comp,
            remainder: local_remainder,
            remainder_comp: local_remainder_comp,
            abs_remainder: local_abs_remainder,
            abs_c: local_abs_c,
            max_abs_c_or_1: local_max_abs_c_or_1,
            c_times_quotient: local_c_times_quotient,
            carry: local_carry,
            c_times_quotient_lower: local_c_times_quotient_lower,
            c_times_quotient_upper: local_c_times_quotient_upper,
            remainder_lt_gadget: local_remainder_lt_gadget,
            c_neg_gadget: local_c_neg_operation,
            rem_neg_gadget: local_rem_neg_operation,
            is_c_0: local_is_c_0,
            is_div: local_is_div,
            is_divu: local_is_divu,
            is_rem: local_is_rem,
            is_remu: local_is_remu,
            is_divw: local_is_divw,
            is_remw: local_is_remw,
            is_divuw: local_is_divuw,
            is_remuw: local_is_remuw,
            is_overflow: local_is_overflow,
            is_overflow_b: local_is_overflow_b,
            is_overflow_c: local_is_overflow_c,
            b_msb: local_b_msb,
            rem_msb: local_rem_msb,
            c_msb: local_c_msb,
            quot_msb: local_quot_msb,
            b_neg: local_b_neg,
            b_neg_not_overflow: local_b_neg_not_overflow,
            b_not_neg_not_overflow: local_b_not_neg_not_overflow,
            rem_neg: local_rem_neg,
            c_neg: local_c_neg,
            abs_c_alu_event: local_abs_c_alu_event,
            abs_rem_alu_event: local_abs_rem_alu_event,
            is_real: local_is_real,
            is_real_not_word: local_is_real_not_word,
            remainder_check_multiplicity: local_remainder_check_multiplicity,
            ..
        } in local.values
        {
            let is_word_operation = local_is_divw + local_is_remw + local_is_divuw + local_is_remuw;
            let is_unsigned_word_operation = local_is_divuw + local_is_remuw;
            let is_signed_word_operation = local_is_divw + local_is_remw;
            let is_not_word_operation = one.clone() - is_word_operation.clone();
            // Negative if and only if op code is signed & MSB = 1.
            let is_signed_type = local_is_div + local_is_rem + local_is_divw + local_is_remw;

            // Constraint: is_real_not_word = is_real * (1 - is_word_operation)
            builder.assert_eq(
                local_is_real_not_word,
                local_is_real * (one.clone() - is_word_operation.clone()),
            );

            // Calculate whether b, remainder, and c are negative.
            {
                let msb_sign_pairs = [
                    (local_b_msb.msb, local_b_neg),
                    (local_rem_msb.msb, local_rem_neg),
                    (local_c_msb.msb, local_c_neg),
                ];

                for msb_sign_pair in msb_sign_pairs.iter() {
                    let msb = msb_sign_pair.0;
                    let is_negative = msb_sign_pair.1;
                    builder.assert_eq(msb * is_signed_type.clone(), is_negative);
                }
            }

            // For word operations, constrain the upper limbs of b and c to be proper sign/zero
            // extension. Without b's constraint, a prover can pick a large quotient q such that
            // c×q overflows into b[2]/b[3], satisfying c×q+r=b with an incorrect quotient.
            // Without c's constraint, a prover can set c[2]!=0 while c[0]=c[1]=0, making
            // is_c_0 false while the actual 32-bit divisor is zero, bypassing div-by-zero.
            for i in WORD_SIZE / 2..WORD_SIZE {
                builder.when(is_word_operation.clone()).assert_eq(
                    local_b[i],
                    local_b_neg * CB::F::from_canonical_u16(u16::MAX),
                );
                builder.when(is_word_operation.clone()).assert_eq(
                    local_c[i],
                    local_c_neg * CB::F::from_canonical_u16(u16::MAX),
                );
            }

            // Set up `quotient_comp` and `remainder_comp`.
            // `quotient_comp` is defined as following:
            // - `quotient` for 64-bit operations and signed word operations.
            // - for signed operations, this is the 32-bit result sign-extended to 64 bits.
            // - `quotient` but truncated to 32-bit for unsigned word operations.
            {
                for i in 0..WORD_SIZE / 2 {
                    builder.assert_eq(local_quotient_comp[i], local_quotient[i]);
                }

                for i in WORD_SIZE / 2..WORD_SIZE {
                    builder
                        .when(is_unsigned_word_operation.clone())
                        .assert_eq(local_quotient_comp[i], zero.clone());
                    builder.when(is_signed_word_operation.clone()).assert_eq(
                        local_quotient_comp[i],
                        local_quot_msb.msb * CB::F::from_canonical_u16(u16::MAX),
                    );
                    builder.when(is_word_operation.clone()).assert_eq(
                        local_quotient[i],
                        local_quot_msb.msb * CB::F::from_canonical_u16(u16::MAX),
                    );
                    builder
                        .when(is_not_word_operation.clone())
                        .assert_eq(local_quotient_comp[i], local_quotient[i]);
                }

                // `remainder_comp` is defined as following:
                // - `remainder` for 64-bit operations and signed word operations.
                // - for signed operations, this is the 32-bit result sign-extended to 64 bits.
                // - `remainder_comp` but truncated to 32-bit for unsigned word operations.
                for i in 0..WORD_SIZE / 2 {
                    builder.assert_eq(local_remainder_comp[i], local_remainder[i]);
                }

                for i in WORD_SIZE / 2..WORD_SIZE {
                    builder
                        .when(is_unsigned_word_operation.clone())
                        .assert_eq(local_remainder_comp[i], zero.clone());
                    builder.when(is_signed_word_operation.clone()).assert_eq(
                        local_remainder_comp[i],
                        local_rem_msb.msb * CB::F::from_canonical_u16(u16::MAX),
                    );
                    builder.when(is_word_operation.clone()).assert_eq(
                        local_remainder[i],
                        local_rem_msb.msb * CB::F::from_canonical_u16(u16::MAX),
                    );
                    builder
                        .when(is_not_word_operation.clone())
                        .assert_eq(local_remainder_comp[i], local_remainder[i]);
                }
            }

            // Use the mul table to compute c * quotient and compare it to local.c_times_quotient.
            {
                // The lower 8 bytes of c_times_quotient are always computed by `MUL` opcode.
                MulGadget::<CB::F>::eval(
                    builder,
                    Word(local_c_times_quotient[..4].try_into().unwrap()),
                    local_quotient_comp,
                    local_c,
                    local_c_times_quotient_lower,
                    local_is_real.into(),
                    local_is_real.into(), // is_mul
                    zero.clone(),         // is_mulh
                    zero.clone(),         // is_mulw
                    zero.clone(),         // is_mulhu
                    zero.clone(),         // is_mulhsu
                );

                // SAFETY: Since exactly one flag is turned on, `is_mulh` and `is_mulhu` are correct.
                let is_mulh = local_is_div + local_is_rem;
                let is_mulhu = local_is_divu + local_is_remu;

                // The upper 8 bytes of c_times_quotient are computed by `MULH` or `MULHU` opcode.
                MulGadget::<CB::F>::eval(
                    builder,
                    Word(local_c_times_quotient[4..].try_into().unwrap()),
                    local_quotient_comp,
                    local_c,
                    local_c_times_quotient_upper,
                    local_is_real_not_word.into(),
                    zero.clone(),     // is_mul
                    is_mulh.clone(),  // is_mulh
                    zero.clone(),     // is_mulw
                    is_mulhu.clone(), // is_mulhu
                    zero.clone(),     // is_mulhsu
                );
            }

            // Calculate is_overflow. This is true if and only if `b, c` are overflow cases, and it's a
            // signed operation. The overflow cases for `b, c` are defined as
            // - For word operations, `b == -2^31` and `c == -1`.
            // - For 64-bit operations, `b == -2^63`, and `c == -1`.
            {
                // 1. For 64-bit operations (non-word): check b == i64::MIN, c == -1
                IsEqualWordGadget::<CB::F>::eval(
                    builder,
                    local_b.map(|x| x.into()),
                    Word::from(i64::MIN as u64).map(|x: CB::F| x.into()),
                    local_is_overflow_b,
                    local_is_real_not_word.into(),
                );

                IsEqualWordGadget::<CB::F>::eval(
                    builder,
                    local_c.map(|x| x.into()),
                    Word::from(-1i64 as u64).map(|x: CB::F| x.into()),
                    local_is_overflow_c,
                    local_is_real_not_word.into(),
                );

                // 2. For word operations: use truncated b/c (lower 32 bits)
                let truncated_b: Word<CB::Expr> = Word([
                    local_b[0].into(),
                    local_b[1].into(),
                    zero.clone(),
                    zero.clone(),
                ]);
                let truncated_c: Word<CB::Expr> = Word([
                    local_c[0].into(),
                    local_c[1].into(),
                    zero.clone(),
                    zero.clone(),
                ]);

                IsEqualWordGadget::<CB::F>::eval(
                    builder,
                    truncated_b,
                    Word::from(i32::MIN as u32 as u64).map(|x: CB::F| x.into()),
                    local_is_overflow_b,
                    is_word_operation.clone(),
                );

                IsEqualWordGadget::<CB::F>::eval(
                    builder,
                    truncated_c,
                    Word::from(-1i32 as u32 as u64).map(|x: CB::F| x.into()),
                    local_is_overflow_c,
                    is_word_operation.clone(),
                );

                builder.assert_eq(
                    local_is_overflow,
                    local_is_overflow_b.is_diff_zero.result
                        * local_is_overflow_c.is_diff_zero.result
                        * is_signed_type.clone(),
                );

                // Compute b_neg_not_overflow and b_not_neg_not_overflow
                builder.assert_eq(
                    local_b_neg_not_overflow,
                    local_b_neg * (one.clone() - local_is_overflow),
                );
                builder.assert_eq(
                    local_b_not_neg_not_overflow,
                    (one.clone() - local_b_neg) * (one.clone() - local_is_overflow),
                );

                // For overflow cases, explicitly constrain the result.
                // When b = -2^31 and c = -1 (overflow case), quotient = b and remainder = 0
                for i in 0..WORD_SIZE {
                    builder
                        .when(local_is_overflow)
                        .assert_eq(local_quotient[i], local_b[i]);
                    builder
                        .when(local_is_overflow)
                        .assert_eq(local_remainder[i], zero.clone());
                }
            }

            // Add remainder to product c * quotient, and compare it to b.
            {
                let sign_extension = local_rem_neg * CB::F::from_canonical_u16(u16::MAX);
                let mut c_times_quotient_plus_remainder: Vec<CB::Expr> =
                    vec![CB::F::ZERO.into(); LONG_WORD_SIZE];

                c_times_quotient_plus_remainder
                    .iter_mut()
                    .enumerate()
                    .for_each(|(i, quotient_plus_remainder_times)| {
                        // Add remainder to c_times_quotient and propagate carry.
                        {
                            *quotient_plus_remainder_times = local_c_times_quotient[i].into();

                            // Add remainder.
                            if i < WORD_SIZE {
                                *quotient_plus_remainder_times = quotient_plus_remainder_times
                                    .clone()
                                    + local_remainder_comp[i].into();
                            } else {
                                // If rem is negative, add 0xff to the upper 4 bytes.
                                *quotient_plus_remainder_times =
                                    quotient_plus_remainder_times.clone() + sign_extension.clone();
                            }

                            // Propagate carry.
                            // SAFETY: Since carry is a boolean and `c_times_quotient_plus_remainder` are u16s,
                            // the results are guaranteed to be correct by the constraints.
                            *quotient_plus_remainder_times =
                                quotient_plus_remainder_times.clone() - local_carry[i] * base;
                            if i > 0 {
                                *quotient_plus_remainder_times = quotient_plus_remainder_times
                                    .clone()
                                    + local_carry[i - 1].into();
                            }
                        }

                        // Compare c_times_quotient_plus_remainder to b by checking each limb.
                        {
                            if i < WORD_SIZE {
                                // The lower 4 bytes: when NOT overflow, must match b
                                builder
                                    .when_not(local_is_overflow)
                                    .assert_eq(local_b[i], quotient_plus_remainder_times.clone());
                            } else {
                                // The upper 4 bytes: when NOT overflow, must equal b_neg * 0xFFFF
                                builder.when_not(local_is_overflow).assert_eq(
                                    local_b_neg * CB::F::from_canonical_u16(u16::MAX),
                                    quotient_plus_remainder_times.clone(),
                                );
                            }
                        }
                    });

                builder.slice_range_check_u16(&c_times_quotient_plus_remainder, local_is_real);
            }

            // `a` must equal remainder or quotient depending on the opcode.
            for i in 0..WORD_SIZE {
                builder
                    .when(local_is_divu + local_is_div + local_is_divuw + local_is_divw)
                    .assert_eq(local_quotient[i], local_a[i]);
                builder
                    .when(local_is_remu + local_is_rem + local_is_remuw + local_is_remw)
                    .assert_eq(local_remainder[i], local_a[i]);
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
                    rem_byte_sum = rem_byte_sum.clone() + local_remainder[i].into();
                    b_byte_sum = b_byte_sum.clone() + local_b[i].into();
                }

                // 1. If remainder < 0, then b < 0.
                builder
                    .when(local_rem_neg) // rem is negative.
                    .assert_one(local_b_neg); // b is negative.

                // 2. If remainder > 0, then b >= 0.
                builder
                    .when(rem_byte_sum.clone()) // remainder is nonzero.
                    .when(one.clone() - local_rem_neg) // rem is not negative.
                    .assert_zero(local_b_neg); // b is not negative.
            }

            // When division by 0, quotient must be 0xffffffff_ffffffff = u64::MAX per RISC-V spec.
            {
                // Calculate whether c is 0.
                IsZeroWordGadget::<CB::F>::eval(
                    builder,
                    local_c.map(|x| x.into()),
                    local_is_c_0,
                    local_is_real.into(),
                );

                // If is_c_0 is true, then quotient must be 0xffffffff_ffffffff = u64::MAX.
                for i in 0..WORD_SIZE {
                    builder
                        .when(local_is_c_0.result)
                        .assert_eq(local_quotient[i], CB::F::from_canonical_u16(u16::MAX));
                }

                // If is_c_0 is true, then the remainder must be b.
                for i in 0..WORD_SIZE {
                    builder
                        .when(local_is_c_0.result)
                        .assert_eq(local_remainder_comp[i], local_b[i]);
                }
            }

            // Range check remainder. (i.e., |remainder| < |c| when not is_c_0)
            {
                // For each of `c` and `rem`, assert that the absolute value is equal to the original
                // value, if the original value is non-negative or the minimum i32.
                for i in 0..WORD_SIZE {
                    builder
                        .when_not(local_c_neg)
                        .assert_eq(local_c[i], local_abs_c[i]);
                    builder
                        .when_not(local_rem_neg)
                        .assert_eq(local_remainder[i], local_abs_remainder[i]);
                }
                // In the case that `c` or `rem` is negative, instead check that their sum is zero by
                // sending an AddEvent.
                builder.looking_alu(
                    CB::Expr::from_canonical_u32(Opcode::ADD as u32),
                    Word([zero.clone(), zero.clone(), zero.clone(), zero.clone()]),
                    local_c,
                    local_abs_c,
                    local_abs_c_alu_event,
                );
                builder.looking_alu(
                    CB::Expr::from_canonical_u32(Opcode::ADD as u32),
                    Word([zero.clone(), zero.clone(), zero.clone(), zero.clone()]),
                    local_remainder,
                    local_abs_remainder,
                    local_abs_rem_alu_event,
                );

                // max(abs(c), 1) = abs(c) * (1 - is_c_0) + 1 * is_c_0
                let max_abs_c_or_1: Word<CB::Expr> = {
                    let mut v = vec![zero.clone(); WORD_SIZE];

                    // Set the least significant byte to 1 if is_c_0 is true.
                    v[0] = local_is_c_0.result * one.clone()
                        + (one.clone() - local_is_c_0.result) * local_abs_c[0];

                    // Set the remaining bytes to 0 if is_c_0 is true.
                    for i in 1..WORD_SIZE {
                        v[i] = (one.clone() - local_is_c_0.result) * local_abs_c[i];
                    }
                    Word(v.try_into().unwrap_or_else(|_| panic!("Incorrect length")))
                };
                for i in 0..WORD_SIZE {
                    builder.assert_eq(local_max_abs_c_or_1[i], max_abs_c_or_1[i].clone());
                }

                // Handle cases:
                // - If is_real == 0 then remainder_check_multiplicity == 0 is forced.
                // - If is_real == 1 then is_c_0_result must be the expected one, so
                //   remainder_check_multiplicity = (1 - is_c_0_result) * is_real.
                builder.assert_eq(
                    (CB::Expr::ONE - local_is_c_0.result) * local_is_real,
                    local_remainder_check_multiplicity,
                );

                // the cleaner idea is simply remainder_check_multiplicity == (1 - is_c_0_result) *
                // is_real

                // Check that the absolute value selector columns are computed correctly.
                builder.assert_eq(local_abs_c_alu_event, local_c_neg * local_is_real);
                builder.assert_eq(local_abs_rem_alu_event, local_rem_neg * local_is_real);

                // Evaluate c_neg_operation to compute absolute value of c.
                // When c is negative, we verify c + abs_c = 0. When c is positive, c = abs_c.
                AddGadget::<CB::F>::eval(
                    builder,
                    local_c,
                    local_abs_c,
                    local_c_neg_operation,
                    local_abs_c_alu_event.into(),
                );
                builder.slice_range_check_u16(&local_abs_c.0, local_is_real);

                // Evaluate rem_neg_operation to compute absolute value of remainder.
                // When remainder is negative, we verify remainder + abs_remainder = 0.
                AddGadget::<CB::F>::eval(
                    builder,
                    local_remainder_comp,
                    local_abs_remainder,
                    local_rem_neg_operation,
                    local_abs_rem_alu_event.into(),
                );
                builder.slice_range_check_u16(&local_abs_remainder.0, local_is_real);

                // When c is negative, the result of c_neg_operation should be 0.
                builder.when(local_abs_c_alu_event).assert_word_eq(
                    Word([zero.clone(), zero.clone(), zero.clone(), zero.clone()]),
                    local_c_neg_operation.value,
                );

                // When remainder is negative, the result of rem_neg_operation should be 0.
                builder.when(local_abs_rem_alu_event).assert_word_eq(
                    Word([zero.clone(), zero.clone(), zero.clone(), zero.clone()]),
                    local_rem_neg_operation.value,
                );

                // Dispatch abs(remainder) < max(abs(c), 1), this is equivalent to abs(remainder) <
                // abs(c) if not division by 0.
                LtWordU16Gadget::<CB::F>::eval(
                    builder,
                    local_abs_remainder.map(|v| v.into()),
                    local_max_abs_c_or_1.map(|v| v.into()),
                    local_remainder_lt_gadget,
                    local_remainder_check_multiplicity.into(),
                );
                // Enforce that the LT relation actually holds (bit = 1 means a < b).
                // Without this, a prover could set bit = 0 and claim remainder >= divisor.
                builder
                    .when(local_remainder_check_multiplicity)
                    .assert_one(local_remainder_lt_gadget.bit);
            }

            // Check that the MSBs are correct.
            {
                // If not word operation, we check the last limb.
                let msb_pairs_not_word = [
                    (local_b_msb, local_b[WORD_SIZE - 1].into()),
                    (local_c_msb, local_c[WORD_SIZE - 1].into()),
                    (local_rem_msb, local_remainder[WORD_SIZE - 1].into()),
                ];
                for msb_pair in msb_pairs_not_word.iter() {
                    let (msb, byte) = msb_pair;
                    U16MSBGadget::<CB::F>::eval(
                        builder,
                        byte.clone(),
                        *msb,
                        local_is_real_not_word.into(),
                    );
                }

                // If word operation, we check the second limb.
                let msb_pairs_word = [
                    (local_b_msb, local_b[WORD_SIZE / 2 - 1].into()),
                    (local_c_msb, local_c[WORD_SIZE / 2 - 1].into()),
                    (local_rem_msb, local_remainder[WORD_SIZE / 2 - 1].into()),
                    (local_quot_msb, local_quotient[WORD_SIZE / 2 - 1].into()),
                ];
                for msb_pair in msb_pairs_word.iter() {
                    let (msb, byte) = msb_pair;
                    U16MSBGadget::<CB::F>::eval(
                        builder,
                        byte.clone(),
                        *msb,
                        is_word_operation.clone(),
                    );
                }
            }

            // Range check all the u16 limbs and boolean carries.
            {
                builder.slice_range_check_u16(&local_quotient.0, local_is_real);
                builder.slice_range_check_u16(&local_remainder.0, local_is_real);

                local_carry.iter().for_each(|carry| {
                    builder.assert_bool(*carry);
                });

                builder.slice_range_check_u16(&local_c_times_quotient, local_is_real);
            }

            // Check that the flags are boolean.
            {
                [
                    local_is_div,
                    local_is_divu,
                    local_is_rem,
                    local_is_remu,
                    local_is_divw,
                    local_is_remw,
                    local_is_divuw,
                    local_is_remuw,
                    local_is_overflow,
                    local_is_real_not_word,
                    local_b_neg,
                    local_b_neg_not_overflow,
                    local_b_not_neg_not_overflow,
                    local_rem_neg,
                    local_c_neg,
                    local_is_real,
                    local_abs_c_alu_event,
                    local_abs_rem_alu_event,
                ]
                .iter()
                .for_each(|flag| builder.assert_bool(*flag));
            }

            // Receive the arguments.
            {
                // Exactly one of the opcode flags must be on.
                builder.assert_eq(
                    one.clone(),
                    local_is_divu
                        + local_is_remu
                        + local_is_div
                        + local_is_rem
                        + local_is_divw
                        + local_is_remw
                        + local_is_divuw
                        + local_is_remuw,
                );

                let opcode = {
                    let divu: CB::Expr = CB::F::from_canonical_u32(Opcode::DIVU as u32).into();
                    let remu: CB::Expr = CB::F::from_canonical_u32(Opcode::REMU as u32).into();
                    let div: CB::Expr = CB::F::from_canonical_u32(Opcode::DIV as u32).into();
                    let rem: CB::Expr = CB::F::from_canonical_u32(Opcode::REM as u32).into();
                    let divw: CB::Expr = CB::F::from_canonical_u32(Opcode::DIVW as u32).into();
                    let remw: CB::Expr = CB::F::from_canonical_u32(Opcode::REMW as u32).into();
                    let divuw: CB::Expr = CB::F::from_canonical_u32(Opcode::DIVUW as u32).into();
                    let remuw: CB::Expr = CB::F::from_canonical_u32(Opcode::REMUW as u32).into();

                    local_is_divu * divu
                        + local_is_remu * remu
                        + local_is_div * div
                        + local_is_rem * rem
                        + local_is_divw * divw
                        + local_is_remw * remw
                        + local_is_divuw * divuw
                        + local_is_remuw * remuw
                };

                builder.looked_alu(opcode, local_a, local_b, local_c, local_is_real);
            }
        }
    }
}
