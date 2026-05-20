#![allow(clippy::assign_op_pattern)]

use super::{columns::ShiftRightCols, traces::ShiftRightChip};
use crate::{
    chips::{chips::alu::sr::columns::ShiftRightValueCols, gadgets::msb::U16MSBGadget},
    compiler::riscv::opcode::{ByteOpcode, Opcode},
    machine::builder::{ChipBuilder, ChipLookupBuilder},
    primitives::consts::WORD_SIZE,
};
use p3_air::{Air, AirBuilder};
use p3_field::Field;
use p3_matrix::Matrix;
use std::borrow::Borrow;

impl<F: Field, CB> Air<CB> for ShiftRightChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &ShiftRightCols<CB::Var> = (*local).borrow();
        let zero: CB::Expr = CB::F::ZERO.into();
        let one: CB::Expr = CB::F::ONE.into();

        for ShiftRightValueCols {
            a,
            b,
            c_for_lookup,
            b_msb,
            srw_msb,
            c_bits,
            c,
            sra_msb_v0123,
            v_0123,
            v_012,
            v_01,
            lower_limb,
            higher_limb,
            limb_result,
            shift_u16,
            is_srl,
            is_sra,
            is_srlw,
            is_sraw,
            is_w_imm,
            imm_c,
        } in local.values
        {
            // Compute is_real from the opcode flags
            // Note: Var types implement Copy, so .clone() is unnecessary
            let is_real = is_srl + is_sra + is_srlw + is_sraw;

            // Check that the operation flags are boolean (Var types - no clone needed)
            builder.assert_bool(is_srl);
            builder.assert_bool(is_sra);
            builder.assert_bool(is_srlw);
            builder.assert_bool(is_sraw);
            builder.assert_bool(imm_c);

            let is_word = is_srlw + is_sraw;
            let not_word = is_srl + is_sra;

            // Constrain is_w_imm = (is_srlw + is_sraw) * imm_c
            builder.assert_eq(is_w_imm, is_word.clone() * imm_c);

            // Check that c_bits are the 6 lowest bits of c (Var types - no clone needed)
            for i in 0..6 {
                builder.assert_bool(c_bits[i]);
            }
            let mut c_lower_bits = zero.clone();
            let mut bit_shift = zero.clone();
            for i in 0..6 {
                c_lower_bits = c_lower_bits + c_bits[i] * CB::F::from_canonical_u32(1 << i);
                if i == 3 {
                    bit_shift = c_lower_bits.clone();
                }
            }

            // Check that bits 6-15 of c are zero
            let inverse_64: CB::Expr = CB::F::from_canonical_u32(64).inverse().into();
            builder.looking_byte(
                CB::F::from_canonical_u32(ByteOpcode::BitRange as u32),
                (c - c_lower_bits) * inverse_64,
                CB::F::from_canonical_u32(10),
                zero.clone(),
                is_real.clone(),
            );

            // Check v_01, v_012, v_0123 constraints
            let two = CB::F::from_canonical_u32(2);
            let three = CB::F::from_canonical_u32(3);
            let fifteen = CB::F::from_canonical_u32(15);
            let two_fifty_five = CB::F::from_canonical_u32(255);

            builder.assert_eq(
                v_01,
                (((one.clone() - c_bits[0]) + one.clone()) * two)
                    * ((one.clone() - c_bits[1]) * three + one.clone()),
            );
            builder.assert_eq(
                v_012,
                v_01 * ((one.clone() - c_bits[2]) * fifteen + one.clone()),
            );
            builder.assert_eq(
                v_0123,
                v_012 * ((one.clone() - c_bits[3]) * two_fifty_five + one.clone()),
            );

            // Check shift_u16 constraints (Var types - no clone needed)
            for i in 0..4 {
                builder.when(shift_u16[i]).assert_eq(
                    c_bits[4] + c_bits[5] * CB::F::from_canonical_u32(2) * not_word.clone(),
                    CB::F::from_canonical_u32(i as u32),
                );
                builder.assert_bool(shift_u16[i]);
            }
            builder.when(is_real.clone()).assert_eq(
                shift_u16[0] + shift_u16[1] + shift_u16[2] + shift_u16[3],
                one.clone(),
            );

            // Check that lower_limb < 2^bit_shift and higher_limb < 2^(16 - bit_shift)
            let sixteen: CB::Expr = CB::F::from_canonical_u32(16).into();
            for i in 0..WORD_SIZE {
                builder.looking_byte(
                    CB::F::from_canonical_u32(ByteOpcode::BitRange as u32),
                    lower_limb[i],
                    bit_shift.clone(),
                    zero.clone(),
                    is_real.clone(),
                );
                builder.looking_byte(
                    CB::F::from_canonical_u32(ByteOpcode::BitRange as u32),
                    higher_limb[i],
                    sixteen.clone() - bit_shift.clone(),
                    zero.clone(),
                    is_real.clone(),
                );
            }

            // Check limb_result = higher_limb + lower_limb[i+1] * v_0123
            for i in 0..WORD_SIZE {
                let mut limb_res: CB::Expr = higher_limb[i].into();
                if i != WORD_SIZE - 1 {
                    limb_res = limb_res + lower_limb[i + 1] * v_0123;
                }
                builder.assert_eq(limb_result[i], limb_res);
            }

            // Check U16MSB for b_msb (only for SRA/SRAW operations)
            U16MSBGadget::eval(builder, b.0[3].into(), b_msb, is_sra.into());
            U16MSBGadget::eval(builder, b.0[1].into(), b_msb, is_sraw.into());

            builder.when(is_srl + is_srlw).assert_zero(b_msb.msb);
            builder.assert_eq(sra_msb_v0123, b_msb.msb * v_0123);

            // Check U16MSB for srw_msb (only for word operations)
            U16MSBGadget::eval(builder, a.0[1].into(), srw_msb, is_word.clone());
            builder.when(not_word.clone()).assert_zero(srw_msb.msb);

            let base = CB::F::from_canonical_u32(1 << 16);
            let base_minus_one = CB::F::from_canonical_u16(u16::MAX);

            // Constrain the final result based on shift amount
            // For 64-bit operations (SRL/SRA)
            for i in 0..WORD_SIZE {
                for j in 0..(WORD_SIZE - 1 - i) {
                    builder
                        .when(not_word.clone())
                        .when(shift_u16[i])
                        .assert_eq(a[j], limb_result[i + j]);
                }

                builder.when(not_word.clone()).when(shift_u16[i]).assert_eq(
                    a[WORD_SIZE - 1 - i],
                    limb_result[WORD_SIZE - 1] + (b_msb.msb * base - sra_msb_v0123),
                );

                for j in (WORD_SIZE - i)..WORD_SIZE {
                    builder
                        .when(not_word.clone())
                        .when(shift_u16[i])
                        .assert_eq(a[j], b_msb.msb * base_minus_one);
                }
            }

            // Constrain 32-bit operations (SRLW/SRAW): a[0] and a[1]
            let half = WORD_SIZE / 2;
            for i in 0..half {
                for j in 0..(half - 1 - i) {
                    builder
                        .when(is_word.clone())
                        .when(shift_u16[i])
                        .assert_eq(a[j], limb_result[i + j]);
                }

                builder.when(is_word.clone()).when(shift_u16[i]).assert_eq(
                    a[half - 1 - i],
                    higher_limb[half - 1] + (b_msb.msb * base - sra_msb_v0123),
                );

                for j in (half - i)..half {
                    builder
                        .when(is_word.clone())
                        .when(shift_u16[i])
                        .assert_eq(a[j], b_msb.msb * base_minus_one);
                }
            }

            // For word operations, the upper bits should be sign-extended
            for i in WORD_SIZE / 2..WORD_SIZE {
                builder
                    .when(is_word.clone())
                    .assert_eq(a[i], srw_msb.msb * base_minus_one);
            }

            // Receive the arguments via ALU lookup
            builder.looked_alu(
                is_srl * CB::F::from_canonical_u32(Opcode::SRL as u32)
                    + is_sra * CB::F::from_canonical_u32(Opcode::SRA as u32)
                    + is_srlw * CB::F::from_canonical_u32(Opcode::SRLW as u32)
                    + is_sraw * CB::F::from_canonical_u32(Opcode::SRAW as u32),
                a,
                b,
                c_for_lookup,
                is_real,
            );
        }
    }
}
