use std::borrow::Borrow;

use super::{columns::ShiftLeftCols, traces::SLLChip, ShiftLeftValueCols};
use crate::{
    chips::gadgets::msb::U16MSBGadget,
    compiler::riscv::opcode::{ByteOpcode, Opcode},
    machine::builder::{ChipBuilder, ChipLookupBuilder},
    primitives::consts::WORD_SIZE,
};
use p3_air::{Air, AirBuilder};
use p3_field::{Field, FieldAlgebra};
use p3_matrix::Matrix;

impl<F: Field, CB> Air<CB> for SLLChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &ShiftLeftCols<CB::Var> = (*local).borrow();

        let zero: CB::Expr = CB::F::ZERO.into();

        for ShiftLeftValueCols {
            a,
            b,
            c,
            c_bits,
            v_01,
            v_012,
            v_0123,
            shift_u16,
            lower_limb,
            higher_limb,
            limb_result,
            sllw_msb,
            is_sll,
            is_sllw,
        } in local.values
        {
            let is_real = is_sll + is_sllw;
            builder.assert_bool(is_real.clone());
            builder.assert_bool(is_sll);
            builder.assert_bool(is_sllw);

            for i in 0..6 {
                builder.assert_bool(c_bits[i]);
            }

            let mut c_lower_bits = zero.clone();
            let mut bit_shift = zero.clone();
            for i in 0..6 {
                c_lower_bits += c_bits[i] * CB::F::from_canonical_u32(1 << i);
                if i == 3 {
                    bit_shift = c_lower_bits.clone();
                }
            }
            let inverse_64 = CB::F::from_canonical_u32(64).inverse();
            builder.looking_byte(
                CB::F::from_canonical_u32(ByteOpcode::BitRange as u32),
                (c[0] - c_lower_bits) * inverse_64,
                CB::F::from_canonical_u32(10),
                zero.clone(),
                is_real.clone(),
            );

            let not_sllw = is_sll;
            for i in 0..4 {
                builder.when(shift_u16[i]).assert_eq(
                    c_bits[4] + c_bits[5] * CB::F::from_canonical_u32(2) * not_sllw,
                    CB::F::from_canonical_u32(i as u32),
                );
                builder.assert_bool(shift_u16[i]);
            }
            builder.when(is_real.clone()).assert_eq(
                shift_u16[0] + shift_u16[1] + shift_u16[2] + shift_u16[3],
                CB::F::from_canonical_u32(1),
            );

            let one = CB::F::from_canonical_u32(1);
            let three = CB::F::from_canonical_u32(3);
            let fifteen = CB::F::from_canonical_u32(15);
            let two_fifty_five = CB::F::from_canonical_u32(255);
            builder.assert_eq(v_01, (c_bits[0] + one) * (c_bits[1] * three + one));
            builder.assert_eq(v_012, v_01 * (c_bits[2] * fifteen + one));
            builder.assert_eq(v_0123, v_012 * (c_bits[3] * two_fifty_five + one));

            for i in 0..WORD_SIZE {
                let limb = b[i];
                // Check that `lower_limb < 2^(16 - bit_shift)`
                builder.looking_byte(
                    CB::F::from_canonical_u32(ByteOpcode::BitRange as u32),
                    lower_limb[i],
                    CB::Expr::from_canonical_u32(16) - bit_shift.clone(),
                    zero.clone(),
                    is_real.clone(),
                );
                // Check that `higher_limb < 2^(bit_shift)`
                builder.looking_byte(
                    CB::F::from_canonical_u32(ByteOpcode::BitRange as u32),
                    higher_limb[i],
                    bit_shift.clone(),
                    zero.clone(),
                    is_real.clone(),
                );
                // Check that `limb == higher_limb * 2^(16 - bit_shift) + lower_limb`
                // Multiply `2^(bit_shift)` to the equation to avoid populating `2^(16 - bit_shift)`.
                // This is possible, since `2^(bit_shift)` is not zero.
                builder.assert_eq(
                    limb * v_0123,
                    higher_limb[i] * CB::F::from_canonical_u32(1 << 16) + lower_limb[i] * v_0123,
                );
            }

            // Compute the limb result based on the lower limbs and higher limbs.
            for i in 0..WORD_SIZE {
                let mut tmp_limb_result = lower_limb[i] * v_0123;
                if i != 0 {
                    tmp_limb_result = tmp_limb_result.clone() + higher_limb[i - 1];
                }
                builder.assert_eq(limb_result[i], tmp_limb_result);
            }

            // Perform the limb shifts based on `shift_u16` boolean flags.
            for i in 0..WORD_SIZE {
                for j in 0..WORD_SIZE {
                    if j < i {
                        builder.when(is_sll).when(shift_u16[i]).assert_zero(a[j]);
                    } else {
                        builder
                            .when(is_sll)
                            .when(shift_u16[i])
                            .assert_eq(a[j], limb_result[j - i]);
                    }
                }
            }

            for i in 0..WORD_SIZE / 2 {
                for j in 0..WORD_SIZE / 2 {
                    if j < i {
                        builder.when(is_sllw).when(shift_u16[i]).assert_zero(a[j]);
                    } else {
                        builder
                            .when(is_sllw)
                            .when(shift_u16[i])
                            .assert_eq(a[j], limb_result[j - i]);
                    }
                }
            }
            let u16_max = CB::F::from_canonical_u16(u16::MAX);
            for i in WORD_SIZE / 2..WORD_SIZE {
                builder
                    .when(is_sllw)
                    .assert_eq(sllw_msb.msb * u16_max, a[i]);
            }

            U16MSBGadget::<CB::F>::eval(builder, a[1].into(), sllw_msb, is_sllw.into());

            let opcode = is_sll * CB::F::from_canonical_u32(Opcode::SLL as u32)
                + is_sllw * CB::F::from_canonical_u32(Opcode::SLLW as u32);

            builder.looked_alu(opcode, a, b, c, is_real);
        }
    }
}
