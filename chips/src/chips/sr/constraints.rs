use super::{
    columns::{ShiftRightCols, LONG_WORD_SIZE},
    trace::ShiftRightChip,
};
use p3_air::{Air, AirBuilder};
use p3_field::Field;
use p3_matrix::Matrix;
use pico_compiler::{
    opcode::{ByteOpcode, Opcode},
    word::{BYTE_SIZE, WORD_SIZE},
};
use pico_machine::builder::{ChipBuilder, ChipLookupBuilder, ChipRangeBuilder};
use std::borrow::Borrow;

impl<F: Field, CB> Air<CB> for ShiftRightChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &ShiftRightCols<CB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &ShiftRightCols<CB::Var> = (*next).borrow();
        let zero: CB::Expr = CB::F::zero().into();
        let one: CB::Expr = CB::F::one().into();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder
            .when_transition()
            .assert_eq(local.nonce + one.clone(), next.nonce);

        // Check that the MSB of most_significant_byte matches local.b_msb using lookup.
        {
            let byte = local.b[WORD_SIZE - 1];
            let opcode = CB::F::from_canonical_u32(ByteOpcode::MSB as u32);
            let msb = local.b_msb;
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

        // Calculate the number of bits and bytes to shift by from c.
        {
            // The sum of c_least_sig_byte[i] * 2^i must match c[0].
            let mut c_byte_sum = zero.clone();
            for i in 0..BYTE_SIZE {
                let val: CB::Expr = CB::F::from_canonical_u32(1 << i).into();
                c_byte_sum += val * local.c_least_sig_byte[i];
            }
            builder.assert_eq(c_byte_sum, local.c[0]);

            // Number of bits to shift.

            // The 3-bit number represented by the 3 least significant bits of c equals the number
            // of bits to shift.
            let mut num_bits_to_shift = zero.clone();
            for i in 0..3 {
                num_bits_to_shift += local.c_least_sig_byte[i] * CB::F::from_canonical_u32(1 << i);
            }
            for i in 0..BYTE_SIZE {
                builder
                    .when(local.shift_by_n_bits[i])
                    .assert_eq(num_bits_to_shift.clone(), CB::F::from_canonical_usize(i));
            }

            // Exactly one of the shift_by_n_bits must be 1.
            builder.assert_eq(
                local
                    .shift_by_n_bits
                    .iter()
                    .fold(zero.clone(), |acc, &x| acc + x),
                one.clone(),
            );

            // The 2-bit number represented by the 3rd and 4th least significant bits of c is the
            // number of bytes to shift.
            let num_bytes_to_shift = local.c_least_sig_byte[3]
                + local.c_least_sig_byte[4] * CB::F::from_canonical_u32(2);

            // If shift_by_n_bytes[i] = 1, then i = num_bytes_to_shift.
            for i in 0..WORD_SIZE {
                builder
                    .when(local.shift_by_n_bytes[i])
                    .assert_eq(num_bytes_to_shift.clone(), CB::F::from_canonical_usize(i));
            }

            // Exactly one of the shift_by_n_bytes must be 1.
            builder.assert_eq(
                local
                    .shift_by_n_bytes
                    .iter()
                    .fold(zero.clone(), |acc, &x| acc + x),
                one.clone(),
            );
        }

        // Byte shift the sign-extended b.
        {
            // The leading bytes of b should be 0xff if b's MSB is 1 & opcode = SRA, 0 otherwise.
            let leading_byte = local.is_sra * local.b_msb * F::from_canonical_u8(0xff);
            let mut sign_extended_b: Vec<CB::Expr> = vec![];
            for i in 0..WORD_SIZE {
                sign_extended_b.push(local.b[i].into());
            }
            for _ in 0..WORD_SIZE {
                sign_extended_b.push(leading_byte.clone());
            }

            // Shift the bytes of sign_extended_b by num_bytes_to_shift.
            for num_bytes_to_shift in 0..WORD_SIZE {
                for i in 0..(LONG_WORD_SIZE - num_bytes_to_shift) {
                    builder
                        .when(local.shift_by_n_bytes[num_bytes_to_shift])
                        .assert_eq(
                            local.byte_shift_result[i],
                            sign_extended_b[i + num_bytes_to_shift].clone(),
                        );
                }
            }
        }

        // Bit shift the byte_shift_result using ShrCarry, and compare the result to a.
        {
            // The carry multiplier is 2^(8 - num_bits_to_shift).
            let mut carry_multiplier = zero.clone();
            for i in 0..BYTE_SIZE {
                let val: CB::Expr = F::from_canonical_u32(1u32 << (8 - i)).into();

                carry_multiplier += val * local.shift_by_n_bits[i];
            }

            // The 3-bit number represented by the 3 least significant bits of c equals the number
            // of bits to shift.
            let mut num_bits_to_shift = zero.clone();
            for i in 0..3 {
                num_bits_to_shift += local.c_least_sig_byte[i] * CB::F::from_canonical_u32(1 << i);
            }

            // Calculate ShrCarry.
            for i in (0..LONG_WORD_SIZE).rev() {
                builder.looking_byte_pair(
                    CB::F::from_canonical_u32(ByteOpcode::ShrCarry as u32),
                    local.shr_carry_output_shifted_byte[i],
                    local.shr_carry_output_carry[i],
                    local.byte_shift_result[i],
                    num_bits_to_shift.clone(),
                    local.chunk,
                    local.channel,
                    local.is_real,
                );
            }

            // Use the results of ShrCarry to calculate the bit shift result.
            for i in (0..LONG_WORD_SIZE).rev() {
                let mut v: CB::Expr = local.shr_carry_output_shifted_byte[i].into();
                if i + 1 < LONG_WORD_SIZE {
                    v += local.shr_carry_output_carry[i + 1] * carry_multiplier.clone();
                }
                builder.assert_eq(v, local.bit_shift_result[i]);
            }
        }

        // The 4 least significant bytes must match a. The 4 most significant bytes of result may be
        // inaccurate.
        {
            for i in 0..WORD_SIZE {
                builder.assert_eq(local.a[i], local.bit_shift_result[i]);
            }
        }

        // Check that the flags are indeed boolean.
        {
            let flags = [local.is_srl, local.is_sra, local.is_real, local.b_msb];
            for flag in flags.iter() {
                builder.assert_bool(*flag);
            }
            for shift_by_n_byte in local.shift_by_n_bytes.iter() {
                builder.assert_bool(*shift_by_n_byte);
            }
            for shift_by_n_bit in local.shift_by_n_bits.iter() {
                builder.assert_bool(*shift_by_n_bit);
            }
            for bit in local.c_least_sig_byte.iter() {
                builder.assert_bool(*bit);
            }
        }

        let long_words = [
            local.byte_shift_result,
            local.bit_shift_result,
            local.shr_carry_output_carry,
            local.shr_carry_output_shifted_byte,
        ];

        for long_word in long_words.iter() {
            builder.slice_range_check_u8(long_word, local.chunk, local.channel, local.is_real);
        }

        // Check that the operation flags are boolean.
        builder.assert_bool(local.is_srl);
        builder.assert_bool(local.is_sra);
        builder.assert_bool(local.is_real);

        // Check that is_real is the sum of the two operation flags.
        builder.assert_eq(local.is_srl + local.is_sra, local.is_real);

        // Receive the arguments.
        builder.looked_alu(
            local.is_srl * CB::F::from_canonical_u32(Opcode::SRL as u32)
                + local.is_sra * CB::F::from_canonical_u32(Opcode::SRA as u32),
            local.a,
            local.b,
            local.c,
            local.chunk,
            local.channel,
            F::zero(),
            local.is_real,
        );
    }
}
