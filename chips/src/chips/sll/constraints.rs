use std::{borrow::Borrow, iter::once};

use p3_air::{Air, AirBuilder};
use p3_field::Field;
use p3_matrix::Matrix;
use pico_compiler::{
    opcode::Opcode,
    word::{Word, BYTE_SIZE, WORD_SIZE},
};
use pico_machine::{
    builder::ChipBuilder,
    lookup::{LookupType, SymbolicLookup},
};

use super::{columns::ShiftLeftCols, traces::SLLChip};

impl<F: Field, CB> Air<CB> for SLLChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &ShiftLeftCols<CB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &ShiftLeftCols<CB::Var> = (*next).borrow();

        let zero: CB::Expr = CB::F::zero().into();
        let one: CB::Expr = CB::F::one().into();
        let base: CB::Expr = CB::F::from_canonical_u32(1 << BYTE_SIZE).into();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder
            .when_transition()
            .assert_eq(local.nonce + one.clone(), next.nonce);

        // Check the sum of c_lsb[i] * 2^i equals c[0].
        let mut c_byte_sum = zero.clone();
        for i in 0..BYTE_SIZE {
            let val: CB::Expr = F::from_canonical_u32(1 << i).into();
            c_byte_sum += val * local.c_lsb[i];
        }
        builder.assert_eq(c_byte_sum, local.c[0]);

        // Check shift_by_n_bits[i] is 1 if i = num_bits_to_shift.
        let mut num_bits_to_shift = zero.clone();

        //  num_bits_to_shift = event.c as usize % BYTE_SIZE, so the maximum value of num_bits_to_shift is 7, just neeed 3 bits to calculate this.
        for i in 0..3 {
            num_bits_to_shift += local.c_lsb[i] * F::from_canonical_u32(1 << i);
        }
        // check num_bits_to_shift i'th is 1
        for i in 0..BYTE_SIZE {
            builder
                .when(local.shift_by_n_bits[i])
                .assert_eq(num_bits_to_shift.clone(), F::from_canonical_usize(i));
        }

        // Check bit_shift_multiplier = 2^num_bits_to_shift by using shift_by_n_bits.
        for i in 0..BYTE_SIZE {
            builder
                .when(local.shift_by_n_bits[i])
                .assert_eq(local.bit_shift_multiplier, F::from_canonical_usize(1 << i));
        }

        // Check bit_shift_result = b * bit_shift_multiplier by using bit_shift_result_carry to
        // carry-propagate.
        for i in 0..WORD_SIZE {
            let mut v = local.b[i] * local.bit_shift_multiplier
                - local.shift_result_carry[i] * base.clone();
            if i > 0 {
                v += local.shift_result_carry[i - 1].into();
            }
            builder.assert_eq(local.shift_result[i], v);
        }

        //  num_bytes_to_shift = (event.c & 0b11111) as usize / BYTE_SIZE; use the c_lsb 4th and 5th presents the byte shift number
        let num_bytes_to_shift = local.c_lsb[3] + local.c_lsb[4] * F::from_canonical_u32(2);

        // Verify that shift_by_n_bytes[i] = 1 if and only if i = num_bytes_to_shift.
        for i in 0..WORD_SIZE {
            builder
                .when(local.shift_by_n_bytes[i])
                .assert_eq(num_bytes_to_shift.clone(), F::from_canonical_usize(i));
        }

        // The bytes of a must match those of bit_shift_result, taking into account the byte
        // shifting.
        for shift_size in 0..WORD_SIZE {
            let mut shifting = builder.when(local.shift_by_n_bytes[shift_size]);
            for i in 0..WORD_SIZE {
                if i < shift_size {
                    // The first num_bytes_to_shift bytes must be zero.
                    shifting.assert_eq(local.a[i], zero.clone());
                } else {
                    shifting.assert_eq(local.a[i], local.shift_result[i - shift_size]);
                }
            }
        }

        for bit in local.c_lsb.iter() {
            builder.assert_bool(*bit);
        }

        for shift in local.shift_by_n_bits.iter() {
            builder.assert_bool(*shift);
        }
        builder.assert_eq(
            local
                .shift_by_n_bits
                .iter()
                .fold(zero.clone(), |acc, &x| acc + x),
            one.clone(),
        );

        for shift in local.shift_by_n_bytes.iter() {
            builder.assert_bool(*shift);
        }

        builder.assert_eq(
            local
                .shift_by_n_bytes
                .iter()
                .fold(zero.clone(), |acc, &x| acc + x),
            one.clone(),
        );

        builder.assert_bool(local.is_real);

        // range check
        builder.slice_range_check_u8(
            &local.shift_result,
            local.chunk,
            local.channel,
            local.is_real,
        );
        builder.slice_range_check_u8(
            &local.shift_result_carry,
            local.chunk,
            local.channel,
            local.is_real,
        );

        self.looked_sll(
            builder,
            F::from_canonical_u32(Opcode::SLL as u32),
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

#[allow(clippy::too_many_arguments)]
impl<F: Field> SLLChip<F> {
    pub fn looked_sll<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        opcode: impl Into<CB::Expr>,
        a: Word<impl Into<CB::Expr>>,
        b: Word<impl Into<CB::Expr>>,
        c: Word<impl Into<CB::Expr>>,
        chunk: impl Into<CB::Expr>,
        channel: impl Into<CB::Expr>,
        nonce: impl Into<CB::Expr>,
        multiplicity: impl Into<CB::Expr>,
    ) {
        let values = once(opcode.into())
            .chain(a.0.into_iter().map(Into::into))
            .chain(b.0.into_iter().map(Into::into))
            .chain(c.0.into_iter().map(Into::into))
            .chain(once(chunk.into()))
            .chain(once(channel.into()))
            .chain(once(nonce.into()))
            .collect();

        builder.looked(SymbolicLookup::new(
            values,
            multiplicity.into(),
            LookupType::Alu,
        ));
    }
}
