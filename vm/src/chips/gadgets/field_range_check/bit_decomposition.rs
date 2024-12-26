use p3_air::AirBuilder;
use p3_baby_bear::BabyBear;
use p3_field::{Field, FieldAlgebra};
use p3_koala_bear::KoalaBear;
use p3_mersenne_31::Mersenne31;
use pico_derive::AlignedBorrow;
use std::{any::TypeId, array};

use crate::chips::gadgets::is_zero::IsZeroGadget;

#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct FieldBitDecomposition<T> {
    /// The bit decoposition of the`value`.
    pub bits: [T; 32],

    /// Check the range of the last byte.
    pub upper_all_one: IsZeroGadget<T>,
}

impl<F: Field> FieldBitDecomposition<F> {
    pub fn populate(&mut self, value: u32) {
        self.bits = array::from_fn(|i| F::from_canonical_u32((value >> i) & 1));
        let one_start_idx = if TypeId::of::<F>() == TypeId::of::<BabyBear>() {
            3u32
        } else if TypeId::of::<F>() == TypeId::of::<KoalaBear>() {
            0
        } else if TypeId::of::<F>() == TypeId::of::<Mersenne31>() {
            return;
        } else {
            unimplemented!("Unsupported field type");
        };
        let most_sig_byte_decomp = &self.bits[24..32];
        self.upper_all_one.populate_from_field_element(
            most_sig_byte_decomp[one_start_idx as usize..]
                .iter()
                .cloned()
                .sum::<F>()
                - F::from_canonical_u32(7 - one_start_idx),
        );
    }

    pub fn range_check<AB: AirBuilder>(
        builder: &mut AB,
        value: AB::Var,
        cols: FieldBitDecomposition<AB::Var>,
        is_real: AB::Expr,
    ) {
        let mut reconstructed_value = AB::Expr::ZERO;
        for (i, bit) in cols.bits.iter().enumerate() {
            builder.when(is_real.clone()).assert_bool(*bit);
            reconstructed_value += AB::Expr::from_wrapped_u32(1 << i) * *bit;
        }

        // Assert that bits2num(bits) == value.
        builder
            .when(is_real.clone())
            .assert_eq(reconstructed_value, value);

        // Assert that the most significant bit is zero
        let most_sig_byte_decomp = &cols.bits[24..32];
        builder
            .when(is_real.clone())
            .assert_zero(most_sig_byte_decomp[7]);

        if TypeId::of::<F>() == TypeId::of::<BabyBear>()
            || TypeId::of::<F>() == TypeId::of::<KoalaBear>()
        {
            // Range check that value is less than baby bear modulus.  To do this, it is sufficient
            // to just do comparisons for the most significant byte. BabyBear's modulus is (in big
            // endian binary) 01111000_00000000_00000000_00000001.  So we need to check the
            // following conditions:
            // 1) if most_sig_byte > 01111000, then fail.
            // 2) if most_sig_byte == 01111000, then value's lower sig bytes must all be 0.
            // 3) if most_sig_byte < 01111000, then pass.

            // Koala Modulus in big endian format
            // 01111111 00000000 00000000 00000001
            // 2^31 - 2^24 + 1

            let one_start_idx = if TypeId::of::<F>() == TypeId::of::<BabyBear>() {
                3
            } else {
                0
            };

            // If the top bits are all 1, then the lower bits must all be 0.
            let mut upper_bits_sum: AB::Expr = AB::Expr::ZERO;
            for bit in most_sig_byte_decomp[one_start_idx..7].iter() {
                upper_bits_sum = upper_bits_sum + *bit;
            }
            upper_bits_sum -= AB::F::from_canonical_u32(7 - one_start_idx as u32).into();
            IsZeroGadget::<F>::eval(builder, upper_bits_sum, cols.upper_all_one, is_real.clone());

            let mut lower_bits_sum: AB::Expr = AB::Expr::ZERO;
            for bit in cols.bits[0..24 + one_start_idx].iter() {
                lower_bits_sum = lower_bits_sum + *bit;
            }

            builder
                .when(is_real)
                .when(cols.upper_all_one.result)
                .assert_zero(lower_bits_sum);
        } else if TypeId::of::<F>() == TypeId::of::<Mersenne31>() {
            // Mersenne31 Modulus in big endian format
            // 01111111 11111111 11111111 11111111
            // 2^31 - 1
        } else {
            unimplemented!("Unsupported field type");
        }
    }
}
