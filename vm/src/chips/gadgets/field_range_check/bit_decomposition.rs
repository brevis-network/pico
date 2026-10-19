#![allow(clippy::assign_op_pattern)]

use p3_air::AirBuilder;
use p3_field::{Field, PrimeCharacteristicRing};
use pico_derive::AlignedBorrow;
use std::array;

use crate::{
    chips::gadgets::is_zero::IsZeroGadget,
    machine::field::{FieldBehavior, FieldType},
};

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
        self.bits = array::from_fn(|i| F::from_u32((value >> i) & 1));
        match F::field_type() {
            FieldType::TypeKoalaBear => {
                let most_sig_byte_decomp = &self.bits[24..32];
                self.upper_all_one.populate_from_field_element(
                    most_sig_byte_decomp.iter().cloned().sum::<F>() - F::from_u32(7),
                );
            }
            _ => unimplemented!("Unsupported field type"),
        }
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
            reconstructed_value = reconstructed_value.clone() + AB::Expr::from_u32(1 << i) * *bit;
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

        match F::field_type() {
            FieldType::TypeKoalaBear => {
                // Range check that value is less than the modulus. Comparing the most significant
                // byte is sufficient. Koala Modulus in big endian format
                // 01111111 00000000 00000000 00000001
                // 2^31 - 2^24 + 1
                // So we need to check the following conditions:
                // 1) if most_sig_byte > 01111111, then fail.
                // 2) if most_sig_byte == 01111111, then value's lower sig bytes must all be 0.
                // 3) if most_sig_byte < 01111111, then pass.

                // If the top bits are all 1, then the lower bits must all be 0.
                let mut upper_bits_sum: AB::Expr = AB::Expr::ZERO;
                for bit in most_sig_byte_decomp[0..7].iter() {
                    upper_bits_sum = upper_bits_sum + *bit;
                }
                upper_bits_sum = upper_bits_sum - AB::Expr::from_u32(7);
                IsZeroGadget::<F>::eval(
                    builder,
                    upper_bits_sum,
                    cols.upper_all_one,
                    is_real.clone(),
                );

                let mut lower_bits_sum: AB::Expr = AB::Expr::ZERO;
                for bit in cols.bits[0..24].iter() {
                    lower_bits_sum = lower_bits_sum + *bit;
                }

                builder
                    .when(is_real)
                    .when(cols.upper_all_one.result)
                    .assert_zero(lower_bits_sum);
            }
            _ => {
                unimplemented!("Unsupported field type");
            }
        }
    }
}
