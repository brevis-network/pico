use crate::{
    chips::gadgets::is_zero::IsZeroGadget,
    compiler::word::Word,
    machine::field::{FieldBehavior, FieldType},
};
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};
use pico_derive::AlignedBorrow;
use std::array;

/// A set of columns needed to compute the add of two words.
#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct FieldWordRangeChecker<T> {
    /// Most sig byte LE bit decomposition.
    pub most_sig_byte_decomp: [T; 8],

    /// Check the range of the last byte.
    pub upper_all_one: IsZeroGadget<T>,
}

impl<F: Field> FieldWordRangeChecker<F> {
    pub fn populate(&mut self, value: u32) {
        self.most_sig_byte_decomp = array::from_fn(|i| F::from_bool(value & (1 << (i + 24)) != 0));
        match F::field_type() {
            FieldType::TypeBabyBear | FieldType::TypeKoalaBear => {
                let one_start_idx = if F::field_type() == FieldType::TypeBabyBear {
                    3u32
                } else {
                    0
                };
                self.upper_all_one.populate_from_field_element(
                    self.most_sig_byte_decomp[one_start_idx as usize..]
                        .iter()
                        .cloned()
                        .sum::<F>()
                        - F::from_canonical_u32(7 - one_start_idx),
                );
            }
            FieldType::TypeMersenne31 => {
                let sum = (0..4).map(|i| (value >> (8 * i)) & 255).sum::<u32>();
                self.upper_all_one
                    .populate_from_field_element(-F::from_canonical_u32((127 + 255 * 3) - sum));
            }
            _ => {
                unimplemented!("Unsupported field type");
            }
        }
    }

    pub fn range_check<AB: AirBuilder>(
        builder: &mut AB,
        value: Word<AB::Var>,
        cols: FieldWordRangeChecker<AB::Var>,
        is_real: AB::Expr,
    ) {
        let mut recomposed_byte = AB::Expr::ZERO;
        cols.most_sig_byte_decomp
            .iter()
            .enumerate()
            .for_each(|(i, value)| {
                builder.when(is_real.clone()).assert_bool(*value);
                recomposed_byte =
                    recomposed_byte.clone() + AB::Expr::from_canonical_usize(1 << i) * *value;
            });

        builder
            .when(is_real.clone())
            .assert_eq(recomposed_byte, value[3]);

        builder
            .when(is_real.clone())
            .assert_zero(cols.most_sig_byte_decomp[7]);

        match F::field_type() {
            FieldType::TypeBabyBear | FieldType::TypeKoalaBear => {
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

                let one_start_idx = if F::field_type() == FieldType::TypeBabyBear {
                    3
                } else {
                    0
                };

                // If the top bits are all 1, then the lower bits must all be 0.
                let mut upper_bits_sum: AB::Expr = AB::Expr::ZERO;
                for bit in cols.most_sig_byte_decomp[one_start_idx..7].iter() {
                    upper_bits_sum = upper_bits_sum + *bit;
                }
                upper_bits_sum -= AB::F::from_canonical_u32(7 - one_start_idx as u32).into();
                IsZeroGadget::<F>::eval(
                    builder,
                    upper_bits_sum,
                    cols.upper_all_one,
                    is_real.clone(),
                );

                let bottom_bits: AB::Expr = cols.most_sig_byte_decomp[0..one_start_idx]
                    .iter()
                    .map(|bit| (*bit).into())
                    .sum();
                builder
                    .when(is_real.clone())
                    .when(cols.upper_all_one.result)
                    .assert_zero(bottom_bits);
                builder
                    .when(is_real)
                    .when(cols.upper_all_one.result)
                    .assert_zero(value[0] + value[1] + value[2]);
            }
            FieldType::TypeMersenne31 => {
                // Mersenne31 Modulus in big endian format
                // 01111111 11111111 11111111 11111111
                // 2^31 - 1

                // All the four bytes are all within a certain range:
                // 00000000 <= bytes[3] <= 01111111
                // 00000000 <= bytes[2] <= 11111111
                // 00000000 <= bytes[1] <= 11111111
                // 00000000 <= bytes[0] <= 11111111
                // which means 00000000 <= sum(bytes) <= 127 + 255 * 3,
                // which means word == 2^31 - 1 <=> sum(bytes) == 127 + 255 * 3.
                // Therefore, we use the IsZeroGadget to guarantee that sum(bytes) != 127 + 255 * 3.
                let mut byte_sum = value[0] + value[1] + value[2] + value[3];
                byte_sum -= AB::F::from_canonical_u32(127u32 + 255 * 3).into();
                // TODO: uncommenting the below line causes all sorts of failures with the m31 prover
                // however, the m31 prover is already experiencing lookup and constraint evaluation issues
                // so I am leaving this uncommented because commenting it introduces an underconstrained variable
                // cols.upper_all_one.
                IsZeroGadget::<F>::eval(builder, byte_sum, cols.upper_all_one, is_real.clone());
                builder.when(is_real).assert_zero(cols.upper_all_one.result)
            }
            _ => {
                unimplemented!("Unsupported field type")
            }
        }
    }
}
