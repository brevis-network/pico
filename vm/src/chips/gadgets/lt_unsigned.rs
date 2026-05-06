//! Unsigned less-than gadget

use crate::{
    chips::chips::byte::event::{ByteLookupEvent, ByteRecordBehavior},
    compiler::{riscv::opcode::ByteOpcode, word::Word},
    machine::builder::{ChipBuilder, ChipLookupBuilder},
    primitives::consts::WORD_SIZE,
};
use itertools::izip;
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};
use pico_derive::AlignedBorrow;

/// Instance of `LtOperation` to check if abs(remainder) < abs(c).
#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct LtUnsignedGadget<T> {
    /// Boolean flags to indicate the first byte in which the remainder is smaller than c.
    pub byte_flags: [T; WORD_SIZE],

    /// The comparison byte for a (remainder).
    pub a_comparison_byte: T,

    /// The comparison byte for b (c).
    pub b_comparison_byte: T,
}

impl<T: Default + Copy> Default for LtUnsignedGadget<T> {
    fn default() -> Self {
        Self {
            byte_flags: [T::default(); WORD_SIZE],
            a_comparison_byte: T::default(),
            b_comparison_byte: T::default(),
        }
    }
}

impl<F: Field> LtUnsignedGadget<F> {
    /// Populate the unsigned less-than gadget from values.
    pub fn populate(&mut self, record: &mut impl ByteRecordBehavior, a_u64: u64, b_u64: u64) {
        let a_bytes = a_u64.to_le_bytes();
        let b_bytes = b_u64.to_le_bytes();

        let mut found = false;
        for (i, (a_byte, b_byte)) in a_bytes.iter().zip(b_bytes.iter()).enumerate().rev() {
            if a_byte < b_byte {
                self.byte_flags[i] = F::ONE;
                self.a_comparison_byte = F::from_canonical_u8(*a_byte);
                self.b_comparison_byte = F::from_canonical_u8(*b_byte);
                found = true;

                // Add the LTU byte lookup event
                record.add_byte_lookup_event(ByteLookupEvent {
                    opcode: ByteOpcode::LTU,
                    a1: 1,
                    a2: 0,
                    b: *a_byte,
                    c: *b_byte,
                });
                break;
            } else if a_byte > b_byte {
                // If a > b at any byte, then a >= b
                self.byte_flags[i] = F::ZERO;
                found = true;
                break;
            }
        }

        // If all bytes are equal (found == false), ensure all flags are 0
        // If we found a difference (found == true), only one flag should be set (already done above)
        if !found {
            for flag in self.byte_flags.iter_mut() {
                *flag = F::ZERO;
            }
        }
    }

    /// Populate the unsigned less-than gadget from values.
    /// Checks if a < b, using c as additional context (for range checks).
    pub fn populate_unsigned(
        &mut self,
        record: &mut impl ByteRecordBehavior,
        a_u64: u64,
        b_u64: u64,
        c_u64: u64,
    ) {
        let a_bytes = a_u64.to_le_bytes();
        let b_bytes = b_u64.to_le_bytes();

        let mut found = false;
        for (i, (a_byte, b_byte)) in a_bytes.iter().zip(b_bytes.iter()).enumerate().rev() {
            if a_byte < b_byte {
                self.byte_flags[i] = F::ONE;
                self.a_comparison_byte = F::from_canonical_u8(*a_byte);
                self.b_comparison_byte = F::from_canonical_u8(*b_byte);
                found = true;

                // Add the LTU byte lookup event
                record.add_byte_lookup_event(ByteLookupEvent {
                    opcode: ByteOpcode::LTU,
                    a1: 1,
                    a2: 0,
                    b: *a_byte,
                    c: *b_byte,
                });
                break;
            } else if a_byte > b_byte {
                // If a > b at any byte, then a >= b
                self.byte_flags[i] = F::ZERO;
                found = true;
                break;
            }
        }

        // If all bytes are equal (found == false), ensure all flags are 0
        if !found {
            for flag in self.byte_flags.iter_mut() {
                *flag = F::ZERO;
            }
        }

        // Add range check events for the inputs
        let c_bytes = c_u64.to_le_bytes();
        record.add_u8_range_checks(a_bytes);
        record.add_u8_range_checks(b_bytes);
        record.add_u8_range_checks(c_bytes);
    }

    /// Evaluate the unsigned less-than gadget constraints.
    pub fn eval<AB: ChipBuilder<F>>(
        builder: &mut AB,
        a: Word<AB::Expr>,
        b: Word<AB::Expr>,
        cols: LtUnsignedGadget<AB::Var>,
        is_real: AB::Expr,
    ) {
        // Check that exactly one flag is set to 1
        let mut sum_flags: AB::Expr = AB::Expr::ZERO;
        for &flag in cols.byte_flags.iter() {
            builder.assert_bool(flag);
            sum_flags += flag.into();
        }
        builder.when(is_real.clone()).assert_one(sum_flags);

        // Check the less-than condition
        // A flag to indicate whether an equality check is necessary
        let mut is_inequality_visited = AB::Expr::ZERO;
        let mut first_lt_byte = AB::Expr::ZERO;
        let mut comparison_byte = AB::Expr::ZERO;

        for (a_byte, b_byte, &flag) in izip!(
            a.0.iter().rev(),
            b.0.iter().rev(),
            cols.byte_flags.iter().rev()
        ) {
            is_inequality_visited += flag.into();
            first_lt_byte += a_byte.clone() * flag;
            comparison_byte += b_byte.clone() * flag;

            builder
                .when_not(is_inequality_visited.clone())
                .when(is_real.clone())
                .assert_eq(a_byte.clone(), b_byte.clone());
        }

        builder
            .when(is_real.clone())
            .assert_eq(cols.a_comparison_byte, first_lt_byte);
        builder
            .when(is_real.clone())
            .assert_eq(cols.b_comparison_byte, comparison_byte);

        // Send the comparison interaction
        builder.looking_byte(
            ByteOpcode::LTU.as_field::<AB::F>(),
            AB::F::ONE,
            cols.a_comparison_byte,
            cols.b_comparison_byte,
            is_real,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::{builder::PublicValuesBuilder, folder::SymbolicConstraintFolder};
    use p3_koala_bear::KoalaBear;
    use p3_matrix::Matrix;
    use pico_derive::AlignedBorrow;
    use std::{borrow::Borrow, mem::size_of};

    #[derive(AlignedBorrow, Clone, Copy)]
    #[repr(C)]
    struct TestCols<T> {
        a: Word<T>,
        b: Word<T>,
        lt_unsigned: LtUnsignedGadget<T>,
        is_real: T,
    }

    #[test]
    fn test_lt_unsigned_gadget_simple_eval() {
        let width = size_of::<TestCols<u8>>();
        let mut builder = SymbolicConstraintFolder::new(0, width);
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &TestCols<_> = (*local).borrow();

        LtUnsignedGadget::<KoalaBear>::eval(
            &mut builder,
            local.a.map(|v| v.into()),
            local.b.map(|v| v.into()),
            local.lt_unsigned,
            local.is_real.into(),
        );

        assert_eq!(builder.num_constraints(), 11);
        assert_eq!(builder.public_values().len(), 119);
        assert_eq!(builder.num_lookups(), 1);
    }
}
