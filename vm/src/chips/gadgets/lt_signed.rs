//! Signed less-than gadget
//!
//! Combines unsigned less-than comparison with MSB extraction for signed comparison.

use crate::{
    chips::chips::byte::event::ByteRecordBehavior,
    compiler::word::Word,
    machine::builder::{ChipBuilder, ChipLookupBuilder, ChipRangeBuilder},
};
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};
use pico_derive::AlignedBorrow;

use super::{lt_word_u16::LtWordU16Gadget, msb::U16MSBGadget};

/// Signed less-than gadget for comparing two 64-bit values as signed or unsigned integers.
///
/// For signed comparison (SLT):
/// - Extract MSB of both operands to determine sign
/// - XOR operands with (1 << 63) to convert to unsigned
/// - Perform unsigned comparison on the converted values
/// - Combine result with sign bits:
///
/// For unsigned comparison (SLTU):
/// - Simply perform unsigned comparison
#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct LtSignedGadget<T> {
    /// The result of the SLTU operation.
    pub result: LtWordU16Gadget<T>,

    /// The most significant bit of operand b if `is_signed` is true.
    pub b_msb: U16MSBGadget<T>,

    /// The most significant bit of operand c if `is_signed` is true.
    pub c_msb: U16MSBGadget<T>,
}

impl<T: Default + Copy> Default for LtSignedGadget<T> {
    fn default() -> Self {
        Self {
            result: LtWordU16Gadget::default(),
            b_msb: U16MSBGadget::default(),
            c_msb: U16MSBGadget::default(),
        }
    }
}

impl<F: Field> LtSignedGadget<F> {
    /// Populate the signed less-than gadget.
    ///
    /// For signed operation:
    /// - Extract MSB of b and c
    /// - XOR b and c with (1 << 63) to treat them as unsigned
    /// - Perform unsigned comparison
    /// - The result is: (b_msb && !c_msb) || (b_msb == c_msb && unsigned_result)
    ///
    /// For unsigned operation:
    /// - Simply perform unsigned comparison
    pub fn populate_signed(
        &mut self,
        record: &mut impl ByteRecordBehavior,
        a_u64: u64,
        b_u64: u64,
        c_u64: u64,
        is_signed: bool,
    ) {
        let b_limbs = crate::primitives::consts::u64_to_u16_limbs(b_u64);
        let c_limbs = crate::primitives::consts::u64_to_u16_limbs(c_u64);

        if is_signed {
            // Extract MSB for signed comparison
            self.b_msb.populate(record, b_limbs[3]);
            self.c_msb.populate(record, c_limbs[3]);

            // XOR with (1 << 63) to convert signed to unsigned representation
            let b_converted = b_u64 ^ (1 << 63);
            let c_converted = c_u64 ^ (1 << 63);

            // Compare b < c (signed) by comparing converted values
            self.result
                .populate(record, a_u64, b_converted, c_converted);
        } else {
            // For unsigned, MSB should be zero (no sign bit)
            self.b_msb.msb = F::ZERO;
            self.c_msb.msb = F::ZERO;

            // Compare b < c (unsigned)
            self.result.populate(record, a_u64, b_u64, c_u64);
        }
    }

    /// Evaluate the signed LT operation.
    /// Assumes that `b`, `c` are valid `Word`s of u16 limbs.
    /// Constrains that `is_signed` is boolean.
    /// Constrains that `is_real` is boolean.
    /// If `is_real` is true, constrains that the result is the signed LT of `b` and `c`.
    pub fn eval<AB>(
        builder: &mut AB,
        b: Word<AB::Var>,
        c: Word<AB::Var>,
        cols: LtSignedGadget<AB::Var>,
        is_signed: AB::Var,
        is_real: AB::Expr,
    ) where
        AB: ChipBuilder<F> + ChipLookupBuilder<F> + ChipRangeBuilder<F>,
    {
        builder.assert_bool(is_signed);
        builder.assert_bool(is_real.clone());
        // If `is_real` is false, assert that `is_signed` is zero.
        builder
            .when_not(is_real.clone())
            .assert_zero(is_signed.into());

        // Constrain the MSB of `b` and `c` if `is_signed` is true.
        // This will be used to determine the sign of `b` and `c`.
        U16MSBGadget::<AB::F>::eval(builder, b.0[3].into(), cols.b_msb, is_signed.into());
        U16MSBGadget::<AB::F>::eval(builder, c.0[3].into(), cols.c_msb, is_signed.into());

        // Constrain `b` and `c` to be considered positive if `is_signed` is false.
        builder.when_not(is_signed).assert_zero(cols.b_msb.msb);
        builder.when_not(is_signed).assert_zero(cols.c_msb.msb);

        let base = AB::Expr::from_canonical_u32(1 << 16);

        // XOR `1 << 63` to `b` and `c` if `is_signed` is true.
        // If `is_signed` is false, the `msb` values are constrained to be zero.
        // If `is_signed` is true, the `msb` values are constrained by `U16MSBGadget`.
        // In both cases, `b_compare` and `c_compare` are correct.
        let b_compare: Word<AB::Expr> = b.map(|v| v.into());
        let c_compare: Word<AB::Expr> = c.map(|v| v.into());

        let mut b_compare_arr = b_compare.0;
        let mut c_compare_arr = c_compare.0;

        b_compare_arr[3] = b_compare_arr[3].clone()
            + is_signed.into() * AB::Expr::from_canonical_u32(1 << 15)
            - base.clone() * cols.b_msb.msb.into();
        c_compare_arr[3] = c_compare_arr[3].clone()
            + is_signed.into() * AB::Expr::from_canonical_u32(1 << 15)
            - base.clone() * cols.c_msb.msb.into();

        // Now apply the unsigned LT operation.
        // We pass b_compare as the first arg (a) and c_compare as the second arg (b)
        // because the gadget checks if a < b, which becomes b_compare < c_compare
        LtWordU16Gadget::<AB::F>::eval(
            builder,
            Word(b_compare_arr),
            Word(c_compare_arr),
            cols.result,
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
        b: Word<T>,
        c: Word<T>,
        lt_signed: LtSignedGadget<T>,
        is_signed: T,
        is_real: T,
    }

    #[test]
    fn test_lt_signed_gadget_simple_eval() {
        let width = size_of::<TestCols<u8>>();
        let mut builder = SymbolicConstraintFolder::new(0, width);
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &TestCols<_> = (*local).borrow();

        LtSignedGadget::<KoalaBear>::eval(
            &mut builder,
            local.b,
            local.c,
            local.lt_signed,
            local.is_signed,
            local.is_real.into(),
        );

        assert_eq!(builder.num_constraints(), 24);
        assert_eq!(builder.public_values().len(), 119);
        assert_eq!(builder.num_lookups(), 3);
    }
}
