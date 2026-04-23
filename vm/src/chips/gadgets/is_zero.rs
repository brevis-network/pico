//! A gadget to check if the input is 0.
//!
//! This is guaranteed to return 1 if and only if the input is 0.
//! The idea is that 1 - input * inverse is exactly the boolean value indicating whether the input
//! is 0.

use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};
use pico_derive::AlignedBorrow;

/// A set of columns needed to compute whether the given word is 0.
#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct IsZeroGadget<T> {
    /// The inverse of the input.
    pub inverse: T,

    /// Result indicating whether the input is 0. This equals `inverse * input == 0`.
    pub result: T,
}

impl<F: Field> IsZeroGadget<F> {
    pub fn populate(&mut self, a: u32) -> u32 {
        self.populate_from_field_element(F::from_canonical_u32(a))
    }

    pub fn populate_from_field_element(&mut self, a: F) -> u32 {
        if a == F::ZERO {
            self.inverse = F::ZERO;
            self.result = F::ONE;
        } else {
            self.inverse = a.inverse();
            self.result = F::ZERO;
        }
        let prod = self.inverse * a;
        debug_assert!(prod == F::ONE || prod == F::ZERO);
        (a == F::ZERO) as u32
    }

    pub fn eval<AB: AirBuilder>(
        builder: &mut AB,
        a: AB::Expr,
        cols: IsZeroGadget<AB::Var>,
        is_real: AB::Expr,
    ) {
        let one: AB::Expr = AB::F::ONE.into();

        // 1. Input == 0 => is_zero = 1 regardless of the inverse.
        // 2. Input != 0
        //   2.1. inverse is correctly set => is_zero = 0.
        //   2.2. inverse is incorrect
        //     2.2.1 inverse is nonzero => is_zero isn't bool, it fails.
        //     2.2.2 inverse is 0 => is_zero is 1. But then we would assert that a = 0. And that
        //                           assert fails.

        // If the input is 0, then any product involving it is 0. If it is nonzero and its inverse
        // is correctly set, then the product is 1.
        let is_zero = one.clone() - cols.inverse * a.clone();
        builder
            .when(is_real.clone())
            .assert_eq(is_zero, cols.result);
        builder.when(is_real.clone()).assert_bool(cols.result);

        // If the result is 1, then the input is 0.
        builder
            .when(is_real.clone())
            .when(cols.result)
            .assert_zero(a.clone());
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
        a: T,
        is_zero: IsZeroGadget<T>,
        is_real: T,
    }

    #[test]
    fn test_is_zero_gadget_simple_eval() {
        let width = size_of::<TestCols<u8>>();
        let mut builder: SymbolicConstraintFolder<KoalaBear> =
            SymbolicConstraintFolder::new(0, width);
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &TestCols<_> = (*local).borrow();

        IsZeroGadget::<KoalaBear>::eval(
            &mut builder,
            local.a.into(),
            local.is_zero,
            local.is_real.into(),
        );

        assert_eq!(builder.num_constraints(), 3);
        assert_eq!(builder.public_values().len(), 119);
        assert_eq!(builder.num_lookups(), 0);
    }
}
