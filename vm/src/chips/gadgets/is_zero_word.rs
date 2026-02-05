//! A gadget to check if the input word is 0.
//!
//! This is bijective (i.e., returns 1 if and only if the input is 0). It is also worth noting that
//! this operation doesn't do a range check.

use crate::{
    chips::gadgets::is_zero::IsZeroGadget, compiler::word::Word, machine::builder::ChipBuilder,
    primitives::consts::WORD_SIZE,
};
use p3_air::AirBuilder;
use p3_field::Field;
use pico_derive::AlignedBorrow;

/// A set of columns needed to compute whether the given word is 0.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct IsZeroWordGadget<T> {
    /// `IsZeroGadget` to check if each byte in the input word is zero.
    pub is_zero_byte: [IsZeroGadget<T>; WORD_SIZE],

    /// A boolean flag indicating whether the lower word (the bottom 16 bits of the input) is 0.
    /// This equals `is_zero_byte[0] * is_zero_byte[1]`.
    pub is_lower_half_zero: T,

    /// A boolean flag indicating whether the upper word (the top 16 bits of the input) is 0. This
    /// equals `is_zero_byte[2] * is_zero_byte[3]`.
    pub is_upper_half_zero: T,

    /// A boolean flag indicating whether the word is zero. This equals `is_zero_byte[0] * ... *
    /// is_zero_byte[WORD_SIZE - 1]`.
    pub result: T,
}

impl<F: Field> IsZeroWordGadget<F> {
    pub fn populate(&mut self, a_u32: u32) -> u32 {
        self.populate_from_field_element(Word::from(a_u32))
    }

    pub fn populate_from_field_element(&mut self, a: Word<F>) -> u32 {
        let mut is_zero = true;
        for i in 0..WORD_SIZE {
            is_zero &= self.is_zero_byte[i].populate_from_field_element(a[i]) == 1;
        }
        self.is_lower_half_zero = self.is_zero_byte[0].result * self.is_zero_byte[1].result;
        self.is_upper_half_zero = self.is_zero_byte[2].result * self.is_zero_byte[3].result;
        self.result = F::from_bool(is_zero);
        is_zero as u32
    }

    pub fn eval<CB: ChipBuilder<F>>(
        builder: &mut CB,
        a: Word<CB::Expr>,
        cols: IsZeroWordGadget<CB::Var>,
        is_real: CB::Expr,
    ) {
        // Calculate whether each byte is 0.
        for i in 0..WORD_SIZE {
            IsZeroGadget::<CB::F>::eval(
                builder,
                a[i].clone(),
                cols.is_zero_byte[i],
                is_real.clone(),
            );
        }

        // From here, we only assert when is_real is true.
        builder.assert_bool(is_real.clone());
        let mut builder_is_real = builder.when(is_real.clone());

        // Calculate is_upper_half_zero and is_lower_half_zero and finally the result.
        builder_is_real.assert_bool(cols.is_lower_half_zero);
        builder_is_real.assert_bool(cols.is_upper_half_zero);
        builder_is_real.assert_bool(cols.result);
        builder_is_real.assert_eq(
            cols.is_lower_half_zero,
            cols.is_zero_byte[0].result * cols.is_zero_byte[1].result,
        );
        builder_is_real.assert_eq(
            cols.is_upper_half_zero,
            cols.is_zero_byte[2].result * cols.is_zero_byte[3].result,
        );
        builder_is_real.assert_eq(
            cols.result,
            cols.is_lower_half_zero * cols.is_upper_half_zero,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{chips::gadgets::is_zero::IsZeroGadget, machine::folder::SymbolicConstraintFolder};
    use p3_field::FieldAlgebra;
    use p3_koala_bear::KoalaBear;
    use p3_uni_stark::{Entry, SymbolicExpression, SymbolicVariable};
    use std::array;

    #[test]
    fn test_is_zero_word_gadget_simple_eval() {
        let expr = SymbolicExpression::Constant(KoalaBear::ZERO);
        let var = SymbolicVariable::new(Entry::Main { offset: 0 }, 0);
        let word = Word(array::from_fn(|_| expr.clone()));

        // create a new gadget
        let is_zero_gadget = IsZeroGadget {
            inverse: var,
            result: var,
        };
        let gadget = IsZeroWordGadget {
            is_zero_byte: [is_zero_gadget; 4],
            is_lower_half_zero: var,
            is_upper_half_zero: var,
            result: var,
        };
        // create a constraint builder
        let mut builder = SymbolicConstraintFolder::new(0, size_of::<IsZeroWordGadget<u8>>());

        // evaluate with this gadget
        IsZeroWordGadget::<KoalaBear>::eval(&mut builder, word, gadget, Default::default());

        // check the constraints and public values
        assert_eq!(builder.constraints.len(), 19);
        assert_eq!(builder.public_values.len(), 231);

        // check the looking (sending) and looked (receiving) lookups
        let (looking, looked) = builder.lookups();
        assert_eq!(looking.len(), 0);
        assert_eq!(looked.len(), 0);
    }
}
