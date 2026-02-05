use crate::{
    chips::chips::byte::event::ByteRecordBehavior,
    compiler::word::Word,
    machine::builder::{ChipLookupBuilder, ChipRangeBuilder},
    primitives::consts::WORD_SIZE,
};
use p3_air::AirBuilder;
use p3_field::Field;
use pico_derive::AlignedBorrow;

/// A set of columns needed to compute the not of a word.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct NotOperation<T> {
    /// The result of `!x`.
    pub value: Word<T>,
}

impl<F: Field> NotOperation<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecordBehavior, x: u32) -> u32 {
        let expected = !x;
        let x_bytes = x.to_le_bytes();
        for i in 0..WORD_SIZE {
            self.value[i] = F::from_canonical_u8(!x_bytes[i]);
        }
        record.add_u8_range_checks(x_bytes);
        expected
    }

    #[allow(unused_variables)]
    pub fn eval<CB: ChipLookupBuilder<F>>(
        builder: &mut CB,
        a: Word<CB::Var>,
        cols: NotOperation<CB::Var>,
        is_real: impl Into<CB::Expr> + Copy,
    ) {
        for i in (0..WORD_SIZE).step_by(2) {
            builder.slice_range_check_u8(&[a[i], a[i + 1]], is_real);
        }

        // For any byte b, b + !b = 0xFF.
        for i in 0..WORD_SIZE {
            builder
                .when(is_real)
                .assert_eq(cols.value[i] + a[i], CB::F::from_canonical_u8(u8::MAX));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::folder::SymbolicConstraintFolder;
    use p3_field::FieldAlgebra;
    use p3_koala_bear::KoalaBear;
    use p3_uni_stark::{Entry, SymbolicVariable};

    #[test]
    fn test_not_gadget_simple_eval() {
        let var = SymbolicVariable::new(Entry::Main { offset: 0 }, 0);
        let word = Word([var; 4]);

        // create a new gadget
        let gadget = NotOperation { value: word };
        // create a constraint builder
        let mut builder = SymbolicConstraintFolder::new(0, size_of::<NotOperation<u8>>());

        // evaluate with this gadget
        NotOperation::<KoalaBear>::eval(&mut builder, word, gadget, KoalaBear::ZERO);

        // check the constraints and public values
        assert_eq!(builder.constraints.len(), 4);
        assert_eq!(builder.public_values.len(), 231);

        // check the looking (sending) and looked (receiving) lookups
        let (looking, looked) = builder.lookups();
        assert_eq!(looking.len(), 2);
        assert_eq!(looked.len(), 0);
    }
}
