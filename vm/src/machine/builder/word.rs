//! Word associating builder functions

use super::ChipBuilder;
use crate::compiler::word::{Word, WORD_SIZE};
use itertools::Itertools;
use p3_field::Field;
use std::array;

pub trait ChipWordBuilder<F: Field>: ChipBuilder<F> {
    /// Asserts that the two words are equal.
    fn assert_word_eq(
        &mut self,
        left: Word<impl Into<Self::Expr>>,
        right: Word<impl Into<Self::Expr>>,
    ) {
        for (left, right) in left.0.into_iter().zip(right.0) {
            self.assert_eq(left, right);
        }
    }

    /// Asserts that the word is zero.
    fn assert_word_zero(&mut self, word: Word<impl Into<Self::Expr>>) {
        for limb in word.0 {
            self.assert_zero(limb);
        }
    }

    /// Index an array of words using an index bitmap.
    fn index_word_array(
        &mut self,
        array: &[Word<impl Into<Self::Expr> + Clone>],
        index_bitmap: &[impl Into<Self::Expr> + Clone],
    ) -> Word<Self::Expr> {
        let mut result = Word::default();
        for i in 0..WORD_SIZE {
            result[i] = self.index_array(
                array
                    .iter()
                    .map(|word| word[i].clone())
                    .collect_vec()
                    .as_slice(),
                index_bitmap,
            );
        }
        result
    }

    /// Same as `if_else` above, but arguments are `Word` instead of individual expressions.
    fn select_word(
        &mut self,
        condition: impl Into<Self::Expr> + Clone,
        a: Word<impl Into<Self::Expr> + Clone>,
        b: Word<impl Into<Self::Expr> + Clone>,
    ) -> Word<Self::Expr> {
        Word(array::from_fn(|i| {
            self.if_else(condition.clone(), a[i].clone(), b[i].clone())
        }))
    }
}
