use crate::{
    extension::BinomialExtension,
    folder::{ProverConstraintFolder, VerifierConstraintFolder},
    lookup::{symbolic_to_virtual_pair, LookupType, SymbolicLookup, VirtualPairLookup},
};
use itertools::Itertools;
use p3_air::{
    AirBuilder, AirBuilderWithPublicValues, ExtensionBuilder, FilteredAirBuilder, PairCol,
    PermutationAirBuilder,
};
use p3_field::{AbstractExtensionField, AbstractField, ExtensionField, Field};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_uni_stark::{Entry, SymbolicExpression, SymbolicVariable};
use pico_compiler::{
    opcode::ByteOpcode,
    word::{Word, WORD_SIZE},
};
use pico_configs::config::{StarkGenericConfig, Val};
use std::{array, iter::once};

/// Chip builder
pub trait ChipBuilder<F: Field>:
    AirBuilder<F = F> + LookupBuilder<SymbolicLookup<Self::Expr>> + PublicValuesBuilder
{
    /// Returns a sub-builder whose constraints are enforced only when `condition` is not one.
    fn when_not<I: Into<Self::Expr>>(&mut self, condition: I) -> FilteredAirBuilder<Self> {
        self.when_ne(condition, Self::F::one())
    }

    /// Asserts that an iterator of expressions are all equal.
    fn assert_all_eq<I1: Into<Self::Expr>, I2: Into<Self::Expr>>(
        &mut self,
        left: impl IntoIterator<Item = I1>,
        right: impl IntoIterator<Item = I2>,
    ) {
        for (left, right) in left.into_iter().zip_eq(right) {
            self.assert_eq(left, right);
        }
    }

    /// Asserts that an iterator of expressions are all zero.
    fn assert_all_zero<I: Into<Self::Expr>>(&mut self, iter: impl IntoIterator<Item = I>) {
        iter.into_iter().for_each(|expr| self.assert_zero(expr));
    }

    /// Will return `a` if `condition` is 1, else `b`.  This assumes that `condition` is already
    /// checked to be a boolean.
    #[inline]
    fn if_else(
        &mut self,
        condition: impl Into<Self::Expr> + Clone,
        a: impl Into<Self::Expr> + Clone,
        b: impl Into<Self::Expr> + Clone,
    ) -> Self::Expr {
        condition.clone().into() * a.into() + (Self::Expr::one() - condition.into()) * b.into()
    }

    /// Index an array of expressions using an index bitmap.  This function assumes that the
    /// `EIndex` type is a boolean and that `index_bitmap`'s entries sum to 1.
    fn index_array(
        &mut self,
        array: &[impl Into<Self::Expr> + Clone],
        index_bitmap: &[impl Into<Self::Expr> + Clone],
    ) -> Self::Expr {
        let mut result = Self::Expr::zero();

        for (value, i) in array.iter().zip_eq(index_bitmap) {
            result += value.clone().into() * i.clone().into();
        }

        result
    }

    /// Extension field-related

    /// Asserts that the two field extensions are equal.
    fn assert_ext_eq<I: Into<Self::Expr>>(
        &mut self,
        left: BinomialExtension<I>,
        right: BinomialExtension<I>,
    ) {
        for (left, right) in left.0.into_iter().zip(right.0) {
            self.assert_eq(left, right);
        }
    }

    /// Checks if an extension element is a base element.
    fn assert_is_base_element<I: Into<Self::Expr> + Clone>(
        &mut self,
        element: BinomialExtension<I>,
    ) {
        let base_slice = element.as_base_slice();
        let degree = base_slice.len();
        base_slice[1..degree].iter().for_each(|coeff| {
            self.assert_zero(coeff.clone().into());
        });
    }

    /// Performs an if else on extension elements.
    fn if_else_ext(
        &mut self,
        condition: impl Into<Self::Expr> + Clone,
        a: BinomialExtension<impl Into<Self::Expr> + Clone>,
        b: BinomialExtension<impl Into<Self::Expr> + Clone>,
    ) -> BinomialExtension<Self::Expr> {
        BinomialExtension(array::from_fn(|i| {
            self.if_else(condition.clone(), a.0[i].clone(), b.0[i].clone())
        }))
    }

    /// get preprocessed trace
    /// Originally from PaiBuilder in p3
    fn preprocessed(&self) -> Self::M;
}

pub trait ChipLookupBuilder<F: Field>: ChipBuilder<F> {
    /// Looking for  an ALU operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn looking_alu(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: Word<impl Into<Self::Expr>>,
        b: Word<impl Into<Self::Expr>>,
        c: Word<impl Into<Self::Expr>>,
        chunk: impl Into<Self::Expr>,
        channel: impl Into<Self::Expr>,
        nonce: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values = once(opcode.into())
            .chain(a.0.into_iter().map(Into::into))
            .chain(b.0.into_iter().map(Into::into))
            .chain(c.0.into_iter().map(Into::into))
            .chain(once(chunk.into()))
            .chain(once(channel.into()))
            .chain(once(nonce.into()))
            .collect();

        self.looking(SymbolicLookup::new(
            values,
            multiplicity.into(),
            LookupType::Alu,
        ));
    }

    /// Looked for an ALU operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn looked_alu(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: Word<impl Into<Self::Expr>>,
        b: Word<impl Into<Self::Expr>>,
        c: Word<impl Into<Self::Expr>>,
        chunk: impl Into<Self::Expr>,
        channel: impl Into<Self::Expr>,
        nonce: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values = once(opcode.into())
            .chain(a.0.into_iter().map(Into::into))
            .chain(b.0.into_iter().map(Into::into))
            .chain(c.0.into_iter().map(Into::into))
            .chain(once(chunk.into()))
            .chain(once(channel.into()))
            .chain(once(nonce.into()))
            .collect();

        self.looked(SymbolicLookup::new(
            values,
            multiplicity.into(),
            LookupType::Alu,
        ));
    }

    /// Sends a byte operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn looking_byte(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        chunk: impl Into<Self::Expr>,
        channel: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.looking_byte_pair(
            opcode,
            a,
            Self::Expr::zero(),
            b,
            c,
            chunk,
            channel,
            multiplicity,
        );
    }

    /// Sends a byte operation with two outputs to be processed.
    #[allow(clippy::too_many_arguments)]
    fn looking_byte_pair(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a1: impl Into<Self::Expr>,
        a2: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        chunk: impl Into<Self::Expr>,
        channel: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.looking(SymbolicLookup::new(
            vec![
                opcode.into(),
                a1.into(),
                a2.into(),
                b.into(),
                c.into(),
                chunk.into(),
                channel.into(),
            ],
            multiplicity.into(),
            LookupType::Byte,
        ));
    }

    /// Receives a byte operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn looked_byte(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        chunk: impl Into<Self::Expr>,
        channel: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.looked_byte_pair(
            opcode,
            a,
            Self::Expr::zero(),
            b,
            c,
            chunk,
            channel,
            multiplicity,
        );
    }

    /// Receives a byte operation with two outputs to be processed.
    #[allow(clippy::too_many_arguments)]
    fn looked_byte_pair(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a1: impl Into<Self::Expr>,
        a2: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        chunk: impl Into<Self::Expr>,
        channel: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.looked(SymbolicLookup::new(
            vec![
                opcode.into(),
                a1.into(),
                a2.into(),
                b.into(),
                c.into(),
                chunk.into(),
                channel.into(),
            ],
            multiplicity.into(),
            LookupType::Byte,
        ));
    }
}

pub trait ChipRangeBuilder<F: Field>: ChipBuilder<F> {
    /// Check that each limb of the given slice is a u8.
    fn slice_range_check_u8(
        &mut self,
        input: &[impl Into<Self::Expr> + Clone],
        chunk: impl Into<Self::Expr> + Clone,
        channel: impl Into<Self::Expr> + Clone,
        mult: impl Into<Self::Expr> + Clone,
    ) {
        let mut index = 0;
        while index + 1 < input.len() {
            self.looking_byte(
                Self::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
                Self::Expr::zero(),
                input[index].clone(),
                input[index + 1].clone(),
                chunk.clone(),
                channel.clone(),
                mult.clone(),
            );
            index += 2;
        }
        if index < input.len() {
            self.looking_byte(
                Self::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
                Self::Expr::zero(),
                input[index].clone(),
                Self::Expr::zero(),
                chunk.clone(),
                channel.clone(),
                mult.clone(),
            );
        }
    }

    /// Check that each limb of the given slice is a u16.
    fn slice_range_check_u16(
        &mut self,
        input: &[impl Into<Self::Expr> + Copy],
        chunk: impl Into<Self::Expr> + Clone,
        channel: impl Into<Self::Expr> + Clone,
        mult: impl Into<Self::Expr> + Clone,
    ) {
        input.iter().for_each(|limb| {
            self.looking_byte(
                Self::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
                *limb,
                Self::Expr::zero(),
                Self::Expr::zero(),
                chunk.clone(),
                channel.clone(),
                mult.clone(),
            );
        });
    }

    /// Verifies the inputted value is within 24 bits.
    ///
    /// This method verifies that the inputted is less than 2^24 by doing a 16 bit and 8 bit range
    /// check on it's limbs.  It will also verify that the limbs are correct.  This method is needed
    /// since the memory access timestamp check (see [Self::verify_mem_access_ts]) needs to assume
    /// the clk is within 24 bits.
    fn range_check_u24(
        &mut self,
        value: impl Into<Self::Expr>,
        limb_16: impl Into<Self::Expr> + Clone,
        limb_8: impl Into<Self::Expr> + Clone,
        chunk: impl Into<Self::Expr> + Clone,
        channel: impl Into<Self::Expr> + Clone,
        do_check: impl Into<Self::Expr> + Clone,
    ) {
        // Verify that value = limb_16 + limb_8 * 2^16.
        self.when(do_check.clone()).assert_eq(
            value,
            limb_16.clone().into()
                + limb_8.clone().into() * Self::Expr::from_canonical_u32(1 << 16),
        );

        // Send the range checks for the limbs.
        self.looking_byte(
            Self::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
            limb_16,
            Self::Expr::zero(),
            Self::Expr::zero(),
            chunk.clone(),
            channel.clone(),
            do_check.clone(),
        );
        self.looking_byte(
            Self::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
            Self::Expr::zero(),
            Self::Expr::zero(),
            limb_8,
            chunk.clone(),
            channel.clone(),
            do_check,
        )
    }
}

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

// aggregation of chip-related builders
impl<F: Field, CB: ChipBuilder<F>> ChipRangeBuilder<F> for CB {}
impl<F: Field, CB: ChipBuilder<F>> ChipWordBuilder<F> for CB {}
impl<F: Field, CB: ChipBuilder<F>> ChipLookupBuilder<F> for CB {}

impl<'a, F: Field, AB: AirBuilder<F = F> + PublicValuesBuilder> ChipBuilder<F>
    for FilteredAirBuilder<'a, AB>
{
    fn preprocessed(&self) -> Self::M {
        panic!("Should not be called!")
    }
}

impl<'a, AB: PublicValuesBuilder> PublicValuesBuilder for FilteredAirBuilder<'a, AB> {
    type PublicVar = AB::PublicVar;

    fn public_values(&self) -> &[Self::PublicVar] {
        self.inner.public_values()
    }
}

/// message builder for the chips.
pub trait LookupBuilder<M> {
    fn looking(&mut self, message: M);

    fn looked(&mut self, message: M);
}

/// A message builder for which sending and receiving messages is a no-op.
pub trait EmptyLookupBuilder: AirBuilder {}

impl<AB: EmptyLookupBuilder, M> LookupBuilder<M> for AB {
    fn looking(&mut self, _message: M) {}

    fn looked(&mut self, _message: M) {}
}

impl<'a, SC: StarkGenericConfig> EmptyLookupBuilder for ProverConstraintFolder<'a, SC> {}
impl<'a, SC: StarkGenericConfig> EmptyLookupBuilder for VerifierConstraintFolder<'a, SC> {}
impl<'a, F: Field, AB: AirBuilder<F = F>> EmptyLookupBuilder for FilteredAirBuilder<'a, AB> {}

/// Permutation builder to include all permutation-related variables
pub trait PermutationBuilder: AirBuilder + ExtensionBuilder {
    /// from PermutationAirBuilder
    type MP: Matrix<Self::VarEF>;

    type RandomVar: Into<Self::ExprEF> + Copy;

    fn permutation(&self) -> Self::MP;

    fn permutation_randomness(&self) -> &[Self::RandomVar];

    /// for cumulative sum
    // The type of the cumulative sum.
    type Sum: Into<Self::ExprEF>;

    // Returns the cumulative sum of the permutation.
    fn cumulative_sum(&self) -> Self::Sum;
}

/// AirBuilder with public values
/// originally from AirBuilderWithPublicValues in p3
pub trait PublicValuesBuilder: AirBuilder {
    type PublicVar: Into<Self::Expr> + Copy;

    fn public_values(&self) -> &[Self::PublicVar];
}
