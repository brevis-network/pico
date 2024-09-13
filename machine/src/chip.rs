use crate::{
    builder::{ChipProxyBuilder, MessageBuilder, PermSumAirBuilder},
    lookup::{AirInteraction, LookupPayload},
    permutation::{eval_permutation_constraints, generate_permutation_trace},
};
use itertools::Itertools;
use log::debug;
use p3_air::{Air, AirBuilder, BaseAir, FilteredAirBuilder, PairBuilder};
use p3_field::{AbstractField, ExtensionField, Field};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{get_log_quotient_degree, SymbolicAirBuilder};
use pico_compiler::record::ExecutionRecord;

/// Chip behavior
pub trait ChipBehavior<F: Field>: BaseAir<F> + Sync {
    /// Returns the name of the chip.
    fn name(&self) -> String;

    fn generate_preprocessed(&self, _input: &ExecutionRecord) -> Option<RowMajorMatrix<F>> {
        None
    }

    fn generate_main(&self, input: &ExecutionRecord) -> RowMajorMatrix<F>;

    fn preprocessed_width(&self) -> usize {
        0
    }
}

/// Chip builder
pub trait ChipBuilder<F: Field>:
    AirBuilder<F = F> + MessageBuilder<AirInteraction<Self::Expr>>
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
}

/// Chip wrapper, includes interactions
pub struct MetaChip<F: Field, C> {
    /// Underlying chip
    chip: C,
    /// messages for chip as looking table
    looking: Vec<LookupPayload<F>>,
    /// messages for chip as looked table
    looked: Vec<LookupPayload<F>>,
    /// log degree of quotient polynomial
    log_quotient_degree: usize,
}

impl<F: Field, C> MetaChip<F, C> {
    pub fn new(chip: C) -> Self
    where
        C: ChipBehavior<F> + Air<ChipProxyBuilder<F>> + Air<SymbolicAirBuilder<F>>,
    {
        let mut builder = ChipProxyBuilder::new(chip.preprocessed_width(), chip.width());
        chip.eval(&mut builder);
        let (looking, looked) = builder.lookup_message();

        // need to dive deeper, currently following p3 and some constants aren't included in chip.rs of sp1
        let log_quotient_degree =
            get_log_quotient_degree::<F, C>(&chip, chip.preprocessed_width(), 0);
        debug!(
            "chip_preprocessed_width = {}, log_quotient_degree = {}",
            chip.preprocessed_width(),
            log_quotient_degree
        );
        Self {
            chip,
            looking,
            looked,
            log_quotient_degree,
        }
    }

    pub fn generate_permutation<EF: ExtensionField<F>>(
        &self,
        preprocessed: Option<&RowMajorMatrix<F>>,
        main: &RowMajorMatrix<F>,
        perm_challenges: &[EF],
    ) -> RowMajorMatrix<EF> {
        let batch_size = 1 << self.log_quotient_degree;

        // Generate the RLC elements to uniquely identify each interaction.
        let alpha = perm_challenges[0];

        // Generate the RLC elements to uniquely identify each item in the looked up tuple.
        let beta = perm_challenges[1];

        generate_permutation_trace(
            &self.looking,
            &self.looked,
            preprocessed,
            main,
            alpha,
            beta,
            batch_size,
        )
    }

    pub fn get_log_quotient_degree(&self) -> usize {
        self.log_quotient_degree
    }
}

/// BaseAir implementation for the chip
impl<F, C> BaseAir<F> for MetaChip<F, C>
where
    F: Field,
    C: BaseAir<F>,
{
    fn width(&self) -> usize {
        self.chip.width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        panic!("Chip should not use the `BaseAir` method, but the `ChipBehavior` method.")
    }
}

/// Air implementation for the chip
impl<F, C, CB> Air<CB> for MetaChip<F, C>
where
    F: Field,
    C: Air<CB>,
    CB: ChipBuilder<F> + PermSumAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut CB) {
        self.chip.eval(builder);
        eval_permutation_constraints(
            &self.looking,
            &self.looked,
            1 << self.log_quotient_degree,
            builder,
        )
    }
}

/// Chip Behavior implementation for the chip
impl<F, C> ChipBehavior<F> for MetaChip<F, C>
where
    F: Field,
    C: ChipBehavior<F>,
{
    fn name(&self) -> String {
        self.chip.name()
    }

    fn generate_preprocessed(&self, input: &ExecutionRecord) -> Option<RowMajorMatrix<F>> {
        self.chip.generate_preprocessed(input)
    }

    fn generate_main(&self, input: &ExecutionRecord) -> RowMajorMatrix<F> {
        self.chip.generate_main(input)
    }

    fn preprocessed_width(&self) -> usize {
        self.chip.preprocessed_width()
    }
}

#[cfg(test)]
mod test {}
