//! Toy chip used for chip initialization tests

use itertools::Itertools;
use p3_air::{Air, BaseAir};
use p3_field::{AbstractField, Field, PrimeField};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::ParallelIterator;
use pico_machine::chip::{ChipBehavior, ChipBuilder};
use std::{marker::PhantomData, mem::size_of};

/// The number of main trace columns for `ToyChip`
pub const NUM_TOY_COLS: usize = size_of::<ToyCols<u8>>();

/// The name of toy chip
const TOY_CHIP_NAME: &str = "Toy";

/// Testing input events used to generate the main trace
const INPUT_EVENTS: [[u8; 3]; 4] = [[1, 2, 3], [2, 4, 6], [5, 3, 8], [0, 6, 6]];

/// A chip that implements a simple addition for two bytes.
#[derive(Debug, Default)]
pub struct ToyChip<F>(PhantomData<F>);

// #[derive(Default)]
// pub struct ToyChip2<F>(PhantomData<F>);

/// The column layout for toy chip
#[derive(Debug)]
pub struct ToyCols<T> {
    pub a: T,
    pub b: T,
    pub result: T,
}

impl<'a, T: Clone> ToyCols<&'a T> {
    fn new(a: &'a T, b: &'a T, result: &'a T) -> Self {
        Self { a, b, result }
    }

    fn to_row(&self) -> [T; NUM_TOY_COLS] {
        [self.a, self.b, self.result].map(Clone::clone)
    }
}

impl<F: Field> ChipBehavior<F> for ToyChip<F> {
    fn name(&self) -> String {
        TOY_CHIP_NAME.to_string()
    }

    fn generate_preprocessed(&self) -> Option<RowMajorMatrix<F>> {
        None
    }

    fn generate_main(&self) -> RowMajorMatrix<F> {
        // Generate the rows for the trace.
        let rows = INPUT_EVENTS
            .into_iter()
            .flat_map(|cols| {
                let [a, b, result] = cols.map(F::from_canonical_u8);

                ToyCols::new(&a, &b, &result).to_row()
            })
            .collect_vec();

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows, NUM_TOY_COLS)
    }
}

impl<F: Field> BaseAir<F> for ToyChip<F> {
    fn width(&self) -> usize {
        NUM_TOY_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        None
    }
}

impl<F, CB> Air<CB> for ToyChip<F>
where
    F: Field,
    CB: ChipBuilder<F>,
{
    fn eval(&self, b: &mut CB) {
        let main = b.main();
        let row = main.row_slice(0);
        let local = ToyCols::new(&row[0], &row[1], &row[2]);

        b.assert_zero(*local.a + *local.b - *local.result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use rand::{thread_rng, Rng};
    use std::array;

    type F = BabyBear;

    #[test]
    fn test_toy_cols() {
        let rng = &mut thread_rng();

        let [a, b, result] = array::from_fn(|_| F::from_canonical_u8(rng.gen()));
        let cols = ToyCols::new(&a, &b, &result);

        assert_eq!(cols.to_row(), [a, b, result]);
    }

    #[test]
    fn test_toy_chip() {
        let chip: ToyChip<F> = ToyChip::default();

        assert_eq!(chip.name(), TOY_CHIP_NAME);
        assert_eq!(chip.width(), NUM_TOY_COLS);

        let rows = INPUT_EVENTS
            .into_iter()
            .flat_map(|cols| cols.map(F::from_canonical_u8))
            .collect_vec();
        let expected_trace = RowMajorMatrix::new(rows, NUM_TOY_COLS);
        let real_trace = chip.generate_main();
        assert_eq!(real_trace, expected_trace);
    }

    // TODO: Add tests for proving and verification.
}
