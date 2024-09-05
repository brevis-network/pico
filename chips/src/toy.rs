//! Toy chip used for chip initialization tests

use itertools::Itertools;
use p3_air::{Air, BaseAir};
use p3_field::{AbstractField, Field};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::ParallelIterator;
use pico_compiler::{opcode::Opcode, record::ExecutionRecord};
use pico_machine::{
    chip::{ChipBehavior, ChipBuilder},
    utils::pad_to_power_of_two,
};
use std::{marker::PhantomData, mem::size_of};

/// The number of main trace columns for `ToyChip`
pub const NUM_TOY_COLS: usize = size_of::<ToyCols<u8>>();

/// The name of toy chip
const TOY_CHIP_NAME: &str = "Toy";

/// A chip that implements a simple addition for two bytes.
#[derive(Debug, Default)]
pub struct ToyChip<F>(PhantomData<F>);

/// The column layout for toy chip
#[derive(Debug)]
pub struct ToyCols<T> {
    pub a: T,
    pub b: T,
    pub result: T,
    pub is_add: T,
}

impl<'a, T: Clone> ToyCols<&'a T> {
    fn new(a: &'a T, b: &'a T, result: &'a T, is_add: &'a T) -> Self {
        Self {
            a,
            b,
            result,
            is_add,
        }
    }

    fn to_row(&self) -> [T; NUM_TOY_COLS] {
        [self.a, self.b, self.result, self.is_add].map(Clone::clone)
    }
}

impl<F: Field> ChipBehavior<F> for ToyChip<F> {
    fn name(&self) -> String {
        TOY_CHIP_NAME.to_string()
    }

    fn generate_preprocessed(&self, input: &ExecutionRecord) -> Option<RowMajorMatrix<F>> {
        // NOTE: It's not reasonable, just for testing.
        Some(self.generate_main(input))
    }

    fn generate_main(&self, input: &ExecutionRecord) -> RowMajorMatrix<F> {
        // Generate the rows for the trace.
        let merged_events = input
            .add_events
            .iter()
            .chain(input.sub_events.iter())
            .collect_vec();

        let rows = merged_events
            .iter()
            .flat_map(|event| {
                let is_add = match event.opcode {
                    Opcode::ADD => 1_u32,
                    Opcode::SUB => 0,
                    _ => unreachable!(),
                };

                let [a, b, result, is_add] =
                    [event.a, event.b, event.c, is_add].map(|v| F::from_canonical_u8(v as u8));

                ToyCols::new(&a, &b, &result, &is_add).to_row()
            })
            .collect_vec();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(rows, NUM_TOY_COLS);

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_TOY_COLS, F>(&mut trace.values);

        trace
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
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let row = main.row_slice(0);
        let local = ToyCols::new(&row[0], &row[1], &row[2], &row[3]);

        let one = CB::Expr::one();

        let [a, b, result, is_add] = [*local.a, *local.b, *local.result, *local.is_add];

        builder.assert_bool(is_add);
        builder.assert_zero(a + is_add * b - (one - is_add) * b - result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use pico_compiler::events::alu::AluEvent;
    use rand::{thread_rng, Rng};
    use std::{array, collections::HashMap};

    type F = BabyBear;

    // Testing input events used to generate the main trace
    const TEST_INPUT_EVENTS: [AluEvent; 3] = [
        AluEvent::new(Opcode::ADD, 1, 2, 3),
        AluEvent::new(Opcode::SUB, 6, 2, 4),
        AluEvent::new(Opcode::SUB, 6, 6, 0),
    ];

    #[test]
    fn test_toy_cols() {
        let rng = &mut thread_rng();

        let [a, b, result] = array::from_fn(|_| F::from_canonical_u8(rng.gen()));
        let is_add = F::from_bool(rng.gen::<bool>());
        let cols = ToyCols::new(&a, &b, &result, &is_add);

        let mut expected_row = vec![a, b, result, is_add];
        pad_to_power_of_two::<NUM_TOY_COLS, F>(&mut expected_row);
        assert_eq!(cols.to_row(), [a, b, result, is_add]);
    }

    #[test]
    fn test_toy_chip() {
        let chip: ToyChip<F> = ToyChip::default();

        assert_eq!(chip.name(), TOY_CHIP_NAME);
        assert_eq!(chip.width(), NUM_TOY_COLS);

        let rows = TEST_INPUT_EVENTS
            .into_iter()
            .flat_map(|event| {
                let is_add = match event.opcode {
                    Opcode::ADD => 1_u32,
                    Opcode::SUB => 0,
                    _ => unreachable!(),
                };

                [event.a, event.b, event.c, is_add].map(|v| F::from_canonical_u8(v as u8))
            })
            .collect_vec();
        let mut expected_trace = RowMajorMatrix::new(rows, NUM_TOY_COLS);
        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_TOY_COLS, F>(&mut expected_trace.values);

        let mut record = ExecutionRecord::new();
        let mut events = HashMap::new();
        TEST_INPUT_EVENTS.into_iter().for_each(|event| {
            events
                .entry(event.opcode)
                .or_insert_with(Vec::new)
                .push(event);
        });
        record.add_alu_events(events);
        let real_trace = chip.generate_main(&record);
        assert_eq!(real_trace, expected_trace);
    }

    // TODO: Add tests for proving and verification.
}
