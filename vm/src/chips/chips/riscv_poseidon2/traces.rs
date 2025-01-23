use super::Poseidon2ChipP3;
use crate::{
    chips::{
        gadgets::poseidon2::{
            columns::{Poseidon2ValueCols, NUM_POSEIDON2_COLS, NUM_POSEIDON2_VALUE_COLS},
            traces::populate_perm,
        },
        utils::next_power_of_two,
    },
    compiler::riscv::program::Program,
    emulator::riscv::record::EmulationRecord,
    machine::chip::ChipBehavior,
    primitives::consts::{PERMUTATION_WIDTH, RISCV_POSEIDON2_DATAPAR},
};
use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::ParallelIterator;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use rayon::{iter::IndexedParallelIterator, join, slice::ParallelSliceMut};
use std::borrow::BorrowMut;

impl<F: PrimeField32, LinearLayers: GenericPoseidon2LinearLayers<F, PERMUTATION_WIDTH>>
    ChipBehavior<F> for Poseidon2ChipP3<F, LinearLayers>
where
    Poseidon2ChipP3<F, LinearLayers>: BaseAir<F>,
{
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        format!("Poseidon2Riscv")
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.poseidon2_events;
        let nb_rows = events.len().div_ceil(RISCV_POSEIDON2_DATAPAR);
        let log_rows = input.shape_chip_size(&self.name());
        let padded_nb_rows = next_power_of_two(nb_rows, log_rows);

        let mut values = vec![F::ZERO; padded_nb_rows * NUM_POSEIDON2_COLS];

        let populate_len = events.len() * NUM_POSEIDON2_VALUE_COLS;
        let (values_pop, values_dummy) = values.split_at_mut(populate_len);
        join(
            || {
                values_pop
                    .par_chunks_mut(NUM_POSEIDON2_VALUE_COLS)
                    .zip_eq(events)
                    .for_each(|(row, event)| {
                        let cols: &mut Poseidon2ValueCols<F> = row.borrow_mut();
                        populate_perm::<F, LinearLayers>(
                            F::ONE,
                            cols,
                            event.input.map(F::from_canonical_u32),
                            Some(event.output.map(F::from_canonical_u32)),
                            &self.constants,
                        );
                    });
            },
            || {
                let mut dummy = vec![F::ZERO; NUM_POSEIDON2_VALUE_COLS];
                let dummy = dummy.as_mut_slice();
                let dummy_cols: &mut Poseidon2ValueCols<F> = dummy.borrow_mut();
                populate_perm::<F, LinearLayers>(
                    F::ZERO,
                    dummy_cols,
                    [F::ZERO; PERMUTATION_WIDTH],
                    None,
                    &self.constants,
                );
                values_dummy
                    .par_chunks_mut(NUM_POSEIDON2_VALUE_COLS)
                    .for_each(|row| row.copy_from_slice(&dummy))
            },
        );

        RowMajorMatrix::new(values, NUM_POSEIDON2_COLS)
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }

    fn local_only(&self) -> bool {
        true
    }
}
