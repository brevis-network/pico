use super::Poseidon2ChipP3;
use crate::{
    chips::{
        gadgets::poseidon2::{
            columns::{Poseidon2ValueCols, NUM_POSEIDON2_VALUE_COLS, RISCV_NUM_POSEIDON2_COLS},
            traces::populate_perm,
        },
        utils::next_power_of_two,
    },
    compiler::riscv::program::Program,
    emulator::riscv::record::EmulationRecord,
    machine::{chip::ChipBehavior, field::same_field},
    primitives::consts::{PERMUTATION_WIDTH, RISCV_POSEIDON2_DATAPAR},
};
use p3_air::BaseAir;
use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{IntoParallelIterator, ParallelIterator};
use p3_mersenne_31::Mersenne31;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use rayon::{iter::IndexedParallelIterator, join, slice::ParallelSliceMut};
use std::borrow::BorrowMut;

impl<
        F: PrimeField32,
        LinearLayers: GenericPoseidon2LinearLayers<F, PERMUTATION_WIDTH>,
        const FIELD_HALF_FULL_ROUNDS: usize,
        const FIELD_PARTIAL_ROUNDS: usize,
        const FIELD_SBOX_REGISTERS: usize,
    > ChipBehavior<F>
    for Poseidon2ChipP3<
        F,
        LinearLayers,
        FIELD_HALF_FULL_ROUNDS,
        FIELD_PARTIAL_ROUNDS,
        FIELD_SBOX_REGISTERS,
    >
where
    Poseidon2ChipP3<
        F,
        LinearLayers,
        FIELD_HALF_FULL_ROUNDS,
        FIELD_PARTIAL_ROUNDS,
        FIELD_SBOX_REGISTERS,
    >: BaseAir<F>,
{
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        if same_field::<F, BabyBear, 4>() {
            "RiscvBabyBearPoseidon2"
        } else if same_field::<F, KoalaBear, 4>() {
            "RiscvKoalaBearPoseidon2"
        } else if same_field::<F, Mersenne31, 3>() {
            "RiscvMersenne31Poseidon2"
        } else {
            panic!("Unsupported field type");
        }
        .to_string()
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.poseidon2_events;
        let nrows = events.len().div_ceil(RISCV_POSEIDON2_DATAPAR);
        let log_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = next_power_of_two(nrows, log_nrows);

        // Calculate total size once
        let total_cols = RISCV_NUM_POSEIDON2_COLS::<
            FIELD_HALF_FULL_ROUNDS,
            FIELD_PARTIAL_ROUNDS,
            FIELD_SBOX_REGISTERS,
        >;
        let value_cols = NUM_POSEIDON2_VALUE_COLS::<
            FIELD_HALF_FULL_ROUNDS,
            FIELD_PARTIAL_ROUNDS,
            FIELD_SBOX_REGISTERS,
        >;

        // Initialize values in parallel
        let mut values: Vec<F> = (0..padded_nrows * total_cols)
            .into_par_iter()
            .map(|_| F::ZERO)
            .collect();

        let populate_len = events.len() * value_cols;
        let (values_pop, values_dummy) = values.split_at_mut(populate_len);

        // Create a shared dummy row that can be reused
        let dummy_row = {
            let mut dummy = vec![F::ZERO; value_cols];
            let dummy_cols: &mut Poseidon2ValueCols<
                F,
                FIELD_HALF_FULL_ROUNDS,
                FIELD_PARTIAL_ROUNDS,
                FIELD_SBOX_REGISTERS,
            > = dummy.as_mut_slice().borrow_mut();

            populate_perm::<
                F,
                LinearLayers,
                FIELD_HALF_FULL_ROUNDS,
                FIELD_PARTIAL_ROUNDS,
                FIELD_SBOX_REGISTERS,
            >(
                F::ZERO,
                dummy_cols,
                [F::ZERO; PERMUTATION_WIDTH],
                None,
                &self.constants,
            );
            dummy
        };

        // Process both parts in parallel using join
        join(
            || {
                // Process actual values in parallel
                values_pop
                    .par_chunks_mut(value_cols)
                    .zip_eq(events)
                    .for_each(|(row, event)| {
                        let cols: &mut Poseidon2ValueCols<
                            F,
                            FIELD_HALF_FULL_ROUNDS,
                            FIELD_PARTIAL_ROUNDS,
                            FIELD_SBOX_REGISTERS,
                        > = row.borrow_mut();
                        populate_perm::<
                            F,
                            LinearLayers,
                            FIELD_HALF_FULL_ROUNDS,
                            FIELD_PARTIAL_ROUNDS,
                            FIELD_SBOX_REGISTERS,
                        >(
                            F::ONE,
                            cols,
                            event.input.map(F::from_canonical_u32),
                            Some(event.output.map(F::from_canonical_u32)),
                            &self.constants,
                        );
                    });
            },
            || {
                // Process dummy values in parallel using the pre-computed dummy row
                values_dummy
                    .par_chunks_mut(value_cols)
                    .for_each(|row| row.copy_from_slice(&dummy_row));
            },
        );

        RowMajorMatrix::new(values, total_cols)
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }

    fn local_only(&self) -> bool {
        true
    }
}
