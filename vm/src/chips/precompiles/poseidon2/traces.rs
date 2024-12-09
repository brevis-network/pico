use std::borrow::BorrowMut;

use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use rayon::{iter::ParallelIterator, slice::ParallelSlice};

use crate::{
    chips::chips::{
        poseidon2_wide::{external_linear_layer, internal_linear_layer},
        poseidon2_wide_v2::{NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, WIDTH},
        rangecheck::event::{RangeLookupEvent, RangeRecordBehavior},
    },
    compiler::riscv::program::Program,
    emulator::riscv::{
        record::EmulationRecord, syscalls::precompiles::poseidon2::event::Poseidon2PermuteEvent,
    },
    machine::chip::ChipBehavior,
    primitives::RC_16_30_U32,
    recursion::stark::utils::pad_rows_fixed,
};

use super::{
    columns::{FullRound, PartialRound, Poseidon2Cols, NUM_POSEIDON2_COLS},
    Poseidon2PermuteChip,
};

impl<F: Field> BaseAir<F> for Poseidon2PermuteChip<F> {
    fn width(&self) -> usize {
        NUM_POSEIDON2_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for Poseidon2PermuteChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Poseidon2Permute".to_string()
    }

    fn generate_main(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
    ) -> p3_matrix::dense::RowMajorMatrix<F> {
        // Generate the trace rows & corresponding records for each chunk of events concurrently.
        let mut new_byte_lookup_events = Vec::new();

        let (_rows, nonces): (Vec<[F; NUM_POSEIDON2_COLS]>, Vec<_>) = input
            .poseidon2_permute_events
            .iter()
            .map(|event| {
                let mut row: [F; NUM_POSEIDON2_COLS] = [F::ZERO; NUM_POSEIDON2_COLS];

                Poseidon2PermuteChip::event_to_row(
                    event,
                    Some(&mut row),
                    &mut new_byte_lookup_events,
                );

                // Retrieve the nonce using the event's lookup_id.
                let nonce = *input.nonce_lookup.get(&event.lookup_id).unwrap();

                (row, nonce)
            })
            .unzip();

        let mut rows = _rows.clone();

        pad_rows_fixed(&mut rows, || [F::ZERO; NUM_POSEIDON2_COLS], None);

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_POSEIDON2_COLS,
        );

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut Poseidon2Cols<F> =
                trace.values[i * NUM_POSEIDON2_COLS..(i + 1) * NUM_POSEIDON2_COLS].borrow_mut();
            let nonce = nonces.get(i).unwrap_or(&0);
            cols.nonce = F::from_canonical_u32(*nonce);
        }

        trace
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        !record.poseidon2_permute_events.is_empty()
    }

    fn generate_preprocessed(
        &self,
        _program: &Self::Program,
    ) -> Option<p3_matrix::dense::RowMajorMatrix<F>> {
        None
    }

    fn extra_record(&self, input: &mut Self::Record, extra: &mut Self::Record) {
        let events = input.poseidon2_permute_events.clone();
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);
        let blu_batches = events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: Vec<RangeLookupEvent> = Vec::new();
                events.iter().for_each(|event| {
                    Poseidon2PermuteChip::<F>::event_to_row(event, None, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();
        for blu in blu_batches {
            for e in blu {
                extra.add_range_lookup_event(e);
            }
        }
    }
}

impl<F: PrimeField32> Poseidon2PermuteChip<F> {
    fn event_to_row(
        event: &Poseidon2PermuteEvent,
        input_row: Option<&mut [F; NUM_POSEIDON2_COLS]>,
        blu: &mut impl RangeRecordBehavior,
    ) {
        let mut row: [F; NUM_POSEIDON2_COLS] = [F::ZERO; NUM_POSEIDON2_COLS];
        let cols: &mut Poseidon2Cols<F> = row.as_mut_slice().borrow_mut();

        // Assign basic values to the columns.
        cols.is_real = F::ONE;
        cols.chunk = F::from_canonical_u32(event.chunk);
        cols.clk = F::from_canonical_u32(event.clk);
        cols.input_memory_ptr = F::from_canonical_u32(event.input_memory_ptr);
        cols.output_memory_ptr = F::from_canonical_u32(event.output_memory_ptr);

        // Populate memory columns.
        for (i, read_record) in event.state_read_records.iter().enumerate() {
            cols.input_memory[i].populate(*read_record, blu);
        }

        let mut state: [F; WIDTH] = event
            .state_values
            .clone()
            .into_iter()
            .map(F::from_wrapped_u32)
            .collect::<Vec<F>>()
            .try_into()
            .unwrap();

        cols.inputs = state;

        // Perform permutation on the state
        external_linear_layer(&mut state);
        cols.state_linear_layer = state;

        for round in 0..NUM_EXTERNAL_ROUNDS / 2 {
            Self::populate_full_round(
                &mut state,
                &mut cols.beginning_full_rounds[round],
                &RC_16_30_U32[round].map(F::from_wrapped_u32),
            );
        }

        for round in 0..NUM_INTERNAL_ROUNDS {
            Self::populate_partial_round(
                &mut state,
                &mut cols.partial_rounds[round],
                &RC_16_30_U32[round + NUM_EXTERNAL_ROUNDS / 2].map(F::from_wrapped_u32)[0],
            );
        }

        for round in 0..NUM_EXTERNAL_ROUNDS / 2 {
            Self::populate_full_round(
                &mut state,
                &mut cols.ending_full_rounds[round],
                &RC_16_30_U32[round + NUM_INTERNAL_ROUNDS + NUM_EXTERNAL_ROUNDS / 2]
                    .map(F::from_wrapped_u32),
            );
        }

        for (i, write_record) in event.state_write_records.iter().enumerate() {
            cols.output_memory[i].populate(*write_record, blu);
        }

        if input_row.as_ref().is_some() {
            input_row.unwrap().copy_from_slice(&row);
        }
    }

    pub fn populate_full_round(
        state: &mut [F; WIDTH],
        full_round: &mut FullRound<F>,
        round_constants: &[F; WIDTH],
    ) {
        for (i, (s, r)) in state.iter_mut().zip(round_constants.iter()).enumerate() {
            *s = *s + *r;
            Self::populate_sbox(&mut full_round.sbox_x3[i], &mut full_round.sbox_x7[i], s);
        }
        external_linear_layer(state);
        full_round.post = *state;
    }

    pub fn populate_partial_round(
        state: &mut [F; WIDTH],
        partial_round: &mut PartialRound<F>,
        round_constant: &F,
    ) {
        state[0] = state[0] + *round_constant;
        Self::populate_sbox(
            &mut partial_round.sbox_x3,
            &mut partial_round.sbox_x7,
            &mut state[0],
        );
        internal_linear_layer(state);
        partial_round.post = *state;
    }

    #[inline]
    pub fn populate_sbox(sbox_x3: &mut F, sbox_x7: &mut F, x: &mut F) {
        *sbox_x3 = x.cube();
        *sbox_x7 = sbox_x3.square() * *x;
        *x = *sbox_x7
    }
}
