use super::{
    columns::{
        FullRound, PartialRound, Poseidon2Cols, BABYBEAR_NUM_POSEIDON2_COLS,
        KOALABEAR_NUM_POSEIDON2_COLS, MERSENNE31_NUM_POSEIDON2_COLS,
    },
    Poseidon2PermuteChip,
};
use crate::{
    chips::{
        chips::rangecheck::event::{RangeLookupEvent, RangeRecordBehavior},
        poseidon2::{external_linear_layer, internal_linear_layer},
    },
    compiler::riscv::program::Program,
    emulator::{
        record::RecordBehavior,
        riscv::{
            record::EmulationRecord,
            syscalls::{
                precompiles::{poseidon2::event::Poseidon2PermuteEvent, PrecompileEvent},
                SyscallCode,
            },
        },
    },
    machine::chip::ChipBehavior,
    primitives::{
        consts::{
            BABYBEAR_NUM_EXTERNAL_ROUNDS, BABYBEAR_NUM_INTERNAL_ROUNDS,
            KOALABEAR_NUM_EXTERNAL_ROUNDS, KOALABEAR_NUM_INTERNAL_ROUNDS,
            MERSENNE31_NUM_EXTERNAL_ROUNDS, MERSENNE31_NUM_INTERNAL_ROUNDS, PERMUTATION_WIDTH,
        },
        RC_16_30_U32,
    },
    recursion_v2::stark::utils::pad_rows_fixed,
};
use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use rayon::{iter::ParallelIterator, slice::ParallelSlice};
use std::borrow::BorrowMut;
use tracing::debug;

#[rustfmt::skip]
macro_rules! impl_poseidon2_permute_chip {
    ($num_cols:expr, $num_external_rounds:expr, $num_internal_rounds:expr) => {
        impl<F: Field> BaseAir<F>
            for Poseidon2PermuteChip<F, { $num_external_rounds / 2 }, $num_internal_rounds>
        {
            fn width(&self) -> usize {
                $num_cols
            }
        }

        impl<F: PrimeField32> ChipBehavior<F>
            for Poseidon2PermuteChip<F, { $num_external_rounds / 2 }, $num_internal_rounds>
        {
            type Record = EmulationRecord;
            type Program = Program;

            fn name(&self) -> String {
                "Poseidon2Permute".to_string()
            }

            fn generate_main(
                &self,
                input: &Self::Record,
                _output: &mut Self::Record,
            ) -> RowMajorMatrix<F> {
                let events: Vec<_> = input
                    .get_precompile_events(SyscallCode::POSEIDON2_PERMUTE)
                    .iter()
                    .filter_map(|(_, event)| {
                        if let PrecompileEvent::Poseidon2Permute(event) = event {
                            Some(event)
                        } else {
                            unreachable!()
                        }
                    })
                    .collect();

                debug!(
                    "record {} poseidon2 precompile events {:?}",
                    input.chunk_index(),
                    events.len()
                );

                // Generate the trace rows & corresponding records for each chunk of events concurrently.
                let mut new_byte_lookup_events = Vec::new();

                let (mut rows, nonces): (Vec<[F; $num_cols]>, Vec<_>) = events
                    .iter()
                    .map(|event| {
                        let mut row: [F; $num_cols] = [F::ZERO; $num_cols];
                        Poseidon2PermuteChip::<
                                                F,
                                                { $num_external_rounds / 2 },
                                                $num_internal_rounds,
                                            >::event_to_row(
                                                event, Some(&mut row), &mut new_byte_lookup_events
                                            );

                        // Retrieve the nonce using the event's lookup_id.
                        let nonce = *input.nonce_lookup.get(&event.lookup_id).unwrap();

                        (row, nonce)
                    })
                    .unzip();

                let log_rows = input.shape_chip_size(&self.name());
                pad_rows_fixed(&mut rows, || [F::ZERO; $num_cols], log_rows);

                // Convert the trace to a row major matrix.
                let mut trace =
                    RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), $num_cols);

                // Write the nonces to the trace.
                for i in 0..trace.height() {
                    let cols: &mut Poseidon2Cols<
                        F,
                        { $num_external_rounds / 2 },
                        $num_internal_rounds,
                    > = trace.values[i * $num_cols..(i + 1) * $num_cols].borrow_mut();
                    let nonce = nonces.get(i).unwrap_or(&0);
                    cols.nonce = F::from_canonical_u32(*nonce);
                }

                trace
            }

            fn is_active(&self, record: &Self::Record) -> bool {
                if let Some(shape) = record.shape.as_ref() {
                    shape.included::<F, _>(self)
                } else {
                    !record
                        .get_precompile_events(SyscallCode::POSEIDON2_PERMUTE)
                        .is_empty()
                }
            }

            fn generate_preprocessed(
                &self,
                _program: &Self::Program,
            ) -> Option<p3_matrix::dense::RowMajorMatrix<F>> {
                None
            }

            fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
                let events: Vec<_> = input
                    .get_precompile_events(SyscallCode::POSEIDON2_PERMUTE)
                    .iter()
                    .filter_map(|(_, event)| {
                        if let PrecompileEvent::Poseidon2Permute(event) = event {
                            Some(event)
                        } else {
                            unreachable!()
                        }
                    })
                    .collect();

                let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);
                let blu_batches = events
                    .par_chunks(chunk_size)
                    .map(|events| {
                        let mut blu: Vec<RangeLookupEvent> = Vec::new();
                        events.iter().for_each(|event| {
                            Poseidon2PermuteChip::<
                                F,
                                {
                                    {
                                        $num_external_rounds / 2
                                    }
                                },
                                { $num_internal_rounds },
                            >::event_to_row(event, None, &mut blu);
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

        impl<F: PrimeField32>
            Poseidon2PermuteChip<F, { $num_external_rounds / 2 }, $num_internal_rounds>
        {
            fn event_to_row(
                event: &Poseidon2PermuteEvent,
                input_row: Option<&mut [F; $num_cols]>,
                blu: &mut impl RangeRecordBehavior,
            ) {
                let mut row: [F; $num_cols] = [F::ZERO; $num_cols];
                let cols: &mut Poseidon2Cols<
                    F,
                    { $num_external_rounds / 2 },
                    $num_internal_rounds,
                > = row.as_mut_slice().borrow_mut();

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

                let mut state: [F; PERMUTATION_WIDTH] = event
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

                for round in 0..$num_external_rounds / 2 {
                    Self::populate_full_round(
                        &mut state,
                        &mut cols.beginning_full_rounds[round],
                        &RC_16_30_U32[round].map(F::from_wrapped_u32),
                    );
                }

                for round in 0..$num_internal_rounds {
                    Self::populate_partial_round(
                        &mut state,
                        &mut cols.partial_rounds[round],
                        &RC_16_30_U32[round + { $num_external_rounds / 2 }]
                            .map(F::from_wrapped_u32)[0],
                    );
                }

                for round in 0..$num_external_rounds / 2 {
                    Self::populate_full_round(
                        &mut state,
                        &mut cols.ending_full_rounds[round],
                        &RC_16_30_U32[round + $num_internal_rounds + { $num_external_rounds / 2 }]
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
                state: &mut [F; PERMUTATION_WIDTH],
                full_round: &mut FullRound<F>,
                round_constants: &[F; PERMUTATION_WIDTH],
            ) {
                for (i, (s, r)) in state.iter_mut().zip(round_constants.iter()).enumerate() {
                    *s += *r;
                    Self::populate_sbox(&mut full_round.sbox_x3[i], &mut full_round.sbox_x7[i], s);
                }
                external_linear_layer(state);
                full_round.post = *state;
            }

            pub fn populate_partial_round(
                state: &mut [F; PERMUTATION_WIDTH],
                partial_round: &mut PartialRound<F>,
                round_constant: &F,
            ) {
                state[0] += *round_constant;
                Self::populate_sbox(
                    &mut partial_round.sbox_x3,
                    &mut partial_round.sbox_x7,
                    &mut state[0],
                );
                internal_linear_layer::<F, _>(state);
                partial_round.post = *state;
            }

            #[inline]
            pub fn populate_sbox(sbox_x3: &mut F, sbox_x7: &mut F, x: &mut F) {
                *sbox_x3 = x.cube();
                *sbox_x7 = sbox_x3.square() * *x;
                *x = *sbox_x7
            }
        }
    };
}

impl_poseidon2_permute_chip!(
    BABYBEAR_NUM_POSEIDON2_COLS,
    BABYBEAR_NUM_EXTERNAL_ROUNDS,
    BABYBEAR_NUM_INTERNAL_ROUNDS
);

impl_poseidon2_permute_chip!(
    KOALABEAR_NUM_POSEIDON2_COLS,
    KOALABEAR_NUM_EXTERNAL_ROUNDS,
    KOALABEAR_NUM_INTERNAL_ROUNDS
);

impl_poseidon2_permute_chip!(
    MERSENNE31_NUM_POSEIDON2_COLS,
    MERSENNE31_NUM_EXTERNAL_ROUNDS,
    MERSENNE31_NUM_INTERNAL_ROUNDS
);
