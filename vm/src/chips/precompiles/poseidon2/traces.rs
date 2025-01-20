use super::{
    columns::{num_poseidon2_cols, FullRound, PartialRound, Poseidon2Cols},
    Poseidon2PermuteChip,
};
use crate::{
    chips::{
        chips::{
            byte::event::ByteRecordBehavior,
            events::ByteLookupEvent,
            poseidon2::utils::{external_linear_layer, internal_linear_layer},
        },
        utils::pad_rows_fixed,
    },
    compiler::riscv::program::Program,
    configs::config::Poseidon2Config,
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
    primitives::{consts::PERMUTATION_WIDTH, RC_16_30_U32},
};
use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use rayon::{iter::ParallelIterator, slice::ParallelSlice};
use std::borrow::BorrowMut;
use tracing::debug;

impl<F: Field, Config: Poseidon2Config> BaseAir<F> for Poseidon2PermuteChip<F, Config> {
    fn width(&self) -> usize {
        num_poseidon2_cols::<Config>()
    }
}

impl<F: PrimeField32, Config: Poseidon2Config> ChipBehavior<F> for Poseidon2PermuteChip<F, Config> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Poseidon2Permute".to_string()
    }

    fn generate_main(&self, input: &Self::Record, _output: &mut Self::Record) -> RowMajorMatrix<F> {
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

        let mut rows: Vec<Vec<F>> = events
            .iter()
            .map(|event| {
                //let mut row: [F; $num_cols] = [F::ZERO; $num_cols];
                // use a Vec because the size is too large to make a generic array
                let mut row = Vec::new();
                Poseidon2PermuteChip::<F, Config>::event_to_row(
                    event,
                    Some(&mut row),
                    &mut new_byte_lookup_events,
                );

                row
            })
            .collect();

        let log_rows = input.shape_chip_size(&self.name());
        pad_rows_fixed(&mut rows, || vec![F::ZERO; self.width()], log_rows);

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), self.width())
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
                let mut blu: Vec<ByteLookupEvent> = Vec::new();
                events.iter().for_each(|event| {
                    Poseidon2PermuteChip::<F, Config>::event_to_row(event, None, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();
        for blu in blu_batches {
            for e in blu {
                extra.add_byte_lookup_event(e);
            }
        }
    }
}

impl<F: PrimeField32, Config: Poseidon2Config> Poseidon2PermuteChip<F, Config> {
    fn event_to_row(
        event: &Poseidon2PermuteEvent,
        input_row: Option<&mut Vec<F>>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        // use Vec because num_cols is too large
        //let mut row: [F; $num_cols] = [F::ZERO; $num_cols];
        let mut row = vec![F::ZERO; num_poseidon2_cols::<Config>()];
        let cols: &mut Poseidon2Cols<F, Config> = row.as_mut_slice().borrow_mut();

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

        for round in 0..Self::NUM_EXTERNAL_ROUNDS / 2 {
            Self::populate_full_round(
                &mut state,
                &mut cols.beginning_full_rounds[round],
                &RC_16_30_U32[round].map(F::from_wrapped_u32),
            );
        }

        for round in 0..Self::NUM_INTERNAL_ROUNDS {
            Self::populate_partial_round(
                &mut state,
                &mut cols.partial_rounds[round],
                &RC_16_30_U32[round + { Self::NUM_EXTERNAL_ROUNDS / 2 }].map(F::from_wrapped_u32)
                    [0],
            );
        }

        for round in 0..Self::NUM_EXTERNAL_ROUNDS / 2 {
            Self::populate_full_round(
                &mut state,
                &mut cols.ending_full_rounds[round],
                &RC_16_30_U32
                    [round + Self::NUM_INTERNAL_ROUNDS + { Self::NUM_EXTERNAL_ROUNDS / 2 }]
                .map(F::from_wrapped_u32),
            );
        }

        for (i, write_record) in event.state_write_records.iter().enumerate() {
            cols.output_memory[i].populate(*write_record, blu);
        }

        if let Some(input_row) = input_row {
            *input_row = row;
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
