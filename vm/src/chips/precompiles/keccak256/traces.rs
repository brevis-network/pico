use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
use p3_keccak_air::{generate_trace_rows, NUM_KECCAK_COLS, NUM_ROUNDS};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator, ParallelSlice};
use std::borrow::BorrowMut;
use tracing::info;

use super::{
    columns::{KeccakMemCols, NUM_KECCAK_MEM_COLS},
    KeccakPermuteChip, STATE_SIZE,
};
use crate::{
    chips::{
        chips::rangecheck::event::{RangeLookupEvent, RangeRecordBehavior},
        utils::zeroed_f_vec,
    },
    compiler::riscv::program::Program,
    emulator::riscv::{
        record::EmulationRecord, syscalls::precompiles::keccak256::event::KeccakPermuteEvent,
    },
    machine::chip::ChipBehavior,
};

impl<F: Field> BaseAir<F> for KeccakPermuteChip<F> {
    fn width(&self) -> usize {
        NUM_KECCAK_MEM_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for KeccakPermuteChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "KeccakPermute".to_string()
    }

    fn generate_preprocessed(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        None
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let chunk_size = 8;

        let blu_events: Vec<Vec<RangeLookupEvent>> = input
            .keccak_permute_events
            .par_chunks(chunk_size)
            .map(|ops: &[KeccakPermuteEvent]| {
                // The blu map stores chunk -> map(byte lookup event -> multiplicity).
                let mut blu: Vec<RangeLookupEvent> = Vec::new();
                let mut rounds = zeroed_f_vec::<F>(NUM_KECCAK_MEM_COLS * NUM_ROUNDS);
                ops.iter().for_each(|event: &KeccakPermuteEvent| {
                    Self::populate_chunk(event, &mut rounds, &mut blu);
                });
                blu
            })
            .collect();

        for blu in blu_events {
            for e in blu {
                extra.add_range_lookup_event(e);
            }
        }
    }

    fn generate_main(&self, input: &Self::Record, _output: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = input.keccak_permute_events.clone();
        info!("keccak precompile events: {:?}", events.len());
        let num_events = events.len();
        let num_rows = (num_events * NUM_ROUNDS).next_power_of_two();
        let chunk_size = 8;
        let values = vec![0u32; num_rows * NUM_KECCAK_MEM_COLS];
        let mut values = unsafe { std::mem::transmute::<Vec<u32>, Vec<F>>(values) };

        let dummy_keccak_rows = generate_trace_rows::<F>(vec![[0; STATE_SIZE]]);
        let mut dummy_chunk = Vec::new();
        for i in 0..NUM_ROUNDS {
            let dummy_row = dummy_keccak_rows.row(i);
            let mut row = [F::ZERO; NUM_KECCAK_MEM_COLS];
            row[..NUM_KECCAK_COLS].copy_from_slice(dummy_row.collect::<Vec<_>>().as_slice());
            dummy_chunk.extend_from_slice(&row);
        }

        values
            .chunks_mut(chunk_size * NUM_KECCAK_MEM_COLS * NUM_ROUNDS)
            .enumerate()
            .par_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_ROUNDS * NUM_KECCAK_MEM_COLS)
                    .enumerate()
                    .for_each(|(j, rounds)| {
                        let idx = i * chunk_size + j;
                        if idx < num_events {
                            let mut new_byte_lookup_events = Vec::new();
                            Self::populate_chunk(&events[idx], rounds, &mut new_byte_lookup_events);
                        } else {
                            rounds.copy_from_slice(&dummy_chunk[..rounds.len()]);
                        }
                    });
            });

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(values, NUM_KECCAK_MEM_COLS);

        // Write the nonce to the trace.
        for i in 0..trace.height() {
            let cols: &mut KeccakMemCols<F> =
                trace.values[i * NUM_KECCAK_MEM_COLS..(i + 1) * NUM_KECCAK_MEM_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        !record.keccak_permute_events.is_empty()
    }
}

impl<F: PrimeField32> KeccakPermuteChip<F> {
    pub fn populate_chunk(
        event: &KeccakPermuteEvent,
        rounds: &mut [F],
        new_byte_lookup_events: &mut Vec<RangeLookupEvent>,
    ) {
        let start_clk = event.clk;
        let chunk = event.chunk;

        let p3_keccak_trace = generate_trace_rows::<F>(vec![event.pre_state]);

        // Create all the rows for the permutation.
        for i in 0..NUM_ROUNDS {
            let p3_keccak_row = p3_keccak_trace.row(i);
            let row = &mut rounds[i * NUM_KECCAK_MEM_COLS..(i + 1) * NUM_KECCAK_MEM_COLS];
            // Copy p3_keccak_row into start of cols
            row[..NUM_KECCAK_COLS].copy_from_slice(p3_keccak_row.collect::<Vec<_>>().as_slice());
            let cols: &mut KeccakMemCols<F> = row.borrow_mut();

            cols.chunk = F::from_canonical_u32(chunk);
            cols.clk = F::from_canonical_u32(start_clk);
            cols.state_addr = F::from_canonical_u32(event.state_addr);
            cols.is_real = F::ONE;

            // If this is the first row, then populate read memory accesses
            if i == 0 {
                for (j, read_record) in event.state_read_records.iter().enumerate() {
                    cols.state_mem[j].populate_read(*read_record, new_byte_lookup_events);
                    new_byte_lookup_events
                        .add_u8_range_checks(read_record.value.to_le_bytes(), Some(chunk))
                }
                cols.do_memory_check = F::ONE;
                cols.receive_ecall = F::ONE;
            }

            // If this is the last row, then populate write memory accesses
            if i == NUM_ROUNDS - 1 {
                for (j, write_record) in event.state_write_records.iter().enumerate() {
                    cols.state_mem[j].populate_write(*write_record, new_byte_lookup_events);
                    new_byte_lookup_events
                        .add_u8_range_checks(write_record.value.to_le_bytes(), Some(chunk));
                }
                cols.do_memory_check = F::ONE;
            }
        }
    }
}
