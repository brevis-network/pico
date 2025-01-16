use super::{
    columns::{MemoryLocalCols, NUM_LOCAL_MEMORY_ENTRIES_PER_ROW, NUM_MEMORY_LOCAL_INIT_COLS},
    MemoryLocalChip,
};
use crate::{
    chips::{chips::byte::event::ByteRecordBehavior, utils::zeroed_f_vec},
    compiler::riscv::program::Program,
    emulator::riscv::record::EmulationRecord,
    machine::{
        chip::ChipBehavior,
        lookup::LookupScope,
        septic::{SepticCurve, SepticCurveComplete, SepticDigest, SepticExtension},
    },
    recursion_v2::stark::utils::next_power_of_two,
};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use rayon_scan::ScanParallelIterator;
use std::borrow::BorrowMut;

impl<F: PrimeField32> ChipBehavior<F> for MemoryLocalChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "MemoryLocal".to_string()
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        _output: &mut EmulationRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let events = input.get_local_mem_events().collect::<Vec<_>>();
        let nb_rows = (events.len() + 3) / 4;
        let log_rows = input.shape_chip_size(&self.name());
        let padded_nb_rows = next_power_of_two(nb_rows, log_rows);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_MEMORY_LOCAL_INIT_COLS);
        let chunk_size = std::cmp::max(nb_rows / num_cpus::get(), 0) + 1;

        let mut chunks = values[..nb_rows * NUM_MEMORY_LOCAL_INIT_COLS]
            .chunks_mut(chunk_size * NUM_MEMORY_LOCAL_INIT_COLS)
            .collect::<Vec<_>>();

        let point_chunks = chunks
            .par_iter_mut()
            .enumerate()
            .map(|(i, rows)| {
                let mut point_chunks =
                    Vec::with_capacity(chunk_size * NUM_LOCAL_MEMORY_ENTRIES_PER_ROW * 2 + 1);
                if i == 0 {
                    point_chunks.push(SepticCurveComplete::Affine(SepticDigest::<F>::zero().0));
                }
                rows.chunks_mut(NUM_MEMORY_LOCAL_INIT_COLS)
                    .enumerate()
                    .for_each(|(j, row)| {
                        let idx = (i * chunk_size + j) * NUM_LOCAL_MEMORY_ENTRIES_PER_ROW;

                        let cols: &mut MemoryLocalCols<F> = row.borrow_mut();
                        for k in 0..NUM_LOCAL_MEMORY_ENTRIES_PER_ROW {
                            let cols = &mut cols.memory_local_entries[k];
                            if idx + k < events.len() {
                                let event = &events[idx + k];
                                cols.addr = F::from_canonical_u32(event.addr);
                                cols.initial_chunk =
                                    F::from_canonical_u32(event.initial_mem_access.chunk);
                                cols.final_chunk =
                                    F::from_canonical_u32(event.final_mem_access.chunk);
                                cols.initial_clk =
                                    F::from_canonical_u32(event.initial_mem_access.timestamp);
                                cols.final_clk =
                                    F::from_canonical_u32(event.final_mem_access.timestamp);
                                cols.initial_value = event.initial_mem_access.value.into();
                                cols.final_value = event.final_mem_access.value.into();
                                cols.is_real = F::ONE;
                                cols.initial_global_interaction_cols.populate_memory(
                                    event.initial_mem_access.chunk,
                                    event.initial_mem_access.timestamp,
                                    event.addr,
                                    event.initial_mem_access.value,
                                    true,
                                    true,
                                );
                                point_chunks.push(SepticCurveComplete::Affine(SepticCurve {
                                    x: SepticExtension(
                                        cols.initial_global_interaction_cols.x_coordinate.0,
                                    ),
                                    y: SepticExtension(
                                        cols.initial_global_interaction_cols.y_coordinate.0,
                                    ),
                                }));
                                cols.final_global_interaction_cols.populate_memory(
                                    event.final_mem_access.chunk,
                                    event.final_mem_access.timestamp,
                                    event.addr,
                                    event.final_mem_access.value,
                                    false,
                                    true,
                                );
                                point_chunks.push(SepticCurveComplete::Affine(SepticCurve {
                                    x: SepticExtension(
                                        cols.final_global_interaction_cols.x_coordinate.0,
                                    ),
                                    y: SepticExtension(
                                        cols.final_global_interaction_cols.y_coordinate.0,
                                    ),
                                }));
                            } else {
                                cols.initial_global_interaction_cols.populate_dummy();
                                cols.final_global_interaction_cols.populate_dummy();
                            }
                        }
                    });
                point_chunks
            })
            .collect::<Vec<_>>();

        let mut points = Vec::with_capacity(1 + events.len() * 2);
        for mut point_chunk in point_chunks {
            points.append(&mut point_chunk);
        }

        if events.is_empty() {
            points = vec![SepticCurveComplete::Affine(SepticDigest::<F>::zero().0)];
        }

        let cumulative_sum = points
            .into_par_iter()
            .with_min_len(1 << 15)
            .scan(|a, b| *a + *b, SepticCurveComplete::Infinity)
            .collect::<Vec<SepticCurveComplete<F>>>();

        let final_digest = cumulative_sum.last().unwrap().point();
        let dummy = SepticCurve::<F>::dummy();
        let final_sum_checker = SepticCurve::<F>::sum_checker_x(final_digest, dummy, final_digest);

        let chunk_size = std::cmp::max(padded_nb_rows / num_cpus::get(), 0) + 1;
        values
            .chunks_mut(chunk_size * NUM_MEMORY_LOCAL_INIT_COLS)
            .enumerate()
            .par_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_MEMORY_LOCAL_INIT_COLS)
                    .enumerate()
                    .for_each(|(j, row)| {
                        let idx = i * chunk_size + j;

                        let cols: &mut MemoryLocalCols<F> = row.borrow_mut();
                        if idx < nb_rows {
                            let start = NUM_LOCAL_MEMORY_ENTRIES_PER_ROW * 2 * idx;
                            let end = std::cmp::min(
                                NUM_LOCAL_MEMORY_ENTRIES_PER_ROW * 2 * (idx + 1) + 1,
                                cumulative_sum.len(),
                            );
                            cols.global_accumulation_cols.populate_real(
                                &cumulative_sum[start..end],
                                final_digest,
                                final_sum_checker,
                            );
                        } else {
                            for k in 0..NUM_LOCAL_MEMORY_ENTRIES_PER_ROW {
                                cols.memory_local_entries[k]
                                    .initial_global_interaction_cols
                                    .populate_dummy();
                                cols.memory_local_entries[k]
                                    .final_global_interaction_cols
                                    .populate_dummy();
                            }
                            cols.global_accumulation_cols
                                .populate_dummy(final_digest, final_sum_checker);
                        }
                    })
            });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_MEMORY_LOCAL_INIT_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let events = input.get_local_mem_events().collect::<Vec<_>>();
        let nb_rows = (events.len() + 3) / 4;
        let chunk_size = std::cmp::max((nb_rows + 1) / num_cpus::get(), 1);

        let blu_events = events
            .par_chunks(chunk_size * NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
            .flat_map(|events| {
                let mut blu = vec![];
                events
                    .chunks(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
                    .for_each(|events| {
                        let mut row = [F::ZERO; NUM_MEMORY_LOCAL_INIT_COLS];
                        let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();
                        for k in 0..NUM_LOCAL_MEMORY_ENTRIES_PER_ROW {
                            let cols = &mut cols.memory_local_entries[k];
                            if k < events.len() {
                                let event = events[k];
                                cols.initial_global_interaction_cols
                                    .populate_memory_range_check_witness(
                                        event.initial_mem_access.chunk,
                                        event.initial_mem_access.value,
                                        true,
                                        &mut blu,
                                    );
                                cols.final_global_interaction_cols
                                    .populate_memory_range_check_witness(
                                        event.final_mem_access.chunk,
                                        event.final_mem_access.value,
                                        true,
                                        &mut blu,
                                    );
                            }
                        }
                    });
                blu
            })
            .collect::<Vec<_>>();
        extra.add_byte_lookup_events(blu_events);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        record.get_local_mem_events().nth(0).is_some()
    }

    fn lookup_scope(&self) -> LookupScope {
        LookupScope::Global
    }
}
