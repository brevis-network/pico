use super::{
    columns::{MemoryLocalCols, NUM_MEMORY_LOCAL_INIT_COLS},
    MemoryLocalChip,
};
use crate::{
    chips::{
        chips::riscv_global::event::GlobalInteractionEvent,
        utils::{next_power_of_two, zeroed_f_vec},
    },
    compiler::riscv::program::Program,
    emulator::riscv::record::EmulationRecord,
    machine::{
        chip::ChipBehavior,
        lookup::{LookupScope, LookupType},
    },
    primitives::consts::LOCAL_MEMORY_DATAPAR,
};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
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

        chunks.par_iter_mut().enumerate().for_each(|(i, rows)| {
            rows.chunks_mut(NUM_MEMORY_LOCAL_INIT_COLS)
                .enumerate()
                .for_each(|(j, row)| {
                    let idx = (i * chunk_size + j) * LOCAL_MEMORY_DATAPAR;

                    let cols: &mut MemoryLocalCols<F> = row.borrow_mut();
                    for k in 0..LOCAL_MEMORY_DATAPAR {
                        let cols = &mut cols.memory_local_entries[k];
                        if idx + k < events.len() {
                            let event = &events[idx + k];
                            cols.addr = F::from_canonical_u32(event.addr);
                            cols.initial_chunk =
                                F::from_canonical_u32(event.initial_mem_access.chunk);
                            cols.final_chunk = F::from_canonical_u32(event.final_mem_access.chunk);
                            cols.initial_clk =
                                F::from_canonical_u32(event.initial_mem_access.timestamp);
                            cols.final_clk =
                                F::from_canonical_u32(event.final_mem_access.timestamp);
                            cols.initial_value = event.initial_mem_access.value.into();
                            cols.final_value = event.final_mem_access.value.into();
                            cols.is_real = F::ONE;
                        }
                    }
                });
        });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_MEMORY_LOCAL_INIT_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let local_mem_events = input.get_local_mem_events().collect::<Vec<_>>();
        let nb_rows = (local_mem_events.len() + 3) / 4;
        let chunk_size = std::cmp::max((nb_rows + 1) / num_cpus::get(), 1);

        let global_events: Vec<_> = local_mem_events
            .par_chunks(chunk_size * LOCAL_MEMORY_DATAPAR)
            .flat_map(|events| {
                let mut global_events = vec![];
                events.chunks(LOCAL_MEMORY_DATAPAR).for_each(|events| {
                    for k in 0..LOCAL_MEMORY_DATAPAR {
                        if k < events.len() {
                            let event = events[k];
                            global_events.push(GlobalInteractionEvent {
                                message: [
                                    event.initial_mem_access.chunk,
                                    event.initial_mem_access.timestamp,
                                    event.addr,
                                    event.initial_mem_access.value & 255,
                                    (event.initial_mem_access.value >> 8) & 255,
                                    (event.initial_mem_access.value >> 16) & 255,
                                    (event.initial_mem_access.value >> 24) & 255,
                                ],
                                is_receive: true,
                                kind: LookupType::Memory as u8,
                            });
                            global_events.push(GlobalInteractionEvent {
                                message: [
                                    event.final_mem_access.chunk,
                                    event.final_mem_access.timestamp,
                                    event.addr,
                                    event.final_mem_access.value & 255,
                                    (event.final_mem_access.value >> 8) & 255,
                                    (event.final_mem_access.value >> 16) & 255,
                                    (event.final_mem_access.value >> 24) & 255,
                                ],
                                is_receive: false,
                                kind: LookupType::Memory as u8,
                            });
                        }
                    }
                });

                global_events
            })
            .collect();

        extra.global_lookup_events.extend(global_events);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        record.get_local_mem_events().nth(0).is_some()
    }

    fn lookup_scope(&self) -> LookupScope {
        LookupScope::Regional
    }
}
