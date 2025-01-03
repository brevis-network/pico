use super::{
    columns::{MemoryLocalCols, NUM_LOCAL_MEMORY_ENTRIES_PER_ROW, NUM_MEMORY_LOCAL_INIT_COLS},
    MemoryLocalChip,
};
use crate::{
    compiler::riscv::program::Program,
    emulator::riscv::record::EmulationRecord,
    machine::{chip::ChipBehavior, lookup::LookupScope, utils::pad_to_power_of_two},
};
use itertools::Itertools;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

impl<F: Field> ChipBehavior<F> for MemoryLocalChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "MemoryLocal".to_string()
    }

    fn generate_main(&self, input: &Self::Record, _output: &mut Self::Record) -> RowMajorMatrix<F> {
        let mut rows = Vec::<[F; NUM_MEMORY_LOCAL_INIT_COLS]>::new();

        for local_mem_events in &input
            .get_local_mem_events()
            .chunks(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
        {
            let mut row = [F::ZERO; NUM_MEMORY_LOCAL_INIT_COLS];
            let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();

            for (cols, event) in cols.memory_local_entries.iter_mut().zip(local_mem_events) {
                cols.addr = F::from_canonical_u32(event.addr);
                cols.initial_chunk = F::from_canonical_u32(event.initial_mem_access.chunk);
                cols.final_chunk = F::from_canonical_u32(event.final_mem_access.chunk);
                cols.initial_clk = F::from_canonical_u32(event.initial_mem_access.timestamp);
                cols.final_clk = F::from_canonical_u32(event.final_mem_access.timestamp);
                cols.initial_value = event.initial_mem_access.value.into();
                cols.final_value = event.final_mem_access.value.into();
                cols.is_real = F::ONE;
            }

            rows.push(row);
        }

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_LOCAL_INIT_COLS,
        );

        // Pad the trace based on shape
        let log_rows = input.shape_chip_size(&self.name());
        pad_to_power_of_two::<NUM_MEMORY_LOCAL_INIT_COLS, F>(&mut trace.values, log_rows);

        trace
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        record.get_local_mem_events().nth(0).is_some()
    }

    fn lookup_scope(&self) -> LookupScope {
        LookupScope::Global
    }
}
