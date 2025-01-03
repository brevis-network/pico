use crate::{
    chips::chips::syscall::{
        columns::SyscallCols, SyscallChip, SyscallChunkKind, NUM_SYSCALL_COLS,
    },
    compiler::riscv::program::Program,
    emulator::riscv::{record::EmulationRecord, syscalls::SyscallEvent},
    machine::{chip::ChipBehavior, lookup::LookupScope},
    recursion_v2::stark::utils::pad_rows_fixed,
};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

impl<F: PrimeField32> ChipBehavior<F> for SyscallChip<F> {
    type Record = EmulationRecord;

    type Program = Program;

    fn name(&self) -> String {
        format!("Syscall{}", self.chunk_kind).to_string()
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        _output: &mut EmulationRecord,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        let row_fn = |syscall_event: &SyscallEvent| {
            let mut row = [F::ZERO; NUM_SYSCALL_COLS];
            let cols: &mut SyscallCols<F> = row.as_mut_slice().borrow_mut();

            cols.chunk = F::from_canonical_u32(syscall_event.chunk);
            cols.clk = F::from_canonical_u32(syscall_event.clk);
            cols.syscall_id = F::from_canonical_u32(syscall_event.syscall_id);
            cols.nonce = F::from_canonical_u32(syscall_event.nonce);
            cols.arg1 = F::from_canonical_u32(syscall_event.arg1);
            cols.arg2 = F::from_canonical_u32(syscall_event.arg2);
            cols.is_real = F::ONE;
            row
        };

        match self.chunk_kind {
            SyscallChunkKind::Riscv => {
                for event in input.syscall_events.iter() {
                    let row = row_fn(event);
                    rows.push(row);
                }
            }
            SyscallChunkKind::Precompile => {
                for event in input.precompile_events.all_events().map(|(event, _)| event) {
                    let row = row_fn(event);
                    rows.push(row);
                }
            }
        };

        // Pad the trace to a power of two depending on the proof shape in `input`.
        let log_rows = input.shape_chip_size(&self.name());
        pad_rows_fixed(&mut rows, || [F::ZERO; NUM_SYSCALL_COLS], log_rows);

        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_SYSCALL_COLS,
        )
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match self.chunk_kind {
                SyscallChunkKind::Riscv => !record.syscall_events.is_empty(),
                SyscallChunkKind::Precompile => {
                    !record.precompile_events.is_empty()
                        && record.cpu_events.is_empty()
                        && record.memory_initialize_events.is_empty()
                        && record.memory_finalize_events.is_empty()
                }
            }
        }
    }

    fn lookup_scope(&self) -> LookupScope {
        LookupScope::Global
    }
}
