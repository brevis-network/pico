use crate::{
    chips::{
        chips::{
            riscv_global::event::GlobalInteractionEvent,
            syscall::{columns::SyscallCols, SyscallChip, SyscallChunkKind, NUM_SYSCALL_COLS},
        },
        utils::pad_rows_fixed,
    },
    compiler::riscv::program::Program,
    emulator::riscv::{record::EmulationRecord, syscalls::SyscallEvent},
    machine::{
        chip::ChipBehavior,
        lookup::{LookupScope, LookupType},
    },
};
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
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

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let events = match self.chunk_kind {
            SyscallChunkKind::Riscv => &input.syscall_events,
            SyscallChunkKind::Precompile => &input
                .precompile_events
                .all_events()
                .map(|(event, _)| event.to_owned())
                .collect_vec(),
        };
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);
        let global_events: Vec<_> = events
            .par_chunks(chunk_size)
            .flat_map(|events| {
                events
                    .iter()
                    .map(|event| GlobalInteractionEvent {
                        message: [
                            event.chunk,
                            event.clk,
                            event.syscall_id,
                            event.arg1,
                            event.arg2,
                            0,
                            0,
                        ],
                        is_receive: self.chunk_kind == SyscallChunkKind::Precompile,
                        kind: LookupType::Syscall as u8,
                    })
                    .collect_vec()
            })
            .collect();
        extra.global_lookup_events.extend(global_events);
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
        LookupScope::Regional
    }
}
