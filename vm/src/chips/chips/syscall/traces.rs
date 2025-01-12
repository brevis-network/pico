use crate::{
    chips::chips::{
        rangecheck::event::RangeLookupEvent,
        syscall::{columns::SyscallCols, SyscallChip, SyscallChunkKind, NUM_SYSCALL_COLS},
    },
    compiler::riscv::program::Program,
    emulator::riscv::{record::EmulationRecord, syscalls::SyscallEvent},
    machine::{chip::ChipBehavior, lookup::LookupScope, septic::SepticDigest},
    recursion_v2::stark::utils::pad_rows_fixed,
};
use hashbrown::HashMap;
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
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
        let mut global_cumulative_sum = SepticDigest::<F>::zero().0;

        let mut rows = Vec::new();

        let row_fn = |syscall_event: &SyscallEvent, is_looked: bool| {
            let mut row = [F::ZERO; NUM_SYSCALL_COLS];
            let cols: &mut SyscallCols<F> = row.as_mut_slice().borrow_mut();

            debug_assert!(syscall_event.clk < (1 << 24));
            let clk_16 = (syscall_event.clk & 65535) as u16;
            let clk_8 = (syscall_event.clk >> 16) as u8;

            cols.chunk = F::from_canonical_u32(syscall_event.chunk);
            cols.clk_16 = F::from_canonical_u16(clk_16);
            cols.clk_8 = F::from_canonical_u8(clk_8);
            cols.nonce = F::from_canonical_u32(syscall_event.nonce);
            cols.syscall_id = F::from_canonical_u32(syscall_event.syscall_id);
            cols.arg1 = F::from_canonical_u32(syscall_event.arg1);
            cols.arg2 = F::from_canonical_u32(syscall_event.arg2);
            cols.is_real = F::ONE;
            cols.global_interaction_cols.populate_syscall(
                syscall_event.chunk,
                clk_16,
                clk_8,
                syscall_event.syscall_id,
                syscall_event.arg1,
                syscall_event.arg2,
                is_looked,
                true,
            );
            row
        };

        match self.chunk_kind {
            SyscallChunkKind::Riscv => {
                for event in input.syscall_events.iter() {
                    let row = row_fn(event, false);
                    rows.push(row);
                }
            }
            SyscallChunkKind::Precompile => {
                for event in input.precompile_events.all_events().map(|(event, _)| event) {
                    let row = row_fn(event, true);
                    rows.push(row);
                }
            }
        };

        let num_events = rows.len();
        for i in 0..num_events {
            let cols: &mut SyscallCols<F> = rows[i].as_mut_slice().borrow_mut();
            cols.global_accumulation_cols.populate(
                &mut global_cumulative_sum,
                [cols.global_interaction_cols],
                [cols.is_real],
            );
        }

        // Pad the trace to a power of two depending on the proof shape in `input`.
        let log_rows = input.shape_chip_size(&self.name());
        pad_rows_fixed(&mut rows, || [F::ZERO; NUM_SYSCALL_COLS], log_rows);

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_SYSCALL_COLS,
        );

        for i in num_events..trace.height() {
            let cols: &mut SyscallCols<F> =
                trace.values[i * NUM_SYSCALL_COLS..(i + 1) * NUM_SYSCALL_COLS].borrow_mut();
            cols.global_interaction_cols.populate_dummy();
            cols.global_accumulation_cols.populate(
                &mut global_cumulative_sum,
                [cols.global_interaction_cols],
                [cols.is_real],
            );
        }

        trace
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let events = match self.chunk_kind {
            SyscallChunkKind::Riscv => &input.syscall_events,
            SyscallChunkKind::Precompile => &input
                .precompile_events
                .all_events()
                .map(|(event, _)| event.to_owned())
                .collect::<Vec<_>>(),
        };
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);
        let rangecheck_events = events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<RangeLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = [F::ZERO; NUM_SYSCALL_COLS];
                    let cols: &mut SyscallCols<F> = row.as_mut_slice().borrow_mut();
                    let clk_16 = (event.clk & 65535) as u16;
                    let clk_8 = (event.clk >> 16) as u8;
                    cols.global_interaction_cols
                        .populate_syscall_range_check_witness(
                            event.chunk,
                            clk_16,
                            clk_8,
                            event.syscall_id,
                            true,
                            &mut blu,
                        );
                });
                blu
            })
            .collect::<Vec<_>>();
        extra.add_rangecheck_lookup_events(rangecheck_events);
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
