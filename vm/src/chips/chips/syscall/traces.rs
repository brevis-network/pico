use crate::{
    chips::{
        chips::{
            byte::event::{ByteLookupEvent, ByteRecordBehavior},
            riscv_global::event::GlobalInteractionEvent,
            syscall::{columns::SyscallCols, SyscallChip, SyscallChunkKind, NUM_SYSCALL_COLS},
        },
        utils::pad_rows_fixed,
    },
    compiler::{
        addr::{encode_proof_addr_to_u32_limbs_48, Addr},
        riscv::{opcode::ByteOpcode, program::Program},
    },
    emulator::riscv::{record::EmulationRecord, syscalls::SyscallEvent},
    iter::{IntoPicoIterator, IntoPicoRefIterator, PicoBridge, PicoIterator, PicoSlice},
    machine::{
        chip::ChipBehavior,
        estimator::{EventCapture, EventSizeCapture},
        lookup::{LookupScope, LookupType},
    },
};
use itertools::Itertools;
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
        let row_fn = |syscall_event: &SyscallEvent| {
            let mut row = [F::ZERO; NUM_SYSCALL_COLS];
            let cols: &mut SyscallCols<F> = row.as_mut_slice().borrow_mut();

            cols.clk = F::from_canonical_u32(u32::try_from(syscall_event.clk).unwrap());
            cols.syscall_id = F::from_canonical_u32(syscall_event.syscall_id);
            // Convert u64 arg1/arg2 to Addr (48-bit, 3 x 16-bit limbs)
            cols.arg1 =
                Addr::try_from(syscall_event.arg1).expect("arg1 exceeds 48-bit address range");
            cols.arg2 =
                Addr::try_from(syscall_event.arg2).expect("arg2 exceeds 48-bit address range");
            cols.is_real = F::ONE;
            row
        };

        let events = match self.chunk_kind {
            SyscallChunkKind::Riscv => input
                .syscall_events
                .pico_iter()
                .map(row_fn)
                .collect::<Vec<_>>(),
            SyscallChunkKind::Precompile => input
                .precompile_events
                .all_events()
                .pico_bridge()
                .map(|(event, _)| row_fn(event))
                .collect::<Vec<_>>(),
        };

        // Pad the trace to a power of two depending on the proof shape in `input`.
        let log_rows = input.shape_chip_size(&self.name());
        let mut rows = events;
        pad_rows_fixed(&mut rows, || [F::ZERO; NUM_SYSCALL_COLS], log_rows);

        RowMajorMatrix::new(
            rows.into_pico_iter().flatten().collect::<Vec<_>>(),
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
        // arg1 and arg2 are 48-bit addresses (3 x 16-bit limbs)
        let global_events: Vec<_> = events
            .pico_chunks(chunk_size)
            .flat_map(|events| {
                events
                    .iter()
                    .map(|event| {
                        let [arg1_0, arg1_1, arg1_2] =
                            encode_proof_addr_to_u32_limbs_48(event.arg1, "syscall arg1");
                        let [arg2_0, arg2_1, arg2_2] =
                            encode_proof_addr_to_u32_limbs_48(event.arg2, "syscall arg2");
                        GlobalInteractionEvent {
                            message: [
                                u32::try_from(event.clk).unwrap(), // element 0: clk
                                event.syscall_id + arg1_0 * 256, // element 1: syscall_id + arg1[0] * 256
                                arg1_1,                          // element 2: arg1[1]
                                arg1_2,                          // element 3: arg1[2]
                                arg2_0,                          // element 4: arg2[0]
                                arg2_1,                          // element 5: arg2[1]
                                arg2_2,                          // element 6: arg2[2]
                                0,                               // element 7: zero padding
                            ],
                            is_receive: self.chunk_kind == SyscallChunkKind::Precompile,
                            kind: LookupType::Syscall as u8,
                        }
                    })
                    .collect_vec()
            })
            .collect();
        extra.global_lookup_events.extend(global_events);

        // Add byte lookup events for the range checks on syscall_id (u8) and arg1[0] (u16).
        for event in events.iter() {
            let syscall_id_byte = event.syscall_id as u8;
            // syscall_id is u8: pair it with zero for the U8Range check.
            extra.add_byte_lookup_event(ByteLookupEvent::new(
                ByteOpcode::U8Range,
                0,
                0,
                syscall_id_byte,
                0,
            ));
            // arg1[0] is u16: emit a U16Range check.
            let arg1_0 = (event.arg1 & 0xFFFF) as u16;
            extra.add_byte_lookup_event(ByteLookupEvent::new(
                ByteOpcode::U16Range,
                0,
                0,
                (arg1_0 >> 8) as u8,
                (arg1_0 & 0xFF) as u8,
            ));
        }
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

impl<F> EventCapture for SyscallChip<F> {
    fn count_extra_records(record: &EmulationRecord, event_counter: &mut EventSizeCapture) {
        event_counter.num_syscall_events += record.syscall_events.len();
        event_counter.num_global_lookup_events += event_counter.num_syscall_events;
        event_counter.num_precompile_syscall_events += record
            .precompile_events
            .events
            .iter()
            .map(|(_, v)| v.len())
            .sum::<usize>();
        event_counter.num_global_lookup_events += event_counter.num_precompile_syscall_events;
    }
}
