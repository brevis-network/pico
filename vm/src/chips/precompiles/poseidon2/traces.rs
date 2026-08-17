use super::{columns::num_poseidon2_cols, Poseidon2PermuteChip, STATE_NUM_BYTES, STATE_NUM_DWORDS};
use crate::{
    chips::{
        chips::{
            byte::event::ByteRecordBehavior, events::ByteLookupEvent,
            riscv_memory::event::MemoryWriteRecord,
        },
        gadgets::poseidon2::traces::populate_perm,
        precompiles::{checked_u64_to_u32, poseidon2::columns::Poseidon2Cols},
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
    iter::{PicoIterator, PicoSlice},
    machine::chip::ChipBehavior,
    primitives::consts::PERMUTATION_WIDTH,
};
use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use std::borrow::BorrowMut;
use tracing::debug;

impl<F: Field, LinearLayers, Config: Poseidon2Config> BaseAir<F>
    for Poseidon2PermuteChip<F, LinearLayers, Config>
{
    fn width(&self) -> usize {
        num_poseidon2_cols::<Config>()
    }
}

impl<
        F: PrimeField32,
        LinearLayers: GenericPoseidon2LinearLayers<F, PERMUTATION_WIDTH>,
        Config: Poseidon2Config,
    > ChipBehavior<F> for Poseidon2PermuteChip<F, LinearLayers, Config>
{
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Poseidon2Permute".to_string()
    }

    fn generate_main(&self, input: &Self::Record, _output: &mut Self::Record) -> RowMajorMatrix<F> {
        let syscall_code = SyscallCode::POSEIDON2_PERMUTE;
        let events: Vec<_> = input
            .get_precompile_events(syscall_code)
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
                // use a Vec because the size is too large to make a generic array
                let mut row = Vec::new();
                self.event_to_row(event, Some(&mut row), &mut new_byte_lookup_events);

                row
            })
            .collect();

        // Create a shared dummy row that can be reused
        let dummy_row = {
            let mut dummy = vec![F::ZERO; self.width()];

            let dummy_cols: &mut Poseidon2Cols<F, Config> = dummy.as_mut_slice().borrow_mut();

            let dummy_perm = &mut dummy_cols.value_cols;

            populate_perm::<F, LinearLayers, Config>(
                F::ZERO,
                dummy_perm,
                [F::ZERO; PERMUTATION_WIDTH],
                None,
                &self.constants,
            );

            dummy
        };

        let log_rows = input.shape_chip_size(&self.name());
        pad_rows_fixed(&mut rows, || dummy_row.clone(), log_rows);

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), self.width())
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            let syscalls = [SyscallCode::POSEIDON2_PERMUTE];
            syscalls
                .iter()
                .any(|&syscall| !record.get_precompile_events(syscall).is_empty())
        }
    }

    fn generate_preprocessed(
        &self,
        _program: &Self::Program,
    ) -> Option<p3_matrix::dense::RowMajorMatrix<F>> {
        None
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let syscall_code = SyscallCode::POSEIDON2_PERMUTE;
        let events: Vec<_> = input
            .get_precompile_events(syscall_code)
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
            .pico_chunks(chunk_size)
            .map(|events| {
                let mut blu: Vec<ByteLookupEvent> = Vec::new();
                events.iter().for_each(|event| {
                    self.event_to_row(event, None, &mut blu);
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

impl<
        F: PrimeField32,
        LinearLayers: GenericPoseidon2LinearLayers<F, PERMUTATION_WIDTH>,
        Config: Poseidon2Config,
    > Poseidon2PermuteChip<F, LinearLayers, Config>
{
    fn event_to_row(
        &self,
        event: &Poseidon2PermuteEvent,
        input_row: Option<&mut Vec<F>>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        // use Vec because num_cols is too large
        let mut row = vec![F::ZERO; num_poseidon2_cols::<Config>()];
        let cols: &mut Poseidon2Cols<F, Config> = row.as_mut_slice().borrow_mut();

        // cols.value_cols.is_real is populated in the following populate_perm
        cols.chunk = F::from_canonical_u32(event.chunk);
        cols.clk = F::from_canonical_u32(checked_u64_to_u32(event.clk, "poseidon2 clk"));

        // The pointers are 48-bit addresses, split into 3 u16 limbs by the gadget. `populate`
        // also emits the byte lookups the AIR's range checks and alignment check consume, so
        // this is the trace half of those constraints -- without it the honest proof fails on
        // the Byte bus rather than on a constraint.
        cols.input_memory_ptr
            .populate(blu, event.input_memory_ptr, STATE_NUM_BYTES as u64);
        cols.output_memory_ptr
            .populate(blu, event.output_memory_ptr, STATE_NUM_BYTES as u64);
        for i in 0..STATE_NUM_DWORDS {
            cols.input_addrs[i].populate(blu, event.input_memory_ptr, 8 * i as u64);
            cols.output_addrs[i].populate(blu, event.output_memory_ptr, 8 * i as u64);
        }

        // Populate memory columns, one per dword.
        //
        // The event carries one record per 32-bit state *word*, but the emulator only performed
        // one memory access per dword: `read_word_records_via_dwords` pushes the same
        // `MemoryReadRecord` into slots `2k` and `2k + 1`, so slot `2k` is the dword record.
        for i in 0..STATE_NUM_DWORDS {
            cols.input_memory[i].populate(event.state_read_records[2 * i], blu);
            // `populate` only emits the byte lookups for the timestamp diff, never for the value
            // itself -- but the AIR range checks the value's limbs, so this is that trace half.
            blu.add_u16_range_checks_field(&cols.input_memory[i].access.value.0);
        }

        let state: [F; PERMUTATION_WIDTH] = event
            .state_values
            .clone()
            .into_iter()
            .map(F::from_canonical_u32)
            .collect::<Vec<F>>()
            .try_into()
            .unwrap();

        let perm = &mut cols.value_cols;

        populate_perm::<F, LinearLayers, Config>(F::ONE, perm, state, None, &self.constants);

        // Same story on the write side, except `write_word_records_via_dwords` splits one dword
        // write into two synthetic half-word records: slot `2k` carries the dword's original
        // `prev_value` and slot `2k + 1` carries its final `value`. The single access the
        // emulator actually performed is the composition of the two.
        for i in 0..STATE_NUM_DWORDS {
            let first = event.state_write_records[2 * i];
            let last = event.state_write_records[2 * i + 1];
            debug_assert!(
                first.chunk == last.chunk
                    && first.timestamp == last.timestamp
                    && first.prev_chunk == last.prev_chunk
                    && first.prev_timestamp == last.prev_timestamp,
                "the two half-word write records of one dword must share its timestamp"
            );
            cols.output_memory[i].populate(
                MemoryWriteRecord {
                    value: last.value,
                    prev_value: first.prev_value,
                    ..first
                },
                blu,
            );
            blu.add_u16_range_checks_field(&cols.output_memory[i].access.value.0);
        }

        if let Some(input_row) = input_row {
            *input_row = row;
        }
    }
}
