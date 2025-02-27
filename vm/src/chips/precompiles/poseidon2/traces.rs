use super::{columns::num_poseidon2_cols, Poseidon2PermuteChip};
use crate::{
    chips::{
        chips::{byte::event::ByteRecordBehavior, events::ByteLookupEvent},
        gadgets::poseidon2::traces::populate_perm,
        precompiles::poseidon2::columns::Poseidon2Cols,
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
    machine::{
        chip::ChipBehavior,
        field::{FieldBehavior, FieldType},
    },
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
        let syscall_code = match F::field_type() {
            FieldType::TypeBabyBear => SyscallCode::POSEIDON2_PERMUTE_BB,
            FieldType::TypeKoalaBear => SyscallCode::POSEIDON2_PERMUTE_KB,
            FieldType::TypeMersenne31 => SyscallCode::POSEIDON2_PERMUTE_M31,
            _ => unimplemented!("Unsupported field type"),
        };
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
            let syscalls = [
                SyscallCode::POSEIDON2_PERMUTE_BB,
                SyscallCode::POSEIDON2_PERMUTE_KB,
                SyscallCode::POSEIDON2_PERMUTE_M31,
            ];
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
        let syscall_code = match F::field_type() {
            FieldType::TypeBabyBear => SyscallCode::POSEIDON2_PERMUTE_BB,
            FieldType::TypeKoalaBear => SyscallCode::POSEIDON2_PERMUTE_KB,
            FieldType::TypeMersenne31 => SyscallCode::POSEIDON2_PERMUTE_M31,
            _ => unimplemented!("Unsupported field type"),
        };
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
        cols.clk = F::from_canonical_u32(event.clk);
        cols.input_memory_ptr = F::from_canonical_u32(event.input_memory_ptr);
        cols.output_memory_ptr = F::from_canonical_u32(event.output_memory_ptr);

        // Populate memory columns.
        for (i, read_record) in event.state_read_records.iter().enumerate() {
            cols.input_memory[i].populate(*read_record, blu);
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

        for (i, write_record) in event.state_write_records.iter().enumerate() {
            cols.output_memory[i].populate(*write_record, blu);
        }

        if let Some(input_row) = input_row {
            *input_row = row;
        }
    }
}
