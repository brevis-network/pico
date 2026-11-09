#[cfg(feature = "cuda")]
use crate::{
    chips::{
        chips::alu::add::traces::{chunk_history, split_trace_from_history},
        trace::TraceData,
    },
    emulator::riscv::history_fill::HISTORY_LAYOUT,
    instances::preparer::{PreallocatedGpuMemory, PreparedGpuEvents},
    machine::chip::GpuChipBehavior,
};
use crate::{
    chips::{
        chips::{
            alu::{
                event::AluEvent,
                subw::{
                    columns::{SubwValueCols, NUM_SUBW_COLS, NUM_SUBW_VALUE_COLS},
                    SubwChip,
                },
            },
            byte::event::ByteRecordBehavior,
        },
        utils::next_power_of_two,
    },
    compiler::{
        riscv::{opcode::Opcode, program::Program},
        word::Word,
    },
    emulator::riscv::record::{AluStream, EmulationRecord},
    iter::{IndexedPicoIterator, PicoIterator, PicoSliceMut},
    machine::chip::ChipBehavior,
    primitives::consts::ADD_DATAPAR,
};
use core::borrow::BorrowMut;
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
#[cfg(feature = "cuda")]
use pico_gpu_api::history_add_sub_divrem::cuda_subw_generate_extra_record_and_main_history;

impl<F: PrimeField32> ChipBehavior<F> for SubwChip<F> {
    type Record = EmulationRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Subw".to_string()
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let ops = input.alu_ops(AluStream::Sub);
        let positions = ops.positions(Opcode::SUBW);

        let nrows = positions.len().div_ceil(ADD_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };
        let mut values = vec![F::ZERO; padded_nrows * NUM_SUBW_COLS];

        let populate_len = positions.len() * NUM_SUBW_VALUE_COLS;
        values[..populate_len]
            .pico_chunks_mut(NUM_SUBW_VALUE_COLS)
            .zip_eq(positions)
            .for_each(|(row, index)| {
                let cols: &mut SubwValueCols<_> = row.borrow_mut();
                self.event_to_row(&ops.get(index), cols, &mut vec![]);
            });

        RowMajorMatrix::new(values, NUM_SUBW_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let blu_batches = input.alu_ops(AluStream::Sub).par_flat_map(|event, blu| {
            if event.opcode == Opcode::SUBW {
                let mut dummy = SubwValueCols::default();
                self.event_to_row(event, &mut dummy, blu);
            }
        });

        extra.add_byte_lookup_events(blu_batches);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        // Under a pad shape the shape decides presence, so a bucketed chunk's proof shape
        // depends on the chunk kind rather than on its opcode mix. Without a shape the
        // chip is event-driven, which is what the natural-height path wants.
        if let Some(shape) = record.shape.as_ref() {
            return shape.included::<F, _>(self);
        }
        record.alu_ops(AluStream::Sub).contains(Opcode::SUBW)
    }

    fn local_only(&self) -> bool {
        true
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for SubwChip<F> {
    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        self.gpu_generate_from_history(
            device_id,
            input,
            prepared_gpu_events,
            preallocated_gpu_memory,
        )
    }

    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        record.event_counter.num_subw_events > 0
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> SubwChip<F> {
    /// The trace from the chunk's history on the device: the sub list's SUBW rows, split there
    /// from its SUB rows. The fill's descriptor counts them, which is the height the counter
    /// the activity check read gave.
    fn gpu_generate_from_history(
        &self,
        device_id: usize,
        input: &EmulationRecord,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let rows = chunk_history(preallocated_gpu_memory)
            .descriptor()
            .subw_rows as usize;
        split_trace_from_history(
            device_id,
            &self.name(),
            input,
            rows,
            prepared_gpu_events.event_counter.num_subw_events,
            NUM_SUBW_COLS,
            preallocated_gpu_memory,
            None,
            |args, trace_size, d_trace, d_byte_trace, stream| unsafe {
                cuda_subw_generate_extra_record_and_main_history(
                    args,
                    HISTORY_LAYOUT,
                    NUM_SUBW_VALUE_COLS,
                    trace_size,
                    d_trace,
                    d_byte_trace,
                    stream.into(),
                )
            },
        )
    }
}

impl<F: Field> SubwChip<F> {
    /// Populate a single trace row from a SUBW event.
    ///
    /// Computes `(b as i32).wrapping_sub(c as i32)` sign-extended to u64,
    /// stores lower 32 bits as two u16 limbs and records the MSB for sign extension.
    fn event_to_row(
        &self,
        event: &AluEvent,
        cols: &mut SubwValueCols<F>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        cols.is_subw = F::ONE;
        cols.subw_operation.populate(blu, event.b, event.c);
        cols.operand_1 = Word::from(event.b);
        cols.operand_2 = Word::from(event.c);
    }
}
