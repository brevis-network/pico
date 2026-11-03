use super::columns::NUM_SLL_COLS;
#[cfg(feature = "cuda")]
use crate::{
    chips::trace::TraceData,
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    emulator::riscv::{history::ExecutionHistory, history_fill::HISTORY_LAYOUT},
    instances::preparer::{PreallocatedGpuMemory, PreparedGpuEvents, Readiness},
    machine::chip::GpuChipBehavior,
    mle::{machine::trace_oracle::history_launch, spans::device},
};
use crate::{
    chips::{
        chips::{
            alu::{
                event::AluEvent,
                sll::{ShiftLeftValueCols, NUM_SLL_VALUE_COLS},
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
    machine::{
        chip::ChipBehavior,
        estimator::{EventCapture, EventSizeCapture},
    },
    primitives::consts::{u32_to_u16_limbs, u64_to_u16_limbs, SLL_DATAPAR, WORD_SIZE},
};
#[cfg(feature = "cuda")]
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::CudaSliceMut,
    stream::{CudaStream, CudaStreamCreateFlags},
};
use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
#[cfg(feature = "cuda")]
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
#[cfg(feature = "cuda")]
use pico_gpu_api::history_bitwise_mul_shift::cuda_sll_generate_extra_record_and_main_history;
use std::{borrow::BorrowMut, marker::PhantomData};
#[cfg(feature = "cuda")]
use tracing::info;

#[derive(Default, Clone, Debug)]
pub struct SLLChip<F>(PhantomData<F>);

impl<F: Field> BaseAir<F> for SLLChip<F> {
    fn width(&self) -> usize {
        NUM_SLL_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for SLLChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "ShiftLeft".to_string()
    }

    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {
        let ops = input.alu_ops(AluStream::ShiftLeft);
        let nrows = ops.len().div_ceil(SLL_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let mut values = vec![F::ZERO; padded_nrows * NUM_SLL_COLS];

        let populate_len = ops.len() * NUM_SLL_VALUE_COLS;
        values[..populate_len]
            .pico_chunks_mut(NUM_SLL_VALUE_COLS)
            .enumerate()
            .for_each(|(index, row)| {
                let cols: &mut ShiftLeftValueCols<_> = row.borrow_mut();
                self.event_to_row(&ops.get(index), cols, &mut vec![]);
            });

        let padded_row_template = {
            let mut row = [F::ZERO; NUM_SLL_VALUE_COLS];
            let cols: &mut ShiftLeftValueCols<F> = row.as_mut_slice().borrow_mut();
            cols.v_01 = F::ONE;
            cols.v_012 = F::ONE;
            cols.v_0123 = F::ONE;
            row
        };

        for i in populate_len..values.len() {
            values[i] = padded_row_template[i % NUM_SLL_VALUE_COLS];
        }

        RowMajorMatrix::new(values, NUM_SLL_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let blu_batches = input
            .alu_ops(AluStream::ShiftLeft)
            .par_flat_map(|event, blu| {
                let mut dummy = ShiftLeftValueCols::default();
                self.event_to_row(event, &mut dummy, blu);
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
        !record.alu_ops(AluStream::ShiftLeft).is_empty()
    }

    fn local_only(&self) -> bool {
        true
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for SLLChip<F> {
    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        record.event_counter.num_shift_left_events > 0
    }

    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let view = input
            .history_view()
            .expect("a CPU chunk's record carries its execution history");
        self.gpu_generate_from_history(
            device_id,
            input,
            view.history,
            prepared_gpu_events,
            preallocated_gpu_memory,
        )
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> SLLChip<F> {
    /// The trace from the chunk's history on the device: the kernel reads the shift-left list
    /// there, so no event is uploaded, and the list's length sizes the trace. The counter the
    /// activity check read must have counted the same list.
    fn gpu_generate_from_history(
        &self,
        device_id: usize,
        input: &EmulationRecord,
        history: &ExecutionHistory,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let event_size = history.chip_steps.alu(AluStream::ShiftLeft).len();
        assert_eq!(
            prepared_gpu_events.event_counter.num_shift_left_events, event_size,
            "the counter's shift-left height is not the history's shift-left list"
        );

        let nrows = event_size.div_ceil(SLL_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let d_byte_trace = preallocated_gpu_memory
            .d_byte_trace
            .as_mut()
            .unwrap()
            .as_mut_ptr();

        let trace_size = padded_nrows * NUM_SLL_COLS;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();

        // Waits on `stream` for the whole fill; dropped after the launch, its end-of-reads mark is
        // what the fill's error-word read-back and free follow.
        let reader = preallocated_gpu_memory
            .d_history
            .as_ref()
            .expect("a chunk whose chips read its history has its fill on the device")
            .reader(stream, Readiness::Complete)
            .unwrap_or_else(|e| panic!("reading the chunk's device history: {e}"));
        let args = reader.args();
        let kernels = device::start(stream);
        let err = unsafe {
            cuda_sll_generate_extra_record_and_main_history(
                std::ptr::from_ref(&args).cast(),
                HISTORY_LAYOUT,
                NUM_SLL_VALUE_COLS,
                trace_size,
                d_trace.as_mut_ptr() as *mut _,
                d_byte_trace as *mut _,
                stream.into(),
            )
        };
        assert_eq!(
            err.code, 0,
            "cuda_sll_generate_extra_record_and_main_history failed: {err}"
        );
        history_launch::note(&self.name());
        drop(reader);

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        device::launched(kernels, stream);
        device::wait(stream).unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        device::wait(stream).unwrap();
        device::wait(main_stream).unwrap();

        info!("[sll-chip] generate_extra_record_and_main from the history on GPU");

        TraceData::Gpu(NUM_SLL_COLS, d_trace)
    }
}

impl<F: Field> SLLChip<F> {
    fn event_to_row(
        &self,
        event: &AluEvent,
        cols: &mut ShiftLeftValueCols<F>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        let c = u64_to_u16_limbs(event.c)[0];

        if event.opcode == Opcode::SLLW {
            let sllw_val = ((event.b as i64) << (c & 0x1f)) as u32;
            let sllw_limbs = u32_to_u16_limbs(sllw_val);
            cols.sllw_msb.populate(blu, sllw_limbs[1]);
        } else {
            cols.sllw_msb.msb = F::ZERO;
        }

        cols.a = Word::from(event.a);
        cols.b = Word::from(event.b);
        cols.c = Word::from(event.c);
        let is_sll = event.opcode == Opcode::SLL;
        cols.is_sll = F::from_bool(is_sll);

        cols.is_sllw = F::from_bool(event.opcode == Opcode::SLLW);

        for i in 0..6 {
            cols.c_bits[i] = F::from_u16((c >> i) & 1);
        }
        blu.add_bit_range_check(c >> 6, 10);

        cols.v_01 = F::from_u16(1 << (c & 3));
        cols.v_012 = F::from_u16(1 << (c & 7));
        cols.v_0123 = F::from_u16(1 << (c & 15));

        let shift_amount = ((c >> 4) & 1) + 2 * ((c >> 5) & 1) * (is_sll as u16);

        let mut shift = [0u16; 4];
        for i in 0..4 {
            if i == shift_amount as usize {
                shift[i] = 1;
            }
        }

        let b = u64_to_u16_limbs(event.b);
        let bit_shift = (c & 0xF) as u8;
        for i in 0..WORD_SIZE {
            let limb = b[i] as u32;
            let lower_limb = (limb & ((1 << (16 - bit_shift)) - 1)) as u16;
            let higher_limb = (limb >> (16 - bit_shift)) as u16;
            cols.lower_limb[i] = F::from_u16(lower_limb);
            cols.higher_limb[i] = F::from_u16(higher_limb);
            blu.add_bit_range_check(lower_limb, 16 - bit_shift);
            blu.add_bit_range_check(higher_limb, bit_shift);
        }

        for i in 0..WORD_SIZE {
            cols.limb_result[i] = cols.lower_limb[i] * F::from_u32(1u32 << bit_shift);
            if i != 0 {
                cols.limb_result[i] += cols.higher_limb[i - 1];
            }
        }

        cols.shift_u16 = shift.map(|x| F::from_u16(x));
    }
}

impl<F> EventCapture for SLLChip<F> {
    fn count_extra_records(record: &EmulationRecord, event_counter: &mut EventSizeCapture) {
        event_counter.num_shift_left_events += record.alu_ops(AluStream::ShiftLeft).len();
    }
}
