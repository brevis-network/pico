use crate::{
    chips::{
        chips::select::{
            columns::{
                SelectPreprocessedValueCols, SelectValueCols, NUM_SELECT_COLS,
                NUM_SELECT_PREPROCESSED_COLS, NUM_SELECT_PREPROCESSED_VALUE_COLS,
                NUM_SELECT_VALUE_COLS,
            },
            SelectChip,
        },
        trace::TraceData,
        utils::next_power_of_two,
    },
    compiler::recursion::{
        instruction::Instruction, program::RecursionProgram, types::SelectInstr,
    },
    cuda_adaptor::{get_global_mem_pool, get_global_stream_pool},
    emulator::recursion::emulator::RecursionRecord,
    iter::{
        current_num_threads, IndexedPicoIterator, IntoPicoRefIterator, PicoIterator, PicoSliceMut,
    },
    machine::chip::{ChipBehavior, PreprocessedRows},
    primitives::consts::SELECT_DATAPAR,
};
use core::borrow::BorrowMut;
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
use cudart_sys::*;
use log::info;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use pico_gpu_api::{cuda_select_generate_main, cuda_select_generate_preprocessed};

impl<F: PrimeField32> ChipBehavior<F> for SelectChip<F> {
    type Record = RecursionRecord<F>;
    type GpuRecord = ();
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "Select".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_SELECT_PREPROCESSED_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(program.prep_row_counts().select))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let instructions: Vec<_> = program
            .instructions
            .pico_iter()
            .filter_map(|instruction| match instruction {
                Instruction::Select(x) => Some(x),
                _ => None,
            })
            .collect();

        let nrows = instructions.len().div_ceil(SELECT_DATAPAR);
        let padded_nrows = program.padded_prep_rows(&self.name(), nrows);

        let mut values: Vec<F> = vec![F::ZERO; padded_nrows * NUM_SELECT_PREPROCESSED_COLS];

        let chunk_size = (instructions.len() / current_num_threads()).max(1);
        let populate_len = instructions.len() * NUM_SELECT_PREPROCESSED_VALUE_COLS;

        values[..populate_len]
            .pico_chunks_mut(NUM_SELECT_PREPROCESSED_VALUE_COLS)
            .zip_eq(instructions)
            .with_min_len(chunk_size)
            .for_each(|(row, instr)| {
                let SelectInstr {
                    addrs,
                    mult1,
                    mult2,
                } = instr;
                let value_col: &mut SelectPreprocessedValueCols<_> = row.borrow_mut();
                *value_col = SelectPreprocessedValueCols {
                    is_real: F::ONE,
                    addrs: addrs.to_owned(),
                    mult1: mult1.to_owned(),
                    mult2: mult2.to_owned(),
                };
            });

        Some(RowMajorMatrix::new(values, NUM_SELECT_PREPROCESSED_COLS))
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.select_events;
        let nrows = events.len().div_ceil(SELECT_DATAPAR);
        let fixed_log2_nrows = input.fixed_log2_rows(&self.name());
        let padded_nrows = match fixed_log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let mut values: Vec<F> = vec![F::ZERO; padded_nrows * NUM_SELECT_COLS];

        let chunk_size = (events.len() / current_num_threads()).max(1);
        let populate_len = events.len() * NUM_SELECT_VALUE_COLS;

        values[..populate_len]
            .pico_chunks_mut(NUM_SELECT_VALUE_COLS)
            .zip_eq(events)
            .with_min_len(chunk_size)
            .for_each(|(row, &vals)| {
                let cols: &mut SelectValueCols<_> = row.borrow_mut();
                *cols = SelectValueCols { vals };
            });

        RowMajorMatrix::new(values, NUM_SELECT_COLS)
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }

    fn gpu_generate_preprocessed(
        &self,
        device_id: usize,
        program: &Self::Program,
    ) -> Option<TraceData<'_, F>> {
        use p3_koala_bear::KoalaBear;

        let instructions: Box<[_]> = if let Some(guard) = program.get_buckets() {
            let buckets = guard.as_ref().unwrap();
            buckets.select.to_vec().into_boxed_slice()
        } else {
            program
                .instructions
                .iter()
                .filter_map(|instruction| match instruction {
                    Instruction::Select(x) => Some(*x),
                    _ => None,
                })
                .collect::<Box<[_]>>()
        };

        let nb_rows = instructions.len().div_ceil(SELECT_DATAPAR);
        let padded_nb_rows = program.padded_prep_rows(&self.name(), nb_rows);

        let sync_stream = get_global_stream_pool(device_id);
        let stream = &sync_stream.0;
        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * self.preprocessed_width();
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();
        unsafe {
            let _ = cudaMemsetAsync(
                d_trace.as_mut_ptr() as *mut _,
                0,
                trace_size * size_of::<KoalaBear>(),
                stream.into(),
            );
        }

        let num_instrs = instructions.len();
        if num_instrs > 0 {
            use crate::compiler::recursion::types::SelectInstr;
            let mut d_instrs = DevicePoolAllocation::<SelectInstr<F>>::alloc_from_pool_async(
                num_instrs, mem_pool, stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_instrs.as_mut_c_void_ptr(),
                    instructions.as_c_void_ptr(),
                    num_instrs * size_of::<SelectInstr<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_select_generate_preprocessed(
                    d_instrs.as_ptr() as *const _,
                    num_instrs,
                    d_trace.as_mut_ptr() as *mut _,
                    self.preprocessed_width(),
                    stream.into(),
                );
            }
        }

        // No per-chip synchronization — caller (BaseProver) syncs once after all chips.
        info!("[select-chip] generate_preprocessed on GPU");

        Some(TraceData::Gpu(self.preprocessed_width(), d_trace))
    }

    fn gpu_generate_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        _: &mut Self::Record,
        _: Option<&Self::GpuRecord>,
    ) -> TraceData<'_, F> {
        use p3_koala_bear::KoalaBear;

        let events = &input.select_events;

        let nb_rows = events.len().div_ceil(SELECT_DATAPAR);
        let log_rows = input.fixed_log2_rows(&self.name());
        let padded_nb_rows = match log_rows {
            Some(log_rows) => 1 << log_rows,
            None => next_power_of_two(nb_rows, None),
        };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * NUM_SELECT_COLS;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();
        unsafe {
            let _ = cudaMemsetAsync(
                d_trace.as_mut_ptr() as *mut _,
                0,
                trace_size * size_of::<KoalaBear>(),
                stream.into(),
            );
        }

        let event_size = events.len();
        if event_size > 0 {
            use crate::compiler::recursion::types::SelectEvent;
            let mut d_events = DevicePoolAllocation::<SelectEvent<F>>::alloc_from_pool_async(
                event_size, mem_pool, stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_c_void_ptr(),
                    event_size * size_of::<SelectEvent<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
            }

            unsafe {
                cuda_select_generate_main(
                    d_events.as_ptr() as *const _,
                    event_size,
                    d_trace.as_mut_ptr() as *mut _,
                    NUM_SELECT_COLS,
                    stream.into(),
                );
            }
        }

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream.synchronize().unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        stream.synchronize().unwrap();
        main_stream.synchronize().unwrap();

        info!("[select-chip] generate_main on GPU");

        TraceData::Gpu(NUM_SELECT_COLS, d_trace)
    }
}
