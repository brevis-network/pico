use crate::{
    chips::{
        chips::alu_ext::{
            columns::{
                ExtAluAccessCols, ExtAluValueCols, NUM_EXT_ALU_ACCESS_COLS, NUM_EXT_ALU_COLS,
                NUM_EXT_ALU_PREPROCESSED_COLS, NUM_EXT_ALU_VALUE_COLS,
            },
            ExtAluChip,
        },
        trace::TraceData,
        utils::next_power_of_two,
    },
    compiler::recursion::{
        instruction::Instruction, program::RecursionProgram, types::ExtAluInstr,
    },
    cuda_adaptor::{get_global_mem_pool, get_global_stream_pool},
    emulator::recursion::emulator::{ExtAluOpcode, RecursionRecord},
    iter::{IndexedPicoIterator, PicoIterator, PicoSliceMut},
    machine::chip::{ChipBehavior, PreprocessedRows},
    primitives::consts::{EXTENSION_DEGREE, EXT_ALU_DATAPAR},
};
use core::borrow::BorrowMut;
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
use cudart_sys::*;
use log::info;
use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use pico_gpu_api::{cuda_alu_ext_generate_main, cuda_alu_ext_generate_preprocessed};

impl<F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>> ChipBehavior<F> for ExtAluChip<F> {
    type Record = RecursionRecord<F>;
    type GpuRecord = ();
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "ExtAlu".to_string()
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().ext_alu,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let instructions = program
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instruction::ExtAlu(x) => Some(x),
                _ => None,
            })
            .collect::<Vec<_>>();

        let nb_rows = instructions.len().div_ceil(EXT_ALU_DATAPAR);
        let padded_nb_rows = program.padded_prep_rows(&self.name(), nb_rows);
        let mut values = vec![F::ZERO; padded_nb_rows * NUM_EXT_ALU_PREPROCESSED_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = instructions.len() * NUM_EXT_ALU_ACCESS_COLS;
        values[..populate_len]
            .pico_chunks_mut(NUM_EXT_ALU_ACCESS_COLS)
            .zip_eq(instructions)
            .for_each(|(row, instr)| {
                let ExtAluInstr {
                    opcode,
                    mult,
                    addrs,
                } = instr;
                let access: &mut ExtAluAccessCols<_> = row.borrow_mut();
                *access = ExtAluAccessCols {
                    addrs: addrs.to_owned(),
                    is_add: F::from_bool(false),
                    is_sub: F::from_bool(false),
                    is_mul: F::from_bool(false),
                    is_div: F::from_bool(false),
                    mult: mult.to_owned(),
                };
                let target_flag = match opcode {
                    ExtAluOpcode::AddE => &mut access.is_add,
                    ExtAluOpcode::SubE => &mut access.is_sub,
                    ExtAluOpcode::MulE => &mut access.is_mul,
                    ExtAluOpcode::DivE => &mut access.is_div,
                };
                *target_flag = F::from_bool(true);
            });

        // Convert the trace to a row major matrix.
        Some(RowMajorMatrix::new(values, NUM_EXT_ALU_PREPROCESSED_COLS))
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.ext_alu_events;
        let nrows = events.len().div_ceil(EXT_ALU_DATAPAR);
        let fixed_log2_rows = input.fixed_log2_rows(&self.name());
        let padded_nb_rows = match fixed_log2_rows {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(nrows, None),
        };
        let mut values = vec![F::ZERO; padded_nb_rows * NUM_EXT_ALU_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = events.len() * NUM_EXT_ALU_VALUE_COLS;
        values[..populate_len]
            .pico_chunks_mut(NUM_EXT_ALU_VALUE_COLS)
            .zip_eq(events)
            .for_each(|(row, &vals)| {
                let cols: &mut ExtAluValueCols<_> = row.borrow_mut();
                *cols = ExtAluValueCols { vals };
            });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_EXT_ALU_COLS)
    }

    fn preprocessed_width(&self) -> usize {
        NUM_EXT_ALU_PREPROCESSED_COLS
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }

    fn local_only(&self) -> bool {
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
            buckets.ext_alu.to_vec().into_boxed_slice()
        } else {
            program
                .instructions
                .iter()
                .filter_map(|instruction| match instruction {
                    Instruction::ExtAlu(x) => Some(*x),
                    _ => None,
                })
                .collect::<Box<[_]>>()
        };

        let nb_rows = instructions.len().div_ceil(EXT_ALU_DATAPAR);
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
            use crate::compiler::recursion::types::ExtAluInstr;
            let mut d_instrs = DevicePoolAllocation::<ExtAluInstr<F>>::alloc_from_pool_async(
                num_instrs, mem_pool, stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_instrs.as_mut_c_void_ptr(),
                    instructions.as_c_void_ptr(),
                    num_instrs * size_of::<ExtAluInstr<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_alu_ext_generate_preprocessed(
                    d_instrs.as_ptr() as *const _,
                    num_instrs,
                    d_trace.as_mut_ptr() as *mut _,
                    self.preprocessed_width(),
                    stream.into(),
                );
            }
        }

        // No per-chip synchronization — caller (BaseProver) syncs once after all chips.
        info!("[alu-ext-chip] generate_preprocessed on GPU");

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

        let events = &input.ext_alu_events;

        let nb_rows = events.len().div_ceil(EXT_ALU_DATAPAR);
        let log_rows = input.fixed_log2_rows(&self.name());
        let padded_nb_rows = match log_rows {
            Some(log_rows) => 1 << log_rows,
            None => next_power_of_two(nb_rows, None),
        };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * NUM_EXT_ALU_COLS;
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
            use crate::compiler::recursion::types::ExtAluEvent;
            let mut d_events = DevicePoolAllocation::<ExtAluEvent<F>>::alloc_from_pool_async(
                event_size, mem_pool, stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_c_void_ptr(),
                    event_size * size_of::<ExtAluEvent<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
            }

            unsafe {
                cuda_alu_ext_generate_main(
                    d_events.as_ptr() as *const _,
                    event_size,
                    d_trace.as_mut_ptr() as *mut _,
                    NUM_EXT_ALU_COLS,
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

        info!("[alu-ext-chip] generate_main on GPU");

        TraceData::Gpu(NUM_EXT_ALU_COLS, d_trace)
    }
}
