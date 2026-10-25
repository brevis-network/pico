use crate::{
    chips::{
        chips::{
            recursion_memory::MemoryAccessCols,
            unpack_block::{
                columns::{
                    UnpackBlockCols, UnpackBlockPreprocessedCols, NUM_UNPACK_BLOCK_COLS,
                    NUM_UNPACK_BLOCK_PREPROCESSED_COLS,
                },
                UnpackBlockChip,
            },
        },
        trace::TraceData,
    },
    compiler::recursion::{
        instruction::Instruction,
        mle_instruction_buckets::MleVariant,
        program::RecursionProgram,
        types::{UnpackBlockEvent, UnpackBlockInstr},
    },
    cuda_adaptor::{get_global_mem_pool, get_global_stream_pool},
    emulator::recursion::emulator::RecursionRecord,
    machine::{
        chip::{ChipBehavior, PreprocessedRows},
        utils::pad_to_power_of_two,
    },
};
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
use cudart_sys::*;
use log::info;
use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use pico_gpu_api::{cuda_unpack_block_generate_main, cuda_unpack_block_generate_preprocessed};
use std::borrow::BorrowMut;

impl<F> BaseAir<F> for UnpackBlockChip<F> {
    fn width(&self) -> usize {
        NUM_UNPACK_BLOCK_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for UnpackBlockChip<F> {
    type Record = RecursionRecord<F>;
    type GpuRecord = ();
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "UnpackBlock".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_UNPACK_BLOCK_PREPROCESSED_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().unpack_block,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_UNPACK_BLOCK_PREPROCESSED_COLS]> = Vec::new();

        program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::UnpackBlock(instr) = instruction {
                    Some(instr.as_ref())
                } else {
                    None
                }
            })
            .for_each(|instr: &UnpackBlockInstr<F>| {
                let mut row = [F::ZERO; NUM_UNPACK_BLOCK_PREPROCESSED_COLS];
                let cols: &mut UnpackBlockPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.is_real = F::ONE;
                cols.in_addr = instr.in_addr;
                cols.out = std::array::from_fn(|i| MemoryAccessCols {
                    addr: instr.out_addrs[i],
                    mult: instr.mults[i],
                });
                rows.push(row);
            });

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_UNPACK_BLOCK_PREPROCESSED_COLS,
        );
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_UNPACK_BLOCK_PREPROCESSED_COLS, F>(&mut trace.values, log_size);
        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let rows = input
            .unpack_block_events
            .iter()
            .map(|event: &UnpackBlockEvent<F>| {
                let mut row = [F::ZERO; NUM_UNPACK_BLOCK_COLS];
                let cols: &mut UnpackBlockCols<F> = row.as_mut_slice().borrow_mut();
                cols.val = event.val;
                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_UNPACK_BLOCK_COLS,
        );
        let log_rows = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_UNPACK_BLOCK_COLS, F>(&mut trace.values, log_rows);
        trace
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

        let instructions: Box<[UnpackBlockInstr<F>]> = program
            .mle_candidates(MleVariant::UnpackBlock)
            .filter_map(|instruction| match instruction {
                Instruction::UnpackBlock(x) => Some(**x),
                _ => None,
            })
            .collect();

        let nb_rows = instructions.len();
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
            let mut d_instrs = DevicePoolAllocation::<UnpackBlockInstr<F>>::alloc_from_pool_async(
                num_instrs, mem_pool, stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_instrs.as_mut_c_void_ptr(),
                    instructions.as_c_void_ptr(),
                    num_instrs * size_of::<UnpackBlockInstr<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_unpack_block_generate_preprocessed(
                    d_instrs.as_ptr() as *const _,
                    num_instrs,
                    d_trace.as_mut_ptr() as *mut _,
                    self.preprocessed_width(),
                    stream.into(),
                );
            }
        }

        info!("[unpack-block-chip] generate_preprocessed on GPU");

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

        let events = &input.unpack_block_events;

        let nb_rows = events.len().max(16);
        let padded_nb_rows = match input.fixed_log2_rows(&self.name()) {
            Some(log_rows) => {
                let specified = 1 << log_rows;
                assert!(
                    specified >= nb_rows,
                    "fixed_log2_rows too small: 2^{log_rows}={specified} < {nb_rows} real rows"
                );
                specified
            }
            None => nb_rows.next_power_of_two(),
        };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * NUM_UNPACK_BLOCK_COLS;
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
            let mut d_events = DevicePoolAllocation::<UnpackBlockEvent<F>>::alloc_from_pool_async(
                event_size, mem_pool, stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_c_void_ptr(),
                    event_size * size_of::<UnpackBlockEvent<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_unpack_block_generate_main(
                    d_events.as_ptr() as *const _,
                    event_size,
                    d_trace.as_mut_ptr() as *mut _,
                    NUM_UNPACK_BLOCK_COLS,
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

        info!("[unpack-block-chip] generate_main on GPU");

        TraceData::Gpu(NUM_UNPACK_BLOCK_COLS, d_trace)
    }
}
