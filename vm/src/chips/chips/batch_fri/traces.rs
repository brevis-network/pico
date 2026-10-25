use crate::{
    chips::{
        chips::batch_fri::{
            columns::{
                BatchFRICols, BatchFRIPreprocessedCols, NUM_BATCH_FRI_COLS,
                NUM_BATCH_FRI_PREPROCESSED_COLS,
            },
            BatchFRIChip,
        },
        trace::TraceData,
        utils::next_power_of_two,
    },
    compiler::recursion::{
        instruction::Instruction,
        program::RecursionProgram,
        types::{preprocess_batch_fri_ffi, BatchFRIInstr},
    },
    cuda_adaptor::{get_global_mem_pool, get_global_stream_pool},
    emulator::recursion::emulator::RecursionRecord,
    machine::{chip::ChipBehavior, utils::pad_to_power_of_two},
};
use core::borrow::BorrowMut;
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
use pico_gpu_api::{cuda_batch_fri_generate_main, cuda_batch_fri_generate_preprocessed};

impl<F> BaseAir<F> for BatchFRIChip<F> {
    fn width(&self) -> usize {
        NUM_BATCH_FRI_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for BatchFRIChip<F> {
    type Record = RecursionRecord<F>;
    type GpuRecord = ();
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "BatchFRI".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BATCH_FRI_PREPROCESSED_COLS
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_BATCH_FRI_PREPROCESSED_COLS]> = Vec::new();
        program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::BatchFRI(instr) = instruction {
                    Some(instr)
                } else {
                    None
                }
            })
            .for_each(|instruction| {
                let BatchFRIInstr {
                    base_vec_addrs,
                    ext_single_addrs,
                    ext_vec_addrs,
                    acc_mult,
                } = instruction.as_ref();
                let len = ext_vec_addrs.p_at_z.len();
                let mut row_add = vec![[F::ZERO; NUM_BATCH_FRI_PREPROCESSED_COLS]; len];
                debug_assert_eq!(*acc_mult, F::ONE);

                row_add.iter_mut().enumerate().for_each(|(_i, row)| {
                    let row: &mut BatchFRIPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                    row.is_real = F::ONE;
                    row.is_end = F::from_bool(_i == len - 1);
                    row.acc_addr = ext_single_addrs.acc;
                    row.alpha_pow_addr = ext_vec_addrs.alpha_pow[_i];
                    row.p_at_z_addr = ext_vec_addrs.p_at_z[_i];
                    row.p_at_x_addr = base_vec_addrs.p_at_x[_i];
                });
                rows.extend(row_add);
            });

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_BATCH_FRI_PREPROCESSED_COLS,
        );

        // Pad the trace to a power of two.
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_BATCH_FRI_PREPROCESSED_COLS, F>(&mut trace.values, log_size);

        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let rows = input
            .batch_fri_events
            .iter()
            .map(|event| {
                let mut row = [F::ZERO; NUM_BATCH_FRI_COLS];
                let cols: &mut BatchFRICols<F> = row.as_mut_slice().borrow_mut();
                cols.acc = event.ext_single.acc;
                cols.alpha_pow = event.ext_vec.alpha_pow;
                cols.p_at_z = event.ext_vec.p_at_z;
                cols.p_at_x = event.base_vec.p_at_x;
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_BATCH_FRI_COLS,
        );

        let log_rows = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_BATCH_FRI_COLS, F>(&mut trace.values, log_rows);

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

        let (instrs, p_at_x, p_at_z, alpha_pow, good_heuristic, nb_rows) =
            if let Some(guard) = program.get_buckets() {
                let buckets = guard.as_ref().unwrap();
                preprocess_batch_fri_ffi(&buckets.batch_fri)
            } else {
                let batch_fri_instrs: Box<[_]> = program
                    .instructions
                    .iter()
                    .filter_map(|instruction| {
                        if let Instruction::BatchFRI(instr) = instruction {
                            Some(instr)
                        } else {
                            None
                        }
                    })
                    .collect();
                preprocess_batch_fri_ffi(&batch_fri_instrs)
            };

        if good_heuristic {
            info!("good batch fri hueristic! if you get more of these, consider updating the preprocess kernel to be more parallel");
        } else {
            info!("bad batch fri hueristic! batch fri preprocess kernel cannot be more parallel");
        }

        let log_rows = program.fixed_log2_rows(&self.name());
        let padded_nb_rows = match log_rows {
            Some(log_rows) => 1 << log_rows,
            None => next_power_of_two(nb_rows, None),
        };

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

        let num_instrs = instrs.len();
        if num_instrs > 0 {
            use crate::compiler::recursion::types::{Address, BatchFRIInstrFfi};
            let mut d_instrs = DevicePoolAllocation::<BatchFRIInstrFfi<F>>::alloc_from_pool_async(
                num_instrs, mem_pool, stream,
            )
            .unwrap();
            let mut d_p_at_x = DevicePoolAllocation::<Address<F>>::alloc_from_pool_async(
                p_at_x.len(),
                mem_pool,
                stream,
            )
            .unwrap();
            let mut d_p_at_z = DevicePoolAllocation::<Address<F>>::alloc_from_pool_async(
                p_at_z.len(),
                mem_pool,
                stream,
            )
            .unwrap();
            let mut d_alpha_pow = DevicePoolAllocation::<Address<F>>::alloc_from_pool_async(
                alpha_pow.len(),
                mem_pool,
                stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_instrs.as_mut_c_void_ptr(),
                    instrs.as_c_void_ptr(),
                    num_instrs * size_of::<BatchFRIInstrFfi<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
                let _ = cudaMemcpyAsync(
                    d_p_at_x.as_mut_c_void_ptr(),
                    p_at_x.as_c_void_ptr(),
                    p_at_x.len() * size_of::<Address<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
                let _ = cudaMemcpyAsync(
                    d_p_at_z.as_mut_c_void_ptr(),
                    p_at_z.as_c_void_ptr(),
                    p_at_z.len() * size_of::<Address<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
                let _ = cudaMemcpyAsync(
                    d_alpha_pow.as_mut_c_void_ptr(),
                    alpha_pow.as_c_void_ptr(),
                    alpha_pow.len() * size_of::<Address<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_batch_fri_generate_preprocessed(
                    d_instrs.as_ptr() as *const _,
                    num_instrs,
                    d_p_at_x.as_ptr() as *const _,
                    d_p_at_z.as_ptr() as *const _,
                    d_alpha_pow.as_ptr() as *const _,
                    d_trace.as_mut_ptr() as *mut _,
                    self.preprocessed_width(),
                    stream.into(),
                );
            }
        }

        // No per-chip synchronization — caller (BaseProver) syncs once after all chips.
        info!("[batch-fri-chip] generate_preprocessed on GPU");

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

        let events = &input.batch_fri_events;

        let nb_rows = events.len();
        let log_rows = input.fixed_log2_rows(&self.name());
        let padded_nb_rows = match log_rows {
            Some(log_rows) => 1 << log_rows,
            None => next_power_of_two(nb_rows, None),
        };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * NUM_BATCH_FRI_COLS;
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
            use crate::compiler::recursion::types::BatchFRIEvent;
            let mut d_events = DevicePoolAllocation::<BatchFRIEvent<F>>::alloc_from_pool_async(
                event_size, mem_pool, stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_c_void_ptr(),
                    event_size * size_of::<BatchFRIEvent<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
            }

            unsafe {
                cuda_batch_fri_generate_main(
                    d_events.as_ptr() as *const _,
                    event_size,
                    d_trace.as_mut_ptr() as *mut _,
                    NUM_BATCH_FRI_COLS,
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

        info!("[batch-fri-chip] generate_main on GPU");

        TraceData::Gpu(NUM_BATCH_FRI_COLS, d_trace)
    }
}
