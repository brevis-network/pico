use crate::{
    chips::{
        chips::frac_fold::{
            columns::{
                FracFoldCols, FracFoldPreprocessedCols, NUM_FRAC_FOLD_COLS,
                NUM_FRAC_FOLD_PREPROCESSED_COLS,
            },
            FracFoldChip,
        },
        trace::TraceData,
    },
    compiler::recursion::{
        instruction::Instruction,
        mle_instruction_buckets::MleVariant,
        program::RecursionProgram,
        types::{FracFoldEvent, FracFoldInstr},
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
use pico_gpu_api::{cuda_frac_fold_generate_main, cuda_frac_fold_generate_preprocessed};
use std::borrow::BorrowMut;

impl<F> BaseAir<F> for FracFoldChip<F> {
    fn width(&self) -> usize {
        NUM_FRAC_FOLD_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for FracFoldChip<F> {
    type Record = RecursionRecord<F>;
    type GpuRecord = ();
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "FracFold".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_FRAC_FOLD_PREPROCESSED_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().frac_fold,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_FRAC_FOLD_PREPROCESSED_COLS]> = Vec::new();

        program
            .instructions
            .iter()
            .filter_map(|instr| {
                if let Instruction::FracFold(i) = instr {
                    Some(i)
                } else {
                    None
                }
            })
            .for_each(|instr: &FracFoldInstr<F>| {
                let mut row = [F::ZERO; NUM_FRAC_FOLD_PREPROCESSED_COLS];
                let cols: &mut FracFoldPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.is_real = F::ONE;
                cols.in_p1_addr = instr.in_p1_addr;
                cols.in_q1_addr = instr.in_q1_addr;
                cols.in_p2_addr = instr.in_p2_addr;
                cols.in_q2_addr = instr.in_q2_addr;
                cols.out_p_addr = instr.out_p_addr;
                cols.out_q_addr = instr.out_q_addr;
                cols.mult = instr.mult;
                rows.push(row);
            });

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_FRAC_FOLD_PREPROCESSED_COLS,
        );
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_FRAC_FOLD_PREPROCESSED_COLS, F>(&mut trace.values, log_size);
        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let rows = input
            .frac_fold_events
            .iter()
            .map(|event: &FracFoldEvent<F>| {
                let mut row = [F::ZERO; NUM_FRAC_FOLD_COLS];
                let cols: &mut FracFoldCols<F> = row.as_mut_slice().borrow_mut();
                cols.p1 = event.p1;
                cols.q1 = event.q1;
                cols.p2 = event.p2;
                cols.q2 = event.q2;
                cols.out_p = event.out_p;
                cols.out_q = event.out_q;
                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_FRAC_FOLD_COLS,
        );
        let log_rows = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_FRAC_FOLD_COLS, F>(&mut trace.values, log_rows);
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

        let instructions: Box<[FracFoldInstr<F>]> = program
            .mle_candidates(MleVariant::FracFold)
            .filter_map(|instruction| match instruction {
                Instruction::FracFold(x) => Some(*x),
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
            let mut d_instrs = DevicePoolAllocation::<FracFoldInstr<F>>::alloc_from_pool_async(
                num_instrs, mem_pool, stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_instrs.as_mut_c_void_ptr(),
                    instructions.as_c_void_ptr(),
                    num_instrs * size_of::<FracFoldInstr<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_frac_fold_generate_preprocessed(
                    d_instrs.as_ptr() as *const _,
                    num_instrs,
                    d_trace.as_mut_ptr() as *mut _,
                    self.preprocessed_width(),
                    stream.into(),
                );
            }
        }

        // No per-chip synchronization — caller (BaseProver) syncs once after all chips.
        info!("[frac-fold-chip] generate_preprocessed on GPU");

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

        let events = &input.frac_fold_events;

        let nb_rows = events.len().max(16);
        let padded_nb_rows = match input.fixed_log2_rows(&self.name()) {
            Some(log_rows) => {
                let specified = 1 << log_rows;
                // Mirror the CPU `pad_to_power_of_two` guard, which panics unconditionally: a fixed
                // size below the real row count would silently under-allocate the device trace.
                // Must be `assert!` (not `debug_assert!`) so release builds fail like the CPU path.
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

        let trace_size = padded_nb_rows * NUM_FRAC_FOLD_COLS;
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
            let mut d_events = DevicePoolAllocation::<FracFoldEvent<F>>::alloc_from_pool_async(
                event_size, mem_pool, stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_c_void_ptr(),
                    event_size * size_of::<FracFoldEvent<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_frac_fold_generate_main(
                    d_events.as_ptr() as *const _,
                    event_size,
                    d_trace.as_mut_ptr() as *mut _,
                    NUM_FRAC_FOLD_COLS,
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

        info!("[frac-fold-chip] generate_main on GPU");

        TraceData::Gpu(NUM_FRAC_FOLD_COLS, d_trace)
    }
}
