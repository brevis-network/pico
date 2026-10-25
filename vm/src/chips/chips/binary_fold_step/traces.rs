use crate::{
    chips::{
        chips::binary_fold_step::{
            columns::{
                BinaryFoldStepCols, BinaryFoldStepPreprocessedCols, NUM_BINARY_FOLD_STEP_COLS,
                NUM_BINARY_FOLD_STEP_PREPROCESSED_COLS,
            },
            BinaryFoldStepChip,
        },
        trace::TraceData,
    },
    compiler::recursion::{
        instruction::Instruction,
        ir::Block,
        mle_instruction_buckets::MleVariant,
        program::RecursionProgram,
        types::{BinaryFoldStepEvent, BinaryFoldStepInstr},
    },
    cuda_adaptor::{get_global_mem_pool, get_global_stream_pool},
    emulator::recursion::emulator::RecursionRecord,
    machine::{
        chip::{ChipBehavior, PreprocessedRows},
        utils::pad_to_power_of_two,
    },
    primitives::consts::EXTENSION_DEGREE,
};
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
use cudart_sys::*;
use log::info;
use p3_air::BaseAir;
use p3_field::{extension::BinomiallyExtendable, Field, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use pico_gpu_api::{
    cuda_binary_fold_step_generate_main, cuda_binary_fold_step_generate_preprocessed,
};
use std::borrow::BorrowMut;

impl<F> BaseAir<F> for BinaryFoldStepChip<F> {
    fn width(&self) -> usize {
        NUM_BINARY_FOLD_STEP_COLS
    }
}

impl<F: PrimeField32 + Field + BinomiallyExtendable<EXTENSION_DEGREE>> ChipBehavior<F>
    for BinaryFoldStepChip<F>
{
    type Record = RecursionRecord<F>;
    type GpuRecord = ();
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "BinaryFoldStep".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BINARY_FOLD_STEP_PREPROCESSED_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().binary_fold_step,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_BINARY_FOLD_STEP_PREPROCESSED_COLS]> = Vec::new();

        program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::BinaryFoldStep(instr) = instruction {
                    Some(instr.as_ref())
                } else {
                    None
                }
            })
            .for_each(|instr: &BinaryFoldStepInstr<F>| {
                let mut row = [F::ZERO; NUM_BINARY_FOLD_STEP_PREPROCESSED_COLS];
                let cols: &mut BinaryFoldStepPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.is_real = F::ONE;
                cols.tw_addr = instr.tw_addr;
                cols.xi_addr = instr.xi_addr;
                cols.inv_tw_addr = instr.inv_tw_addr;
                cols.xi_inv_addr = instr.xi_inv_addr;
                cols.alpha_addr = instr.alpha_addr;
                cols.v_lo_addr = instr.v_lo_addr;
                cols.v_hi_addr = instr.v_hi_addr;
                cols.out_addr = instr.out_addr;
                cols.mult = instr.mult;
                rows.push(row);
            });

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_BINARY_FOLD_STEP_PREPROCESSED_COLS,
        );
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_BINARY_FOLD_STEP_PREPROCESSED_COLS, F>(
            &mut trace.values,
            log_size,
        );
        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        // EF helpers over [F; 4] (same as univariate_fold tracegen).
        let w = <F as BinomiallyExtendable<EXTENSION_DEGREE>>::W;
        let ef_mul = |a: [F; 4], b: [F; 4]| -> [F; 4] {
            [
                a[0] * b[0] + w * (a[1] * b[3] + a[2] * b[2] + a[3] * b[1]),
                a[0] * b[1] + a[1] * b[0] + w * (a[2] * b[3] + a[3] * b[2]),
                a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + w * a[3] * b[3],
                a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0],
            ]
        };

        let inv2 = F::TWO.inverse();
        let rows = input
            .binary_fold_step_events
            .iter()
            .map(|event: &BinaryFoldStepEvent<F>| {
                let mut row = [F::ZERO; NUM_BINARY_FOLD_STEP_COLS];
                let cols: &mut BinaryFoldStepCols<F> = row.as_mut_slice().borrow_mut();
                cols.tw = event.tw;
                cols.xi = event.xi;
                cols.inv_tw = event.inv_tw;
                cols.xi_inv = event.xi_inv;
                cols.alpha = event.alpha;
                cols.v_lo = event.v_lo;
                cols.v_hi = event.v_hi;
                // amt = alpha - tw*xi (only the base lane of tw*xi is nonzero).
                let mut amt = event.alpha.0;
                amt[0] -= event.tw * event.xi;
                cols.amt = Block(amt);
                cols.tih = event.inv_tw * event.xi_inv * inv2;
                cols.out = event.out;
                // Recompute out for a tracegen-side sanity check in debug builds.
                debug_assert_eq!(
                    {
                        let mut diff = event.v_lo.0;
                        for i in 0..4 {
                            diff[i] -= event.v_hi.0[i];
                        }
                        let t = ef_mul(cols.amt.0, diff);
                        let mut o = event.v_lo.0;
                        for i in 0..4 {
                            o[i] += t[i] * cols.tih;
                        }
                        o
                    },
                    event.out.0
                );
                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_BINARY_FOLD_STEP_COLS,
        );
        let log_rows = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_BINARY_FOLD_STEP_COLS, F>(&mut trace.values, log_rows);
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
        let instructions: Box<[BinaryFoldStepInstr<F>]> = program
            .mle_candidates(MleVariant::BinaryFoldStep)
            .filter_map(|instruction| match instruction {
                Instruction::BinaryFoldStep(x) => Some(**x),
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
            let mut d_instrs =
                DevicePoolAllocation::<BinaryFoldStepInstr<F>>::alloc_from_pool_async(
                    num_instrs, mem_pool, stream,
                )
                .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_instrs.as_mut_c_void_ptr(),
                    instructions.as_c_void_ptr(),
                    num_instrs * size_of::<BinaryFoldStepInstr<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_binary_fold_step_generate_preprocessed(
                    d_instrs.as_ptr() as *const _,
                    num_instrs,
                    d_trace.as_mut_ptr() as *mut _,
                    self.preprocessed_width(),
                    stream.into(),
                );
            }
        }

        info!("[binary-fold-step-chip] generate_preprocessed on GPU");

        Some(TraceData::Gpu(self.preprocessed_width(), d_trace))
    }

    fn gpu_generate_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        _: &mut Self::Record,
        _: Option<&Self::GpuRecord>,
    ) -> TraceData<'_, F> {
        let events = &input.binary_fold_step_events;

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

        // inv2 = 1/2, passed as its canonical u32 (rebuilt by the FFI wrapper); matches the CPU
        // `tih = inv_tw * xi_inv * (1/2)`.
        let inv2 = F::TWO.inverse().as_canonical_u32();

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * NUM_BINARY_FOLD_STEP_COLS;
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
            let mut d_events =
                DevicePoolAllocation::<BinaryFoldStepEvent<F>>::alloc_from_pool_async(
                    event_size, mem_pool, stream,
                )
                .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_c_void_ptr(),
                    event_size * size_of::<BinaryFoldStepEvent<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_binary_fold_step_generate_main(
                    d_events.as_ptr() as *const _,
                    event_size,
                    d_trace.as_mut_ptr() as *mut _,
                    NUM_BINARY_FOLD_STEP_COLS,
                    inv2,
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

        info!("[binary-fold-step-chip] generate_main on GPU");

        TraceData::Gpu(NUM_BINARY_FOLD_STEP_COLS, d_trace)
    }
}
