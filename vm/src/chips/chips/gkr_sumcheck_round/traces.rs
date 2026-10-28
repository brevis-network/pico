use crate::{
    chips::chips::gkr_sumcheck_round::{
        columns::{
            GkrSumcheckRoundCols, GkrSumcheckRoundPreprocessedCols, NUM_GKR_SUMCHECK_ROUND_COLS,
            NUM_GKR_SUMCHECK_ROUND_PREPROCESSED_COLS,
        },
        GkrSumcheckRoundChip,
    },
    compiler::recursion::{
        instruction::Instruction,
        ir::Block,
        program::RecursionProgram,
        types::{GkrSumcheckRoundEvent, GkrSumcheckRoundInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::{
        chip::{ChipBehavior, PreprocessedRows},
        utils::pad_to_power_of_two,
    },
    primitives::consts::EXTENSION_DEGREE,
};
#[cfg(feature = "cuda")]
use crate::{
    chips::trace::TraceData,
    compiler::recursion::mle_instruction_buckets::MleVariant,
    cuda_adaptor::{get_global_mem_pool, get_global_stream_pool},
    machine::chip::GpuChipBehavior,
};
#[cfg(feature = "cuda")]
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
#[cfg(feature = "cuda")]
use cudart_sys::*;
#[cfg(feature = "cuda")]
use log::info;
use p3_air::BaseAir;
use p3_field::{extension::BinomiallyExtendable, Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
#[cfg(feature = "cuda")]
use pico_gpu_api::{
    cuda_gkr_sumcheck_round_generate_main, cuda_gkr_sumcheck_round_generate_preprocessed,
};
use std::borrow::BorrowMut;

impl<F> BaseAir<F> for GkrSumcheckRoundChip<F> {
    fn width(&self) -> usize {
        NUM_GKR_SUMCHECK_ROUND_COLS
    }
}

impl<F: PrimeField32 + Field + BinomiallyExtendable<EXTENSION_DEGREE>> ChipBehavior<F>
    for GkrSumcheckRoundChip<F>
{
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "GkrSumcheckRound".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_GKR_SUMCHECK_ROUND_PREPROCESSED_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().gkr_sumcheck_round,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_GKR_SUMCHECK_ROUND_PREPROCESSED_COLS]> = Vec::new();

        program
            .instructions
            .iter()
            .filter_map(|instr| {
                if let Instruction::GkrSumcheckRound(i) = instr {
                    Some(i.as_ref())
                } else {
                    None
                }
            })
            .for_each(|instr: &GkrSumcheckRoundInstr<F>| {
                let mut row = [F::ZERO; NUM_GKR_SUMCHECK_ROUND_PREPROCESSED_COLS];
                let cols: &mut GkrSumcheckRoundPreprocessedCols<F> =
                    row.as_mut_slice().borrow_mut();
                cols.is_real = F::ONE;
                cols.claim_addr = instr.claim_addr;
                cols.s1_addr = instr.s1_addr;
                cols.s2_addr = instr.s2_addr;
                cols.s3_addr = instr.s3_addr;
                cols.r_addr = instr.r_addr;
                cols.xi_addr = instr.xi_addr;
                cols.eq_in_addr = instr.eq_in_addr;
                cols.next_claim_addr = instr.next_claim_addr;
                cols.eq_out_addr = instr.eq_out_addr;
                cols.mult_next = instr.mult_next;
                cols.mult_eq = instr.mult_eq;
                rows.push(row);
            });

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_GKR_SUMCHECK_ROUND_PREPROCESSED_COLS,
        );
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_GKR_SUMCHECK_ROUND_PREPROCESSED_COLS, F>(
            &mut trace.values,
            log_size,
        );
        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        // EF multiplication over [F; 4] using the binomial extension with W
        // (same helper as univariate_fold's Horner ladder tracegen).
        let w = <F as BinomiallyExtendable<EXTENSION_DEGREE>>::W;
        let ef_mul = |a: [F; 4], b: [F; 4]| -> [F; 4] {
            [
                a[0] * b[0] + w * (a[1] * b[3] + a[2] * b[2] + a[3] * b[1]),
                a[0] * b[1] + a[1] * b[0] + w * (a[2] * b[3] + a[3] * b[2]),
                a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + w * a[3] * b[3],
                a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0],
            ]
        };

        let rows = input
            .gkr_sumcheck_round_events
            .iter()
            .map(|event: &GkrSumcheckRoundEvent<F>| {
                let mut row = [F::ZERO; NUM_GKR_SUMCHECK_ROUND_COLS];
                let cols: &mut GkrSumcheckRoundCols<F> = row.as_mut_slice().borrow_mut();
                cols.claim = event.claim;
                cols.s1 = event.s1;
                cols.s2 = event.s2;
                cols.s3 = event.s3;
                cols.r = event.r;
                cols.xi = event.xi;
                cols.eq_in = event.eq_in;
                cols.r_sq = Block(ef_mul(event.r.0, event.r.0));
                cols.next_claim = event.next_claim;
                cols.eq_out = event.eq_out;
                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_GKR_SUMCHECK_ROUND_COLS,
        );
        let log_rows = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_GKR_SUMCHECK_ROUND_COLS, F>(&mut trace.values, log_rows);
        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32 + Field + BinomiallyExtendable<EXTENSION_DEGREE>> GpuChipBehavior<F>
    for GkrSumcheckRoundChip<F>
{
    fn gpu_generate_preprocessed(
        &self,
        device_id: usize,
        program: &Self::Program,
    ) -> Option<TraceData<'_, F>> {
        use p3_koala_bear::KoalaBear;

        let instructions: Box<[GkrSumcheckRoundInstr<F>]> = program
            .mle_candidates(MleVariant::GkrSumcheckRound)
            .filter_map(|instruction| match instruction {
                Instruction::GkrSumcheckRound(x) => Some(**x),
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
                DevicePoolAllocation::<GkrSumcheckRoundInstr<F>>::alloc_from_pool_async(
                    num_instrs, mem_pool, stream,
                )
                .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_instrs.as_mut_c_void_ptr(),
                    instructions.as_c_void_ptr(),
                    num_instrs * size_of::<GkrSumcheckRoundInstr<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_gkr_sumcheck_round_generate_preprocessed(
                    d_instrs.as_ptr() as *const _,
                    num_instrs,
                    d_trace.as_mut_ptr() as *mut _,
                    self.preprocessed_width(),
                    stream.into(),
                );
            }
        }

        info!("[gkr-sumcheck-round-chip] generate_preprocessed on GPU");

        Some(TraceData::Gpu(self.preprocessed_width(), d_trace))
    }

    fn gpu_generate_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        _: &mut Self::Record,
    ) -> TraceData<'_, F> {
        use p3_koala_bear::KoalaBear;

        let events = &input.gkr_sumcheck_round_events;

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

        // Binomial extension constant W, passed as its canonical u32 (the FFI wrapper rebuilds the
        // field element); matches the CPU `ef_mul` computing r_sq = r * r.
        let w = <F as BinomiallyExtendable<EXTENSION_DEGREE>>::W.as_canonical_u32();

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * NUM_GKR_SUMCHECK_ROUND_COLS;
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
                DevicePoolAllocation::<GkrSumcheckRoundEvent<F>>::alloc_from_pool_async(
                    event_size, mem_pool, stream,
                )
                .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_c_void_ptr(),
                    event_size * size_of::<GkrSumcheckRoundEvent<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_gkr_sumcheck_round_generate_main(
                    d_events.as_ptr() as *const _,
                    event_size,
                    d_trace.as_mut_ptr() as *mut _,
                    NUM_GKR_SUMCHECK_ROUND_COLS,
                    w,
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

        info!("[gkr-sumcheck-round-chip] generate_main on GPU");

        TraceData::Gpu(NUM_GKR_SUMCHECK_ROUND_COLS, d_trace)
    }
}
