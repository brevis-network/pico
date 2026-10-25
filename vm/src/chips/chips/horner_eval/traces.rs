use crate::{
    chips::{
        chips::horner_eval::{
            columns::{
                HornerEvalCols, HornerEvalPreprocessedCols, NUM_HORNER_EVAL_COLS,
                NUM_HORNER_EVAL_PREPROCESSED_COLS,
            },
            HornerEvalChip,
        },
        trace::TraceData,
    },
    compiler::recursion::{
        instruction::Instruction,
        ir::Block,
        mle_instruction_buckets::MleVariant,
        program::RecursionProgram,
        types::{Address, HornerEvalEvent, HornerEvalInstr},
    },
    cuda_adaptor::{get_global_mem_pool, get_global_stream_pool},
    emulator::recursion::emulator::RecursionRecord,
    machine::{
        chip::{ChipBehavior, PreprocessedRows},
        utils::pad_to_power_of_two,
    },
    primitives::consts::{EXTENSION_DEGREE, HORNER_EVAL_DATAPAR},
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
use pico_gpu_api::{cuda_horner_eval_generate_main, cuda_horner_eval_generate_preprocessed};
use std::borrow::BorrowMut;

/// H2D mirror of the CUDA `HornerEvalPreprocMeta`: per-instruction bookkeeping for the two-buffer
/// device-side row expansion (the coefficient addresses live in a separate flat buffer).
#[repr(C)]
#[derive(Clone, Copy)]
struct HornerEvalPreprocMeta<F: Copy> {
    num_coeffs: u32,
    coeff_offset: u32,
    row_offset: u32,
    x_addr: Address<F>,
    out_addr: Address<F>,
    mult: F,
}

impl<F> BaseAir<F> for HornerEvalChip<F> {
    fn width(&self) -> usize {
        NUM_HORNER_EVAL_COLS
    }
}

impl<F: PrimeField32 + Field + BinomiallyExtendable<EXTENSION_DEGREE>> ChipBehavior<F>
    for HornerEvalChip<F>
{
    type Record = RecursionRecord<F>;
    type GpuRecord = ();
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "HornerEval".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_HORNER_EVAL_PREPROCESSED_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().horner_eval,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_HORNER_EVAL_PREPROCESSED_COLS]> = Vec::new();

        program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::HornerEval(instr) = instruction {
                    Some(instr.as_ref())
                } else {
                    None
                }
            })
            .for_each(|instr: &HornerEvalInstr<F>| {
                let len = instr.coeff_addrs.len();
                // The lowering front-pads the coefficient vector to a DATAPAR multiple.
                debug_assert_eq!(len % HORNER_EVAL_DATAPAR, 0);
                let n_rows = len / HORNER_EVAL_DATAPAR;
                for i in 0..n_rows {
                    let mut row = [F::ZERO; NUM_HORNER_EVAL_PREPROCESSED_COLS];
                    let cols: &mut HornerEvalPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                    cols.is_real = F::ONE;
                    cols.is_start = F::from_bool(i == 0);
                    cols.is_end = F::from_bool(i == n_rows - 1);
                    for j in 0..HORNER_EVAL_DATAPAR {
                        cols.coeff_addrs[j] = instr.coeff_addrs[HORNER_EVAL_DATAPAR * i + j];
                    }
                    cols.x_addr = instr.x_addr;
                    cols.out_addr = instr.out_addr;
                    cols.mult = if i == n_rows - 1 { instr.mult } else { F::ZERO };
                    rows.push(row);
                }
            });

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_HORNER_EVAL_PREPROCESSED_COLS,
        );
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_HORNER_EVAL_PREPROCESSED_COLS, F>(&mut trace.values, log_size);
        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        // EF multiplication over [F; 4] (same helper as univariate_fold tracegen).
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
            .horner_eval_events
            .iter()
            .map(|event: &HornerEvalEvent<F>| {
                let mut row = [F::ZERO; NUM_HORNER_EVAL_COLS];
                let cols: &mut HornerEvalCols<F> = row.as_mut_slice().borrow_mut();
                cols.coeffs = event.coeffs;
                cols.x = event.x;
                let x2 = ef_mul(event.x.0, event.x.0);
                cols.x2 = Block(x2);
                cols.x3 = Block(ef_mul(x2, event.x.0));
                cols.x4 = Block(ef_mul(x2, x2));
                cols.acc = event.acc;
                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_HORNER_EVAL_COLS,
        );
        let log_rows = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_HORNER_EVAL_COLS, F>(&mut trace.values, log_rows);
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
        // Two-buffer layout: the coefficient addresses go into a flat side buffer and the kernel
        // expands each instruction's len/DATAPAR rows on the device. The host only serializes the
        // `Vec<Address>` and computes integer offsets (row_offset = prefix sum of row counts).
        let width = NUM_HORNER_EVAL_PREPROCESSED_COLS;
        let mut coeff_addrs_flat: Vec<Address<F>> = Vec::new();
        let mut metas: Vec<HornerEvalPreprocMeta<F>> = Vec::new();
        let mut row_cursor: u32 = 0;
        program
            .mle_candidates(MleVariant::HornerEval)
            .filter_map(|instruction| {
                if let Instruction::HornerEval(instr) = instruction {
                    Some(instr.as_ref())
                } else {
                    None
                }
            })
            .for_each(|instr: &HornerEvalInstr<F>| {
                let len = instr.coeff_addrs.len();
                let n_rows = (len / HORNER_EVAL_DATAPAR) as u32;
                let coeff_offset = coeff_addrs_flat.len() as u32;
                coeff_addrs_flat.extend_from_slice(&instr.coeff_addrs);
                metas.push(HornerEvalPreprocMeta {
                    num_coeffs: len as u32,
                    coeff_offset,
                    row_offset: row_cursor,
                    x_addr: instr.x_addr,
                    out_addr: instr.out_addr,
                    mult: instr.mult,
                });
                row_cursor += n_rows;
            });

        let num_rows = row_cursor as usize;
        let padded_nb_rows = program.padded_prep_rows(&self.name(), num_rows);

        let sync_stream = get_global_stream_pool(device_id);
        let stream = &sync_stream.0;
        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * width;
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

        if num_rows > 0 {
            let num_instrs = metas.len();
            let mut d_metas =
                DevicePoolAllocation::<HornerEvalPreprocMeta<F>>::alloc_from_pool_async(
                    num_instrs, mem_pool, stream,
                )
                .unwrap();
            let mut d_coeffs = DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(
                coeff_addrs_flat.len(),
                mem_pool,
                stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_metas.as_mut_c_void_ptr(),
                    metas.as_c_void_ptr(),
                    num_instrs * size_of::<HornerEvalPreprocMeta<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
                let _ = cudaMemcpyAsync(
                    d_coeffs.as_mut_c_void_ptr(),
                    coeff_addrs_flat.as_c_void_ptr(),
                    coeff_addrs_flat.len() * size_of::<Address<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_horner_eval_generate_preprocessed(
                    d_metas.as_ptr() as *const _,
                    num_instrs,
                    d_coeffs.as_ptr() as *const _,
                    d_trace.as_mut_ptr() as *mut _,
                    width,
                    stream.into(),
                );
            }
        }

        info!("[horner-eval-chip] generate_preprocessed on GPU");

        Some(TraceData::Gpu(width, d_trace))
    }

    fn gpu_generate_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        _: &mut Self::Record,
        _: Option<&Self::GpuRecord>,
    ) -> TraceData<'_, F> {
        let events = &input.horner_eval_events;

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

        // Binomial extension constant W, passed as its canonical u32 (rebuilt by the FFI wrapper);
        // matches the CPU `ef_mul` computing x^2/x^3/x^4.
        let w = <F as BinomiallyExtendable<EXTENSION_DEGREE>>::W.as_canonical_u32();

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * NUM_HORNER_EVAL_COLS;
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
            let mut d_events = DevicePoolAllocation::<HornerEvalEvent<F>>::alloc_from_pool_async(
                event_size, mem_pool, stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_c_void_ptr(),
                    event_size * size_of::<HornerEvalEvent<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_horner_eval_generate_main(
                    d_events.as_ptr() as *const _,
                    event_size,
                    d_trace.as_mut_ptr() as *mut _,
                    NUM_HORNER_EVAL_COLS,
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

        info!("[horner-eval-chip] generate_main on GPU");

        TraceData::Gpu(NUM_HORNER_EVAL_COLS, d_trace)
    }
}
