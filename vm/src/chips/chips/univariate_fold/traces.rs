use crate::{
    chips::{
        chips::univariate_fold::{
            columns::{
                UnivariateFoldCols, UnivariateFoldPreprocessedCols, NUM_UNIVARIATE_FOLD_COLS,
                NUM_UNIVARIATE_FOLD_PREPROCESSED_COLS,
            },
            UnivariateFoldChip, MAX_COEFFS,
        },
        trace::TraceData,
    },
    compiler::recursion::{
        instruction::Instruction,
        ir::Block,
        mle_instruction_buckets::MleVariant,
        program::RecursionProgram,
        types::{Address, UnivariateFoldEvent, UnivariateFoldInstr},
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
use p3_matrix::dense::RowMajorMatrix;
use pico_gpu_api::{
    cuda_univariate_fold_generate_main, cuda_univariate_fold_generate_preprocessed,
};
use std::borrow::BorrowMut;

/// H2D mirror of the CUDA `UnivariateFoldFlatEvent`: the `Vec<Block>` coefficients padded to a
/// fixed `MAX_COEFFS` array so the event copies to the device with a raw memcpy.
#[repr(C)]
#[derive(Clone, Copy)]
struct UnivariateFoldFlatEvent<F: Copy> {
    coeffs: [Block<F>; MAX_COEFFS],
    claimed_sum: Block<F>,
    r: Block<F>,
    next_sum: Block<F>,
}

/// H2D mirror of the CUDA `UnivariateFoldInstr`: the `Vec<Address>` coefficient addresses padded to
/// `MAX_COEFFS` plus the active `num_coeffs` count.
#[repr(C)]
#[derive(Clone, Copy)]
struct UnivariateFoldFlatInstr<F: Copy> {
    coeffs_addrs: [Address<F>; MAX_COEFFS],
    num_coeffs: F,
    claimed_sum_addr: Address<F>,
    r_addr: Address<F>,
    next_sum_addr: Address<F>,
    mult: F,
}

impl<F> BaseAir<F> for UnivariateFoldChip<F> {
    fn width(&self) -> usize {
        NUM_UNIVARIATE_FOLD_COLS
    }
}

impl<F: PrimeField32 + Field + BinomiallyExtendable<EXTENSION_DEGREE>> ChipBehavior<F>
    for UnivariateFoldChip<F>
{
    type Record = RecursionRecord<F>;
    type GpuRecord = ();
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "UnivariateFold".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_UNIVARIATE_FOLD_PREPROCESSED_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().univariate_fold,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_UNIVARIATE_FOLD_PREPROCESSED_COLS]> = Vec::new();

        program
            .instructions
            .iter()
            .filter_map(|instr| {
                if let Instruction::UnivariateFold(i) = instr {
                    Some(i.as_ref())
                } else {
                    None
                }
            })
            .for_each(|instr: &UnivariateFoldInstr<F>| {
                let mut row = [F::ZERO; NUM_UNIVARIATE_FOLD_PREPROCESSED_COLS];
                let cols: &mut UnivariateFoldPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.is_real = F::ONE;
                cols.num_coeffs = F::from_usize(instr.coeffs_addrs.len());
                for (dst, src) in cols.coeffs_addrs.iter_mut().zip(instr.coeffs_addrs.iter()) {
                    *dst = *src;
                }
                cols.claimed_sum_addr = instr.claimed_sum_addr;
                cols.r_addr = instr.r_addr;
                cols.next_sum_addr = instr.next_sum_addr;
                cols.mult = instr.mult;
                rows.push(row);
            });

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_UNIVARIATE_FOLD_PREPROCESSED_COLS,
        );
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_UNIVARIATE_FOLD_PREPROCESSED_COLS, F>(
            &mut trace.values,
            log_size,
        );
        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let rows = input
            .univariate_fold_events
            .iter()
            .map(|event: &UnivariateFoldEvent<F>| {
                let mut row = [F::ZERO; NUM_UNIVARIATE_FOLD_COLS];
                let cols: &mut UnivariateFoldCols<F> = row.as_mut_slice().borrow_mut();

                // Fill coefficients (padded to MAX_COEFFS).
                for (dst, src) in cols.coeffs.iter_mut().zip(event.coeffs.iter()) {
                    *dst = *src;
                }

                cols.claimed_sum = event.claimed_sum;
                cols.r = event.r;
                cols.next_sum = event.next_sum;

                // eval_at_0 = coeffs[0].
                cols.eval_at_0 = event.coeffs.first().copied().unwrap_or_default();

                // eval_at_1 = coeffs[omega_order] where omega_order = (MAX_COEFFS+1)/2 = 16.
                let omega_order = MAX_COEFFS.div_ceil(2);
                cols.eval_at_1 = event.coeffs.get(omega_order).copied().unwrap_or_default();

                // Horner accumulator: acc[0] = coeffs[MAX_COEFFS-1],
                // acc[i] = acc[i-1] * r + coeffs[MAX_COEFFS-1-i] for i in 1..(MAX_COEFFS-1).
                // Matches the Horner constraints in constraints.rs (next_sum = p(r)).
                {
                    // EF multiplication over [F; 4] using binomial extension with W.
                    let w = <F as BinomiallyExtendable<EXTENSION_DEGREE>>::W;
                    let ef_mul = |a: [F; 4], b: [F; 4]| -> [F; 4] {
                        [
                            a[0] * b[0] + w * (a[1] * b[3] + a[2] * b[2] + a[3] * b[1]),
                            a[0] * b[1] + a[1] * b[0] + w * (a[2] * b[3] + a[3] * b[2]),
                            a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + w * a[3] * b[3],
                            a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0],
                        ]
                    };
                    let ef_add = |a: [F; 4], b: [F; 4]| -> [F; 4] {
                        [a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3]]
                    };
                    let r_arr = event.r.0;
                    // acc[0] = coeffs[MAX_COEFFS-1]
                    let c_top = event
                        .coeffs
                        .get(MAX_COEFFS - 1)
                        .copied()
                        .unwrap_or_default();
                    cols.acc[0].0 = c_top.0;
                    // acc[i] = acc[i-1] * r + coeffs[MAX_COEFFS-1-i]
                    for i in 1..(MAX_COEFFS - 1) {
                        let prev = cols.acc[i - 1].0;
                        let coeff = event
                            .coeffs
                            .get(MAX_COEFFS - 1 - i)
                            .copied()
                            .unwrap_or_default();
                        cols.acc[i].0 = ef_add(ef_mul(prev, r_arr), coeff.0);
                    }
                }

                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_UNIVARIATE_FOLD_COLS,
        );
        let log_rows = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_UNIVARIATE_FOLD_COLS, F>(&mut trace.values, log_rows);
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

        // The `filter_map` flattens each `Vec<Address>` into the fixed `MAX_COEFFS` layout the
        // kernel expects.
        let instructions: Box<[UnivariateFoldFlatInstr<F>]> = program
            .mle_candidates(MleVariant::UnivariateFold)
            .filter_map(|instruction| match instruction {
                Instruction::UnivariateFold(i) => {
                    let instr = i.as_ref();
                    let mut coeffs_addrs = [Address(F::ZERO); MAX_COEFFS];
                    for (dst, src) in coeffs_addrs.iter_mut().zip(instr.coeffs_addrs.iter()) {
                        *dst = *src;
                    }
                    Some(UnivariateFoldFlatInstr {
                        coeffs_addrs,
                        num_coeffs: F::from_usize(instr.coeffs_addrs.len()),
                        claimed_sum_addr: instr.claimed_sum_addr,
                        r_addr: instr.r_addr,
                        next_sum_addr: instr.next_sum_addr,
                        mult: instr.mult,
                    })
                }
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
                DevicePoolAllocation::<UnivariateFoldFlatInstr<F>>::alloc_from_pool_async(
                    num_instrs, mem_pool, stream,
                )
                .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_instrs.as_mut_c_void_ptr(),
                    instructions.as_c_void_ptr(),
                    num_instrs * size_of::<UnivariateFoldFlatInstr<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_univariate_fold_generate_preprocessed(
                    d_instrs.as_ptr() as *const _,
                    num_instrs,
                    d_trace.as_mut_ptr() as *mut _,
                    self.preprocessed_width(),
                    stream.into(),
                );
            }
        }

        // No per-chip synchronization — caller (BaseProver) syncs once after all chips.
        info!("[univariate-fold-chip] generate_preprocessed on GPU");

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

        // Flatten each event's `Vec<Block>` coefficients into the fixed `MAX_COEFFS` layout; the
        // kernel then derives eval_at_0/eval_at_1 and the Horner accumulator.
        let events: Box<[UnivariateFoldFlatEvent<F>]> = input
            .univariate_fold_events
            .iter()
            .map(|ev| {
                let mut coeffs = [Block([F::ZERO; EXTENSION_DEGREE]); MAX_COEFFS];
                for (dst, src) in coeffs.iter_mut().zip(ev.coeffs.iter()) {
                    *dst = *src;
                }
                UnivariateFoldFlatEvent {
                    coeffs,
                    claimed_sum: ev.claimed_sum,
                    r: ev.r,
                    next_sum: ev.next_sum,
                }
            })
            .collect();

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
        // field element); matches the CPU `ef_mul` which uses `<F as BinomiallyExtendable>::W`.
        let w = <F as BinomiallyExtendable<EXTENSION_DEGREE>>::W.as_canonical_u32();

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * NUM_UNIVARIATE_FOLD_COLS;
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
                DevicePoolAllocation::<UnivariateFoldFlatEvent<F>>::alloc_from_pool_async(
                    event_size, mem_pool, stream,
                )
                .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_c_void_ptr(),
                    event_size * size_of::<UnivariateFoldFlatEvent<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_univariate_fold_generate_main(
                    d_events.as_ptr() as *const _,
                    event_size,
                    d_trace.as_mut_ptr() as *mut _,
                    NUM_UNIVARIATE_FOLD_COLS,
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

        info!("[univariate-fold-chip] generate_main on GPU");

        TraceData::Gpu(NUM_UNIVARIATE_FOLD_COLS, d_trace)
    }
}
