use crate::{
    chips::{
        chips::digest_select::{
            columns::{
                DigestSelectCols, DigestSelectPreprocessedCols, DigestSelectPreprocessedValueCols,
                DigestSelectValueCols, NUM_DIGEST_SELECT_COLS, NUM_DIGEST_SELECT_PREPROCESSED_COLS,
            },
            DigestSelectChip,
        },
        trace::TraceData,
    },
    compiler::recursion::{
        instruction::Instruction,
        mle_instruction_buckets::MleVariant,
        program::RecursionProgram,
        types::{DigestSelectEvent, DigestSelectInstr},
    },
    cuda_adaptor::{get_global_mem_pool, get_global_stream_pool},
    emulator::recursion::emulator::RecursionRecord,
    machine::{
        chip::{ChipBehavior, PreprocessedRows},
        utils::pad_to_power_of_two,
    },
    primitives::consts::DIGEST_SELECT_DATAPAR,
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
use pico_gpu_api::{cuda_digest_select_generate_main, cuda_digest_select_generate_preprocessed};
use std::borrow::BorrowMut;

impl<F> BaseAir<F> for DigestSelectChip<F> {
    fn width(&self) -> usize {
        NUM_DIGEST_SELECT_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for DigestSelectChip<F> {
    type Record = RecursionRecord<F>;
    type GpuRecord = ();
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "DigestSelect".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_DIGEST_SELECT_PREPROCESSED_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().digest_select,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let instrs: Vec<&DigestSelectInstr<F>> = program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::DigestSelect(instr) = instruction {
                    Some(instr.as_ref())
                } else {
                    None
                }
            })
            .collect();

        let mut rows: Vec<[F; NUM_DIGEST_SELECT_PREPROCESSED_COLS]> = Vec::new();
        for chunk in instrs.chunks(DIGEST_SELECT_DATAPAR) {
            let mut row = [F::ZERO; NUM_DIGEST_SELECT_PREPROCESSED_COLS];
            let cols: &mut DigestSelectPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
            for (k, instr) in chunk.iter().enumerate() {
                cols.values[k] = DigestSelectPreprocessedValueCols {
                    is_real: F::ONE,
                    bit_addr: instr.bit_addr,
                    in1_addrs: instr.in1_addrs,
                    in2_addrs: instr.in2_addrs,
                    out_addrs: instr.out_addrs,
                    mults: instr.mults,
                };
            }
            rows.push(row);
        }

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_DIGEST_SELECT_PREPROCESSED_COLS,
        );
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_DIGEST_SELECT_PREPROCESSED_COLS, F>(&mut trace.values, log_size);
        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.digest_select_events;
        let mut rows: Vec<[F; NUM_DIGEST_SELECT_COLS]> = Vec::new();
        for chunk in events.chunks(DIGEST_SELECT_DATAPAR) {
            let mut row = [F::ZERO; NUM_DIGEST_SELECT_COLS];
            let cols: &mut DigestSelectCols<F> = row.as_mut_slice().borrow_mut();
            for (k, event) in chunk.iter().enumerate() {
                let e: &DigestSelectEvent<F> = event;
                cols.values[k] = DigestSelectValueCols {
                    bit: e.bit,
                    in1: e.in1,
                    in2: e.in2,
                    out: e.out,
                };
            }
            rows.push(row);
        }

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_DIGEST_SELECT_COLS,
        );
        let log_rows = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_DIGEST_SELECT_COLS, F>(&mut trace.values, log_rows);
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

        // One instruction per datapar slot; the kernel maps each to its (row, slot).
        let instructions: Box<[DigestSelectInstr<F>]> = program
            .mle_candidates(MleVariant::DigestSelect)
            .filter_map(|instruction| match instruction {
                Instruction::DigestSelect(x) => Some(**x),
                _ => None,
            })
            .collect();

        let nb_rows = instructions.len().div_ceil(DIGEST_SELECT_DATAPAR);
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
            let mut d_instrs = DevicePoolAllocation::<DigestSelectInstr<F>>::alloc_from_pool_async(
                num_instrs, mem_pool, stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_instrs.as_mut_c_void_ptr(),
                    instructions.as_c_void_ptr(),
                    num_instrs * size_of::<DigestSelectInstr<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_digest_select_generate_preprocessed(
                    d_instrs.as_ptr() as *const _,
                    num_instrs,
                    d_trace.as_mut_ptr() as *mut _,
                    self.preprocessed_width(),
                    stream.into(),
                );
            }
        }

        info!("[digest-select-chip] generate_preprocessed on GPU");

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

        let events = &input.digest_select_events;

        let nb_rows = events.len().div_ceil(DIGEST_SELECT_DATAPAR).max(16);
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

        let trace_size = padded_nb_rows * NUM_DIGEST_SELECT_COLS;
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
            let mut d_events = DevicePoolAllocation::<DigestSelectEvent<F>>::alloc_from_pool_async(
                event_size, mem_pool, stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_c_void_ptr(),
                    event_size * size_of::<DigestSelectEvent<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_digest_select_generate_main(
                    d_events.as_ptr() as *const _,
                    event_size,
                    d_trace.as_mut_ptr() as *mut _,
                    NUM_DIGEST_SELECT_COLS,
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

        info!("[digest-select-chip] generate_main on GPU");

        TraceData::Gpu(NUM_DIGEST_SELECT_COLS, d_trace)
    }
}
