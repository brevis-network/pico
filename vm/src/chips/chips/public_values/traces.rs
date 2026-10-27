use super::columns::{
    PublicValuesCols, PublicValuesPreprocessedCols, NUM_PUBLIC_VALUES_COLS,
    NUM_PUBLIC_VALUES_PREPROCESSED_COLS,
};
#[cfg(feature = "cuda")]
use crate::{
    chips::trace::TraceData,
    compiler::recursion::types::CommitPublicValuesInstr,
    cuda_adaptor::{get_global_mem_pool, get_global_stream_pool},
    machine::chip::GpuChipBehavior,
};
use crate::{
    chips::{
        chips::{
            public_values::{PublicValuesChip, PUB_VALUES_LOG_HEIGHT},
            recursion_memory::MemoryAccessCols,
        },
        utils::pad_rows_fixed,
    },
    compiler::recursion::{instruction::Instruction, program::RecursionProgram},
    emulator::recursion::emulator::RecursionRecord,
    machine::chip::{ChipBehavior, PreprocessedRows},
};
use core::borrow::BorrowMut;
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
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
#[cfg(feature = "cuda")]
use pico_gpu_api::{cuda_public_values_generate_main, cuda_public_values_generate_preprocessed};

impl<F: PrimeField32> ChipBehavior<F> for PublicValuesChip<F> {
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "PublicValues".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PUBLIC_VALUES_PREPROCESSED_COLS
    }

    /// Pads to a constant, never to the program's shape — mirroring
    /// `pad_rows_fixed(.., Some(PUB_VALUES_LOG_HEIGHT))` below.
    fn preprocessed_rows(&self, _program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::FixedLog2(PUB_VALUES_LOG_HEIGHT))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_PUBLIC_VALUES_PREPROCESSED_COLS]> = Vec::new();
        let commit_pv_hash_instructions = program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::CommitPublicValues(instr) = instruction {
                    Some(instr)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if commit_pv_hash_instructions.len() != 1 {
            tracing::warn!("Expected exactly one CommitPVHash instruction.");
        }

        // We only take 1 commit pv hash instruction, since our air only checks for one public
        // values hash.
        for instruction in commit_pv_hash_instructions.iter().take(1) {
            for (i, addr) in instruction.pv_addrs.digest.iter().enumerate() {
                let mut row = [F::ZERO; NUM_PUBLIC_VALUES_PREPROCESSED_COLS];
                let cols: &mut PublicValuesPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.pv_idx[i] = F::ONE;
                cols.pv_mem = MemoryAccessCols {
                    addr: *addr,
                    mult: F::NEG_ONE,
                };
                rows.push(row);
            }
        }

        // Pad the preprocessed rows to log size 4.
        pad_rows_fixed(
            &mut rows,
            || [F::ZERO; NUM_PUBLIC_VALUES_PREPROCESSED_COLS],
            Some(PUB_VALUES_LOG_HEIGHT),
        );

        let trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect(),
            NUM_PUBLIC_VALUES_PREPROCESSED_COLS,
        );
        Some(trace)
    }

    fn generate_main(
        &self,
        input: &RecursionRecord<F>,
        _: &mut RecursionRecord<F>,
    ) -> RowMajorMatrix<F> {
        if input.commit_pv_hash_events.len() != 1 {
            tracing::warn!("Expected exactly one CommitPVHash event.");
        }

        let mut rows: Vec<[F; NUM_PUBLIC_VALUES_COLS]> = Vec::new();

        // We only take 1 commit pv hash instruction, since our air only checks for one public
        // values hash.
        for event in input.commit_pv_hash_events.iter().take(1) {
            for element in event.public_values.digest.iter() {
                let mut row = [F::ZERO; NUM_PUBLIC_VALUES_COLS];
                let cols: &mut PublicValuesCols<F> = row.as_mut_slice().borrow_mut();

                cols.pv_element = *element;
                rows.push(row);
            }
        }

        // Pad the trace to log size 4
        pad_rows_fixed(
            &mut rows,
            || [F::ZERO; NUM_PUBLIC_VALUES_COLS],
            Some(PUB_VALUES_LOG_HEIGHT),
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect(), NUM_PUBLIC_VALUES_COLS)
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for PublicValuesChip<F> {
    fn gpu_generate_preprocessed(
        &self,
        device_id: usize,
        program: &Self::Program,
    ) -> Option<TraceData<'_, F>> {
        use crate::{compiler::recursion::types::Address, primitives::consts::DIGEST_SIZE};
        use p3_koala_bear::KoalaBear;

        let commit_pv_instrs: Vec<Box<CommitPublicValuesInstr<_>>> =
            if let Some(guard) = program.get_buckets() {
                let buckets = guard.as_ref().unwrap();
                buckets.commit_public_values.to_vec()
            } else {
                program
                    .instructions
                    .iter()
                    .filter_map(|instruction| {
                        if let Instruction::CommitPublicValues(instr) = instruction {
                            Some(instr.clone())
                        } else {
                            None
                        }
                    })
                    .collect()
            };

        assert_eq!(commit_pv_instrs.len(), 1);
        let instr = commit_pv_instrs[0].as_ref();

        // fixed log size
        let nb_rows = 16;

        let sync_stream = get_global_stream_pool(device_id);
        let stream = &sync_stream.0;
        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = nb_rows * self.preprocessed_width();
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

        let mut d_digest =
            DevicePoolAllocation::<F>::alloc_from_pool_async(DIGEST_SIZE, mem_pool, stream)
                .unwrap();
        unsafe {
            let _ = cudaMemcpyAsync(
                d_digest.as_mut_c_void_ptr(),
                instr.pv_addrs.digest.as_c_void_ptr(),
                size_of::<[Address<F>; DIGEST_SIZE]>(),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );

            cuda_public_values_generate_preprocessed(
                d_digest.as_ptr() as *const _,
                d_trace.as_mut_ptr() as *mut _,
                self.preprocessed_width(),
                stream.into(),
            );
        }

        // No per-chip synchronization — caller (BaseProver) syncs once after all chips.
        info!("[public-values-chip] generate_main on GPU");

        Some(TraceData::Gpu(self.preprocessed_width(), d_trace))
    }

    fn gpu_generate_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        _: &mut Self::Record,
    ) -> TraceData<'_, F> {
        use crate::primitives::consts::DIGEST_SIZE;
        use p3_koala_bear::KoalaBear;

        let events = &input.commit_pv_hash_events;
        assert_eq!(events.len(), 1);

        // fixed log size
        let nb_rows = 16;

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = nb_rows * NUM_PUBLIC_VALUES_COLS;
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

        let mut d_digest =
            DevicePoolAllocation::<F>::alloc_from_pool_async(DIGEST_SIZE, mem_pool, stream)
                .unwrap();
        unsafe {
            let _ = cudaMemcpyAsync(
                d_digest.as_mut_c_void_ptr(),
                events[0].public_values.digest.as_c_void_ptr(),
                size_of::<[F; DIGEST_SIZE]>(),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
        }

        unsafe {
            cuda_public_values_generate_main(
                d_digest.as_ptr() as *const _,
                d_trace.as_mut_ptr() as *mut _,
                NUM_PUBLIC_VALUES_COLS,
                stream.into(),
            );
        }

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream.synchronize().unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        stream.synchronize().unwrap();
        main_stream.synchronize().unwrap();

        info!("[public-values-chip] generate_main on GPU");

        TraceData::Gpu(NUM_PUBLIC_VALUES_COLS, d_trace)
    }
}
