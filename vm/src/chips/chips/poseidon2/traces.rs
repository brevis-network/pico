use crate::{
    chips::{
        chips::{
            poseidon2::{Poseidon2Chip, POSEIDON2_CHIPNAME},
            recursion_memory::MemoryAccessCols,
        },
        gadgets::poseidon2::{
            columns::{
                Poseidon2PreprocessedValueCols, Poseidon2ValueCols, NUM_POSEIDON2_COLS,
                NUM_POSEIDON2_VALUE_COLS, NUM_PREPROCESSED_POSEIDON2_COLS,
                NUM_PREPROCESSED_POSEIDON2_VALUE_COLS,
            },
            traces::populate_perm,
        },
        trace::TraceData,
        utils::next_power_of_two,
    },
    compiler::recursion::{
        instruction::Instruction::Poseidon2, program::RecursionProgram, types::Poseidon2Io,
    },
    configs::config::Poseidon2Config,
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    emulator::recursion::emulator::RecursionRecord,
    iter::{join, IndexedPicoIterator, PicoIterator, PicoSliceMut},
    machine::chip::{ChipBehavior, PreprocessedRows},
    primitives::consts::{PERMUTATION_WIDTH, POSEIDON2_DATAPAR},
};
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
use cudart_sys::{cudaMemcpyAsync, cudaMemsetAsync, CudaMemoryCopyKind};
use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use pico_gpu_api::{
    cuda_recursion_poseidon2_generate_main, cuda_recursion_poseidon2_generate_preprocessed,
};
use std::borrow::BorrowMut;
use tracing::info;

impl<
        F: PrimeField32,
        LinearLayers: GenericPoseidon2LinearLayers<PERMUTATION_WIDTH>,
        Config: Poseidon2Config,
    > ChipBehavior<F> for Poseidon2Chip<F, LinearLayers, Config>
{
    type Record = RecursionRecord<F>;
    type GpuRecord = ();
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        POSEIDON2_CHIPNAME.to_string()
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().poseidon2,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let instructions = program
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Poseidon2(instr) => Some(instr.as_ref()),
                _ => None,
            })
            .collect::<Vec<_>>();

        let nrows = instructions.len().div_ceil(POSEIDON2_DATAPAR);
        let padded_nrows = program.padded_prep_rows(&self.name(), nrows);

        let mut values = vec![F::ZERO; padded_nrows * NUM_PREPROCESSED_POSEIDON2_COLS];

        let populate_len = instructions.len() * NUM_PREPROCESSED_POSEIDON2_VALUE_COLS;
        values[..populate_len]
            .pico_chunks_mut(NUM_PREPROCESSED_POSEIDON2_VALUE_COLS)
            .zip_eq(instructions)
            .for_each(|(row, instruction)| {
                // Set the memory columns.
                // read once, at the first iteration,
                // write once, at the last iteration.
                *row.borrow_mut() = Poseidon2PreprocessedValueCols {
                    input: instruction.addrs.input,
                    output: std::array::from_fn(|j| MemoryAccessCols {
                        addr: instruction.addrs.output[j],
                        mult: instruction.mults[j],
                    }),
                    is_real_neg: F::NEG_ONE,
                }
            });
        Some(RowMajorMatrix::new(values, NUM_PREPROCESSED_POSEIDON2_COLS))
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.poseidon2_events;
        let nrows = events.len().div_ceil(POSEIDON2_DATAPAR);
        let fixed_log2_nrows = input.fixed_log2_rows(&self.name());
        let padded_nrows = match fixed_log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let mut values = vec![F::ZERO; padded_nrows * NUM_POSEIDON2_COLS::<Config>];

        let populate_len = events.len() * NUM_POSEIDON2_VALUE_COLS::<Config>;
        let (values_pop, values_dummy) = values.split_at_mut(populate_len);
        join(
            || {
                values_pop
                    .pico_chunks_mut(NUM_POSEIDON2_VALUE_COLS::<Config>)
                    .zip_eq(events)
                    .for_each(|(row, event)| {
                        let cols: &mut Poseidon2ValueCols<F, Config> = row.borrow_mut();
                        populate_perm::<F, LinearLayers, Config>(
                            F::ONE,
                            cols,
                            event.input,
                            Some(event.output),
                            &self.constants,
                        );
                    });
            },
            || {
                let mut dummy = vec![F::ZERO; NUM_POSEIDON2_VALUE_COLS::<Config>];
                let dummy = dummy.as_mut_slice();
                let dummy_cols: &mut Poseidon2ValueCols<F, Config> = dummy.borrow_mut();
                populate_perm::<F, LinearLayers, Config>(
                    F::ZERO,
                    dummy_cols,
                    [F::ZERO; PERMUTATION_WIDTH],
                    None,
                    &self.constants,
                );
                values_dummy
                    .pico_chunks_mut(NUM_POSEIDON2_VALUE_COLS::<Config>)
                    .for_each(|row| row.copy_from_slice(dummy))
            },
        );

        RowMajorMatrix::new(values, NUM_POSEIDON2_COLS::<Config>)
    }

    fn gpu_generate_preprocessed(
        &self,
        device_id: usize,
        program: &Self::Program,
    ) -> Option<TraceData<'_, F>> {
        use p3_koala_bear::KoalaBear;

        let instructions: Box<[_]> = if let Some(guard) = program.get_buckets() {
            let buckets = guard.as_ref().unwrap();
            buckets.poseidon2.to_vec().into_boxed_slice()
        } else {
            program
                .instructions
                .iter()
                .filter_map(|instruction| match instruction {
                    Poseidon2(x) => Some(x.as_ref().clone()),
                    _ => None,
                })
                .collect::<Box<[_]>>()
        };

        let nb_rows = instructions.len().div_ceil(POSEIDON2_DATAPAR);
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
            use crate::compiler::recursion::types::Poseidon2Instr;
            let mut d_instrs = DevicePoolAllocation::<Poseidon2Instr<F>>::alloc_from_pool_async(
                num_instrs, mem_pool, stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_instrs.as_mut_c_void_ptr(),
                    instructions.as_c_void_ptr(),
                    num_instrs * size_of::<Poseidon2Instr<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_recursion_poseidon2_generate_preprocessed(
                    d_instrs.as_ptr() as *const _,
                    num_instrs,
                    d_trace.as_mut_ptr() as *mut _,
                    self.preprocessed_width(),
                    stream.into(),
                );
            }
        }

        // No per-chip synchronization — caller (BaseProver) syncs once after all chips.
        info!("[recursion-poseidon2-chip] generate_preprocessed on GPU");

        Some(TraceData::Gpu(self.preprocessed_width(), d_trace))
    }

    fn gpu_generate_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        _: &mut Self::Record,
        _: Option<&Self::GpuRecord>,
    ) -> TraceData<'_, F> {
        let events = &input.poseidon2_events;
        let nrows = events.len().div_ceil(POSEIDON2_DATAPAR);
        let fixed_log2_nrows = input.fixed_log2_rows(&self.name());
        let padded_nrows = match fixed_log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let total_cols = NUM_POSEIDON2_COLS::<Config>;
        let value_cols = NUM_POSEIDON2_VALUE_COLS::<Config>;

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let event_size = events.len();
        // Allocate at least one element so the device pointer is non-null even with zero events
        // (the kernel then fills every padded row from the dummy row); avoids a 0-size-alloc UB.
        let mut d_events = DevicePoolAllocation::<Poseidon2Io<u32>>::alloc_from_pool_async(
            event_size.max(1),
            mem_pool,
            stream,
        )
        .unwrap();
        // The dummy row and the round constants both come from THIS chip's constants (the FRI and
        // MLE recursion machines instantiate this chip with different Poseidon2 constants, so a
        // compiled-in table would silently diverge for one of them).
        let mut dummy_row = vec![F::ZERO; value_cols];
        {
            let cols: &mut Poseidon2ValueCols<F, Config> = dummy_row.as_mut_slice().borrow_mut();
            populate_perm::<F, LinearLayers, Config>(
                F::ZERO,
                cols,
                [F::ZERO; PERMUTATION_WIDTH],
                None,
                &self.constants,
            );
        }
        let rc_flat = self.constants.flatten_for_gpu();
        let mut d_dummy_row = DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(
            dummy_row.len(),
            mem_pool,
            stream,
        )
        .unwrap();
        let mut d_round_constants = DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(
            rc_flat.len(),
            mem_pool,
            stream,
        )
        .unwrap();
        unsafe {
            if event_size > 0 {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_c_void_ptr(),
                    event_size * size_of::<Poseidon2Io<u32>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
            }
            let _ = cudaMemcpyAsync(
                d_dummy_row.as_mut_c_void_ptr(),
                dummy_row.as_c_void_ptr(),
                dummy_row.len() * size_of::<F>(),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
            let _ = cudaMemcpyAsync(
                d_round_constants.as_mut_c_void_ptr(),
                rc_flat.as_c_void_ptr(),
                rc_flat.len() * size_of::<F>(),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
        }

        let trace_size = padded_nrows * total_cols;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();
        unsafe {
            cuda_recursion_poseidon2_generate_main(
                value_cols,
                event_size,
                trace_size,
                d_events.as_ptr() as *const _,
                d_trace.as_mut_ptr() as *mut _,
                d_dummy_row.as_ptr() as *const _,
                d_round_constants.as_ptr() as *const _,
                stream.into(),
            );
        }

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream.synchronize().unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        stream.synchronize().unwrap();
        main_stream.synchronize().unwrap();

        info!("[recursion-poseidon2-chip] generate_main on GPU");

        TraceData::Gpu(total_cols, d_trace)
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PREPROCESSED_POSEIDON2_COLS
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }

    fn local_only(&self) -> bool {
        true
    }
}
