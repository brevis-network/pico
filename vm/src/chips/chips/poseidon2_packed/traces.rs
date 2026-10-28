#[cfg(feature = "cuda")]
use crate::{
    chips::trace::TraceData,
    compiler::recursion::{mle_instruction_buckets::MleVariant, types::Poseidon2Io},
    cuda_adaptor::{get_global_mem_pool, get_global_stream_pool},
    machine::chip::GpuChipBehavior,
};
use crate::{
    chips::{
        chips::{
            poseidon2_packed::{
                columns::{
                    Poseidon2PackedPreprocessedCols, NUM_POSEIDON2_PACKED_PREPROCESSED_COLS,
                },
                Poseidon2PackedChip, POSEIDON2_PACKED_CHIPNAME,
            },
            recursion_memory::MemoryAccessCols,
        },
        gadgets::poseidon2::{
            columns::{Poseidon2ValueCols, NUM_POSEIDON2_VALUE_COLS},
            traces::populate_perm,
        },
        utils::next_power_of_two,
    },
    compiler::recursion::{
        instruction::Instruction, program::RecursionProgram, types::Poseidon2PackedInstr,
    },
    configs::config::Poseidon2Config,
    emulator::recursion::emulator::RecursionRecord,
    iter::{join, IndexedPicoIterator, PicoIterator, PicoSliceMut},
    machine::{
        chip::{ChipBehavior, PreprocessedRows},
        utils::pad_to_power_of_two,
    },
    primitives::consts::PERMUTATION_WIDTH,
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
use p3_field::PrimeField32;
#[cfg(feature = "cuda")]
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
#[cfg(feature = "cuda")]
use pico_gpu_api::{
    cuda_poseidon2_packed_generate_preprocessed, cuda_recursion_poseidon2_generate_main,
};
use std::borrow::BorrowMut;

impl<
        F: PrimeField32,
        LinearLayers: GenericPoseidon2LinearLayers<PERMUTATION_WIDTH>,
        Config: Poseidon2Config,
    > ChipBehavior<F> for Poseidon2PackedChip<F, LinearLayers, Config>
{
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        POSEIDON2_PACKED_CHIPNAME.to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_POSEIDON2_PACKED_PREPROCESSED_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().poseidon2_packed,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_POSEIDON2_PACKED_PREPROCESSED_COLS]> = Vec::new();

        program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::Poseidon2Packed(instr) = instruction {
                    Some(instr.as_ref())
                } else {
                    None
                }
            })
            .for_each(|instr: &Poseidon2PackedInstr<F>| {
                let mut row = [F::ZERO; NUM_POSEIDON2_PACKED_PREPROCESSED_COLS];
                let cols: &mut Poseidon2PackedPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.is_real = F::ONE;
                cols.input = instr.input_addrs;
                cols.output = std::array::from_fn(|j| MemoryAccessCols {
                    addr: instr.output_addrs[j],
                    mult: instr.mults[j],
                });
                rows.push(row);
            });

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_POSEIDON2_PACKED_PREPROCESSED_COLS,
        );
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_POSEIDON2_PACKED_PREPROCESSED_COLS, F>(
            &mut trace.values,
            log_size,
        );
        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.poseidon2_packed_events;
        let nrows = events.len();
        let fixed_log2_nrows = input.fixed_log2_rows(&self.name());
        let padded_nrows = match fixed_log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let mut values = vec![F::ZERO; padded_nrows * NUM_POSEIDON2_VALUE_COLS::<Config>];

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

        RowMajorMatrix::new(values, NUM_POSEIDON2_VALUE_COLS::<Config>)
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }

    fn local_only(&self) -> bool {
        true
    }
}

#[cfg(feature = "cuda")]
impl<
        F: PrimeField32,
        LinearLayers: GenericPoseidon2LinearLayers<PERMUTATION_WIDTH>,
        Config: Poseidon2Config,
    > GpuChipBehavior<F> for Poseidon2PackedChip<F, LinearLayers, Config>
{
    fn gpu_generate_preprocessed(
        &self,
        device_id: usize,
        program: &Self::Program,
    ) -> Option<TraceData<'_, F>> {
        let instructions: Box<[Poseidon2PackedInstr<F>]> = program
            .mle_candidates(MleVariant::Poseidon2Packed)
            .filter_map(|instruction| match instruction {
                Instruction::Poseidon2Packed(x) => Some(**x),
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
                DevicePoolAllocation::<Poseidon2PackedInstr<F>>::alloc_from_pool_async(
                    num_instrs, mem_pool, stream,
                )
                .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_instrs.as_mut_c_void_ptr(),
                    instructions.as_c_void_ptr(),
                    num_instrs * size_of::<Poseidon2PackedInstr<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_poseidon2_packed_generate_preprocessed(
                    d_instrs.as_ptr() as *const _,
                    num_instrs,
                    d_trace.as_mut_ptr() as *mut _,
                    self.preprocessed_width(),
                    stream.into(),
                );
            }
        }

        info!("[poseidon2-packed-chip] generate_preprocessed on GPU");

        Some(TraceData::Gpu(self.preprocessed_width(), d_trace))
    }

    fn gpu_generate_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        _: &mut Self::Record,
    ) -> TraceData<'_, F> {
        // The main columns are the shared Poseidon2ValueCols (one permutation per row), identical to
        // the recursion poseidon2 chip, so the permutation trace is produced by the same kernel; only
        // the event source differs. NUM_POSEIDON2_COLS == NUM_POSEIDON2_VALUE_COLS (DATAPAR == 1).
        let events = &input.poseidon2_packed_events;
        let nb_rows = events.len();
        let padded_nb_rows = match input.fixed_log2_rows(&self.name()) {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nb_rows, None),
        };

        let value_cols = NUM_POSEIDON2_VALUE_COLS::<Config>;

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let event_size = events.len();
        // Allocate at least one element so the device pointer is non-null even with zero events
        // (the kernel still fills every padded row from the dummy row); avoids a 0-size-alloc UB.
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

        let trace_size = padded_nb_rows * value_cols;
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

        info!("[poseidon2-packed-chip] generate_main on GPU");

        TraceData::Gpu(value_cols, d_trace)
    }
}
