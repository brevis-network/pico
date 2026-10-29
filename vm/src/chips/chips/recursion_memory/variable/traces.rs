use super::{
    super::{MemoryAccessCols, NUM_MEM_ACCESS_COLS},
    columns::{MemoryCols, NUM_MEM_INIT_COLS, NUM_MEM_PREPROCESSED_INIT_COLS},
    MemoryVarChip,
};
#[cfg(feature = "cuda")]
use crate::{
    chips::{trace::TraceData, utils::next_power_of_two},
    cuda_adaptor::{get_global_mem_pool, get_global_stream_pool},
    machine::chip::GpuChipBehavior,
};
use crate::{
    compiler::recursion::{
        instruction::{
            HintAddCurveInstr, HintBitsInstr, HintExt2FeltsInstr, HintInstr, Instruction,
        },
        program::RecursionProgram,
    },
    emulator::recursion::emulator::RecursionRecord,
    iter::{IndexedPicoIterator, IntoPicoRefIterator, PicoIterator, PicoSliceMut},
    machine::{
        chip::{ChipBehavior, PreprocessedRows},
        utils::pad_to_power_of_two,
    },
    primitives::consts::VAR_MEM_DATAPAR,
};
use core::{borrow::BorrowMut, iter::zip};
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
use pico_gpu_api::{
    cuda_recursion_mem_var_generate_main, cuda_recursion_mem_var_generate_preprocessed,
};
#[cfg(feature = "cuda")]
use tracing::debug;

impl<F: PrimeField32> ChipBehavior<F> for MemoryVarChip<F> {
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "MemoryVar".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_MEM_PREPROCESSED_INIT_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().memory_var,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        // Allocating an intermediate `Vec` is faster.
        let accesses = program
            .instructions
            .pico_iter() // Using `rayon` here provides a big speedup.
            .flat_map_iter(|instruction| match instruction {
                Instruction::Hint(HintInstr { output_addrs_mults })
                | Instruction::HintBits(HintBitsInstr {
                    output_addrs_mults,
                    input_addr: _, // No receive interaction for the hint operation
                }) => output_addrs_mults.iter().collect(),
                Instruction::HintExt2Felts(HintExt2FeltsInstr {
                    output_addrs_mults,
                    input_addr: _, // No receive interaction for the hint operation
                }) => output_addrs_mults.iter().collect(),
                Instruction::HintAddCurve(instr) => {
                    let HintAddCurveInstr {
                        output_x_addrs_mults,
                        output_y_addrs_mults, .. // No receive interaction for the hint operation
                    } = instr.as_ref();
                    output_x_addrs_mults
                        .iter()
                        .chain(output_y_addrs_mults.iter())
                        .collect()
                }
                _ => vec![],
            })
            .collect::<Vec<_>>();

        let nb_rows = accesses.len().div_ceil(VAR_MEM_DATAPAR);
        let padded_nb_rows = program.padded_prep_rows(&self.name(), nb_rows);
        let mut values = vec![F::ZERO; padded_nb_rows * NUM_MEM_PREPROCESSED_INIT_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = accesses.len() * NUM_MEM_ACCESS_COLS;
        values[..populate_len]
            .pico_chunks_mut(NUM_MEM_ACCESS_COLS)
            .zip_eq(accesses)
            .for_each(|(row, &(addr, mult))| *row.borrow_mut() = MemoryAccessCols { addr, mult });

        let trace = RowMajorMatrix::new(values, NUM_MEM_PREPROCESSED_INIT_COLS);

        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let rows = input
            .mem_var_events
            .chunks(VAR_MEM_DATAPAR)
            .map(|row_events| {
                let mut row = [F::ZERO; NUM_MEM_INIT_COLS];
                let cols: &mut MemoryCols<_> = row.as_mut_slice().borrow_mut();
                for (cell, vals) in zip(&mut cols.values, row_events) {
                    *cell = vals.inner;
                }
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEM_INIT_COLS,
        );

        // Pad the trace to a power of two based on shape, if available.
        let log_size = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_MEM_INIT_COLS, F>(&mut trace.values, log_size);

        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }

    fn local_only(&self) -> bool {
        true
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for MemoryVarChip<F> {
    fn gpu_generate_preprocessed(
        &self,
        device_id: usize,
        program: &Self::Program,
    ) -> Option<TraceData<'_, F>> {
        use p3_koala_bear::KoalaBear;

        // Allocating an intermediate `Vec` is faster.
        let start = std::time::Instant::now();
        let accesses: Box<[_]> = if let Some(guard) = program.get_buckets() {
            let buckets = guard.as_ref().unwrap();
            buckets.mem_var_accesses.clone()
        } else {
            program
                .instructions
                // NOTE: the `rayon` method affected the performance, it could be tested by the below
                // debug log when running a single-node prove.
                // .pico_iter() // Using `rayon` here provides a big speedup.
                // .flat_map_iter(|instruction| match instruction {
                .iter()
                .flat_map(|instruction| match instruction {
                    Instruction::Hint(HintInstr { output_addrs_mults })
                    | Instruction::HintBits(HintBitsInstr {
                        output_addrs_mults,
                        input_addr: _, // No receive interaction for the hint operation
                    }) => output_addrs_mults.iter().collect(),
                    Instruction::HintExt2Felts(HintExt2FeltsInstr {
                        output_addrs_mults,
                        input_addr: _, // No receive interaction for the hint operation
                    }) => output_addrs_mults.iter().collect(),
                    Instruction::HintAddCurve(instr) => {
                        let HintAddCurveInstr {
                            output_x_addrs_mults,
                            output_y_addrs_mults, .. // No receive interaction for the hint operation
                        } = instr.as_ref();
                        output_x_addrs_mults
                            .iter()
                            .chain(output_y_addrs_mults.iter())
                            .collect()
                    }
                    _ => vec![],
                })
                .map(MemoryAccessCols::from)
                .collect::<Box<[_]>>()
        };
        debug!(
            "recursion_mem_var_access_collect_time={} ms",
            start.elapsed().as_millis(),
        );

        let nb_rows = accesses.len().div_ceil(VAR_MEM_DATAPAR);
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

        let num_instrs = accesses.len();
        if num_instrs > 0 {
            let mut d_instrs = DevicePoolAllocation::<MemoryAccessCols<F>>::alloc_from_pool_async(
                num_instrs, mem_pool, stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_instrs.as_mut_c_void_ptr(),
                    accesses.as_c_void_ptr(),
                    num_instrs * size_of::<MemoryAccessCols<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_recursion_mem_var_generate_preprocessed(
                    d_instrs.as_ptr() as *const _,
                    num_instrs,
                    d_trace.as_mut_ptr() as *mut _,
                    self.preprocessed_width(),
                    stream.into(),
                );
            }
        }

        // No per-chip synchronization — caller (BaseProver) syncs once after all chips.
        info!("[recursion-memory-var-chip] generate_preprocessed on GPU");

        Some(TraceData::Gpu(self.preprocessed_width(), d_trace))
    }

    fn gpu_generate_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        _: &mut Self::Record,
    ) -> TraceData<'_, F> {
        use p3_koala_bear::KoalaBear;

        let events = &input.mem_var_events;

        let nb_rows = events.len().div_ceil(VAR_MEM_DATAPAR);
        let log_rows = input.fixed_log2_rows(&self.name());
        let padded_nb_rows = match log_rows {
            Some(log_rows) => 1 << log_rows,
            None => next_power_of_two(nb_rows, None),
        };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * NUM_MEM_INIT_COLS;
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
            use super::super::MemEvent;
            let mut d_events = DevicePoolAllocation::<MemEvent<F>>::alloc_from_pool_async(
                event_size, mem_pool, stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_c_void_ptr(),
                    event_size * size_of::<MemEvent<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
            }

            unsafe {
                cuda_recursion_mem_var_generate_main(
                    d_events.as_ptr() as *const _,
                    event_size,
                    d_trace.as_mut_ptr() as *mut _,
                    NUM_MEM_INIT_COLS,
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

        info!("[recursion-memory-var-chip] generate_main on GPU");

        TraceData::Gpu(NUM_MEM_INIT_COLS, d_trace)
    }
}
