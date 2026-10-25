use crate::{
    chips::{
        chips::{
            exp_reverse_bits::{
                columns::{
                    ExpReverseBitsLenCols, ExpReverseBitsLenPreprocessedCols,
                    NUM_EXP_REVERSE_BITS_LEN_COLS, NUM_EXP_REVERSE_BITS_LEN_PREPROCESSED_COLS,
                },
                ExpReverseBitsLenChip,
            },
            recursion_memory::MemoryAccessCols,
        },
        trace::TraceData,
        utils::next_power_of_two,
    },
    compiler::recursion::{instruction::Instruction, program::RecursionProgram},
    cuda_adaptor::{get_global_mem_pool, get_global_stream_pool},
    emulator::recursion::emulator::RecursionRecord,
    machine::chip::ChipBehavior,
};
use core::borrow::BorrowMut;
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
use cudart_sys::*;
use log::info;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use pico_gpu_api::{cuda_exp_bits_generate_main, cuda_exp_bits_generate_preprocessed};

use crate::{chips::utils::pad_rows_fixed, compiler::recursion::types::ExpReverseBitsInstr};

impl<F: PrimeField32> ChipBehavior<F> for ExpReverseBitsLenChip<F> {
    type Record = RecursionRecord<F>;
    type GpuRecord = ();
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "ExpReverseBitsLen".to_string()
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_EXP_REVERSE_BITS_LEN_PREPROCESSED_COLS]> = Vec::new();
        program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::ExpReverseBitsLen(instr) = instruction {
                    Some(instr)
                } else {
                    None
                }
            })
            .for_each(|instruction| {
                let ExpReverseBitsInstr { addrs, mult } = instruction;
                let mut row_add =
                    vec![[F::ZERO; NUM_EXP_REVERSE_BITS_LEN_PREPROCESSED_COLS]; addrs.exp.len()];
                row_add.iter_mut().enumerate().for_each(|(i, row)| {
                    let row: &mut ExpReverseBitsLenPreprocessedCols<F> =
                        row.as_mut_slice().borrow_mut();
                    row.iteration_num = F::from_u32(i as u32);
                    row.is_first = F::from_bool(i == 0);
                    row.is_last = F::from_bool(i == addrs.exp.len() - 1);
                    row.is_real = F::ONE;
                    row.x_mem = MemoryAccessCols {
                        addr: addrs.base,
                        mult: -F::from_bool(i == 0),
                    };
                    row.exponent_mem = MemoryAccessCols {
                        addr: addrs.exp[i],
                        mult: F::NEG_ONE,
                    };
                    row.result_mem = MemoryAccessCols {
                        addr: addrs.result,
                        mult: *mult * F::from_bool(i == addrs.exp.len() - 1),
                    };
                });
                rows.extend(row_add);
            });

        // Pad the trace to a power of two.
        pad_rows_fixed(
            &mut rows,
            || [F::ZERO; NUM_EXP_REVERSE_BITS_LEN_PREPROCESSED_COLS],
            program.fixed_log2_rows(&self.name()),
        );

        let trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect(),
            NUM_EXP_REVERSE_BITS_LEN_PREPROCESSED_COLS,
        );
        Some(trace)
    }

    fn generate_main(
        &self,
        input: &RecursionRecord<F>,
        _: &mut RecursionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut overall_rows = Vec::new();
        input.exp_reverse_bits_len_events.iter().for_each(|event| {
            let mut rows = vec![vec![F::ZERO; NUM_EXP_REVERSE_BITS_LEN_COLS]; event.exp.len()];

            let mut accum = F::ONE;

            rows.iter_mut().enumerate().for_each(|(i, row)| {
                let cols: &mut ExpReverseBitsLenCols<F> = row.as_mut_slice().borrow_mut();

                let prev_accum = accum;
                accum = prev_accum
                    * prev_accum
                    * if event.exp[i] == F::ONE {
                        event.base
                    } else {
                        F::ONE
                    };

                cols.x = event.base;
                cols.current_bit = event.exp[i];
                cols.accum = accum;
                cols.accum_squared = accum * accum;
                cols.prev_accum_squared = prev_accum * prev_accum;
                cols.multiplier = if event.exp[i] == F::ONE {
                    event.base
                } else {
                    F::ONE
                };
                cols.prev_accum_squared_times_multiplier =
                    cols.prev_accum_squared * cols.multiplier;
                if i == event.exp.len() {
                    assert_eq!(event.result, accum);
                }
            });

            overall_rows.extend(rows);
        });

        // Pad the trace to a power of two.
        pad_rows_fixed(
            &mut overall_rows,
            || [F::ZERO; NUM_EXP_REVERSE_BITS_LEN_COLS].to_vec(),
            input.fixed_log2_rows(&self.name()),
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            overall_rows.into_iter().flatten().collect(),
            NUM_EXP_REVERSE_BITS_LEN_COLS,
        )
    }

    fn preprocessed_width(&self) -> usize {
        NUM_EXP_REVERSE_BITS_LEN_PREPROCESSED_COLS
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }

    fn gpu_generate_preprocessed(
        &self,
        device_id: usize,
        program: &Self::Program,
    ) -> Option<TraceData<'_, F>> {
        use crate::compiler::recursion::types::{
            preprocess_exp_reverse_bits_instr_ffi, ExpReverseBitsInstrFfi,
        };
        use p3_koala_bear::KoalaBear;

        let exp_reverse_bits_instrs: Box<[ExpReverseBitsInstr<_>]> =
            if let Some(guard) = program.get_buckets() {
                let buckets = guard.as_ref().unwrap();
                buckets.exp_reverse_bits.clone()
            } else {
                program
                    .instructions
                    .iter()
                    .filter_map(|instruction| {
                        if let Instruction::ExpReverseBitsLen(instr) = instruction {
                            Some(instr.clone())
                        } else {
                            None
                        }
                    })
                    .collect::<Box<[_]>>()
            };
        let exp_reverse_bits_refs: Box<[_]> = exp_reverse_bits_instrs.iter().collect();
        let (instrs, addrs) = preprocess_exp_reverse_bits_instr_ffi(&exp_reverse_bits_refs);

        let nb_rows = addrs.len();
        let log_rows = program.fixed_log2_rows(&self.name());
        let padded_nb_rows = match log_rows {
            Some(log_rows) => 1 << log_rows,
            None => next_power_of_two(nb_rows, None),
        };

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

        let num_instrs = instrs.len();
        if num_instrs > 0 {
            use crate::compiler::recursion::types::Address;
            let mut d_instrs =
                DevicePoolAllocation::<ExpReverseBitsInstrFfi<F>>::alloc_from_pool_async(
                    num_instrs, mem_pool, stream,
                )
                .unwrap();
            let mut d_addrs = DevicePoolAllocation::<Address<F>>::alloc_from_pool_async(
                addrs.len(),
                mem_pool,
                stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_instrs.as_mut_c_void_ptr(),
                    instrs.as_c_void_ptr(),
                    num_instrs * size_of::<ExpReverseBitsInstrFfi<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
                let _ = cudaMemcpyAsync(
                    d_addrs.as_mut_c_void_ptr(),
                    addrs.as_c_void_ptr(),
                    addrs.len() * size_of::<Address<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_exp_bits_generate_preprocessed(
                    d_instrs.as_ptr() as *const _,
                    num_instrs,
                    d_addrs.as_ptr() as *const _,
                    d_trace.as_mut_ptr() as *mut _,
                    self.preprocessed_width(),
                    stream.into(),
                );
            }
        }

        // No per-chip synchronization — caller (BaseProver) syncs once after all chips.
        info!("[batch-fri-chip] generate_preprocessed on GPU");

        Some(TraceData::Gpu(self.preprocessed_width(), d_trace))
    }

    fn gpu_generate_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        _: &mut Self::Record,
        _: Option<&Self::GpuRecord>,
    ) -> TraceData<'_, F> {
        use crate::compiler::recursion::types::{
            preprocess_exp_reverse_bits_ffi, ExpReverseBitsFfiEvent,
        };
        use p3_koala_bear::KoalaBear;

        let (events, bits) = preprocess_exp_reverse_bits_ffi(&input.exp_reverse_bits_len_events);

        let nb_rows = bits.len();
        let log_rows = input.fixed_log2_rows(&self.name());
        let padded_nb_rows = match log_rows {
            Some(log_rows) => 1 << log_rows,
            None => next_power_of_two(nb_rows, None),
        };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * NUM_EXP_REVERSE_BITS_LEN_COLS;
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
                DevicePoolAllocation::<ExpReverseBitsFfiEvent<F>>::alloc_from_pool_async(
                    event_size, mem_pool, stream,
                )
                .unwrap();
            let mut d_bits =
                DevicePoolAllocation::<F>::alloc_from_pool_async(bits.len(), mem_pool, stream)
                    .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_c_void_ptr(),
                    event_size * size_of::<ExpReverseBitsFfiEvent<F>>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
                let _ = cudaMemcpyAsync(
                    d_bits.as_mut_c_void_ptr(),
                    bits.as_c_void_ptr(),
                    bits.len() * size_of::<F>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );

                cuda_exp_bits_generate_main(
                    d_events.as_ptr() as *const _,
                    event_size,
                    d_bits.as_ptr() as *const _,
                    d_trace.as_mut_ptr() as *mut _,
                    NUM_EXP_REVERSE_BITS_LEN_COLS,
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

        info!("[exp-reverse-bits-len-chip] generate_main on GPU");

        TraceData::Gpu(NUM_EXP_REVERSE_BITS_LEN_COLS, d_trace)
    }
}
