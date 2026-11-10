use crate::{
    chips::{
        chips::{
            byte::event::{ByteLookupEvent, ByteRecordBehavior},
            riscv_global::event::GlobalInteractionEvent,
            syscall::{columns::SyscallCols, SyscallChip, SyscallChunkKind, NUM_SYSCALL_COLS},
        },
        utils::pad_rows_fixed,
    },
    compiler::{
        addr::{encode_proof_addr_to_u32_limbs_48, Addr},
        riscv::{opcode::ByteOpcode, program::Program},
    },
    emulator::riscv::{record::EmulationRecord, syscalls::SyscallEvent},
    iter::{IntoPicoIterator, IntoPicoRefIterator, PicoIterator, PicoSlice},
    machine::{
        chip::ChipBehavior,
        estimator::{EventCapture, EventSizeCapture},
        lookup::{LookupScope, LookupType},
    },
};
#[cfg(feature = "cuda")]
use crate::{
    chips::{trace::TraceData, utils::next_power_of_two},
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    emulator::riscv::{history::ExecutionHistory, history_fill::HISTORY_LAYOUT},
    instances::preparer::{PreallocatedGpuMemory, PreparedGpuEvents, Readiness},
    machine::chip::GpuChipBehavior,
    mle::{machine::trace_oracle::history_launch, spans::device},
};
#[cfg(feature = "cuda")]
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
#[cfg(feature = "cuda")]
use cudart_sys::*;
use itertools::Itertools;
use p3_field::PrimeField32;
#[cfg(feature = "cuda")]
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
#[cfg(feature = "cuda")]
use pico_gpu_api::{
    cuda_syscall_generate_extra_record_and_main_u64,
    history_ecall_syscall::cuda_syscall_generate_extra_record_and_main_history,
};
use std::borrow::BorrowMut;
#[cfg(feature = "cuda")]
use tracing::info;

impl<F: PrimeField32> ChipBehavior<F> for SyscallChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        format!("Syscall{}", self.chunk_kind).to_string()
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        _output: &mut EmulationRecord,
    ) -> RowMajorMatrix<F> {
        let row_fn = |syscall_event: &SyscallEvent| {
            let mut row = [F::ZERO; NUM_SYSCALL_COLS];
            let cols: &mut SyscallCols<F> = row.as_mut_slice().borrow_mut();

            cols.chunk = F::from_u32(syscall_event.chunk);
            cols.clk = F::from_u32(u32::try_from(syscall_event.clk).unwrap());
            cols.syscall_id = F::from_u32(syscall_event.syscall_id);
            // Convert u64 arg1/arg2 to Addr (48-bit, 3 x 16-bit limbs)
            cols.arg1 =
                Addr::try_from(syscall_event.arg1).expect("arg1 exceeds 48-bit address range");
            cols.arg2 =
                Addr::try_from(syscall_event.arg2).expect("arg2 exceeds 48-bit address range");
            cols.is_real = F::ONE;
            row
        };

        let events = match self.chunk_kind {
            SyscallChunkKind::Riscv => input.syscalls().pico_iter().map(row_fn).collect::<Vec<_>>(),
            SyscallChunkKind::Precompile => input
                .precompile_events
                .sorted_groups()
                .pico_iter()
                .flat_map_iter(|(_, v)| v.iter().map(|(e, _)| row_fn(e)))
                .collect::<Vec<_>>(),
        };

        // Pad the trace to a power of two depending on the proof shape in `input`.
        let log_rows = input.shape_chip_size(&self.name());
        let mut rows = events;
        pad_rows_fixed(&mut rows, || [F::ZERO; NUM_SYSCALL_COLS], log_rows);

        RowMajorMatrix::new(
            rows.into_pico_iter().flatten().collect::<Vec<_>>(),
            NUM_SYSCALL_COLS,
        )
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let sorted_precompile_events: Vec<_>;
        let events: &[SyscallEvent] = match self.chunk_kind {
            SyscallChunkKind::Riscv => input.syscalls(),
            SyscallChunkKind::Precompile => {
                sorted_precompile_events = input
                    .precompile_events
                    .sorted_groups()
                    .pico_iter()
                    .flat_map_iter(|(_, v)| v.iter().map(|(e, _)| *e))
                    .collect();
                &sorted_precompile_events
            }
        };
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);
        // arg1 and arg2 are 48-bit addresses (3 x 16-bit limbs)
        let global_events: Vec<_> = events
            .pico_chunks(chunk_size)
            .flat_map(|events| {
                events
                    .iter()
                    .map(|event| {
                        let [arg1_0, arg1_1, arg1_2] =
                            encode_proof_addr_to_u32_limbs_48(event.arg1, "syscall arg1");
                        let [arg2_0, arg2_1, arg2_2] =
                            encode_proof_addr_to_u32_limbs_48(event.arg2, "syscall arg2");
                        GlobalInteractionEvent {
                            message: [
                                u32::try_from(event.clk).unwrap(), // element 0: clk
                                event.syscall_id + arg1_0 * 256, // element 1: syscall_id + arg1[0] * 256
                                arg1_1,                          // element 2: arg1[1]
                                arg1_2,                          // element 3: arg1[2]
                                arg2_0,                          // element 4: arg2[0]
                                arg2_1,                          // element 5: arg2[1]
                                arg2_2,                          // element 6: arg2[2]
                                event.chunk,                     // element 7: chunk
                            ],
                            is_receive: self.chunk_kind == SyscallChunkKind::Precompile,
                            kind: LookupType::Syscall as u8,
                        }
                    })
                    .collect_vec()
            })
            .collect();
        extra.global_lookup_events.extend(global_events);

        // Add byte lookup events for the range checks on syscall_id (u8) and arg1[0] (u16).
        for event in events.iter() {
            let syscall_id_byte = event.syscall_id as u8;
            // syscall_id is u8: pair it with zero for the U8Range check.
            extra.add_byte_lookup_event(ByteLookupEvent::new(
                ByteOpcode::U8Range,
                0,
                0,
                syscall_id_byte,
                0,
            ));
            // arg1[0] is u16: emit a U16Range check.
            let arg1_0 = (event.arg1 & 0xFFFF) as u16;
            extra.add_byte_lookup_event(ByteLookupEvent::new(
                ByteOpcode::U16Range,
                0,
                0,
                (arg1_0 >> 8) as u8,
                (arg1_0 & 0xFF) as u8,
            ));
        }
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match self.chunk_kind {
                SyscallChunkKind::Riscv => !record.syscalls().is_empty(),
                // A deferred record that carries precompile events needs this receiver whatever
                // else it carries: its Regional sends would otherwise lose their counterpart and
                // unbalance the SYSCALL bus. A memory-only record raises no such send, so it does
                // not need it. The CPU-step guard stays: CPU chunks defer their precompile
                // events out and are served by the Riscv-kind chip.
                SyscallChunkKind::Precompile => {
                    !record.precompile_events.is_empty() && record.cpu_steps().is_empty()
                }
            }
        }
    }

    fn lookup_scope(&self) -> LookupScope {
        LookupScope::Regional
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for SyscallChip<F> {
    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match self.chunk_kind {
                SyscallChunkKind::Riscv => record.event_counter.num_syscall_events > 0,
                // Tail-merge: keep in lockstep with `is_active` above — catch-all chunks may
                // carry memory events alongside precompile events (memory must not deactivate).
                SyscallChunkKind::Precompile => {
                    !record.precompile_syscall_events.is_empty()
                        && record.event_counter.num_cpu_events == 0
                }
            }
        }
    }

    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        // The history holds the RISC-V chunk's own syscalls; a precompile chunk's receivers come
        // from its precompile events.
        if self.chunk_kind == SyscallChunkKind::Riscv {
            let view = input
                .history_view()
                .expect("a CPU chunk's record carries its execution history");
            return self.gpu_generate_from_history(
                device_id,
                input,
                view.history,
                prepared_gpu_events,
                preallocated_gpu_memory,
            );
        }

        let events = &prepared_gpu_events.precompile_syscall_events;

        let nb_rows = events.len();
        let log_rows = input.shape_chip_size(&self.name());
        let padded_nb_rows = match log_rows {
            Some(log_rows) => 1 << log_rows,
            None => next_power_of_two(nb_rows, None),
        };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * NUM_SYSCALL_COLS;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();
        let fill = device::start(stream);
        unsafe {
            let _ = cudaMemsetAsync(
                d_trace.as_mut_ptr() as *mut _,
                0,
                trace_size * size_of::<KoalaBear>(),
                stream.into(),
            );
        }
        device::filled(fill, stream);

        let event_size = events.len();
        if event_size > 0 {
            let mut d_events = DevicePoolAllocation::<SyscallEvent>::alloc_from_pool_async(
                event_size, mem_pool, stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_c_void_ptr(),
                    event_size * size_of::<SyscallEvent>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
            }

            let d_global_events = preallocated_gpu_memory.d_global_events.as_mut().unwrap();

            let start_index = prepared_gpu_events
                .event_counter
                .start_indices
                .syscall_precompile_extra_global_lookup_start_index;

            let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();

            let kernels = device::start(stream);
            unsafe {
                cuda_syscall_generate_extra_record_and_main_u64(
                    NUM_SYSCALL_COLS,
                    event_size,
                    trace_size,
                    d_events.as_ptr() as *const _,
                    d_trace.as_mut_ptr() as *mut _,
                    stream.into(),
                    d_global_events.as_mut_ptr() as *mut _,
                    start_index,
                    self.chunk_kind as u8,
                    d_byte_trace.as_mut_ptr() as *mut _,
                );
            }
            device::launched(kernels, stream);
        }

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        device::wait(stream).unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        device::wait(main_stream).unwrap();

        info!("[syscall-chip] generate_extra_record_and_main on GPU");

        TraceData::Gpu(NUM_SYSCALL_COLS, d_trace)
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> SyscallChip<F> {
    /// The RISC-V syscall trace from the chunk's history on the device: the kernel reads the
    /// history's syscall rows there, so no event is uploaded, and their count sizes the trace. Each
    /// row's global event goes to the slot the counter reserved for it, and the kernel refuses a
    /// fill whose count is not the slots reserved.
    fn gpu_generate_from_history(
        &self,
        device_id: usize,
        input: &EmulationRecord,
        history: &ExecutionHistory,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let event_counter = &prepared_gpu_events.event_counter;
        let event_size = history.syscalls.len();
        assert_eq!(
            event_counter.num_syscall_events, event_size,
            "the counter's RISC-V syscall height is not the history's syscall rows"
        );

        let log_rows = input.shape_chip_size(&self.name());
        let padded_nb_rows = match log_rows {
            Some(log_rows) => 1 << log_rows,
            None => next_power_of_two(event_size, None),
        };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let d_byte_trace = preallocated_gpu_memory
            .d_byte_trace
            .as_mut()
            .unwrap()
            .as_mut_ptr();
        // The buffer is taken only when there are rows to send, and the kernel checks that the
        // fill has none either.
        let d_global_events = if event_size > 0 {
            preallocated_gpu_memory
                .d_global_events
                .as_mut()
                .unwrap()
                .as_mut_ptr()
        } else {
            std::ptr::null_mut()
        };

        let trace_size = padded_nb_rows * NUM_SYSCALL_COLS;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();

        let reader = preallocated_gpu_memory
            .d_history
            .as_ref()
            .expect("a record traced from its history reached a chip without its device fill")
            .reader(stream, Readiness::Complete)
            .unwrap_or_else(|e| panic!("reading the chunk's device history: {e}"));
        let args = reader.args();
        let kernels = device::start(stream);
        let err = unsafe {
            cuda_syscall_generate_extra_record_and_main_history(
                std::ptr::from_ref(&args).cast(),
                HISTORY_LAYOUT,
                NUM_SYSCALL_COLS,
                trace_size,
                d_trace.as_mut_ptr() as *mut _,
                d_byte_trace as *mut _,
                d_global_events as *mut _,
                event_counter
                    .start_indices
                    .syscall_riscv_extra_global_lookup_start_index,
                event_counter.num_syscall_events,
                stream.into(),
            )
        };
        assert_eq!(
            err.code, 0,
            "cuda_syscall_generate_extra_record_and_main_history failed: {err}"
        );
        history_launch::note(&self.name());
        drop(reader);

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        device::launched(kernels, stream);
        device::wait(stream).unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        device::wait(main_stream).unwrap();

        info!("[syscall-chip] generate_extra_record_and_main from the history on GPU");
        TraceData::Gpu(NUM_SYSCALL_COLS, d_trace)
    }
}

impl<F> EventCapture for SyscallChip<F> {
    fn count_extra_records(record: &EmulationRecord, event_counter: &mut EventSizeCapture) {
        event_counter.num_syscall_events += record.syscalls().len();
        event_counter.num_global_lookup_events += event_counter.num_syscall_events;
        event_counter.num_precompile_syscall_events += record
            .precompile_events
            .events
            .iter()
            .map(|(_, v)| v.len())
            .sum::<usize>();
        event_counter.num_global_lookup_events += event_counter.num_precompile_syscall_events;
    }
}
