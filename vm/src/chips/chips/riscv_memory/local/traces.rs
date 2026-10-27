use std::borrow::BorrowMut;

use super::{
    columns::{MemoryLocalCols, NUM_MEMORY_LOCAL_INIT_COLS},
    MemoryLocalChip,
};
#[cfg(feature = "cuda")]
use crate::{
    chips::{
        chips::riscv_memory::{
            event::FfiMemoryLocalEvent, local::columns::NUM_SINGLE_MEMORY_LOCAL_COLS,
        },
        trace::TraceData,
    },
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    instances::preparer::{EventCounter, PreallocatedGpuMemory, PreparedGpuEvents},
    machine::chip::GpuChipBehavior,
};
use crate::{
    chips::{
        chips::{
            byte::event::ByteRecordBehavior, events::MemoryLocalEvent,
            riscv_global::event::GlobalInteractionEvent,
            riscv_memory::event::is_fresh_local_mem_event,
        },
        utils::{next_power_of_two, zeroed_f_vec},
    },
    compiler::riscv::program::Program,
    emulator::riscv::record::EmulationRecord,
    iter::PicoIterator,
    machine::{
        chip::ChipBehavior,
        estimator::{EventCapture, EventSizeCapture},
        lookup::{LookupScope, LookupType},
    },
    primitives::consts::LOCAL_MEMORY_DATAPAR,
};
#[cfg(feature = "cuda")]
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
#[cfg(feature = "cuda")]
use cudart_sys::{cudaMemcpyAsync, CudaMemoryCopyKind, *};
use p3_field::PrimeField32;
#[cfg(feature = "cuda")]
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
#[cfg(feature = "cuda")]
use pico_gpu_api::cuda_memory_local_generate_extra_record_and_main_u64;
use rayon::{
    iter::IndexedParallelIterator,
    slice::{ParallelSlice, ParallelSliceMut},
};
#[cfg(feature = "cuda")]
use tracing::info;

/// Split a u64 addr into 3×u16 limbs.
#[inline(always)]
fn addr_to_u16_limbs(addr: u64) -> [u32; 3] {
    [
        (addr & 0xFFFF) as u32,
        ((addr >> 16) & 0xFFFF) as u32,
        ((addr >> 32) & 0xFFFF) as u32,
    ]
}

/// Split a u64 value into 4×u16 limbs.
#[inline(always)]
fn value_to_u16_limbs(value: u64) -> [u32; 4] {
    [
        (value & 0xFFFF) as u32,
        ((value >> 16) & 0xFFFF) as u32,
        ((value >> 32) & 0xFFFF) as u32,
        ((value >> 48) & 0xFFFF) as u32,
    ]
}

/// Split an entry into the shape flag, the `clk` its initial state puts on the regional bus, and
/// `final_clk - initial_clk - 1`.
///
/// An interval that starts in an earlier chunk cannot name its real `initial_clk` on the regional
/// bus — that clock belongs to a chunk which has since reset — so it carries the sentinel `0`,
/// which is what the first access of the interval also names as its `prev_clk`. Intervals that
/// start inside this chunk carry the real value, and only those get the `initial_clk < final_clk`
/// check (the diff is unconstrained, hence zero, on the others).
#[inline(always)]
fn normalize_initial(event: &MemoryLocalEvent) -> (bool, u32, u64) {
    let initial = &event.initial_mem_access;
    let final_ = &event.final_mem_access;
    if initial.chunk == final_.chunk {
        let diff = u64::from(final_.timestamp) - u64::from(initial.timestamp) - 1;
        assert!(
            diff < (1 << 25),
            "memory-local clk diff {diff} exceeds the 25-bit budget"
        );
        (true, initial.timestamp, diff)
    } else {
        (false, 0, 0)
    }
}

/// Build a packed 8-slot Global message from (chunk, clk, addr, value).
/// Layout: [chunk, clk, addr[0], addr[1], addr[2], v0+v2_lower<<16, v1+v2_upper<<16, v3]
///
/// v2 packing trick: v[2] is split into v2_lower (bits 0..7) and v2_upper (bits 8..15),
/// then packed into slot5 and slot6 respectively.
#[inline(always)]
fn build_global_message(chunk: u32, clk: u32, addr: u64, value: u64) -> [u32; 8] {
    let a = addr_to_u16_limbs(addr);
    let v = value_to_u16_limbs(value);
    let v2_lower = v[2] & 0xFF; // lower 8 bits of v[2]
    let v2_upper = (v[2] >> 8) & 0xFF; // upper 8 bits of v[2]
    [
        chunk,
        clk,
        a[0],
        a[1],
        a[2],
        v[0] + (v2_lower << 16), // slot5: v0 + v2_lower<<16
        v[1] + (v2_upper << 16), // slot6: v1 + v2_upper<<16
        v[3],                    // slot7: v3
    ]
}

impl<F: PrimeField32> ChipBehavior<F> for MemoryLocalChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "MemoryLocal".to_string()
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        _output: &mut EmulationRecord,
    ) -> RowMajorMatrix<F> {
        let events = input.get_local_mem_events().collect::<Vec<_>>();
        let image = &input.program.memory_image;
        let nb_rows = events.len().div_ceil(LOCAL_MEMORY_DATAPAR);
        let log_rows = input.shape_chip_size(&self.name());
        let padded_nb_rows = next_power_of_two(nb_rows, log_rows);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_MEMORY_LOCAL_INIT_COLS);

        // Parallelize the main computation using par_chunks_mut
        values[..nb_rows * NUM_MEMORY_LOCAL_INIT_COLS]
            .par_chunks_mut(NUM_MEMORY_LOCAL_INIT_COLS)
            .enumerate()
            .for_each(|(row_idx, row)| {
                let base_event_idx = row_idx * LOCAL_MEMORY_DATAPAR;
                let cols: &mut MemoryLocalCols<F> = row.borrow_mut();

                for k in 0..LOCAL_MEMORY_DATAPAR {
                    let cols = &mut cols.memory_local_entries[k];
                    if base_event_idx + k < events.len() {
                        let event = &events[base_event_idx + k];

                        // addr: 3×u16 limbs directly from u64
                        let addr_limbs = addr_to_u16_limbs(event.addr);
                        cols.addr = addr_limbs.map(F::from_u32);

                        cols.initial_chunk = F::from_u32(event.initial_mem_access.chunk);
                        cols.final_chunk = F::from_u32(event.final_mem_access.chunk);
                        cols.initial_clk = F::from_u32(event.initial_mem_access.timestamp);
                        cols.final_clk = F::from_u32(event.final_mem_access.timestamp);

                        // Value: 4×u16 limbs directly from u64
                        let init_v = value_to_u16_limbs(event.initial_mem_access.value);
                        cols.initial_value = crate::compiler::word::Word(init_v.map(F::from_u32));

                        let final_v = value_to_u16_limbs(event.final_mem_access.value);
                        cols.final_value = crate::compiler::word::Word(final_v.map(F::from_u32));

                        // v2 packing: value[2] = value_lower + value_upper * 256
                        cols.initial_value_lower = F::from_u32(init_v[2] & 0xFF);
                        cols.initial_value_upper = F::from_u32((init_v[2] >> 8) & 0xFF);
                        cols.final_value_lower = F::from_u32(final_v[2] & 0xFF);
                        cols.final_value_upper = F::from_u32((final_v[2] >> 8) & 0xFF);

                        // Which shape this entry has, and the normalized `clk` that follows.
                        let (in_chunk, clk_regional, clk_diff) = normalize_initial(event);
                        cols.initial_in_chunk = F::from_bool(in_chunk);
                        cols.initial_clk_regional = F::from_u32(clk_regional);
                        cols.clk_diff_16bit_limb = F::from_u16((clk_diff & 0xffff) as u16);
                        cols.clk_diff_hi9 = F::from_u16(((clk_diff >> 16) & 0x1ff) as u16);

                        cols.is_real = F::ONE;
                        // A fresh entry declares its (zero) initial state instead of receiving
                        // it; see `riscv_memory/event.rs`.
                        cols.has_initial = F::from_bool(!is_fresh_local_mem_event(event, image));
                    }
                }
            });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_MEMORY_LOCAL_INIT_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let local_mem_events = input.get_local_mem_events().collect::<Vec<_>>();
        let image = &input.program.memory_image;
        let nb_rows = local_mem_events.len().div_ceil(4);
        let chunk_size = std::cmp::max((nb_rows + 1) / num_cpus::get(), 1);

        let (global_events, blu_batches): (Vec<_>, Vec<_>) = local_mem_events
            .par_chunks(chunk_size * LOCAL_MEMORY_DATAPAR)
            .map(|events| {
                let mut global_events = vec![];
                let mut blu = vec![];

                events.chunks(LOCAL_MEMORY_DATAPAR).for_each(|events| {
                    for k in 0..LOCAL_MEMORY_DATAPAR {
                        if k < events.len() {
                            let event = events[k];

                            // --- Byte lookup events ---

                            // Initial value: u8 range check for v2 packing cols
                            let init_v2_lower =
                                ((event.initial_mem_access.value >> 32) & 0xFF) as u8;
                            let init_v2_upper =
                                ((event.initial_mem_access.value >> 40) & 0xFF) as u8;
                            blu.add_u8_range_check(init_v2_lower, init_v2_upper);

                            // Initial value: u16 range check for limbs 0 and 1 only (the two
                            // Global packing slots); the AIR binds the other limbs through the
                            // memory bus (`local/constraints.rs`).
                            let init_v = value_to_u16_limbs(event.initial_mem_access.value);
                            blu.add_u16_range_checks(&[init_v[0] as u16, init_v[1] as u16]);

                            // Final value: u8 range check for v2 packing cols
                            let final_v2_lower =
                                ((event.final_mem_access.value >> 32) & 0xFF) as u8;
                            let final_v2_upper =
                                ((event.final_mem_access.value >> 40) & 0xFF) as u8;
                            blu.add_u8_range_check(final_v2_lower, final_v2_upper);

                            // No U16 events for the final value or the address: the AIR has no
                            // range checks on them (they are bus-bound, see the constraints).

                            // Whichever shape the entry has, it pays exactly one range check:
                            // the clk gap inside the chunk, or the chunk gap across chunks.
                            let (in_chunk, _, clk_diff) = normalize_initial(event);
                            if in_chunk {
                                blu.add_u16_range_check((clk_diff & 0xffff) as u16);
                                blu.add_bit_range_check(((clk_diff >> 16) & 0x1ff) as u16, 9);
                            } else {
                                let chunk_diff = event.final_mem_access.chunk
                                    - event.initial_mem_access.chunk
                                    - 1;
                                blu.add_u16_range_check(chunk_diff as u16);
                            }

                            // --- Global interaction events ---

                            // Initial: receive interaction. A fresh entry declares its initial
                            // state on the AIR (`has_initial = 0`) and receives nothing; its
                            // byte events above are unchanged (the u8 / u16 checks still run
                            // on the zero limbs). The GPU kernel writes the same events at
                            // `FfiMemoryLocalEvent::global_slot`, and the counters
                            // (`count_extra_records`) subtract the same fresh count.
                            if !is_fresh_local_mem_event(event, image) {
                                global_events.push(GlobalInteractionEvent {
                                    message: build_global_message(
                                        event.initial_mem_access.chunk,
                                        event.initial_mem_access.timestamp,
                                        event.addr,
                                        event.initial_mem_access.value,
                                    ),
                                    is_receive: true,
                                    kind: LookupType::Memory as u8,
                                });
                            }

                            // Final: send interaction
                            global_events.push(GlobalInteractionEvent {
                                message: build_global_message(
                                    event.final_mem_access.chunk,
                                    event.final_mem_access.timestamp,
                                    event.addr,
                                    event.final_mem_access.value,
                                ),
                                is_receive: false,
                                kind: LookupType::Memory as u8,
                            });
                        }
                    }
                });

                (global_events, blu)
            })
            .unzip();

        extra
            .global_lookup_events
            .extend(global_events.into_iter().flatten());
        extra.add_byte_lookup_events(blu_batches.into_iter().flatten().collect());
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        // Under a pad shape the shape decides presence, so a bucketed chunk's proof shape
        // depends on the chunk kind rather than on its opcode mix. Without a shape the
        // chip is event-driven, which is what the natural-height path wants.
        if let Some(shape) = record.shape.as_ref() {
            return shape.included::<F, _>(self);
        }
        record.get_local_mem_events().nth(0).is_some()
    }

    fn lookup_scope(&self) -> LookupScope {
        LookupScope::Regional
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for MemoryLocalChip<F> {
    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let events = &prepared_gpu_events.memory_local_events;

        // Calculate padding rows
        let nb_rows = events.len().div_ceil(LOCAL_MEMORY_DATAPAR);
        let log_rows = input.shape_chip_size(&self.name());
        let padded_nb_rows = next_power_of_two(nb_rows, log_rows);

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * NUM_MEMORY_LOCAL_INIT_COLS;
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
            let mut d_events = DevicePoolAllocation::<FfiMemoryLocalEvent>::alloc_from_pool_async(
                event_size, mem_pool, stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_c_void_ptr(),
                    event_size * size_of::<FfiMemoryLocalEvent>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
            }
            let d_global_events = preallocated_gpu_memory.d_global_events.as_mut().unwrap();
            let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();

            unsafe {
                let err = cuda_memory_local_generate_extra_record_and_main_u64(
                    NUM_SINGLE_MEMORY_LOCAL_COLS,
                    event_size,
                    trace_size,
                    d_events.as_ptr() as *const _,
                    d_trace.as_mut_ptr() as *mut _,
                    stream.into(),
                    d_global_events.as_mut_ptr() as *mut _,
                    prepared_gpu_events
                        .event_counter
                        .start_indices
                        .memory_local_extra_global_start_index,
                    d_byte_trace.as_mut_ptr() as *mut _,
                );
                assert_eq!(
                    err.code, 0,
                    "cuda_memory_local_generate_extra_record_and_main_u64 failed \
                     (CUDA/Rust column-width mismatch?)"
                );
            }
        }

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream.synchronize().unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        stream.synchronize().unwrap();
        main_stream.synchronize().unwrap();

        info!("[memory-local-chip] generate_extra_record_and_main on GPU");
        TraceData::Gpu(NUM_MEMORY_LOCAL_INIT_COLS, d_trace)
    }

    fn count_extra_records(record: &Self::Record, counter: &mut EventCounter) {
        // The precompile local memory events are already counted in the main counting function
        // This function only needs to count the CPU local memory access events
        let cpu_local_mem_count = record.cpu_local_memory_access.len();
        counter.num_cpu_local_memory_access += cpu_local_mem_count;
        counter.num_global_lookup_events += cpu_global_events(record);
    }

    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        !record.memory_local_events.is_empty()
    }
}

impl<F> EventCapture for MemoryLocalChip<F> {
    fn count_extra_records(record: &EmulationRecord, event_counter: &mut EventSizeCapture) {
        event_counter.num_cpu_local_memory_access += record.cpu_local_memory_access.len();
        event_counter.num_global_lookup_events += cpu_global_events(record);
    }
}

/// Global events the CPU local-memory entries of `record` raise: two per entry (initial receive
/// and final send) less one per fresh entry, which sends only. Must agree with `extra_record`
/// above and with the GPU staging (`FfiMemoryLocalEvent::stage`), which all use the same
/// predicate; the precompile entries are counted the same way in
/// `instances/preparer/event_counter.rs`.
pub fn local_mem_global_events<'a>(
    events: impl IntoIterator<Item = &'a MemoryLocalEvent>,
    image: &std::collections::BTreeMap<u64, u64>,
) -> usize {
    events
        .into_iter()
        .map(|e| 2 - usize::from(is_fresh_local_mem_event(e, image)))
        .sum()
}

fn cpu_global_events(record: &EmulationRecord) -> usize {
    local_mem_global_events(
        record.cpu_local_memory_access.iter(),
        &record.program.memory_image,
    )
}
