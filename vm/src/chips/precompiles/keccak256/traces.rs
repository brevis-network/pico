use super::{
    columns::{KeccakMemCols, NUM_KECCAK_MEM_COLS},
    KeccakPermuteChip, STATE_SIZE,
};
use crate::{
    chips::{precompiles::checked_u64_to_u32, trace::TraceData},
    compiler::riscv::program::Program,
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    emulator::{
        record::RecordBehavior,
        riscv::{
            ffi::FFIEmulationRecord,
            record::EmulationRecord,
            syscalls::{
                precompiles::{
                    keccak256::event::FFIKeccakPermuteEvent, KeccakPermuteEvent, PrecompileEvent,
                },
                SyscallCode,
            },
        },
    },
    instances::preparer::{PreallocatedGpuMemory, PreparedGpuEvents},
    iter::{PicoBridge, PicoIterator},
    machine::chip::ChipBehavior,
};
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
use cudart_sys::*;
use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_keccak_air::{
    generate_trace_rows, KeccakCols as UpstreamKeccakCols, NUM_KECCAK_COLS, NUM_ROUNDS,
};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use pico_gpu_api::cuda_precompile_keccak_generate_extra_record_and_main;
use std::borrow::{Borrow, BorrowMut};
use tracing::{debug, info};

impl<F> BaseAir<F> for KeccakPermuteChip<F> {
    fn width(&self) -> usize {
        NUM_KECCAK_MEM_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for KeccakPermuteChip<F> {
    type Record = EmulationRecord;
    type GpuRecord = FFIEmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "KeccakPermute".to_string()
    }

    fn generate_preprocessed(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        None
    }

    // No `extra_record`: this AIR emits no byte lookups any more (the address gadgets and the
    // memory accesses moved to `KeccakControlChip`).

    fn generate_main(&self, input: &Self::Record, _output: &mut Self::Record) -> RowMajorMatrix<F> {
        let events: Vec<_> = input
            .get_precompile_events(SyscallCode::KECCAK_PERMUTE)
            .iter()
            .filter_map(|(_, event)| {
                if let PrecompileEvent::KeccakPermute(event) = event {
                    Some(event)
                } else {
                    unreachable!()
                }
            })
            .collect();
        debug!(
            "record {} keccak precompile events {:?}",
            input.chunk_index(),
            events.len()
        );
        let num_events = events.len();
        // Honor a record shape (the MLE coarse bucket / FRI pad shape); the dummy-chunk padding
        // below fills whatever tail the target height leaves.
        let num_rows = match input.shape_chip_size(&self.name()) {
            Some(log) => {
                let padded = 1usize << log;
                assert!(
                    padded >= num_events * NUM_ROUNDS,
                    "KeccakPermute shape height {padded} < {} real rows (shape bucket too small)",
                    num_events * NUM_ROUNDS
                );
                padded
            }
            None => (num_events * NUM_ROUNDS).next_power_of_two(),
        };
        let chunk_size = 8;
        let values = vec![0u32; num_rows * NUM_KECCAK_MEM_COLS];
        let mut values = unsafe { std::mem::transmute::<Vec<u32>, Vec<F>>(values) };

        // A dummy permutation: the upstream rows for the zero state, projected onto the local
        // layout; `chunk / clk / is_real / export_in` stay zero.
        let dummy_keccak_rows = generate_trace_rows::<F>(vec![[0; STATE_SIZE]], 0);
        let mut dummy_chunk = Vec::new();
        for i in 0..NUM_ROUNDS {
            let src: &UpstreamKeccakCols<F> =
                dummy_keccak_rows.values[i * NUM_KECCAK_COLS..(i + 1) * NUM_KECCAK_COLS].borrow();
            let mut row = [F::ZERO; NUM_KECCAK_MEM_COLS];
            let cols: &mut KeccakMemCols<F> = row.as_mut_slice().borrow_mut();
            cols.keccak.copy_from_upstream(src);
            dummy_chunk.extend_from_slice(&row);
        }

        values
            .chunks_mut(chunk_size * NUM_KECCAK_MEM_COLS * NUM_ROUNDS)
            .enumerate()
            .pico_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_ROUNDS * NUM_KECCAK_MEM_COLS)
                    .enumerate()
                    .for_each(|(j, rounds)| {
                        let idx = i * chunk_size + j;
                        if idx < num_events {
                            Self::populate_chunk(events[idx], rounds);
                        } else {
                            rounds.copy_from_slice(&dummy_chunk[..rounds.len()]);
                        }
                    });
            });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_KECCAK_MEM_COLS)
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !record
                .get_precompile_events(SyscallCode::KECCAK_PERMUTE)
                .is_empty()
        }
    }

    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        _input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let events = &prepared_gpu_events.keccak_events;

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let event_size = events.len();
        let mut d_events = DevicePoolAllocation::<FFIKeccakPermuteEvent>::alloc_from_pool_async(
            event_size, mem_pool, stream,
        )
        .unwrap();
        unsafe {
            let _ = cudaMemcpyAsync(
                d_events.as_mut_c_void_ptr(),
                events.as_c_void_ptr(),
                event_size * size_of::<FFIKeccakPermuteEvent>(),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
        }

        let num_rows = (event_size * NUM_ROUNDS).next_power_of_two();
        let trace_size = num_rows * NUM_KECCAK_MEM_COLS;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();
        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();
        unsafe {
            cuda_precompile_keccak_generate_extra_record_and_main(
                NUM_KECCAK_MEM_COLS,
                event_size,
                trace_size,
                d_events.as_ptr() as *const _,
                d_trace.as_mut_ptr() as *mut _,
                d_byte_trace.as_mut_ptr() as *mut _,
                stream.into(),
            );
        }
        stream.synchronize().unwrap();

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream.synchronize().unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        stream.synchronize().unwrap();
        main_stream.synchronize().unwrap();

        info!("[precompile-keccak-chip] generate_extra_record_and_main on GPU");

        TraceData::Gpu(NUM_KECCAK_MEM_COLS, d_trace)
    }

    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !record.keccak_events.is_empty()
        }
    }
}

impl<F: PrimeField32> KeccakPermuteChip<F> {
    /// The 24 rows of one permutation: the p3 rows for `pre_state` projected onto the local layout
    /// (no `preimage`), tagged with the VM context. `export_in` is set on the first step and
    /// `export` (p3's multiset-export flag, which p3's generator leaves at 0) on the final step:
    /// those rows carry the permutation's input (`a`) and output (`a'''`) onto the `KeccakPermute`
    /// state bus (`constraint.rs`). Mirrored by `keccak_populate.cuh` on the GPU.
    pub fn populate_chunk(event: &KeccakPermuteEvent, rounds: &mut [F]) {
        let start_clk = event.clk;
        let chunk = event.chunk;

        let p3_keccak_trace = generate_trace_rows::<F>(vec![event.pre_state], 0);

        // Create all the rows for the permutation.
        for i in 0..NUM_ROUNDS {
            let src: &UpstreamKeccakCols<F> =
                p3_keccak_trace.values[i * NUM_KECCAK_COLS..(i + 1) * NUM_KECCAK_COLS].borrow();
            let row = &mut rounds[i * NUM_KECCAK_MEM_COLS..(i + 1) * NUM_KECCAK_MEM_COLS];
            let cols: &mut KeccakMemCols<F> = row.borrow_mut();
            cols.keccak.copy_from_upstream(src);

            cols.chunk = F::from_u32(chunk);
            cols.clk = F::from_u32(checked_u64_to_u32(start_clk, "keccak clk"));
            cols.is_real = F::ONE;
            if i == 0 {
                cols.export_in = F::ONE;
            }
            if i == NUM_ROUNDS - 1 {
                cols.keccak.export = F::ONE;
            }
        }
    }
}
