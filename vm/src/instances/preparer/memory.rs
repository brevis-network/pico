//! GPU Preallocated Memory Management Module
//!
//! This module provides GPU memory allocation for RISC-V emulator events.
//! Memory is allocated separately for different event types to support
//! independent timing requirements.

use cudart::{
    memory_pools::{CudaMemPool, DevicePoolAllocation},
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
use cudart_sys::{cudaMemcpyAsync, CudaError, CudaMemoryCopyKind};
use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;
use pico_gpu_api::{
    cuda_extra_record_finalize_byte_trace, cuda_extra_record_initialize_byte_trace,
};

use crate::{
    chips::chips::{
        byte::{
            columns::NUM_BYTE_MULT_COLS,
            event::ByteLookupEvent,
            traces::{byte_lookup_row, NUM_ROWS},
        },
        events::{AluEvent, CpuEvent},
        riscv_global::event::GlobalInteractionEvent,
        riscv_poseidon2::Poseidon2Event,
    },
    cuda_adaptor::get_global_mem_pool,
    emulator::riscv::{event_pool::EventBuffer, record::EmulationRecord},
    instances::preparer::PreparedGpuEvents,
};

/// GPU memory structure with separate allocations for different event types
#[derive(Default)]
pub struct PreallocatedGpuMemory<'a> {
    // CPU events
    pub d_cpu_events: Option<DevicePoolAllocation<'a, CpuEvent>>,

    // ALU events (combined, used by Batch 1 / DivRem for extra-event writes)
    pub d_add_sub_events: Option<DevicePoolAllocation<'a, AluEvent>>,
    // ALU events partitioned by opcode (filled after DivRem, consumed by individual chips)
    pub d_partitioned_add_events: Option<DevicePoolAllocation<'a, AluEvent>>,
    pub d_partitioned_sub_events: Option<DevicePoolAllocation<'a, AluEvent>>,
    pub d_partitioned_addw_events: Option<DevicePoolAllocation<'a, AluEvent>>,
    pub d_partitioned_subw_events: Option<DevicePoolAllocation<'a, AluEvent>>,

    pub d_lt_events: Option<DevicePoolAllocation<'a, AluEvent>>,
    pub d_mul_events: Option<DevicePoolAllocation<'a, AluEvent>>,

    // Global events
    pub d_global_events: Option<DevicePoolAllocation<'a, GlobalInteractionEvent>>,

    // Poseidon2 events
    pub d_poseidon2_events: Option<DevicePoolAllocation<'a, Poseidon2Event>>,

    // Byte trace
    pub d_byte_trace: Option<DevicePoolAllocation<'a, KoalaBear>>,
}

impl<'a> PreallocatedGpuMemory<'a> {
    /// Get mutable reference to CPU events
    pub fn cpu_events_mut(
        &mut self,
    ) -> Result<&mut DevicePoolAllocation<'a, CpuEvent>, GpuMemoryError> {
        self.d_cpu_events
            .as_mut()
            .ok_or_else(|| GpuMemoryError::AllocationFailed("CPU events not allocated".to_string()))
    }

    /// Get mutable reference to add/sub events
    pub fn add_sub_events_mut(
        &mut self,
    ) -> Result<&mut DevicePoolAllocation<'a, AluEvent>, GpuMemoryError> {
        self.d_add_sub_events.as_mut().ok_or_else(|| {
            GpuMemoryError::AllocationFailed("Add/sub events not allocated".to_string())
        })
    }

    /// Get mutable reference to LT events
    pub fn lt_events_mut(
        &mut self,
    ) -> Result<&mut DevicePoolAllocation<'a, AluEvent>, GpuMemoryError> {
        self.d_lt_events
            .as_mut()
            .ok_or_else(|| GpuMemoryError::AllocationFailed("LT events not allocated".to_string()))
    }

    /// Get mutable reference to MUL events
    pub fn mul_events_mut(
        &mut self,
    ) -> Result<&mut DevicePoolAllocation<'a, AluEvent>, GpuMemoryError> {
        self.d_mul_events
            .as_mut()
            .ok_or_else(|| GpuMemoryError::AllocationFailed("MUL events not allocated".to_string()))
    }

    /// Get mutable reference to global events
    pub fn global_events_mut(
        &mut self,
    ) -> Result<&mut DevicePoolAllocation<'a, GlobalInteractionEvent>, GpuMemoryError> {
        self.d_global_events.as_mut().ok_or_else(|| {
            GpuMemoryError::AllocationFailed("Global events not allocated".to_string())
        })
    }

    /// Get mutable reference to Poseidon2 events
    pub fn poseidon2_events_mut(
        &mut self,
    ) -> Result<&mut DevicePoolAllocation<'a, Poseidon2Event>, GpuMemoryError> {
        self.d_poseidon2_events.as_mut().ok_or_else(|| {
            GpuMemoryError::AllocationFailed("Poseidon2 events not allocated".to_string())
        })
    }

    /// Get mutable reference to byte trace
    pub fn byte_trace_mut(
        &mut self,
    ) -> Result<&mut DevicePoolAllocation<'a, KoalaBear>, GpuMemoryError> {
        self.d_byte_trace.as_mut().ok_or_else(|| {
            GpuMemoryError::ByteTraceNotAllocated("Byte trace not allocated".to_string())
        })
    }

    /// Check if ALU and byte memory are allocated
    pub fn has_alu_and_byte_memory(&self) -> bool {
        self.d_add_sub_events.is_some()
            && self.d_lt_events.is_some()
            && self.d_mul_events.is_some()
            && self.d_byte_trace.is_some()
    }

    /// Check if CPU memory is allocated
    pub fn has_cpu_memory(&self) -> bool {
        self.d_cpu_events.is_some() && self.has_alu_and_byte_memory()
    }
}

/// Error type for GPU memory operations
#[derive(Debug, thiserror::Error)]
pub enum GpuMemoryError {
    #[error("Failed to allocate GPU memory: {0}")]
    AllocationFailed(String),
    #[error("Failed to copy memory to GPU: {0}")]
    CopyFailed(String),
    #[error("Failed to initialize byte trace: {0}")]
    ByteTraceInitFailed(String),
    #[error("Failed to finalize byte trace: {0}")]
    ByteTraceFinalizeFailed(String),
    #[error("Byte trace not allocated: {0}")]
    ByteTraceNotAllocated(String),
}

/// Allocate and copy event data to GPU
fn allocate_and_copy_events_cuda_slice<'a, T>(
    source_slice: &EventBuffer<T>,
    mem_pool: &'a CudaMemPool,
    stream: &'a CudaStream,
    complete_event_size: usize,
) -> Result<Option<DevicePoolAllocation<'a, T>>, GpuMemoryError>
where
    T: Copy,
{
    if complete_event_size == 0 {
        return Ok(None);
    }

    let mut d_events =
        DevicePoolAllocation::<T>::alloc_from_pool_async(complete_event_size, mem_pool, stream)
            .map_err(|e| GpuMemoryError::AllocationFailed(e.to_string()))?;

    if !source_slice.is_empty() {
        unsafe {
            let source_cuda_slice = CudaSlice::as_slice(source_slice);
            let err = cudaMemcpyAsync(
                d_events.as_mut_c_void_ptr(),
                source_cuda_slice.as_c_void_ptr(),
                std::mem::size_of_val(source_cuda_slice),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
            if err != CudaError::Success {
                return Err(GpuMemoryError::CopyFailed(format!(
                    "cudaMemcpyAsync failed with code {}",
                    err
                )));
            }
        }
    }

    Ok(Some(d_events))
}

/// Allocate and copy Vec event data to GPU
fn allocate_and_copy_vec_events_cuda_slice<'a, T>(
    source_slice: &Vec<T>,
    mem_pool: &'a CudaMemPool,
    stream: &'a CudaStream,
    complete_event_size: usize,
) -> Result<Option<DevicePoolAllocation<'a, T>>, GpuMemoryError>
where
    T: Copy,
{
    if complete_event_size == 0 {
        return Ok(None);
    }

    let mut d_events =
        DevicePoolAllocation::<T>::alloc_from_pool_async(complete_event_size, mem_pool, stream)
            .map_err(|e| GpuMemoryError::AllocationFailed(e.to_string()))?;

    if !source_slice.is_empty() {
        unsafe {
            let source_cuda_slice = CudaSlice::as_slice(source_slice);
            let err = cudaMemcpyAsync(
                d_events.as_mut_c_void_ptr(),
                source_cuda_slice.as_c_void_ptr(),
                std::mem::size_of_val(source_cuda_slice),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
            if err != CudaError::Success {
                return Err(GpuMemoryError::CopyFailed(format!(
                    "cudaMemcpyAsync failed with code {}",
                    err
                )));
            }
        }
    }

    Ok(Some(d_events))
}

/// Allocate GPU memory for CPU events and copy CPU events to GPU
pub fn gpu_allocate_and_copy_cpu_events<'a>(
    stream: &'a CudaStream,
    device_id: usize,
    record: &'a EmulationRecord,
    prepared_gpu_events: &'a PreparedGpuEvents,
) -> Result<Option<DevicePoolAllocation<'a, CpuEvent>>, GpuMemoryError> {
    let sync_mem_pool = get_global_mem_pool(device_id);
    let mem_pool = &sync_mem_pool.0;

    let d_cpu_events = allocate_and_copy_events_cuda_slice(
        &record.cpu_events,
        mem_pool,
        stream,
        prepared_gpu_events.event_counter.num_cpu_events,
    )?;

    Ok(d_cpu_events)
}

/// Allocate GPU memory for CPU events only
pub fn gpu_allocate_cpu_events<'a>(
    stream: &'a CudaStream,
    device_id: usize,
    prepared_gpu_events: &'a PreparedGpuEvents,
) -> Result<Option<DevicePoolAllocation<'a, CpuEvent>>, GpuMemoryError> {
    let sync_mem_pool = get_global_mem_pool(device_id);
    let mem_pool = &sync_mem_pool.0;

    let complete_event_size = prepared_gpu_events.event_counter.num_cpu_events;

    if complete_event_size == 0 {
        return Ok(None);
    }

    let d_cpu_events = DevicePoolAllocation::<CpuEvent>::alloc_from_pool_async(
        complete_event_size,
        mem_pool,
        stream,
    )
    .map_err(|e| GpuMemoryError::AllocationFailed(e.to_string()))?;

    // stream.synchronize().unwrap();

    Ok(Some(d_cpu_events))
}

/// Copy a packed event stream (`MLE_PACKED_EVENTS`) into a device buffer sized for the fat
/// layout — the packed entries are smaller, so the prefix fits by construction.
fn copy_packed_prefix_into<S: Copy, D>(
    src: &[S],
    dst: &mut DevicePoolAllocation<'_, D>,
    stream: &CudaStream,
) -> Result<(), GpuMemoryError> {
    if src.is_empty() {
        return Ok(());
    }
    assert!(
        std::mem::size_of_val(src) <= std::mem::size_of::<D>() * dst.len(),
        "packed stream exceeds device buffer"
    );
    unsafe {
        let err = cudaMemcpyAsync(
            dst.as_mut_c_void_ptr(),
            src.as_ptr() as *const std::ffi::c_void,
            std::mem::size_of_val(src),
            CudaMemoryCopyKind::HostToDevice,
            stream.into(),
        );
        if err != CudaError::Success {
            return Err(GpuMemoryError::CopyFailed(format!(
                "cudaMemcpyAsync failed with code {err}"
            )));
        }
    }
    Ok(())
}

/// Allocate GPU memory for ALU events and copy ALU events to GPU
// allow: domain-complex signature — tuple reflects prover data-flow structure
#[allow(clippy::type_complexity)]
pub fn gpu_allocate_and_copy_alu_events<'a>(
    stream: &'a CudaStream,
    device_id: usize,
    record: &'a EmulationRecord,
    prepared_gpu_events: &'a PreparedGpuEvents,
) -> Result<
    (
        Option<DevicePoolAllocation<'a, AluEvent>>,
        Option<DevicePoolAllocation<'a, AluEvent>>,
        Option<DevicePoolAllocation<'a, AluEvent>>,
    ),
    GpuMemoryError,
> {
    let sync_mem_pool = get_global_mem_pool(device_id);
    let mem_pool = &sync_mem_pool.0;

    let d_add_sub_events = allocate_and_copy_events_cuda_slice(
        &record.add_sub_events,
        mem_pool,
        stream,
        prepared_gpu_events.event_counter.num_add_sub_events,
    )?;

    let d_lt_events = allocate_and_copy_events_cuda_slice(
        &record.lt_events,
        mem_pool,
        stream,
        prepared_gpu_events.event_counter.num_lt_events,
    )?;

    let d_mul_events = allocate_and_copy_vec_events_cuda_slice(
        &record.mul_events,
        mem_pool,
        stream,
        prepared_gpu_events.event_counter.num_mul_events,
    )?;

    Ok((d_add_sub_events, d_lt_events, d_mul_events))
}

/// Allocate GPU memory for add/sub events and copy add/sub events to GPU
pub fn gpu_allocate_and_copy_add_sub_events<'a>(
    stream: &'a CudaStream,
    device_id: usize,
    record: &'a EmulationRecord,
    prepared_gpu_events: &'a PreparedGpuEvents,
) -> Result<Option<DevicePoolAllocation<'a, AluEvent>>, GpuMemoryError> {
    let sync_mem_pool = get_global_mem_pool(device_id);
    let mem_pool = &sync_mem_pool.0;

    // MLE_PACKED_EVENTS: same fat-typed allocation (partition/extra tails share it), but only
    // the 24B-per-event packed prefix is copied; kernels reinterpret the pointer.
    if let Some(pk) = prepared_gpu_events.packed.as_deref() {
        let n = prepared_gpu_events.event_counter.num_add_sub_events;
        if n == 0 {
            return Ok(None);
        }
        let mut d_events =
            DevicePoolAllocation::<AluEvent>::alloc_from_pool_async(n, mem_pool, stream)
                .map_err(|e| GpuMemoryError::AllocationFailed(e.to_string()))?;
        copy_packed_prefix_into(pk.add_sub_events(), &mut d_events, stream)?;
        return Ok(Some(d_events));
    }

    allocate_and_copy_events_cuda_slice(
        &record.add_sub_events,
        mem_pool,
        stream,
        prepared_gpu_events.event_counter.num_add_sub_events,
    )
}

/// Allocate GPU memory for lt events and copy lt events to GPU
pub fn gpu_allocate_and_copy_lt_events<'a>(
    stream: &'a CudaStream,
    device_id: usize,
    record: &'a EmulationRecord,
    prepared_gpu_events: &'a PreparedGpuEvents,
) -> Result<Option<DevicePoolAllocation<'a, AluEvent>>, GpuMemoryError> {
    let sync_mem_pool = get_global_mem_pool(device_id);
    let mem_pool = &sync_mem_pool.0;

    // MLE_PACKED_EVENTS: packed prefix into the fat-typed allocation (see add_sub twin).
    if let Some(pk) = prepared_gpu_events.packed.as_deref() {
        let n = prepared_gpu_events.event_counter.num_lt_events;
        if n == 0 {
            return Ok(None);
        }
        let mut d_events =
            DevicePoolAllocation::<AluEvent>::alloc_from_pool_async(n, mem_pool, stream)
                .map_err(|e| GpuMemoryError::AllocationFailed(e.to_string()))?;
        copy_packed_prefix_into(pk.lt_events(), &mut d_events, stream)?;
        return Ok(Some(d_events));
    }

    allocate_and_copy_events_cuda_slice(
        &record.lt_events,
        mem_pool,
        stream,
        prepared_gpu_events.event_counter.num_lt_events,
    )
}

/// Allocate GPU memory for mul events and copy mul events to GPU
pub fn gpu_allocate_and_copy_mul_events<'a>(
    stream: &'a CudaStream,
    device_id: usize,
    record: &'a EmulationRecord,
    prepared_gpu_events: &'a PreparedGpuEvents,
) -> Result<Option<DevicePoolAllocation<'a, AluEvent>>, GpuMemoryError> {
    let sync_mem_pool = get_global_mem_pool(device_id);
    let mem_pool = &sync_mem_pool.0;

    allocate_and_copy_vec_events_cuda_slice(
        &record.mul_events,
        mem_pool,
        stream,
        prepared_gpu_events.event_counter.num_mul_events,
    )
}

/// Allocate GPU memory for global events and copy global events to GPU
pub fn gpu_allocate_and_copy_global_events<'a>(
    stream: &'a CudaStream,
    device_id: usize,
    input: &'a EmulationRecord,
    prepared_gpu_events: &'a PreparedGpuEvents,
) -> Result<Option<DevicePoolAllocation<'a, GlobalInteractionEvent>>, GpuMemoryError> {
    let sync_mem_pool = get_global_mem_pool(device_id);
    let mem_pool = &sync_mem_pool.0;

    let d_global_events = allocate_and_copy_vec_events_cuda_slice(
        &input.global_lookup_events,
        mem_pool,
        stream,
        prepared_gpu_events.event_counter.num_global_lookup_events,
    )?;

    Ok(d_global_events)
}

/// Allocate GPU memory for Poseidon2 events and copy original Poseidon2 events to GPU.
/// Global chip will later write its extra events starting at global_extra_poseidon2_start_index.
pub fn gpu_allocate_and_copy_poseidon2_events<'a>(
    stream: &'a CudaStream,
    device_id: usize,
    original_poseidon2_events: &[Poseidon2Event],
    prepared_gpu_events: &'a PreparedGpuEvents,
) -> Result<Option<DevicePoolAllocation<'a, Poseidon2Event>>, GpuMemoryError> {
    let sync_mem_pool = get_global_mem_pool(device_id);
    let mem_pool = &sync_mem_pool.0;

    // Total poseidon2 events = original events + events created by global chip
    let event_size = prepared_gpu_events.event_counter.num_poseidon2_events;
    if event_size == 0 {
        return Ok(None);
    }

    let mut d_poseidon2_events =
        DevicePoolAllocation::<Poseidon2Event>::alloc_from_pool_async(event_size, mem_pool, stream)
            .map_err(|e| GpuMemoryError::AllocationFailed(e.to_string()))?;

    // Copy original poseidon2 events from the record to GPU.
    // Global chip will later fill in the rest starting at global_extra_poseidon2_start_index.
    if !original_poseidon2_events.is_empty() {
        unsafe {
            let _ = cudaMemcpyAsync(
                d_poseidon2_events.as_mut_c_void_ptr(),
                original_poseidon2_events.as_ptr() as *const _,
                std::mem::size_of_val(original_poseidon2_events),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
        }
    }

    Ok(Some(d_poseidon2_events))
}

/// Allocate byte trace GPU memory and initialize byte trace
pub fn gpu_allocate_byte_trace<'a>(
    stream: &'a CudaStream,
    device_id: usize,
) -> Result<Option<DevicePoolAllocation<'a, KoalaBear>>, GpuMemoryError> {
    let sync_mem_pool = get_global_mem_pool(device_id);
    let mem_pool = &sync_mem_pool.0;

    const BYTE_TRACE_SIZE: usize = NUM_ROWS * NUM_BYTE_MULT_COLS;
    let mut d_byte_trace =
        DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(BYTE_TRACE_SIZE, mem_pool, stream)
            .map_err(|e| GpuMemoryError::AllocationFailed(e.to_string()))?;

    unsafe {
        let err = cuda_extra_record_initialize_byte_trace(
            d_byte_trace.as_mut_ptr() as *mut _,
            BYTE_TRACE_SIZE,
            stream.into(),
        );
        if err.code != 0 {
            return Err(GpuMemoryError::ByteTraceInitFailed(format!(
                "cuda_extra_record_initialize_byte_trace failed with code {}",
                err.code
            )));
        }
    }

    Ok(Some(d_byte_trace))
}

/// Finalize byte trace on GPU
pub fn gpu_finalize_byte_trace(
    stream: &CudaStream,
    preallocated_gpu_memory: &mut PreallocatedGpuMemory,
) -> Result<(), GpuMemoryError> {
    const BYTE_TRACE_SIZE: usize = NUM_BYTE_MULT_COLS * NUM_ROWS;

    let d_byte_trace = preallocated_gpu_memory.byte_trace_mut()?;

    unsafe {
        let err = cuda_extra_record_finalize_byte_trace(
            d_byte_trace.as_mut_ptr() as *mut _,
            BYTE_TRACE_SIZE,
            stream.into(),
        );
        if err.code != 0 {
            return Err(GpuMemoryError::ByteTraceFinalizeFailed(format!(
                "cuda_extra_record_finalize_byte_trace failed with code {:?}",
                err.code
            )));
        }
    }

    Ok(())
}

/// Count `byte_lookups`, each a lookup and how many times it is made, into a byte table of raw
/// `u32` multiplicities, the layout the device table has until [`gpu_finalize_byte_trace`]:
/// row-major, `NUM_BYTE_MULT_COLS` slots per row, slot `row * NUM_BYTE_MULT_COLS + opcode`, the
/// row from [`byte_lookup_row`].
///
/// A lookup may come more than once and its counts add up, so a chip can hand over the lookups
/// its rows raise one `(lookup, 1)` at a time instead of merging them into a `HashMap` first: for
/// the ~6M lookups of a full poseidon2 block that merge costs several times the counting.
///
/// # Panics
///
/// On a lookup whose row is outside the table, and on a count that reaches the field order: the
/// finalize kernel reads each slot as a canonical element, so a count at or above `p` would be
/// taken for a different one.
pub fn add_byte_lookups_to_raw_table(
    table: &mut [u32],
    byte_lookups: impl IntoIterator<Item = (ByteLookupEvent, usize)>,
) {
    assert_eq!(
        table.len(),
        NUM_ROWS * NUM_BYTE_MULT_COLS,
        "not a byte table"
    );
    for (lookup, mult) in byte_lookups {
        let row = byte_lookup_row(&lookup);
        assert!(
            row < NUM_ROWS,
            "byte lookup {lookup:?} maps to row {row}, outside the {NUM_ROWS}-row table"
        );
        let opcode = lookup.opcode as usize;
        assert!(
            opcode < NUM_BYTE_MULT_COLS,
            "byte opcode {opcode} has no column"
        );
        let slot = &mut table[row * NUM_BYTE_MULT_COLS + opcode];
        let count = u64::from(*slot) + mult as u64;
        assert!(
            count < u64::from(KoalaBear::ORDER_U32),
            "byte table count at row {row}, opcode {opcode} reaches the field order"
        );
        *slot = count as u32;
    }
}

/// Add byte lookups computed on the host to the device byte table, counted as
/// [`add_byte_lookups_to_raw_table`] counts them.
///
/// For the chips whose traces the GPU prover generates on the host: nothing else puts their
/// lookups on the device, and without them the byte bus does not balance.
///
/// This is a read-modify-write through the host -- D2H, [`add_byte_lookups_to_raw_table`], H2D --
/// on a stream of its own, and it waits on that stream only. The read and the write-back are
/// safe because nothing else touches the table meanwhile: `BaseProver::gpu_generate_extra_record_and_main`
/// runs the chips one at a time, and every chip synchronizes its own streams before it returns, so
/// when a chip calls this every earlier kernel's counts have landed and no later kernel has
/// started. A device-wide synchronize would say the same thing more expensively and is not an
/// option anyway: another prover lane on the card may be capturing a CUDA graph, and a
/// `cudaDeviceSynchronize` from this thread fails that capture.
pub fn gpu_add_host_byte_lookups(
    byte_lookups: impl IntoIterator<Item = (ByteLookupEvent, usize)>,
    preallocated_gpu_memory: &mut PreallocatedGpuMemory,
) -> Result<(), GpuMemoryError> {
    let mut byte_lookups = byte_lookups.into_iter().peekable();
    if byte_lookups.peek().is_none() {
        return Ok(());
    }
    let d_byte_trace = preallocated_gpu_memory.byte_trace_mut()?;
    assert_eq!(
        d_byte_trace.len(),
        NUM_ROWS * NUM_BYTE_MULT_COLS,
        "device byte table has an unexpected size"
    );
    let stream = CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING)
        .map_err(|e| GpuMemoryError::CopyFailed(format!("stream creation failed: {e}")))?;
    let sync = |stream: &CudaStream| {
        stream
            .synchronize()
            .map_err(|e| GpuMemoryError::CopyFailed(format!("stream synchronize failed: {e}")))
    };

    // The slots hold raw `u32` counts until the finalize kernel runs, whatever the element type.
    let mut table = vec![0u32; d_byte_trace.len()];
    let bytes = std::mem::size_of_val(table.as_slice());
    unsafe {
        let err = cudaMemcpyAsync(
            table.as_mut_ptr() as *mut std::ffi::c_void,
            d_byte_trace.as_c_void_ptr(),
            bytes,
            CudaMemoryCopyKind::DeviceToHost,
            (&stream).into(),
        );
        if err != CudaError::Success {
            return Err(GpuMemoryError::CopyFailed(format!(
                "byte table D2H failed with code {err}"
            )));
        }
    }
    sync(&stream)?;

    add_byte_lookups_to_raw_table(&mut table, byte_lookups);

    unsafe {
        let err = cudaMemcpyAsync(
            d_byte_trace.as_mut_c_void_ptr(),
            table.as_ptr() as *const std::ffi::c_void,
            bytes,
            CudaMemoryCopyKind::HostToDevice,
            (&stream).into(),
        );
        if err != CudaError::Success {
            return Err(GpuMemoryError::CopyFailed(format!(
                "byte table H2D failed with code {err}"
            )));
        }
    }
    // Also what keeps `table` alive until the copy has read it.
    sync(&stream)
}
