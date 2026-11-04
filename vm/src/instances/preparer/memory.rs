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
    cuda_extra_record_add_byte_trace_counts, cuda_extra_record_finalize_byte_trace,
    cuda_extra_record_initialize_byte_trace,
};
use std::sync::OnceLock;

use crate::{
    chips::chips::{
        alu::divrem::traces::DivRemAddRows,
        byte::{
            columns::NUM_BYTE_MULT_COLS,
            event::ByteLookupEvent,
            traces::{byte_lookup_row, NUM_ROWS},
        },
        riscv_global::event::GlobalInteractionEvent,
        riscv_poseidon2::Poseidon2Event,
    },
    cuda_adaptor::get_global_mem_pool,
    emulator::riscv::record::EmulationRecord,
    instances::preparer::{DeviceHistory, PreparedGpuEvents},
    mle::spans::device,
};

/// GPU memory structure with separate allocations for different event types
#[derive(Default)]
pub struct PreallocatedGpuMemory<'a> {
    // Global events
    pub d_global_events: Option<DevicePoolAllocation<'a, GlobalInteractionEvent>>,

    // Poseidon2 events
    pub d_poseidon2_events: Option<DevicePoolAllocation<'a, Poseidon2Event>>,

    // Byte trace
    pub d_byte_trace: Option<DevicePoolAllocation<'a, KoalaBear>>,

    /// The chunk's execution history, for a record that carries one. A chip's kernels read it
    /// through a reader made on their stream (`DeviceHistory::reader`), dropped after the last of
    /// them is launched.
    pub d_history: Option<DeviceHistory<'a>>,
    pub d_divrem_add_rows: Option<DivRemAddRows<'a>>,
}

impl<'a> PreallocatedGpuMemory<'a> {
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
    #[error("Byte trace count reaches the field order: {0}")]
    ByteTraceOverflow(String),
}

/// Allocate and copy Vec event data to GPU, a copy of `what` to the device readings
fn allocate_and_copy_vec_events_cuda_slice<'a, T>(
    source_slice: &Vec<T>,
    mem_pool: &'a CudaMemPool,
    stream: &'a CudaStream,
    complete_event_size: usize,
    what: &'static str,
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
            let copy = device::start(stream);
            let err = cudaMemcpyAsync(
                d_events.as_mut_c_void_ptr(),
                source_cuda_slice.as_c_void_ptr(),
                std::mem::size_of_val(source_cuda_slice),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
            device::copied(
                copy,
                stream,
                what,
                Some((
                    source_cuda_slice.as_c_void_ptr(),
                    std::mem::size_of_val(source_cuda_slice),
                )),
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
        "global_events",
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
        let copy = device::start(stream);
        unsafe {
            let _ = cudaMemcpyAsync(
                d_poseidon2_events.as_mut_c_void_ptr(),
                original_poseidon2_events.as_ptr() as *const _,
                std::mem::size_of_val(original_poseidon2_events),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
        }
        device::copied(
            copy,
            stream,
            "poseidon2_events",
            Some((
                original_poseidon2_events.as_ptr() as *const _,
                std::mem::size_of_val(original_poseidon2_events),
            )),
        );
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
/// lookups on the device, and without them the byte bus does not balance. Through the host
/// ([`gpu_add_host_byte_lookups_through_host`]), or with `MLE_BYTE_TABLE_ADDITIVE=1` added on the
/// device ([`gpu_add_host_byte_lookups_additive`]); both leave the table the same.
pub fn gpu_add_host_byte_lookups(
    byte_lookups: impl IntoIterator<Item = (ByteLookupEvent, usize)>,
    preallocated_gpu_memory: &mut PreallocatedGpuMemory,
) -> Result<(), GpuMemoryError> {
    if additive_byte_table() {
        gpu_add_host_byte_lookups_additive(byte_lookups, preallocated_gpu_memory)
    } else {
        gpu_add_host_byte_lookups_through_host(byte_lookups, preallocated_gpu_memory)
    }
}

/// `MLE_BYTE_TABLE_ADDITIVE=1`: [`gpu_add_host_byte_lookups`] takes the additive path.
pub fn additive_byte_table() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| crate::mle::env_flag("MLE_BYTE_TABLE_ADDITIVE"))
}

/// [`gpu_add_host_byte_lookups`] as a read-modify-write through the host -- D2H,
/// [`add_byte_lookups_to_raw_table`], H2D -- on a stream of its own, waiting on that stream only. The read and the write-back are
/// safe because nothing else touches the table meanwhile: `BaseProver::gpu_generate_extra_record_and_main`
/// runs the chips one at a time, and every chip synchronizes its own streams before it returns, so
/// when a chip calls this every earlier kernel's counts have landed and no later kernel has
/// started. A device-wide synchronize would say the same thing more expensively and is not an
/// option anyway: another prover lane on the card may be capturing a CUDA graph, and a
/// `cudaDeviceSynchronize` from this thread fails that capture.
pub fn gpu_add_host_byte_lookups_through_host(
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
    // Each wait names its own line, which a wait inside a shared closure could not.
    let sync_failed =
        |e: CudaError| GpuMemoryError::CopyFailed(format!("stream synchronize failed: {e}"));

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
    device::wait(&stream).map_err(sync_failed)?;

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
    device::wait(&stream).map_err(sync_failed)
}

/// [`gpu_add_host_byte_lookups`] without the read-modify-write: the lookups are counted into a
/// table of raw counts on the host, as [`add_byte_lookups_to_raw_table`] counts them, and a kernel
/// adds it into the device table with atomics. Nothing is read back but an overflow flag, so the
/// add depends on no other writer of the table having finished; only the finalize has to follow it.
/// It waits on its own stream before returning, which keeps the counts alive until the kernel has
/// read them.
///
/// # Errors
///
/// [`GpuMemoryError::ByteTraceOverflow`] when a cell would reach the field order, which the
/// finalize would read as a different element.
pub fn gpu_add_host_byte_lookups_additive(
    byte_lookups: impl IntoIterator<Item = (ByteLookupEvent, usize)>,
    preallocated_gpu_memory: &mut PreallocatedGpuMemory,
) -> Result<(), GpuMemoryError> {
    let mut byte_lookups = byte_lookups.into_iter().peekable();
    if byte_lookups.peek().is_none() {
        return Ok(());
    }
    let d_byte_trace = preallocated_gpu_memory.byte_trace_mut()?;
    let cells = d_byte_trace.len();
    assert_eq!(
        cells,
        NUM_ROWS * NUM_BYTE_MULT_COLS,
        "device byte table has an unexpected size"
    );
    let mut counts = vec![0u32; cells];
    add_byte_lookups_to_raw_table(&mut counts, byte_lookups);

    let stream = CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING)
        .map_err(|e| GpuMemoryError::CopyFailed(format!("stream creation failed: {e}")))?;
    // The counts, then the overflow flag.
    let mut d_counts = DevicePoolAllocation::<u32>::alloc_async(cells + 1, &stream)
        .map_err(|e| GpuMemoryError::AllocationFailed(e.to_string()))?;
    let copied = |err: CudaError, what: &str| {
        if err == CudaError::Success {
            Ok(())
        } else {
            Err(GpuMemoryError::CopyFailed(format!(
                "{what} failed with code {err}"
            )))
        }
    };
    let mut overflow = 0u32;
    unsafe {
        let d_flag = d_counts.as_mut_ptr().add(cells);
        copied(
            cudaMemcpyAsync(
                d_counts.as_mut_c_void_ptr(),
                counts.as_ptr() as *const std::ffi::c_void,
                std::mem::size_of_val(counts.as_slice()),
                CudaMemoryCopyKind::HostToDevice,
                (&stream).into(),
            ),
            "byte counts H2D",
        )?;
        copied(
            cudaMemcpyAsync(
                d_flag as *mut std::ffi::c_void,
                &overflow as *const u32 as *const std::ffi::c_void,
                std::mem::size_of::<u32>(),
                CudaMemoryCopyKind::HostToDevice,
                (&stream).into(),
            ),
            "overflow flag H2D",
        )?;
        let err = cuda_extra_record_add_byte_trace_counts(
            d_byte_trace.as_mut_c_void_ptr(),
            d_counts.as_c_void_ptr(),
            cells,
            d_flag as *mut std::ffi::c_void,
            (&stream).into(),
        );
        if err.code != 0 {
            return Err(GpuMemoryError::CopyFailed(format!(
                "cuda_extra_record_add_byte_trace_counts failed with code {}",
                err.code
            )));
        }
        copied(
            cudaMemcpyAsync(
                &mut overflow as *mut u32 as *mut std::ffi::c_void,
                d_flag as *const std::ffi::c_void,
                std::mem::size_of::<u32>(),
                CudaMemoryCopyKind::DeviceToHost,
                (&stream).into(),
            ),
            "overflow flag D2H",
        )?;
    }
    device::wait(&stream)
        .map_err(|e| GpuMemoryError::CopyFailed(format!("stream synchronize failed: {e}")))?;
    if overflow != 0 {
        return Err(GpuMemoryError::ByteTraceOverflow(
            "a host lookup took a device byte table count to the field order".to_string(),
        ));
    }
    Ok(())
}
