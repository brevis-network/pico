//! Riscv machine wiring of the sliced Keccak AIR and its tables: record events in, traces out,
//! on the host or (feature `cuda`) on the device.

use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;

use super::{
    sliced_counts, sliced_height, sliced_trace, tables::tables_main, KeccakSlicedChip,
    KeccakTables, SlicedPerm, TABLES_PREP_COLS,
};
use crate::{
    chips::precompiles::checked_u64_to_u32,
    compiler::riscv::program::Program,
    emulator::riscv::{
        record::EmulationRecord,
        syscalls::{precompiles::PrecompileEvent, SyscallCode},
    },
    machine::chip::ChipBehavior,
};
#[cfg(feature = "cuda")]
use crate::{instances::preparer::PreparedGpuEvents, machine::chip::GpuChipBehavior};

/// The record's permutations in record order, the order the pairing follows.
fn record_perms(record: &EmulationRecord) -> Vec<SlicedPerm> {
    record
        .get_precompile_events(SyscallCode::KECCAK_PERMUTE)
        .iter()
        .map(|(_, event)| match event {
            PrecompileEvent::KeccakPermute(e) => SlicedPerm {
                state: e.pre_state,
                chunk: e.chunk,
                clk: checked_u64_to_u32(e.clk, "keccak clk"),
            },
            _ => unreachable!(),
        })
        .collect()
}

fn keccak_active<F: PrimeField32, C: ChipBehavior<F>>(chip: &C, record: &EmulationRecord) -> bool {
    match record.shape.as_ref() {
        Some(shape) => shape.included::<F, _>(chip),
        None => !record
            .get_precompile_events(SyscallCode::KECCAK_PERMUTE)
            .is_empty(),
    }
}

impl<F: PrimeField32> ChipBehavior<F> for KeccakSlicedChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    /// The `KeccakPermute` name: the shapes, the AIR-id table and the precompile pool key on it.
    fn name(&self) -> String {
        "KeccakPermute".to_string()
    }

    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {
        let perms = record_perms(input);
        let height = match input.shape_chip_size(&ChipBehavior::<F>::name(self)) {
            Some(log) => 1usize << log,
            None => sliced_height(perms.len()),
        };
        sliced_trace::<F>(&perms, height).main
    }

    fn is_active(&self, record: &EmulationRecord) -> bool {
        keccak_active::<F, _>(self, record)
    }
}

impl<F: PrimeField32> ChipBehavior<F> for KeccakTables<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "KeccakTables".to_string()
    }

    fn generate_preprocessed(&self, _: &Program) -> Option<RowMajorMatrix<F>> {
        BaseAir::<F>::preprocessed_trace(self)
    }

    fn preprocessed_width(&self) -> usize {
        TABLES_PREP_COLS
    }

    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {
        let (chi, xor5) = sliced_counts::<F>(&record_perms(input));
        tables_main(&chi, &xor5)
    }

    fn is_active(&self, record: &EmulationRecord) -> bool {
        keccak_active::<F, _>(self, record)
    }
}

/// Device tracegen: the counts from the device events.
#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for KeccakTables<F> {
    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        match record.shape.as_ref() {
            Some(shape) => shape.included::<F, _>(self),
            None => !record.keccak_events.is_empty(),
        }
    }

    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        _input: &EmulationRecord,
        prepared: &PreparedGpuEvents,
        _mem: &mut crate::instances::preparer::PreallocatedGpuMemory,
    ) -> crate::chips::trace::TraceData<'_, F> {
        gpu::generate::<F>(device_id, prepared, gpu::Part::Tables)
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for KeccakSlicedChip<F> {
    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        match record.shape.as_ref() {
            Some(shape) => shape.included::<F, _>(self),
            None => !record.keccak_events.is_empty(),
        }
    }

    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        _input: &EmulationRecord,
        prepared: &PreparedGpuEvents,
        _mem: &mut crate::instances::preparer::PreallocatedGpuMemory,
    ) -> crate::chips::trace::TraceData<'_, F> {
        gpu::generate::<F>(device_id, prepared, gpu::Part::Main)
    }
}

/// Device tracegen (`gpu-api/cuda/keccak_sliced.cu`), checked against the host path by the
/// `keccak256` GPU parity tests and by `MLE_TRACE_COMPARE`.
#[cfg(feature = "cuda")]
mod gpu {
    use super::*;
    use crate::{
        chips::trace::TraceData,
        cuda_adaptor::resource_pool::{
            mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
        },
        mle::spans::device,
    };
    use cudart::{
        memory_pools::DevicePoolAllocation,
        slice::{CudaSlice, CudaSliceMut},
        stream::{CudaStream, CudaStreamCreateFlags},
    };
    use cudart_sys::{cudaMemcpyAsync, CudaMemoryCopyKind};
    use p3_koala_bear::KoalaBear;
    use std::mem::size_of;

    use super::super::{NUM_SLICED_COLS, TABLES_MAIN_COLS, TABLE_ROWS};

    /// `{ chunk, clk, state }`, the device kernel's `SlicedEvent`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SlicedEventFfi {
        chunk: u32,
        clk: u32,
        state: [u64; 25],
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) enum Part {
        /// [`KeccakSlicedChip`]'s main trace.
        Main,
        /// [`KeccakTables`]' four multiplicity columns.
        Tables,
    }

    pub(super) fn generate<F: PrimeField32>(
        device_id: usize,
        prepared: &PreparedGpuEvents,
        part: Part,
    ) -> TraceData<'static, F> {
        let events: Vec<SlicedEventFfi> = prepared
            .keccak_events
            .iter()
            .map(|e| SlicedEventFfi {
                chunk: e.chunk,
                clk: e.clk,
                state: e.pre_state,
            })
            .collect();
        let height = match prepared
            .shape
            .as_ref()
            .and_then(|s| s.inner.get("KeccakPermute").copied())
        {
            Some(log) if part == Part::Main => 1usize << log,
            _ => sliced_height(events.len()),
        };
        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();
        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;
        let mut d_events = DevicePoolAllocation::<SlicedEventFfi>::alloc_from_pool_async(
            events.len().max(1),
            mem_pool,
            stream,
        )
        .unwrap();
        unsafe {
            let _ = cudaMemcpyAsync(
                d_events.as_mut_c_void_ptr(),
                events.as_ptr() as *const _,
                events.len() * size_of::<SlicedEventFfi>(),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
        }
        let (cells, width) = match part {
            Part::Main => (height * NUM_SLICED_COLS, NUM_SLICED_COLS),
            Part::Tables => (TABLE_ROWS * TABLES_MAIN_COLS, TABLES_MAIN_COLS),
        };
        let mut d_out =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(cells, mem_pool, stream)
                .unwrap();
        let null = std::ptr::null_mut();
        let out = d_out.as_mut_ptr() as *mut core::ffi::c_void;
        let (t, tables) = match part {
            Part::Main => (out, null),
            Part::Tables => (null, out),
        };
        let kernels = device::start(stream);
        unsafe {
            pico_gpu_api::cuda_keccak_sliced_generate(
                d_events.as_ptr() as *const _,
                events.len(),
                height,
                t,
                tables,
                stream.into(),
            );
        }
        device::launched(kernels, stream);
        device::wait(stream).unwrap();
        drop(d_events);
        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        let d_out = d_out.swap_stream(main_stream);
        device::wait(stream).unwrap();
        device::wait(main_stream).unwrap();
        // SAFETY: the pool is the process-global one; `TraceData` only names the lifetime.
        let d_out: DevicePoolAllocation<'static, KoalaBear> =
            unsafe { core::mem::transmute(d_out) };
        TraceData::Gpu(width, d_out)
    }
}
