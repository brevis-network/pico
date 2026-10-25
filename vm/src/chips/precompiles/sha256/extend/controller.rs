use super::ShaExtendControlChip;
use crate::{
    chips::{
        chips::byte::event::ByteRecordBehavior,
        gadgets::{addr_add::AddrAddGadget, syscall_addr::SyscallAddrGadget},
        precompiles::sha256::extend::ffi::ShaExtendFfiEvent,
        trace::TraceData,
        utils::{next_power_of_two, pad_rows_fixed},
    },
    compiler::{riscv::program::Program, word::Word},
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    emulator::riscv::{
        ffi::FFIEmulationRecord,
        record::EmulationRecord,
        syscalls::{
            code::SyscallCode,
            precompiles::{sha256::event::ShaExtendEvent, PrecompileEvent},
        },
    },
    instances::preparer::{PreallocatedGpuMemory, PreparedGpuEvents},
    iter::PicoIterator,
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder},
        chip::ChipBehavior,
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
};
use core::borrow::Borrow;
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::CudaSliceMut,
    stream::{CudaStream, CudaStreamCreateFlags},
};
use cudart_sys::*;
use log::info;
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::ParallelSlice;
use pico_derive::AlignedBorrow;
use pico_gpu_api::cuda_precompile_sha256_extend_control_generate_extra_record_and_main;
use std::{borrow::BorrowMut, iter::once};

pub const NUM_SHA_EXTEND_CONTROL_COLS: usize = size_of::<ShaExtendControlCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ShaExtendControlCols<T> {
    /// The chunk this syscall was executed in.
    ///
    /// Carried on the ShaExtend state bus so the state machine is pinned to one chunk. `clk`
    /// restarts at zero every chunk, so without this the bus cannot tell two chunks apart.
    pub chunk: T,
    pub clk: T,
    pub w_ptr: SyscallAddrGadget<T>,
    pub w_16th_addr: AddrAddGadget<T>,
    pub w_17th_addr: AddrAddGadget<T>,
    pub w_64th_addr: AddrAddGadget<T>,

    pub is_real: T,
}

impl<F: PrimeField32> BaseAir<F> for ShaExtendControlChip<F> {
    fn width(&self) -> usize {
        NUM_SHA_EXTEND_CONTROL_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for ShaExtendControlChip<F> {
    type Program = Program;
    type Record = EmulationRecord;
    type GpuRecord = FFIEmulationRecord;

    fn name(&self) -> String {
        "ShaExtendControl".to_string()
    }

    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {
        let rows = vec![];

        let mut wrapped_rows = Some(rows);
        for (_, event) in input.get_precompile_events(SyscallCode::SHA_EXTEND) {
            let event = if let PrecompileEvent::ShaExtend(event) = event {
                event
            } else {
                unreachable!()
            };
            self.event_to_row(event, &mut wrapped_rows, &mut vec![]);
        }

        let mut rows = wrapped_rows.unwrap();

        let log_rows = input.shape_chip_size(&self.name());
        pad_rows_fixed(
            &mut rows,
            || [F::ZERO; NUM_SHA_EXTEND_CONTROL_COLS],
            log_rows,
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_SHA_EXTEND_CONTROL_COLS,
        )
    }

    fn extra_record(&self, input: &Self::Record, output: &mut Self::Record) {
        let extend_events: Vec<_> = input
            .get_precompile_events(SyscallCode::SHA_EXTEND)
            .iter()
            .filter_map(|(_, event)| {
                if let PrecompileEvent::ShaExtend(event) = event {
                    Some(event)
                } else {
                    unreachable!()
                }
            })
            .collect();

        let chunk_size = std::cmp::max(extend_events.len() / num_cpus::get(), 1);
        let blu_batches = extend_events
            .par_chunks(chunk_size)
            .flat_map(|events| {
                let mut blu = vec![];
                events.iter().for_each(|event| {
                    self.event_to_row(event, &mut None, &mut blu);
                });
                blu
            })
            .collect();

        output.add_byte_lookup_events(blu_batches);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !record
                .get_precompile_events(SyscallCode::SHA_EXTEND)
                .is_empty()
        }
    }

    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !record.sha_extend_events.is_empty()
        }
    }

    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let events = &prepared_gpu_events.sha_extend_events;

        let num_cols_per_row = NUM_SHA_EXTEND_CONTROL_COLS;
        let log_rows = input.shape_chip_size(&self.name());
        let num_total_rows = next_power_of_two(events.len(), log_rows);
        let trace_size = num_total_rows * num_cols_per_row;
        let event_size = events.len();

        let event_alloc_size = if event_size == 0 { 1 } else { event_size };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();
        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let mut d_events = DevicePoolAllocation::<ShaExtendFfiEvent>::alloc_from_pool_async(
            event_alloc_size,
            mem_pool,
            stream,
        )
        .unwrap();

        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();

        if event_size > 0 {
            unsafe {
                let _ = cudart_sys::cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_ptr() as *const _,
                    event_size * std::mem::size_of::<ShaExtendFfiEvent>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
            }
        }

        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();
        info!("[precompile-sha256-extend-control-chip] gpu_generate_extra_record_and_main on GPU");
        unsafe {
            cuda_precompile_sha256_extend_control_generate_extra_record_and_main(
                d_events.as_ptr() as *const _,
                event_size,
                d_trace.as_mut_ptr() as *mut _,
                num_total_rows,
                num_cols_per_row,
                d_byte_trace.as_mut_ptr() as *mut _,
                stream.into(),
            );
        }

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream.synchronize().unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        stream.synchronize().unwrap();
        main_stream.synchronize().unwrap();

        TraceData::Gpu(num_cols_per_row, d_trace)
    }
}

impl<F: PrimeField32> ShaExtendControlChip<F> {
    fn event_to_row(
        &self,
        event: &ShaExtendEvent,
        rows: &mut Option<Vec<[F; NUM_SHA_EXTEND_CONTROL_COLS]>>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        let mut row = [F::ZERO; NUM_SHA_EXTEND_CONTROL_COLS];
        let cols: &mut ShaExtendControlCols<F> = row.as_mut_slice().borrow_mut();

        cols.chunk = F::from_u32(event.chunk);
        cols.clk = F::from_u32(u32::try_from(event.clk).unwrap());
        // This precompile accesses 64 words, which is 512 bytes.
        cols.w_ptr.populate(blu, event.w_ptr, 512);
        // Address of 16th element of W, last read only element
        cols.w_16th_addr.populate(blu, event.w_ptr, 15 * 8);
        // Address of 17th element of W, first written element
        cols.w_17th_addr.populate(blu, event.w_ptr, 16 * 8);
        // Address of 64th element of W, last written element
        cols.w_64th_addr.populate(blu, event.w_ptr, 63 * 8);
        cols.is_real = F::ONE;

        if rows.as_ref().is_some() {
            rows.as_mut().unwrap().push(row);
        }
    }
}

impl<F: PrimeField32, CB: ChipBuilder<F>> Air<CB> for ShaExtendControlChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        // Initialize columns.
        let main = builder.main();
        let local = main.current_slice();
        let local: &ShaExtendControlCols<CB::Var> = (*local).borrow();

        // Check that `is_real` is boolean.
        builder.assert_bool(local.is_real);

        // Check that `w_ptr` is within bounds.
        // SAFETY: `w_ptr` is with 3 u16 limbs, as it is received from the syscall.
        let w_ptr =
            SyscallAddrGadget::<CB::F>::eval(builder, 512, local.w_ptr, local.is_real.into());

        AddrAddGadget::<CB::F>::eval(
            builder,
            Word([
                w_ptr[0].into(),
                w_ptr[1].into(),
                w_ptr[2].into(),
                CB::Expr::ZERO,
            ]),
            Word([
                CB::Expr::from_u32(15 * 8),
                CB::Expr::ZERO,
                CB::Expr::ZERO,
                CB::Expr::ZERO,
            ]),
            local.w_16th_addr,
            local.is_real.into(),
        );

        AddrAddGadget::<CB::F>::eval(
            builder,
            Word([
                w_ptr[0].into(),
                w_ptr[1].into(),
                w_ptr[2].into(),
                CB::Expr::ZERO,
            ]),
            Word([
                CB::Expr::from_u32(16 * 8),
                CB::Expr::ZERO,
                CB::Expr::ZERO,
                CB::Expr::ZERO,
            ]),
            local.w_17th_addr,
            local.is_real.into(),
        );

        AddrAddGadget::<CB::F>::eval(
            builder,
            Word([
                w_ptr[0].into(),
                w_ptr[1].into(),
                w_ptr[2].into(),
                CB::Expr::ZERO,
            ]),
            Word([
                CB::Expr::from_u32(63 * 8),
                CB::Expr::ZERO,
                CB::Expr::ZERO,
                CB::Expr::ZERO,
            ]),
            local.w_64th_addr,
            local.is_real.into(),
        );

        // Receive the syscall.
        builder.looked_syscall(
            local.chunk,
            local.clk,
            CB::F::from_u32(SyscallCode::SHA_EXTEND.syscall_id()),
            w_ptr.map(Into::into),
            [CB::Expr::ZERO, CB::Expr::ZERO, CB::Expr::ZERO],
            local.is_real,
        );

        // Send the initial state, with the starting index being 16.
        let send_values = once(local.chunk.into())
            .chain(once(local.clk.into()))
            .chain(w_ptr.map(Into::into))
            .chain(once(CB::Expr::from_u32(16)))
            .collect::<Vec<_>>();
        builder.looking(SymbolicLookup::new(
            send_values,
            local.is_real.into(),
            LookupType::ShaExtend,
            LookupScope::Regional,
        ));

        // Receive the final state, with the final index being 64.
        let receive_values = once(local.chunk.into())
            .chain(once(local.clk.into() + CB::Expr::from_u8(48)))
            .chain(w_ptr.map(Into::into))
            .chain(once(CB::Expr::from_u32(64)))
            .collect::<Vec<_>>();
        builder.looked(SymbolicLookup::new(
            receive_values,
            local.is_real.into(),
            LookupType::ShaExtend,
            LookupScope::Regional,
        ));
    }
}
