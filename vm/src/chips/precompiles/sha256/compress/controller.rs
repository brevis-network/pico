use super::ShaCompressControlChip;
use crate::{
    chips::{
        chips::byte::event::ByteRecordBehavior,
        gadgets::{addr_add::AddrAddGadget, syscall_addr::SyscallAddrGadget},
        utils::pad_rows_fixed,
    },
    compiler::{riscv::program::Program, word::Word},
    emulator::riscv::{
        record::EmulationRecord,
        syscalls::{
            code::SyscallCode,
            precompiles::{sha256::event::ShaCompressEvent, PrecompileEvent},
        },
    },
    iter::PicoIterator,
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder},
        chip::ChipBehavior,
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
    primitives::consts::u32_to_half_word,
};
#[cfg(feature = "cuda")]
use crate::{
    chips::{
        precompiles::sha256::compress::ffi::ShaCompressFfiEvent, trace::TraceData,
        utils::next_power_of_two,
    },
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    instances::preparer::{PreallocatedGpuMemory, PreparedGpuEvents},
    machine::chip::GpuChipBehavior,
};
use core::borrow::Borrow;
#[cfg(feature = "cuda")]
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::CudaSliceMut,
    stream::{CudaStream, CudaStreamCreateFlags},
};
#[cfg(feature = "cuda")]
use log::info;
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
#[cfg(feature = "cuda")]
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::ParallelSlice;
use pico_derive::AlignedBorrow;
#[cfg(feature = "cuda")]
use pico_gpu_api::cuda_precompile_sha256_compress_control_generate_extra_record_and_main;
use std::{borrow::BorrowMut, iter::once};

pub const NUM_SHA_COMPRESS_CONTROL_COLS: usize = size_of::<ShaCompressControlCols<u8>>();

// W has 64 elements of 4 byte. w_ptr + 63 * 8 gives the last address of W
const OFFSET_LAST_ELEM_W: u64 = 63;
// H has 8 elements of 4 bytes. h_ptr + 7 * 8 gives the last address of H
const OFFSET_LAST_ELEM_H: u64 = 7;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ShaCompressControlCols<T> {
    /// The chunk this syscall was executed in.
    ///
    /// Carried on the ShaCompress state bus so the state machine is pinned to one chunk. `clk`
    /// restarts at zero every chunk, so without this the bus cannot tell two chunks apart.
    pub chunk: T,
    pub clk: T,
    pub w_ptr: SyscallAddrGadget<T>,
    pub h_ptr: SyscallAddrGadget<T>,
    pub w_slice_end: AddrAddGadget<T>,
    pub h_slice_end: AddrAddGadget<T>,
    pub is_real: T,
    pub initial_state: [[T; 2]; 8],
    pub final_state: [[T; 2]; 8],
}

impl<F: PrimeField32> BaseAir<F> for ShaCompressControlChip<F> {
    fn width(&self) -> usize {
        NUM_SHA_COMPRESS_CONTROL_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for ShaCompressControlChip<F> {
    type Program = Program;
    type Record = EmulationRecord;

    fn name(&self) -> String {
        "ShaCompressControl".to_string()
    }

    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {
        let rows = vec![];

        let mut wrapped_rows = Some(rows);
        for (_, event) in input.get_precompile_events(SyscallCode::SHA_COMPRESS) {
            let event = if let PrecompileEvent::ShaCompress(event) = event {
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
            || [F::ZERO; NUM_SHA_COMPRESS_CONTROL_COLS],
            log_rows,
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_SHA_COMPRESS_CONTROL_COLS,
        )
    }

    fn extra_record(&self, input: &Self::Record, output: &mut Self::Record) {
        let compress_events: Vec<_> = input
            .get_precompile_events(SyscallCode::SHA_COMPRESS)
            .iter()
            .filter_map(|(_, event)| {
                if let PrecompileEvent::ShaCompress(event) = event {
                    Some(event)
                } else {
                    unreachable!()
                }
            })
            .collect();

        let chunk_size = std::cmp::max(compress_events.len() / num_cpus::get(), 1);
        let blu_batches = compress_events
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
                .get_precompile_events(SyscallCode::SHA_COMPRESS)
                .is_empty()
        }
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for ShaCompressControlChip<F> {
    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !record.sha_compress_events.is_empty()
        }
    }

    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let events = &prepared_gpu_events.sha_compress_events;

        let num_cols_per_row = NUM_SHA_COMPRESS_CONTROL_COLS;
        let log_rows = input.shape_chip_size(&self.name());
        let num_total_rows = next_power_of_two(events.len(), log_rows);
        let trace_size = num_total_rows * num_cols_per_row;
        let event_size = events.len();

        let event_alloc_size = if event_size == 0 { 1 } else { event_size };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();
        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let mut d_events = DevicePoolAllocation::<ShaCompressFfiEvent>::alloc_from_pool_async(
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
                    event_size * std::mem::size_of::<ShaCompressFfiEvent>(),
                    cudart_sys::CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
            }
        }

        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();
        info!(
            "[precompile-sha256-compress-control-chip] gpu_generate_extra_record_and_main on GPU"
        );
        unsafe {
            cuda_precompile_sha256_compress_control_generate_extra_record_and_main(
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

impl<F: PrimeField32> ShaCompressControlChip<F> {
    fn event_to_row(
        &self,
        event: &ShaCompressEvent,
        rows: &mut Option<Vec<[F; NUM_SHA_COMPRESS_CONTROL_COLS]>>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        let mut row = [F::ZERO; NUM_SHA_COMPRESS_CONTROL_COLS];
        let cols: &mut ShaCompressControlCols<F> = row.as_mut_slice().borrow_mut();

        cols.chunk = F::from_u32(event.chunk);
        cols.clk = F::from_u32(u32::try_from(event.clk).unwrap());
        // `w_ptr` has 64 words, so 512 bytes - but only 256 bytes are actually used.
        cols.w_ptr.populate(blu, event.w_ptr, 512);
        // `h_ptr` has 8 words, so 64 bytes - but only 32 bytes are actually used.
        cols.h_ptr.populate(blu, event.h_ptr, 64);
        cols.w_slice_end
            .populate(blu, event.w_ptr, OFFSET_LAST_ELEM_W * 8);
        cols.h_slice_end
            .populate(blu, event.h_ptr, OFFSET_LAST_ELEM_H * 8);
        cols.is_real = F::ONE;
        for i in 0..8 {
            let prev_value = event.h[i];
            let value = event.h_write_records[i].value;
            // The state is the `a, b, c, d, e, f, g, h` values.
            cols.initial_state[i] = u32_to_half_word(prev_value);
            // The `value` here is the resulting hash values, which are incremented by
            // `a, b, c, d, e, f, g, h` values - therefore, we do a subtraction here.
            cols.final_state[i] = u32_to_half_word((value as u32).wrapping_sub(prev_value));
        }

        if rows.as_ref().is_some() {
            rows.as_mut().unwrap().push(row);
        }
    }
}

impl<F: PrimeField32, CB: ChipBuilder<F>> Air<CB> for ShaCompressControlChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        // Initialize columns.
        let main = builder.main();
        let local = main.current_slice();
        let local: &ShaCompressControlCols<CB::Var> = (*local).borrow();

        // Constrain that `is_real` is boolean.
        builder.assert_bool(local.is_real);

        // Constrain the two pointers.
        // SAFETY: `w_ptr, h_ptr` are with valid u16 limbs, as they are received from the syscall.
        let w_ptr =
            SyscallAddrGadget::<CB::F>::eval(builder, 512, local.w_ptr, local.is_real.into());
        let h_ptr =
            SyscallAddrGadget::<CB::F>::eval(builder, 64, local.h_ptr, local.is_real.into());

        AddrAddGadget::<CB::F>::eval(
            builder,
            Word([
                w_ptr[0].into(),
                w_ptr[1].into(),
                w_ptr[2].into(),
                CB::Expr::ZERO,
            ]),
            Word::from(OFFSET_LAST_ELEM_W * 8_u64),
            local.w_slice_end,
            local.is_real.into(),
        );

        AddrAddGadget::<CB::F>::eval(
            builder,
            Word([
                h_ptr[0].into(),
                h_ptr[1].into(),
                h_ptr[2].into(),
                CB::Expr::ZERO,
            ]),
            Word::from(OFFSET_LAST_ELEM_H * 8_u64),
            local.h_slice_end,
            local.is_real.into(),
        );

        // Receive the syscall.
        builder.looked_syscall(
            local.chunk,
            local.clk,
            CB::F::from_u32(SyscallCode::SHA_COMPRESS.syscall_id()),
            w_ptr.map(Into::into),
            h_ptr.map(Into::into),
            local.is_real,
        );

        // Send the initial state. The initial index is 0.
        // The initial state will be constrained by the `ShaCompressChip`.
        let send_values = once(local.chunk.into())
            .chain(once(local.clk.into()))
            .chain(w_ptr.map(Into::into))
            .chain(h_ptr.map(Into::into))
            .chain(once(CB::Expr::from_u32(0)))
            .chain(
                local
                    .initial_state
                    .into_iter()
                    .flat_map(|word| word.into_iter())
                    .map(Into::into),
            )
            .collect::<Vec<_>>();
        builder.looking(SymbolicLookup::new(
            send_values,
            local.is_real.into(),
            LookupType::ShaCompress,
            LookupScope::Regional,
        ));

        // Receive the final state. The final index is 80.
        // The final state will be constrained by the `ShaCompressChip`.
        let receive_values = once(local.chunk.into())
            .chain(once(local.clk.into()))
            .chain(w_ptr.map(Into::into))
            .chain(h_ptr.map(Into::into))
            .chain(once(CB::Expr::from_u32(80)))
            .chain(
                local
                    .final_state
                    .into_iter()
                    .flat_map(|word| word.into_iter())
                    .map(Into::into),
            )
            .collect::<Vec<_>>();
        builder.looked(SymbolicLookup::new(
            receive_values,
            local.is_real.into(),
            LookupType::ShaCompress,
            LookupScope::Regional,
        ));
    }
}
