use super::columns::{Uint256MulCols, NUM_UINT256_MUL_COLS};
use crate::{
    chips::{
        chips::byte::event::ByteRecordBehavior,
        gadgets::{field::field_op::FieldOperation, is_zero::IsZeroGadget},
        precompiles::{
            checked_u64_to_u32,
            uint256::{Uint256MulChip, UINT256_NUM_WORDS},
        },
        trace::TraceData,
        utils::{next_power_of_two, pad_rows_fixed},
    },
    compiler::riscv::program::Program,
    cuda_adaptor::{get_global_mem_pool, get_global_stream_pool},
    emulator::riscv::{
        ffi::FFIEmulationRecord,
        record::EmulationRecord,
        syscalls::{
            precompiles::{uint256::event::FfiUint256MulEvent, PrecompileEvent},
            SyscallCode,
        },
    },
    instances::preparer::{PreallocatedGpuMemory, PreparedGpuEvents},
    machine::chip::ChipBehavior,
};
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
use cudart_sys::cudaMemcpyAsync;
use num::{BigUint, One, Zero};
use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use pico_gpu_api::cuda_precompile_uint256_generate_extra_record_and_main;
use std::borrow::BorrowMut;
use tracing::info;

impl<F: PrimeField32> ChipBehavior<F> for Uint256MulChip<F> {
    type Record = EmulationRecord;
    type GpuRecord = FFIEmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Uint256MulMod".to_string()
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        output: &mut EmulationRecord,
    ) -> RowMajorMatrix<F> {
        // The record update is used by extra_record
        let mut byte_lookup_events = vec![];

        let events: Vec<_> = input
            .get_precompile_events(SyscallCode::UINT256_MUL)
            .iter()
            .filter_map(|(_, event)| {
                if let PrecompileEvent::Uint256Mul(event) = event {
                    Some(event)
                } else {
                    unreachable!()
                }
            })
            .collect();

        // Generate the trace rows & corresponding records for each event.
        let mut rows = events
            .iter()
            .map(|event| {
                let mut new_byte_lookup_events = vec![];

                let mut row: [F; NUM_UINT256_MUL_COLS] = [F::ZERO; NUM_UINT256_MUL_COLS];
                let cols: &mut Uint256MulCols<F> = row.as_mut_slice().borrow_mut();

                // Decode uint256 values directly from native dword arrays.
                let x = BigUint::from_bytes_le(
                    &event
                        .x
                        .iter()
                        .flat_map(|w| w.to_le_bytes())
                        .collect::<Vec<u8>>(),
                );
                let y = BigUint::from_bytes_le(
                    &event
                        .y
                        .iter()
                        .flat_map(|w| w.to_le_bytes())
                        .collect::<Vec<u8>>(),
                );
                let modulus = BigUint::from_bytes_le(
                    &event
                        .modulus
                        .iter()
                        .flat_map(|w| w.to_le_bytes())
                        .collect::<Vec<u8>>(),
                );

                // The operands may be at or above the modulus. The syscall asks for no particular
                // representative, and revm's 256-bit MODEXP path reduces an unreduced base by
                // multiplying it by one; mainnet blocks reach that with a base above BN254's
                // scalar modulus. The AIR asserts `x * y == result + carry * modulus` and pins the
                // result below the modulus by the existing exit check and to the memory bus, so
                // the value written back is unique whatever representative the operands use.
                //
                // What the columns cannot hold is a carry past their 32 bytes. That is the domain
                // error, named as such here rather than as the limb-count panic in
                // `to_limbs_field` that the same input would otherwise trip.
                //
                // Skipped when the modulus is zero: the chip then works modulo 2^256, where the
                // carry of two 256-bit operands always fits.
                if modulus != BigUint::ZERO {
                    let carry = (&x * &y) / &modulus;
                    assert!(
                        carry.bits() <= 256,
                        "uint256 x * y / modulus must fit in the 256-bit carry"
                    );
                }

                // Assign basic values to the columns.
                cols.is_real = F::ONE;

                cols.chunk = F::from_u32(event.chunk);
                cols.clk = F::from_u32(checked_u64_to_u32(event.clk, "uint256 clk"));

                // Populate pointer gadgets.
                cols.x_ptr
                    .populate(&mut new_byte_lookup_events, event.x_ptr, 32);
                cols.y_ptr
                    .populate(&mut new_byte_lookup_events, event.y_ptr, 64);

                // Populate memory columns with native dword records.
                for i in 0..UINT256_NUM_WORDS {
                    cols.x_memory[i]
                        .inner
                        .populate(event.x_memory_records[i], &mut new_byte_lookup_events);
                    cols.x_memory[i].prev_value_u8.populate_u16_to_u8_safe(
                        &mut new_byte_lookup_events,
                        event.x_memory_records[i].prev_value,
                    );
                    cols.x_addrs[i].populate(
                        &mut new_byte_lookup_events,
                        event.x_ptr,
                        8 * i as u64,
                    );

                    cols.y_memory[i]
                        .inner
                        .populate(event.y_memory_records[i], &mut new_byte_lookup_events);
                    cols.y_memory[i].prev_value_u8.populate_u16_to_u8_safe(
                        &mut new_byte_lookup_events,
                        event.y_memory_records[i].value,
                    );
                    cols.y_and_modulus_addrs[i].populate(
                        &mut new_byte_lookup_events,
                        event.y_ptr,
                        8 * i as u64,
                    );

                    cols.modulus_memory[i]
                        .inner
                        .populate(event.modulus_memory_records[i], &mut new_byte_lookup_events);
                    cols.modulus_memory[i]
                        .prev_value_u8
                        .populate_u16_to_u8_safe(
                            &mut new_byte_lookup_events,
                            event.modulus_memory_records[i].value,
                        );
                    cols.y_and_modulus_addrs[UINT256_NUM_WORDS + i].populate(
                        &mut new_byte_lookup_events,
                        event.y_ptr,
                        8 * (UINT256_NUM_WORDS + i) as u64,
                    );
                }

                // Compute modulus_is_zero from modulus bytes.
                let modulus_bytes: Vec<u8> =
                    event.modulus.iter().flat_map(|w| w.to_le_bytes()).collect();
                let modulus_byte_sum = modulus_bytes.iter().map(|b| *b as u32).sum::<u32>();
                IsZeroGadget::populate(&mut cols.modulus_is_zero, modulus_byte_sum);

                // Populate the output column.
                let effective_modulus = if modulus.is_zero() {
                    BigUint::one() << 256
                } else {
                    modulus.clone()
                };
                cols.modulus_is_not_zero = F::ONE - cols.modulus_is_zero.result;

                let result = cols.output.populate_with_modulus(
                    &mut new_byte_lookup_events,
                    &x,
                    &y,
                    &effective_modulus,
                    FieldOperation::Mul,
                );

                if cols.modulus_is_not_zero == F::ONE {
                    cols.output_range_check.populate(
                        &mut new_byte_lookup_events,
                        &result,
                        &effective_modulus,
                    );
                }

                byte_lookup_events.extend(new_byte_lookup_events);

                row
            })
            .collect();

        let log_rows = input.shape_chip_size(&self.name());

        pad_rows_fixed(
            &mut rows,
            || {
                let mut row: [F; NUM_UINT256_MUL_COLS] = [F::ZERO; NUM_UINT256_MUL_COLS];
                let cols: &mut Uint256MulCols<F> = row.as_mut_slice().borrow_mut();

                let x = BigUint::zero();
                let y = BigUint::zero();
                cols.output
                    .populate(&mut vec![], &x, &y, FieldOperation::Mul);

                row
            },
            log_rows,
        );

        output.add_byte_lookup_events(byte_lookup_events);

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect(), NUM_UINT256_MUL_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        self.generate_main(input, extra);
    }

    fn is_active(&self, chunk: &Self::Record) -> bool {
        // !chunk.uint256_mul_events.is_empty()
        if let Some(shape) = chunk.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !chunk
                .get_precompile_events(SyscallCode::UINT256_MUL)
                .is_empty()
        }
    }

    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !record.uint256_mul_events.is_empty()
        }
    }

    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let events = prepared_gpu_events.uint256_mul_events.as_slice();

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let event_size = events.len();
        let mut d_events = DevicePoolAllocation::<FfiUint256MulEvent>::alloc_from_pool_async(
            event_size, mem_pool, stream,
        )
        .unwrap();
        unsafe {
            let _ = cudaMemcpyAsync(
                d_events.as_mut_c_void_ptr(),
                events.as_c_void_ptr(),
                std::mem::size_of_val(events),
                cudart_sys::CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
        }

        let num_cols_per_row = NUM_UINT256_MUL_COLS;
        let log_rows = input.shape_chip_size(&self.name());
        let num_total_rows = next_power_of_two(events.len(), log_rows);
        let trace_size = num_total_rows * num_cols_per_row;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();
        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();
        unsafe {
            cuda_precompile_uint256_generate_extra_record_and_main(
                num_cols_per_row,
                event_size,
                trace_size,
                d_events.as_ptr() as *const _,
                d_trace.as_mut_ptr() as *mut _,
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

        info!("[precompile-uint256-mul-chip] generate_extra_record_and_main on GPU");

        TraceData::Gpu(NUM_UINT256_MUL_COLS, d_trace)
    }
}
