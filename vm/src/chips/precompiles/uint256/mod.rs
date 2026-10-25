use crate::chips::gadgets::{uint256::U256Field, utils::field_params::NumWords};
use std::marker::PhantomData;
use typenum::Unsigned;

pub mod columns;
mod constraints;
#[cfg(test)]
mod tests;
mod traces;

type Uint256NumWords = <U256Field as NumWords>::WordsFieldElement;
pub const UINT256_NUM_WORDS: usize = Uint256NumWords::USIZE;

#[derive(Default)]
pub struct Uint256MulChip<F> {
    _phantom: PhantomData<F>,
}

#[cfg(test)]
mod gpu_tests {
    use std::{array::from_fn, sync::LazyLock};

    use crate::chips::gadgets::utils::RandBigUint;
    use num::BigUint;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{rng, rngs::ThreadRng, RngExt};

    use crate::{
        chips::{
            chips::{
                byte::{columns::NUM_BYTE_MULT_COLS, ByteChip},
                events::{MemoryReadRecord, MemoryWriteRecord},
            },
            precompiles::uint256::Uint256MulChip,
            tests::init_test_stream,
            trace::TraceData,
        },
        emulator::riscv::{
            record::EmulationRecord,
            syscalls::{
                precompiles::{PrecompileEvent, PrecompileEvents, Uint256MulEvent},
                SyscallCode, SyscallEvent,
            },
        },
        instances::{
            compiler::shapes::riscv_shape::RiscvPadShape,
            preparer::{
                gpu_allocate_byte_trace, gpu_finalize_byte_trace, precompute_event_size,
                PreallocatedGpuMemory, PreparedGpuEvents,
            },
        },
        machine::chip::ChipBehavior,
    };

    type F = KoalaBear;

    static UINT256_MUL_SHARD: LazyLock<EmulationRecord> =
        LazyLock::new(|| generate_record(1 << 20));

    fn cpu_generate_main(chip: &Uint256MulChip<F>, input: &EmulationRecord) -> RowMajorMatrix<F> {
        chip.generate_main(input, &mut EmulationRecord::default())
    }

    pub(super) fn generate_record(size: usize) -> EmulationRecord {
        generate_record_with(size, |rng, modulus| {
            (
                rng.random_biguint(256) % modulus,
                rng.random_biguint(256) % modulus,
            )
        })
    }

    /// Operands at or above the modulus, as revm's 256-bit MODEXP path passes them: alternately
    /// an unreduced `x` times one, and a reduced `x` times an unreduced `y`. Either way the carry
    /// fits in its 32 bytes.
    fn generate_unreduced_record(size: usize) -> EmulationRecord {
        let mut n = 0u32;
        generate_record_with(size, |rng, modulus| {
            n += 1;
            let wide = rng.random_biguint(256);
            if n.is_multiple_of(2) {
                (wide, BigUint::from(1u8))
            } else {
                (rng.random_biguint(256) % modulus, wide)
            }
        })
    }

    /// `size` events, each with a random modulus (2^256 for the first) and the operands
    /// `operands` picks for it.
    fn generate_record_with(
        size: usize,
        mut operands: impl FnMut(&mut ThreadRng, &BigUint) -> (BigUint, BigUint),
    ) -> EmulationRecord {
        let mut rng = rng();
        let size = size as u32;
        let events = (0..size)
            .map(|i| {
                let chunk = 0;
                let clk = i as u64;
                let x_ptr = 0x10000 + (rng.random_range(0..size) * 8) as u64;
                let y_ptr = 0x10000 + (rng.random_range(0..size) * 8) as u64;
                let modulus_biguint = if i == 0 {
                    BigUint::from(1u64) << 256
                } else {
                    rng.random_biguint(256)
                };
                let (x_biguint, y_biguint) = operands(&mut rng, &modulus_biguint);

                let to_u64_arr = |b: &BigUint| -> [u64; 4] {
                    let mut arr = [0u64; 4];
                    let digits = b.to_u64_digits();
                    arr[..digits.len().min(4)].copy_from_slice(&digits[..digits.len().min(4)]);
                    arr
                };

                let modulus = to_u64_arr(&modulus_biguint);
                let x = to_u64_arr(&x_biguint);
                let y = to_u64_arr(&y_biguint);

                let x_memory_records: [MemoryWriteRecord; 4] = from_fn(|_| MemoryWriteRecord {
                    prev_timestamp: i,
                    timestamp: i + 1,
                    ..Default::default()
                });
                let y_memory_records: [MemoryReadRecord; 4] = from_fn(|_| MemoryReadRecord {
                    prev_timestamp: i,
                    timestamp: i + 1,
                    ..Default::default()
                });
                let modulus_memory_records: [MemoryReadRecord; 4] = from_fn(|_| MemoryReadRecord {
                    prev_timestamp: i,
                    timestamp: i + 1,
                    ..Default::default()
                });
                let syscall_event = SyscallEvent {
                    syscall_id: SyscallCode::UINT256_MUL as u32,
                    ..Default::default()
                };
                let event = Uint256MulEvent {
                    chunk,
                    clk,
                    x_ptr,
                    x,
                    y_ptr,
                    y,
                    modulus,
                    x_memory_records,
                    y_memory_records,
                    modulus_memory_records,
                    local_mem_access: vec![],
                };
                (syscall_event, PrecompileEvent::Uint256Mul(event))
            })
            .collect();
        let mut precompile_events = PrecompileEvents::default();
        precompile_events.insert(SyscallCode::UINT256_MUL, events);

        let mut record = EmulationRecord::default();
        record.precompile_events = precompile_events;

        record
    }

    fn gpu_generate_extra_record_and_main(
        chip: &Uint256MulChip<F>,
        input: &EmulationRecord,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> RowMajorMatrix<F> {
        let stream = init_test_stream();
        let trace = chip.gpu_generate_extra_record_and_main(
            0,
            input,
            prepared_gpu_events,
            preallocated_gpu_memory,
        );
        trace.to_host(stream)
    }

    #[test]
    fn test_precompile_u256_mul_generate_extra_record_and_main() {
        // 1 << 20 events corresponds to 2^20 rows
        assert_cpu_and_gpu_traces_agree(LazyLock::force(&UINT256_MUL_SHARD), 20);
    }

    /// The GPU trace of operands at or above the modulus is the CPU one, which the AIR accepts
    /// (`tests::operands_at_or_above_the_modulus_are_proved`).
    #[test]
    fn test_precompile_u256_mul_unreduced_operands() {
        assert_cpu_and_gpu_traces_agree(&generate_unreduced_record(1 << 12), 12);
    }

    fn assert_cpu_and_gpu_traces_agree(original_record: &EmulationRecord, log_rows: usize) {
        let chip = Uint256MulChip::default();

        // Complete the record for CPU computation.
        let mut complete_record = original_record.clone();
        chip.extra_record(original_record, &mut complete_record);
        // Precompute event sizes for GPU computation.
        let mut counted_record = original_record.clone();
        complete_record.shape = Some(RiscvPadShape::default());
        complete_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), log_rows);
        counted_record.shape = Some(RiscvPadShape::default());
        counted_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), log_rows);
        let mut event_counter = precompute_event_size::<F>(&mut counted_record);

        // Ignore Poseidon2 event counting
        event_counter.num_poseidon2_events = complete_record.poseidon2_events.len();
        // Ignore Global lookup event counting
        event_counter.num_global_lookup_events = complete_record.global_lookup_events.len();
        // Assert that the event counts are the same.
        event_counter.assert_event_counts_match(&complete_record);

        // Generate CPU trace.
        let cpu_trace = cpu_generate_main(&chip, &complete_record);
        let byte_chip = ByteChip::<F>::default();
        let cpu_byte_trace =
            byte_chip.generate_main(&complete_record, &mut EmulationRecord::default());

        // Generate GPU trace.
        let stream = init_test_stream();
        let mut preallocated_gpu_memory = PreallocatedGpuMemory {
            d_byte_trace: gpu_allocate_byte_trace(&stream, 0).unwrap(),
            ..Default::default()
        };

        let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter);
        let gpu_trace = gpu_generate_extra_record_and_main(
            &chip,
            &counted_record,
            &prepared_gpu_events,
            &mut preallocated_gpu_memory,
        );
        // Assert trace consistency.
        assert_eq!(cpu_trace, gpu_trace);

        // Finalize the byte trace. And assert that the byte trace is consistent.
        gpu_finalize_byte_trace(stream, &mut preallocated_gpu_memory).unwrap();
        stream.synchronize().unwrap();

        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.take().unwrap();

        let host_gpu_byte_trace =
            TraceData::<F>::Gpu(NUM_BYTE_MULT_COLS, d_byte_trace).to_host(stream);
        assert_eq!(host_gpu_byte_trace.values, cpu_byte_trace.values);
    }

    #[test]
    fn bench_uint256_mul_cpu_vs_gpu() {
        use crate::{
            chips::{
                precompiles::uint256::columns::NUM_UINT256_MUL_COLS, utils::next_power_of_two,
            },
            cuda_adaptor::resource_pool::mem_pool::get_global_mem_pool,
            emulator::riscv::syscalls::precompiles::uint256::event::FfiUint256MulEvent,
        };
        use cudart::{memory_pools::DevicePoolAllocation, slice::CudaSliceMut};
        use cudart_sys::*;
        use pico_gpu_api::cuda_precompile_uint256_generate_extra_record_and_main;
        use std::time::Instant;

        let chip = Uint256MulChip::<F>::default();
        let warmup_sizes: Vec<usize> = vec![1 << 16];
        let bench_sizes: Vec<usize> = vec![1 << 16, 1 << 18, 1 << 20];

        println!("\n{:-<60}", "");
        println!(
            "{:<12} {:>12} {:>12} {:>12}",
            "events", "cpu (ms)", "gpu (ms)", "speedup"
        );
        println!("{:-<60}", "");

        for (is_warmup, &num_events) in warmup_sizes
            .iter()
            .map(|n| (true, n))
            .chain(bench_sizes.iter().map(|n| (false, n)))
        {
            let original_record = generate_record(num_events);

            let mut complete_record = original_record.clone();
            let mut counted_record = original_record.clone();

            let log_rows = (num_events as f64).log2().ceil() as usize + 1;
            complete_record.shape = Some(RiscvPadShape::default());
            complete_record
                .shape
                .as_mut()
                .unwrap()
                .inner
                .insert(chip.name(), log_rows);
            counted_record.shape = Some(RiscvPadShape::default());
            counted_record
                .shape
                .as_mut()
                .unwrap()
                .inner
                .insert(chip.name(), log_rows);

            // CPU
            let cpu_start = Instant::now();
            chip.extra_record(&original_record, &mut complete_record);
            let cpu_trace = cpu_generate_main(&chip, &complete_record);
            let cpu_ms = cpu_start.elapsed().as_secs_f64() * 1000.0;

            // GPU
            let stream = init_test_stream();
            let sync_mem_pool = get_global_mem_pool(0);
            let mem_pool = &sync_mem_pool.0;

            let event_counter = precompute_event_size::<F>(&mut counted_record);
            let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter);
            let events = &prepared_gpu_events.uint256_mul_events;

            let event_size = events.len();
            let num_cols = NUM_UINT256_MUL_COLS;
            let num_total_rows = next_power_of_two(events.len(), Some(log_rows));
            let trace_size = num_total_rows * num_cols;
            let event_alloc_size = if event_size == 0 { 1 } else { event_size };

            let mut d_events = DevicePoolAllocation::<FfiUint256MulEvent>::alloc_from_pool_async(
                event_alloc_size,
                mem_pool,
                stream,
            )
            .unwrap();

            if event_size > 0 {
                unsafe {
                    let _ = cudaMemcpyAsync(
                        d_events.as_mut_c_void_ptr(),
                        events.as_ptr() as *const _,
                        event_size * std::mem::size_of::<FfiUint256MulEvent>(),
                        CudaMemoryCopyKind::HostToDevice,
                        stream.into(),
                    );
                }
            }

            let mut d_trace = DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(
                trace_size, mem_pool, stream,
            )
            .unwrap();
            let mut d_byte_trace = gpu_allocate_byte_trace(stream, 0).unwrap().unwrap();

            stream.synchronize().unwrap();

            let gpu_start = Instant::now();
            unsafe {
                cuda_precompile_uint256_generate_extra_record_and_main(
                    num_cols,
                    event_size,
                    trace_size,
                    d_events.as_ptr() as *const _,
                    d_trace.as_mut_ptr() as *mut _,
                    d_byte_trace.as_mut_ptr() as *mut _,
                    stream.into(),
                );
            }
            stream.synchronize().unwrap();
            let gpu_ms = gpu_start.elapsed().as_secs_f64() * 1000.0;

            if is_warmup {
                println!(
                    "{:<12} {:>12} {:>12} {:>12}",
                    num_events, "warmup", "warmup", "—"
                );
                continue;
            }

            let gpu_trace = TraceData::<F>::Gpu(num_cols, d_trace).to_host(stream);
            stream.synchronize().unwrap();

            assert_eq!(
                cpu_trace.values,
                gpu_trace.values[..cpu_trace.values.len()],
                "Main trace mismatch at bench size {}",
                num_events
            );

            let speedup = cpu_ms / gpu_ms;
            println!(
                "{:<12} {:>12.2} {:>12.2} {:>11.1}x  ✓",
                num_events, cpu_ms, gpu_ms, speedup
            );
        }
        println!("{:-<60}", "");
    }
}
