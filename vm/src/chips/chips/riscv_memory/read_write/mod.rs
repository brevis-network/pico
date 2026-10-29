use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
pub mod traces;

/// A chip for memory read and write
#[derive(Default)]
pub struct MemoryReadWriteChip<F>(PhantomData<F>);

#[cfg(test)]
mod tests {
    #[cfg(feature = "cuda")]
    use super::columns::{NUM_MEMORY_CHIP_COLS, NUM_MEMORY_CHIP_VALUE_COLS};
    #[cfg(feature = "cuda")]
    use crate::emulator::riscv::event_pool::HostAllocFlags;
    #[cfg(feature = "cuda")]
    use crate::machine::chip::GpuChipBehavior;
    #[cfg(feature = "cuda")]
    use crate::{
        chips::{
            chips::{
                byte::{columns::NUM_BYTE_MULT_COLS, ByteChip},
                events::{CpuEvent, MemoryReadRecord, MemoryWriteRecord},
                riscv_memory::{event::MemoryRecordEnum, read_write::MemoryReadWriteChip},
            },
            tests::init_test_stream,
            trace::TraceData,
            utils::next_power_of_two,
        },
        compiler::riscv::{instruction::Instruction, opcode::Opcode},
        cuda_adaptor::resource_pool::mem_pool::get_global_mem_pool,
        emulator::riscv::{
            cpu_event_pool::{init_cpu_event_buffer_pool, is_pool_initialized},
            record::{EmulationRecord, MemoryAccessRecord},
        },
        instances::{
            compiler::shapes::riscv_shape::RiscvPadShape,
            preparer::{
                gpu_allocate_and_copy_cpu_events, gpu_allocate_byte_trace, gpu_finalize_byte_trace,
                precompute_event_size, PreallocatedGpuMemory, PreparedGpuEvents,
            },
        },
        machine::chip::ChipBehavior,
        primitives::consts::MEMORY_RW_DATAPAR,
    };
    #[cfg(feature = "cuda")]
    use cudart::memory_pools::DevicePoolAllocation;
    #[cfg(feature = "cuda")]
    use cudart_sys::{cudaMemcpyAsync, CudaMemoryCopyKind};
    #[cfg(feature = "cuda")]
    use hashbrown::HashMap;
    #[cfg(feature = "cuda")]
    use p3_field::PrimeCharacteristicRing;
    #[cfg(feature = "cuda")]
    use p3_koala_bear::KoalaBear;
    #[cfg(feature = "cuda")]
    use p3_matrix::dense::RowMajorMatrix;
    #[cfg(feature = "cuda")]
    use pico_gpu_api::cuda_memory_read_write_generate_extra_record_and_main_u64;
    #[cfg(feature = "cuda")]
    use rand::{rng, seq::IndexedRandom, RngExt};
    #[cfg(feature = "cuda")]
    use std::{mem::size_of, sync::LazyLock, time::Instant};

    #[cfg(feature = "cuda")]
    type F = KoalaBear;

    #[cfg(feature = "cuda")]
    static SHARD: LazyLock<EmulationRecord> = LazyLock::new(|| generate_record(1 << 16));

    #[cfg(feature = "cuda")]
    fn cpu_generate_main(
        chip: &MemoryReadWriteChip<F>,
        input: &EmulationRecord,
    ) -> RowMajorMatrix<F> {
        chip.generate_main(input, &mut EmulationRecord::default())
    }

    #[cfg(feature = "cuda")]
    fn align_u64(addr: u64) -> u64 {
        addr & !7
    }

    #[cfg(feature = "cuda")]
    fn generate_record(size: usize) -> EmulationRecord {
        if !is_pool_initialized() {
            init_cpu_event_buffer_pool(50, HostAllocFlags::DEFAULT);
        }

        let mut rng = rng();
        let mut hash_map: HashMap<u64, (u64, u32)> = HashMap::new();
        let mut cpu_events = vec![];
        let opcodes = [
            Opcode::SB,
            Opcode::SH,
            Opcode::SW,
            Opcode::SD,
            Opcode::LB,
            Opcode::LBU,
            Opcode::LH,
            Opcode::LHU,
            Opcode::LW,
            Opcode::LWU,
            Opcode::LD,
        ];
        let size = size as u32;
        (1..=size).for_each(|i| {
            let mut addr = i as u64;
            let a: u64 = rng.random();
            let aligned_addr = align_u64(addr);
            let (memory_store_value, timestamp) =
                hash_map.entry(aligned_addr).or_insert((0u64, 0u32));
            let prev_timestamp = *timestamp;
            *timestamp = i;
            let opcode = *opcodes.choose(&mut rng).unwrap();
            let (instruction, record) =
                if matches!(opcode, Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD) {
                    let memory_load_value = *memory_store_value;
                    match opcode {
                        Opcode::SB => {
                            let byte_offset = (addr & 7) as u32;
                            let shift = byte_offset * 8;
                            let mask = !(0xFFu64 << shift);
                            *memory_store_value =
                                (memory_load_value & mask) | (((a & 0xFF) as u64) << shift);
                        }
                        Opcode::SH => {
                            addr &= !1;
                            let limb_index = ((addr >> 1) & 3) as u32;
                            let shift = limb_index * 16;
                            let mask = !(0xFFFFu64 << shift);
                            *memory_store_value =
                                (memory_load_value & mask) | (((a & 0xFFFF) as u64) << shift);
                        }
                        Opcode::SW => {
                            addr &= !3;
                            let word_index = ((addr >> 2) & 1) as u32;
                            let shift = word_index * 32;
                            let mask = !(0xFFFF_FFFFu64 << shift);
                            *memory_store_value =
                                (memory_load_value & mask) | (((a & 0xFFFF_FFFF) as u64) << shift);
                        }
                        Opcode::SD => {
                            addr = aligned_addr;
                            *memory_store_value = a;
                        }
                        _ => unreachable!(),
                    };
                    let instruction = Instruction {
                        opcode,
                        op_a: rng.random_range(1..=31),
                        op_b: 0,
                        op_c: addr,
                        imm_b: false,
                        imm_c: true,
                    };
                    let record = MemoryRecordEnum::Write(MemoryWriteRecord::new(
                        *memory_store_value,
                        0,
                        *timestamp,
                        memory_load_value,
                        0,
                        prev_timestamp,
                    ));
                    (instruction, record)
                } else {
                    match opcode {
                        Opcode::LH | Opcode::LHU => {
                            addr &= !1;
                        }
                        Opcode::LW | Opcode::LWU => {
                            addr &= !3;
                        }
                        Opcode::LD => {
                            addr = aligned_addr;
                        }
                        _ => {}
                    };
                    let instruction = Instruction {
                        opcode,
                        op_a: rng.random_range(1..=31),
                        op_b: 0,
                        op_c: addr,
                        imm_b: false,
                        imm_c: true,
                    };
                    let record = MemoryRecordEnum::Read(MemoryReadRecord::new(
                        *memory_store_value,
                        0,
                        *timestamp,
                        0,
                        prev_timestamp,
                    ));
                    (instruction, record)
                };
            cpu_events.push(CpuEvent::new(
                0,
                *timestamp as u64,
                i as u64,
                (i + 1) as u64,
                instruction,
                a,
                0,
                instruction.op_c,
                Some(*memory_store_value),
                MemoryAccessRecord {
                    a: None,
                    b: None,
                    c: None,
                    memory: Some(record),
                },
                0,
            ));
        });
        let mut memory_read_write_event_indices = vec![];
        for i in 0..cpu_events.len() {
            if cpu_events[i].instruction.is_memory_instruction() {
                memory_read_write_event_indices.push(i);
            }
        }

        let mut record = EmulationRecord::default();
        let added_count = record.add_cpu_events(&cpu_events).unwrap();
        assert_eq!(
            added_count,
            cpu_events.len(),
            "Not all CPU events were added"
        );
        record.memory_read_write_event_indices = memory_read_write_event_indices;

        record
    }

    #[cfg(feature = "cuda")]
    fn gpu_generate_extra_record_and_main(
        chip: &MemoryReadWriteChip<F>,
        input: &EmulationRecord,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> RowMajorMatrix<F> {
        let stream = init_test_stream();
        let trace = chip.gpu_generate_extra_record_and_main(
            0,
            input,
            &prepared_gpu_events,
            preallocated_gpu_memory,
        );
        trace.to_host(stream)
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn test_memory_read_write_gpu_generate_extra_record_and_main() {
        if !is_pool_initialized() {
            init_cpu_event_buffer_pool(50, HostAllocFlags::DEFAULT);
        }

        let original_record = LazyLock::force(&SHARD);

        let chip = MemoryReadWriteChip::default();

        let mut complete_record = original_record.clone();
        chip.extra_record(&original_record, &mut complete_record);

        let mut counted_record = original_record.clone();
        let event_counter = precompute_event_size::<F>(&counted_record);
        event_counter.assert_event_counts_match(&complete_record);

        let log_rows = 17;
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

        let cpu_trace = cpu_generate_main(&chip, &complete_record);
        let byte_chip = ByteChip::<F>::default();
        let cpu_byte_trace =
            byte_chip.generate_main(&complete_record, &mut EmulationRecord::default());

        let stream = init_test_stream();
        let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter.clone());
        let cpu_memory =
            gpu_allocate_and_copy_cpu_events(stream, 0, &counted_record, &prepared_gpu_events)
                .unwrap();
        let mut preallocated_gpu_memory = PreallocatedGpuMemory {
            d_byte_trace: gpu_allocate_byte_trace(&stream, 0).unwrap(),
            ..Default::default()
        };
        preallocated_gpu_memory.d_cpu_events = cpu_memory;
        let gpu_trace = gpu_generate_extra_record_and_main(
            &chip,
            &counted_record,
            &prepared_gpu_events,
            &mut preallocated_gpu_memory,
        );

        assert!(
            !cpu_trace.values.is_empty(),
            "CPU trace should not be empty"
        );
        assert!(
            cpu_trace.values.iter().any(|v| *v != F::ZERO),
            "CPU trace should not be all zeros"
        );

        assert_eq!(cpu_trace, gpu_trace, "CPU and GPU main traces do not match");

        gpu_finalize_byte_trace(&stream, &mut preallocated_gpu_memory).unwrap();
        stream.synchronize().unwrap();

        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.take().unwrap();

        let host_gpu_byte_trace =
            TraceData::<F>::Gpu(NUM_BYTE_MULT_COLS, d_byte_trace).to_host(&stream);
        assert_eq!(
            host_gpu_byte_trace.values, cpu_byte_trace.values,
            "CPU and GPU byte traces do not match"
        );
    }

    #[cfg(feature = "cuda")]
    #[test]
    fn bench_memory_read_write_cpu_vs_gpu() {
        if !is_pool_initialized() {
            init_cpu_event_buffer_pool(50, HostAllocFlags::DEFAULT);
        }

        let warmup_sizes: Vec<usize> = vec![1 << 16];
        let bench_sizes: Vec<usize> = vec![1 << 16, 1 << 18, 1 << 20, 1 << 22];

        println!("\n{:-<60}", "");
        println!(
            "{:<12} {:>12} {:>12} {:>12}",
            "events", "cpu (ms)", "gpu (ms)", "speedup"
        );
        println!("{:-<60}", "");

        for (is_warmup, &n) in warmup_sizes
            .iter()
            .map(|n| (true, n))
            .chain(bench_sizes.iter().map(|n| (false, n)))
        {
            let original_record = generate_record(n);
            let chip = MemoryReadWriteChip::<F>::default();

            let mut complete_record = original_record.clone();
            chip.extra_record(&original_record, &mut complete_record);
            let counted_record = original_record.clone();
            let event_counter = precompute_event_size::<F>(&counted_record);

            let log2 = (n as f64).log2().ceil() as usize + 1;
            complete_record.shape = Some(RiscvPadShape::default());
            complete_record
                .shape
                .as_mut()
                .unwrap()
                .inner
                .insert(chip.name(), log2);
            let mut counted_record_shaped = counted_record.clone();
            counted_record_shaped.shape = Some(RiscvPadShape::default());
            counted_record_shaped
                .shape
                .as_mut()
                .unwrap()
                .inner
                .insert(chip.name(), log2);

            let cpu_start = Instant::now();
            let cpu_trace = cpu_generate_main(&chip, &complete_record);
            let cpu_ms = cpu_start.elapsed().as_secs_f64() * 1000.0;

            let stream = init_test_stream();
            let prepared_gpu_events =
                PreparedGpuEvents::new(&counted_record_shaped, event_counter.clone());
            let cpu_memory = gpu_allocate_and_copy_cpu_events(
                stream,
                0,
                &counted_record_shaped,
                &prepared_gpu_events,
            )
            .unwrap();
            let mut preallocated_gpu_memory = PreallocatedGpuMemory {
                d_byte_trace: gpu_allocate_byte_trace(&stream, 0).unwrap(),
                ..Default::default()
            };
            preallocated_gpu_memory.d_cpu_events = cpu_memory;
            stream.synchronize().unwrap();

            // GPU: alloc + H2D before timer (kernel-only timing, apple-to-apple with CPU)
            let event_size = counted_record_shaped.memory_read_write_event_indices.len();
            let nrows = event_size.div_ceil(MEMORY_RW_DATAPAR);
            let log2_nrows = counted_record_shaped.shape_chip_size(&chip.name());
            let padded_nrows = next_power_of_two(nrows, log2_nrows);
            let trace_size = padded_nrows * NUM_MEMORY_CHIP_COLS;

            let sync_mem_pool = get_global_mem_pool(0);
            let mem_pool = &sync_mem_pool.0;

            let mut d_event_indices =
                DevicePoolAllocation::<usize>::alloc_from_pool_async(event_size, mem_pool, &stream)
                    .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_event_indices.as_mut_ptr() as *mut std::ffi::c_void,
                    counted_record_shaped
                        .memory_read_write_event_indices
                        .as_ptr() as *const std::ffi::c_void,
                    event_size * size_of::<usize>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
            }
            let mut d_trace = DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(
                trace_size, mem_pool, &stream,
            )
            .unwrap();
            stream.synchronize().unwrap();

            let gpu_start = Instant::now();
            let d_cpu_events = preallocated_gpu_memory.d_cpu_events.as_mut().unwrap();
            let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();
            unsafe {
                cuda_memory_read_write_generate_extra_record_and_main_u64(
                    NUM_MEMORY_CHIP_VALUE_COLS,
                    event_size,
                    trace_size,
                    d_cpu_events.as_ptr() as *const _,
                    d_event_indices.as_ptr() as *const _,
                    d_trace.as_mut_ptr() as *mut _,
                    stream.into(),
                    d_byte_trace.as_mut_ptr() as *mut _,
                );
            }
            stream.synchronize().unwrap();
            let gpu_ms = gpu_start.elapsed().as_secs_f64() * 1000.0;

            if is_warmup {
                println!("{:<12} {:>12} {:>12} {:>12}", n, "warmup", "warmup", "—");
                continue;
            }

            let gpu_trace = TraceData::<F>::Gpu(NUM_MEMORY_CHIP_COLS, d_trace).to_host(&stream);
            assert_eq!(
                cpu_trace.values, gpu_trace.values,
                "CPU/GPU MemoryReadWrite trace mismatch at n={}",
                n
            );

            let speedup = cpu_ms / gpu_ms;
            println!(
                "{:<12} {:>12.2} {:>12.2} {:>11.1}x  ✓",
                n, cpu_ms, gpu_ms, speedup
            );
        }
        println!("{:-<60}", "");
    }
}
