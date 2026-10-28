#[cfg(feature = "cuda")]
use crate::{
    chips::{
        chips::{
            alu::{add::AddChip, event::AluEvent},
            byte::{columns::NUM_BYTE_MULT_COLS, ByteChip},
        },
        tests::init_test_stream,
        trace::TraceData,
    },
    compiler::riscv::opcode::Opcode,
    cuda_adaptor::resource_pool::mem_pool::get_global_mem_pool,
    emulator::riscv::{
        alu_event_pool::{init_alu_event_buffer_pool, is_alu_pool_initialized},
        event_pool::HostAllocFlags,
        record::EmulationRecord,
    },
    instances::{
        compiler::shapes::riscv_shape::RiscvPadShape,
        preparer::{
            gpu_allocate_and_copy_add_sub_events, gpu_allocate_byte_trace, gpu_finalize_byte_trace,
            precompute_event_size, PreallocatedGpuMemory, PreparedGpuEvents,
        },
    },
    machine::chip::{ChipBehavior, GpuChipBehavior},
    primitives::consts::ADD_DATAPAR,
};
#[cfg(feature = "cuda")]
use cudart::{memory_pools::DevicePoolAllocation, slice::CudaSliceMut};
#[cfg(feature = "cuda")]
use p3_field::PrimeCharacteristicRing;
#[cfg(feature = "cuda")]
use p3_koala_bear::KoalaBear;
#[cfg(feature = "cuda")]
use rand::{rng, RngExt};
#[cfg(feature = "cuda")]
use std::sync::LazyLock;

#[cfg(feature = "cuda")]
type F = KoalaBear;

#[cfg(feature = "cuda")]
/// Random ADD / SUB / ADDW / SUBW events, interleaved, so the partition step in the test has to
/// pull the ADD rows out of the shared buffer the way the prover does between the DivRem chip
/// and this one.
static GPU_TEST_RECORD: LazyLock<EmulationRecord> =
    LazyLock::new(|| generate_gpu_test_record(1 << 20));

#[cfg(feature = "cuda")]
fn generate_gpu_test_record(event_count: u64) -> EmulationRecord {
    if !is_alu_pool_initialized() {
        init_alu_event_buffer_pool(50, HostAllocFlags::DEFAULT);
    }

    let rng = &mut rng();
    let opcodes = [
        Opcode::ADD,
        Opcode::SUB,
        Opcode::ADD,
        Opcode::ADDW,
        Opcode::SUBW,
    ];
    let events: Vec<AluEvent> = (0..event_count)
        .map(|i| {
            let b: u64 = rng.random();
            let c: u64 = rng.random();
            let op = opcodes[(i % 5) as usize];
            let a = match op {
                Opcode::ADD => b.wrapping_add(c),
                Opcode::SUB => b.wrapping_sub(c),
                Opcode::ADDW => (b as u32).wrapping_add(c as u32) as i32 as i64 as u64,
                _ => (b as u32).wrapping_sub(c as u32) as i32 as i64 as u64,
            };
            AluEvent::new(i, op, a, b, c, false)
        })
        .collect();

    let mut record = EmulationRecord::default();
    record
        .add_sub_events
        .extend_from_alu_slice(&events)
        .expect("fixture fits one ALU event buffer");
    record
}

#[cfg(feature = "cuda")]
fn device_base(buffer: &mut Option<DevicePoolAllocation<'_, AluEvent>>) -> *mut std::ffi::c_void {
    buffer
        .as_mut()
        .map_or(std::ptr::null_mut(), |b| b.as_mut_ptr() as *mut _)
}

#[cfg(feature = "cuda")]
#[test]
fn test_add_sub_gpu_generate_extra_record_and_main() {
    let original_record = LazyLock::force(&GPU_TEST_RECORD);

    let chip = AddChip::<F>::default();

    // Complete the record for CPU computation.
    let mut complete_record = original_record.clone();
    chip.extra_record(original_record, &mut complete_record);
    // Precompute event sizes for GPU computation.
    let mut counted_record = original_record.clone();
    let event_counter = precompute_event_size::<F>(&counted_record);
    assert!(
        event_counter.num_add_events > 0 && event_counter.num_sub_events > 0,
        "fixture must mix ADD with the other add/sub opcodes"
    );

    // Same padded height on both sides: rows pack `ADD_DATAPAR` events each.
    let nrows = event_counter.num_add_events.div_ceil(ADD_DATAPAR);
    let log_height = nrows.next_power_of_two().trailing_zeros() as usize;
    complete_record.shape = Some(RiscvPadShape::default());
    complete_record
        .shape
        .as_mut()
        .unwrap()
        .inner
        .insert(chip.name(), log_height);
    counted_record.shape = Some(RiscvPadShape::default());
    counted_record
        .shape
        .as_mut()
        .unwrap()
        .inner
        .insert(chip.name(), log_height);

    // Generate CPU traces.
    let cpu_trace = chip.generate_main(&complete_record, &mut EmulationRecord::default());
    let byte_chip = ByteChip::<F>::default();
    let cpu_byte_trace = byte_chip.generate_main(&complete_record, &mut EmulationRecord::default());

    // Generate the GPU trace. The chip reads its own pre-partitioned buffer, which the prover
    // fills from the shared add/sub buffer with the order-preserving partition kernel after the
    // DivRem chip has appended its ADDs (`vm/src/machine/prover.rs`); do the same here.
    let stream = init_test_stream();
    let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter.clone());
    let d_add_sub_events =
        gpu_allocate_and_copy_add_sub_events(stream, 0, &counted_record, &prepared_gpu_events)
            .unwrap()
            .expect("fixture has add/sub events");

    let sync_mem_pool = get_global_mem_pool(0);
    let mem_pool = &sync_mem_pool.0;
    let alloc = |n: usize| {
        (n > 0).then(|| {
            DevicePoolAllocation::<AluEvent>::alloc_from_pool_async(n, mem_pool, stream).unwrap()
        })
    };
    let mut d_add = alloc(event_counter.num_add_events);
    let mut d_sub = alloc(event_counter.num_sub_events);
    let mut d_addw = alloc(event_counter.num_addw_events);
    let mut d_subw = alloc(event_counter.num_subw_events);
    unsafe {
        pico_gpu_api::cuda_alu_partition_events(
            d_add_sub_events.as_ptr() as *const _,
            event_counter.num_add_sub_events,
            device_base(&mut d_add),
            device_base(&mut d_sub),
            device_base(&mut d_addw),
            device_base(&mut d_subw),
            stream.into(),
        );
    }
    stream.synchronize().unwrap();

    let mut preallocated_gpu_memory = PreallocatedGpuMemory {
        d_partitioned_add_events: d_add,
        d_byte_trace: gpu_allocate_byte_trace(stream, 0).unwrap(),
        ..Default::default()
    };
    let gpu_trace = chip
        .gpu_generate_extra_record_and_main(
            0,
            &counted_record,
            &prepared_gpu_events,
            &mut preallocated_gpu_memory,
        )
        .to_host(stream);

    // Assert trace consistency.
    assert_eq!(cpu_trace, gpu_trace);
    let non_zero_main = cpu_trace.values.iter().filter(|&&v| v != F::ZERO).count();
    assert!(
        non_zero_main > 0,
        "main trace is all zeros — both CPU and GPU may be broken"
    );

    // Finalize the byte trace and assert that it is consistent.
    gpu_finalize_byte_trace(stream, &mut preallocated_gpu_memory).unwrap();
    stream.synchronize().unwrap();

    let d_byte_trace = preallocated_gpu_memory.d_byte_trace.take().unwrap();
    let host_gpu_byte_trace = TraceData::<F>::Gpu(NUM_BYTE_MULT_COLS, d_byte_trace).to_host(stream);
    assert_eq!(host_gpu_byte_trace.values, cpu_byte_trace.values);
    let non_zero_byte = cpu_byte_trace
        .values
        .iter()
        .filter(|&&v| v != F::ZERO)
        .count();
    assert!(
        non_zero_byte > 0,
        "byte trace is all zeros — both CPU and GPU may be broken"
    );
}
