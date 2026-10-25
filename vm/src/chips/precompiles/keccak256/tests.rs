//! CPU/GPU trace-generation parity for the two Keccak AIRs (main trace and byte lookups).

use crate::{
    chips::{
        chips::{
            byte::{columns::NUM_BYTE_MULT_COLS, ByteChip},
            riscv_memory::event::{MemoryReadRecord, MemoryWriteRecord},
        },
        precompiles::keccak256::{
            columns::{NUM_KECCAK_MEM_COLS, NUM_KECCAK_PERM_COLS},
            control::NUM_KECCAK_CONTROL_COLS,
            KeccakControlChip, KeccakPermuteChip, STATE_SIZE,
        },
        tests::init_test_stream,
        trace::TraceData,
    },
    emulator::riscv::{
        record::EmulationRecord,
        syscalls::{
            precompiles::{KeccakPermuteEvent, PrecompileEvent},
            SyscallCode, SyscallEvent,
        },
    },
    instances::preparer::{
        gpu_allocate_byte_trace, gpu_finalize_byte_trace, precompute_event_size,
        PreallocatedGpuMemory, PreparedGpuEvents,
    },
    machine::chip::ChipBehavior,
};
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::NUM_ROUNDS;
use p3_koala_bear::KoalaBear;
use rand::{rng, RngExt};
use tiny_keccak::keccakf;

type F = KoalaBear;

/// `num_events` random permutations with consistent memory records: reads at `clk`, writes at
/// `clk + 1`, a fresh 200-byte state buffer per event (aligned, above the 64KB stack guard).
pub fn generate_keccak_record(num_events: usize) -> EmulationRecord {
    let mut rng = rng();
    let mut events = Vec::with_capacity(num_events);

    for i in 0..num_events {
        let mut pre_state = [0u64; STATE_SIZE];
        for word in pre_state.iter_mut() {
            *word = rng.random();
        }
        let mut post_state = pre_state;
        keccakf(&mut post_state);

        let clk = (i as u32 + 1) * 100;
        let state_addr = 0x10000u64 + (i as u64) * 0x100;

        let state_read_records = (0..STATE_SIZE)
            .map(|j| MemoryReadRecord {
                value: pre_state[j],
                chunk: 1,
                timestamp: clk,
                prev_chunk: 1,
                // Every other event leaves the buffer "untouched in this chunk" (sentinel 0).
                prev_timestamp: if i % 2 == 0 { 0 } else { clk - 50 },
            })
            .collect();
        let state_write_records = (0..STATE_SIZE)
            .map(|j| MemoryWriteRecord {
                value: post_state[j],
                chunk: 1,
                timestamp: clk + 1,
                prev_value: pre_state[j],
                prev_chunk: 1,
                prev_timestamp: clk,
            })
            .collect();

        events.push(KeccakPermuteEvent {
            chunk: 1,
            clk: u64::from(clk),
            pre_state,
            post_state,
            state_read_records,
            state_write_records,
            state_addr,
            local_mem_access: vec![],
        });
    }

    let mut record = EmulationRecord::default();
    let pre_events: Vec<(SyscallEvent, PrecompileEvent)> = events
        .into_iter()
        .map(|e| (SyscallEvent::default(), PrecompileEvent::KeccakPermute(e)))
        .collect();
    record
        .precompile_events
        .insert(SyscallCode::KECCAK_PERMUTE, pre_events);
    record
}

/// CPU vs GPU for one chip: full main trace (real + dummy rows) and the byte table.
fn assert_cpu_gpu_parity<C: ChipBehavior<F, Record = EmulationRecord>>(
    chip: &C,
    original_record: &EmulationRecord,
    num_cols: usize,
) {
    let mut complete_record = original_record.clone();
    chip.extra_record(original_record, &mut complete_record);

    let mut counted_record = original_record.clone();
    let mut event_counter = precompute_event_size::<F>(&mut counted_record);
    event_counter.num_poseidon2_events = 0;
    event_counter.num_global_lookup_events = 0;
    event_counter.num_syscall_events = 0;
    event_counter.num_precompile_syscall_events = 0;
    event_counter.assert_event_counts_match(&complete_record);

    let cpu_trace = chip.generate_main(&complete_record, &mut EmulationRecord::default());
    let byte_chip = ByteChip::<F>::default();
    let cpu_byte_trace = byte_chip.generate_main(&complete_record, &mut EmulationRecord::default());

    let stream = init_test_stream();
    let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter);
    let mut preallocated_gpu_memory = PreallocatedGpuMemory {
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
    stream.synchronize().unwrap();

    assert_eq!(cpu_trace.width, num_cols);
    assert_eq!(
        cpu_trace.values.len(),
        gpu_trace.values.len(),
        "{}: trace size mismatch (CPU {} rows, GPU {} rows)",
        chip.name(),
        cpu_trace.values.len() / num_cols,
        gpu_trace.values.len() / num_cols
    );
    if cpu_trace.values != gpu_trace.values {
        let num_rows = cpu_trace.values.len() / num_cols;
        for row in 0..num_rows {
            for col in 0..num_cols {
                let idx = row * num_cols + col;
                if cpu_trace.values[idx] != gpu_trace.values[idx] {
                    panic!(
                        "{}: main trace mismatch at row {}, col {}: CPU {:?}, GPU {:?}",
                        chip.name(),
                        row,
                        col,
                        cpu_trace.values[idx],
                        gpu_trace.values[idx]
                    );
                }
            }
        }
    }

    gpu_finalize_byte_trace(stream, &mut preallocated_gpu_memory).unwrap();
    stream.synchronize().unwrap();
    let host_gpu_byte_trace = TraceData::<F>::Gpu(
        NUM_BYTE_MULT_COLS,
        preallocated_gpu_memory.d_byte_trace.take().unwrap(),
    )
    .to_host(stream);
    stream.synchronize().unwrap();
    assert_eq!(
        host_gpu_byte_trace.values,
        cpu_byte_trace.values,
        "{}: byte trace mismatch",
        chip.name()
    );
}

#[test]
fn test_keccak_gpu_generate_extra_record_and_main() {
    // 2^10 permutations x 24 rows -> 2^15 rows (with dummy padding) x 2537 cols.
    let num_events = 1 << 10;
    let record = generate_keccak_record(num_events);
    let chip = KeccakPermuteChip::<F>::default();
    assert_cpu_gpu_parity(&chip, &record, NUM_KECCAK_MEM_COLS);

    // The state bus fires once per permutation: `export` is 1 on every 24th real row only.
    let complete = record.clone();
    let trace = chip.generate_main(&complete, &mut EmulationRecord::default());
    let export_col = NUM_ROUNDS; // `KeccakCols { step_flags: [T; 24], export, .. }`
    let rows = trace.values.len() / NUM_KECCAK_MEM_COLS;
    let exported = (0..rows)
        .filter(|row| trace.values[row * NUM_KECCAK_MEM_COLS + export_col] == F::ONE)
        .count();
    assert_eq!(exported, num_events);
    // The input goes out on the first step: `export_in` is 1 on every 24th real row only.
    let export_in_col = NUM_KECCAK_PERM_COLS + 3; // `KeccakMemCols { keccak, chunk, clk, is_real, export_in }`
    let exported_in = (0..rows)
        .filter(|row| trace.values[row * NUM_KECCAK_MEM_COLS + export_in_col] == F::ONE)
        .count();
    assert_eq!(exported_in, num_events);
    println!("KeccakPermute GPU correctness test passed for {num_events} events!");
}

#[test]
fn test_keccak_control_gpu_generate_extra_record_and_main() {
    let num_events = 1 << 14;
    let record = generate_keccak_record(num_events);
    let chip = KeccakControlChip::<F>::default();
    assert_cpu_gpu_parity(&chip, &record, NUM_KECCAK_CONTROL_COLS);
    println!("KeccakControl GPU correctness test passed for {num_events} events!");
}

/// A non-power-of-two event count, so the control trace has padding rows (CPU `pad_rows_fixed`
/// zero rows vs GPU memset) -- the path the power-of-two case above never exercises.
#[test]
fn test_keccak_control_gpu_generate_with_padding() {
    let num_events = 1000; // -> 1024 rows, 24 padding rows
    let record = generate_keccak_record(num_events);
    let chip = KeccakControlChip::<F>::default();
    assert_cpu_gpu_parity(&chip, &record, NUM_KECCAK_CONTROL_COLS);
    println!("KeccakControl GPU correctness test (with padding) passed for {num_events} events!");
}
