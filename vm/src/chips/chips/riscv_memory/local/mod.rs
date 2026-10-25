use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
pub mod traces;

#[derive(Default)]
pub struct MemoryLocalChip<F>(PhantomData<F>);

#[cfg(test)]
mod tests {
    use crate::{
        chips::{
            chips::{
                byte::{columns::NUM_BYTE_MULT_COLS, ByteChip},
                events::{MemoryLocalEvent, MemoryRecord},
                riscv_memory::{
                    event::FfiMemoryLocalEvent,
                    local::{
                        columns::{NUM_MEMORY_LOCAL_INIT_COLS, NUM_SINGLE_MEMORY_LOCAL_COLS},
                        MemoryLocalChip,
                    },
                },
            },
            tests::init_test_stream,
            trace::TraceData,
            utils::next_power_of_two,
        },
        cuda_adaptor::resource_pool::mem_pool::get_global_mem_pool,
        emulator::riscv::record::EmulationRecord,
        instances::{
            compiler::shapes::riscv_shape::RiscvPadShape,
            preparer::{
                gpu_allocate_and_copy_global_events, gpu_allocate_byte_trace,
                gpu_finalize_byte_trace, precompute_event_size, verify_global_events, EventCounter,
                PreallocatedGpuMemory, PreparedGpuEvents,
            },
        },
        machine::chip::ChipBehavior,
        primitives::consts::LOCAL_MEMORY_DATAPAR,
    };
    use cudart::{memory_pools::DevicePoolAllocation, stream::CudaStream};
    use cudart_sys::{cudaMemcpyAsync, cudaMemsetAsync, CudaMemoryCopyKind};
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use pico_gpu_api::cuda_memory_local_generate_extra_record_and_main_u64;
    use rand::{rng, RngExt};
    use std::{mem::size_of, sync::LazyLock, time::Instant};

    type F = KoalaBear;

    static GPU_TEST_RECORD: LazyLock<EmulationRecord> = LazyLock::new(|| generate_record(1 << 16));

    /// Random entries at addresses outside the (empty) default image; every fourth one starts
    /// at zero and so is fresh (`has_initial = 0`, one Global event instead of two), which is
    /// what exercises the kernel's `global_slot` placement against the host's layout.
    fn generate_record(size: usize) -> EmulationRecord {
        let mut rng = rng();
        let events: Vec<MemoryLocalEvent> = (0..size)
            .map(|i| {
                let addr = (i as u64 + 1) * 8 + 0x100;
                MemoryLocalEvent {
                    addr,
                    initial_mem_access: MemoryRecord {
                        chunk: 0,
                        timestamp: 0,
                        value: if i % 4 == 3 { 0 } else { rng.random() },
                    },
                    final_mem_access: MemoryRecord {
                        chunk: 0,
                        timestamp: (size as u32) + (i as u32),
                        value: rng.random(),
                    },
                }
            })
            .collect();

        let mut record = EmulationRecord::default();
        record.cpu_local_memory_access = events;
        record
    }

    fn cpu_generate_main(chip: &MemoryLocalChip<F>, input: &EmulationRecord) -> RowMajorMatrix<F> {
        chip.generate_main(input, &mut EmulationRecord::default())
    }

    fn gpu_generate_extra_record_and_main(
        chip: &MemoryLocalChip<F>,
        input: &EmulationRecord,
        event_counter: &EventCounter,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
        stream: &CudaStream,
    ) -> RowMajorMatrix<F> {
        let prepared_gpu_events = PreparedGpuEvents::new(input, event_counter.clone());

        let trace = chip.gpu_generate_extra_record_and_main(
            0,
            input,
            &prepared_gpu_events,
            preallocated_gpu_memory,
        );
        trace.to_host(stream)
    }

    #[test]
    fn test_memory_local_gpu_generate_extra_record_and_main() {
        let original_record = LazyLock::force(&GPU_TEST_RECORD).clone();

        assert!(
            !original_record.cpu_local_memory_access.is_empty(),
            "No memory local events generated"
        );

        let chip = MemoryLocalChip::<F>::default();

        let mut complete_record = original_record.clone();
        chip.extra_record(&original_record, &mut complete_record);

        let mut counted_record = original_record.clone();
        let mut event_counter = precompute_event_size::<F>(&mut counted_record);
        event_counter.num_poseidon2_events = complete_record.poseidon2_events.len();
        event_counter.assert_event_counts_match(&complete_record);

        let log_rows = 15;
        complete_record.shape = Some(RiscvPadShape::default());
        complete_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), log_rows);
        let cpu_trace = cpu_generate_main(&chip, &complete_record);

        // Generate CPU byte trace for comparison
        let byte_chip = ByteChip::<F>::default();
        let cpu_byte_trace =
            byte_chip.generate_main(&complete_record, &mut EmulationRecord::default());

        counted_record.shape = Some(RiscvPadShape::default());
        counted_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), log_rows);

        let stream = init_test_stream();
        let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter.clone());
        let mut preallocated_gpu_memory = PreallocatedGpuMemory {
            d_global_events: gpu_allocate_and_copy_global_events(
                &stream,
                0,
                &counted_record,
                &prepared_gpu_events,
            )
            .unwrap(),
            d_byte_trace: gpu_allocate_byte_trace(&stream, 0).unwrap(),
            ..Default::default()
        };
        let gpu_trace = gpu_generate_extra_record_and_main(
            &chip,
            &counted_record,
            &event_counter,
            &mut preallocated_gpu_memory,
            &stream,
        );

        let non_zero_main = cpu_trace.values.iter().filter(|&&v| v != F::ZERO).count();
        assert!(
            !cpu_trace.values.is_empty(),
            "CPU trace should not be empty"
        );
        assert!(non_zero_main > 0, "CPU trace should not be all zeros");

        assert_eq!(cpu_trace, gpu_trace, "CPU and GPU traces do not match");

        verify_global_events(
            &preallocated_gpu_memory.d_global_events,
            &complete_record,
            &stream,
            0,
            event_counter.num_global_lookup_events,
        );

        // Verify byte trace (GPU == CPU)
        gpu_finalize_byte_trace(&stream, &mut preallocated_gpu_memory).unwrap();
        stream.synchronize().unwrap();
        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.take().unwrap();
        let host_gpu_byte_trace =
            TraceData::<F>::Gpu(NUM_BYTE_MULT_COLS, d_byte_trace).to_host(&stream);
        assert_eq!(
            host_gpu_byte_trace.values, cpu_byte_trace.values,
            "CPU and GPU byte traces do not match"
        );

        let non_zero_byte = cpu_byte_trace
            .values
            .iter()
            .filter(|&&v| v != F::ZERO)
            .count();
        assert!(
            non_zero_byte > 0,
            "byte trace is all zeros — both CPU and GPU may be broken"
        );

        println!(
            "memory_local: main trace non-zero: {}/{}, byte trace non-zero: {}/{}",
            non_zero_main,
            cpu_trace.values.len(),
            non_zero_byte,
            cpu_byte_trace.values.len(),
        );
    }

    #[test]
    fn bench_memory_local_cpu_vs_gpu() {
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
            let chip = MemoryLocalChip::<F>::default();

            let mut complete_record = original_record.clone();
            chip.extra_record(&original_record, &mut complete_record);
            let mut counted_record = original_record.clone();
            let mut event_counter = precompute_event_size::<F>(&mut counted_record);
            event_counter.num_poseidon2_events = complete_record.poseidon2_events.len();

            let log2 = (n as f64).log2().ceil() as usize + 1;
            complete_record.shape = Some(RiscvPadShape::default());
            complete_record
                .shape
                .as_mut()
                .unwrap()
                .inner
                .insert(chip.name(), log2);
            counted_record.shape = Some(RiscvPadShape::default());
            counted_record
                .shape
                .as_mut()
                .unwrap()
                .inner
                .insert(chip.name(), log2);

            let cpu_start = Instant::now();
            let cpu_trace = cpu_generate_main(&chip, &complete_record);
            let cpu_ms = cpu_start.elapsed().as_secs_f64() * 1000.0;

            // GPU: alloc + H2D before timer (kernel-only timing, apple-to-apple with CPU)
            let stream = init_test_stream();
            let prepared_gpu_events =
                PreparedGpuEvents::new(&counted_record, event_counter.clone());
            let sync_mem_pool = get_global_mem_pool(0);
            let mem_pool = &sync_mem_pool.0;
            let mut preallocated_gpu_memory = PreallocatedGpuMemory {
                d_global_events: gpu_allocate_and_copy_global_events(
                    &stream,
                    0,
                    &counted_record,
                    &prepared_gpu_events,
                )
                .unwrap(),
                d_byte_trace: gpu_allocate_byte_trace(&stream, 0).unwrap(),
                ..Default::default()
            };
            stream.synchronize().unwrap();

            let events = &prepared_gpu_events.memory_local_events;
            let nb_rows = events.len().div_ceil(LOCAL_MEMORY_DATAPAR);
            let padded_nb_rows = next_power_of_two(nb_rows, Some(log2));
            let trace_size = padded_nb_rows * NUM_MEMORY_LOCAL_INIT_COLS;
            let event_size = events.len();
            let mut d_trace = DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(
                trace_size, mem_pool, &stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemsetAsync(
                    d_trace.as_mut_ptr() as *mut _,
                    0,
                    trace_size * size_of::<KoalaBear>(),
                    stream.into(),
                );
            }
            let mut d_events = DevicePoolAllocation::<FfiMemoryLocalEvent>::alloc_from_pool_async(
                event_size, mem_pool, &stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_ptr() as *mut std::ffi::c_void,
                    events.as_ptr() as *const std::ffi::c_void,
                    event_size * size_of::<FfiMemoryLocalEvent>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
            }
            stream.synchronize().unwrap();

            let gpu_start = Instant::now();
            let d_global_events = preallocated_gpu_memory.d_global_events.as_mut().unwrap();
            let start_index = prepared_gpu_events
                .event_counter
                .start_indices
                .memory_local_extra_global_start_index;
            let d_byte_trace_alloc = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();
            unsafe {
                cuda_memory_local_generate_extra_record_and_main_u64(
                    NUM_SINGLE_MEMORY_LOCAL_COLS,
                    event_size,
                    trace_size,
                    d_events.as_ptr() as *const _,
                    d_trace.as_mut_ptr() as *mut _,
                    stream.into(),
                    d_global_events.as_mut_ptr() as *mut _,
                    start_index,
                    d_byte_trace_alloc.as_mut_ptr() as *mut _,
                );
            }
            stream.synchronize().unwrap();
            let gpu_ms = gpu_start.elapsed().as_secs_f64() * 1000.0;

            if is_warmup {
                println!("{:<12} {:>12} {:>12} {:>12}", n, "warmup", "warmup", "—");
                continue;
            }

            let gpu_trace =
                TraceData::<F>::Gpu(NUM_MEMORY_LOCAL_INIT_COLS, d_trace).to_host(&stream);
            assert_eq!(
                cpu_trace.values, gpu_trace.values,
                "CPU/GPU main trace mismatch at n={}",
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

/// Tests for the three constraints a forged `MemoryLocal` entry would have to satisfy.
///
/// The chip labels the state a chunk inherits with a `clk` sentinel, and carries the real
/// `initial_clk` on every other interval. Those two shapes plus `initial_clk < final_clk` are
/// what a forged entry would have to satisfy — so each of them is
/// checked here against a tampered row.
///
/// `DebugConstraintFolder` is an `EmptyLookupBuilder`, so a failure reported here comes from the
/// algebraic constraints alone, never from a lookup that would have caught the tamper instead.
#[cfg(test)]
mod normalization_tests {
    use super::{
        columns::{MemoryLocalCols, NUM_MEMORY_LOCAL_INIT_COLS},
        MemoryLocalChip,
    };
    use crate::{
        chips::chips::events::{MemoryLocalEvent, MemoryRecord},
        emulator::riscv::record::EmulationRecord,
        machine::{chip::ChipBehavior, debug_folder::DebugConstraintFolder, septic::SepticDigest},
        primitives::consts::CHUNK_CLK_START,
    };
    use p3_air::{Air, RowWindow};
    use p3_field::{extension::BinomialExtensionField, PrimeCharacteristicRing, PrimeField32};
    use p3_koala_bear::KoalaBear;
    use p3_matrix::{dense::RowMajorMatrix, Matrix};
    use std::borrow::{Borrow, BorrowMut};

    type F = KoalaBear;
    type EF = BinomialExtensionField<KoalaBear, 4>;
    type Folder<'a> = DebugConstraintFolder<'a, F, EF>;

    /// One entry that starts in an earlier chunk (the sentinel shape) and one that starts in this
    /// chunk (the real-clk shape) — the two cases every constraint below has to separate.
    fn two_shape_trace() -> RowMajorMatrix<F> {
        let entry = |ic, iclk, fc, fclk| MemoryLocalEvent {
            addr: 0x2_0000,
            initial_mem_access: MemoryRecord {
                chunk: ic,
                timestamp: iclk,
                value: 0x1111_2222_3333_4444,
            },
            final_mem_access: MemoryRecord {
                chunk: fc,
                timestamp: fclk,
                value: 0x5555_6666_7777_8888,
            },
        };
        let mut record = EmulationRecord::default();
        record.cpu_local_memory_access = vec![
            entry(1, 9, 3, 40),               // starts earlier  -> sentinel
            entry(3, CHUNK_CLK_START, 3, 40), // starts here     -> real clk
        ];
        MemoryLocalChip::<F>::default().generate_main(&record, &mut EmulationRecord::default())
    }

    fn failures(row: &[F]) -> usize {
        let chip = MemoryLocalChip::<F>::default();
        let dummy_f = [F::ZERO];
        let mut folder = Folder {
            preprocessed: RowWindow::from_two_rows(&dummy_f, &dummy_f),
            main: RowWindow::from_two_rows(row, row),
            global_cumulative_sum: SepticDigest::<F>::zero(),
            is_first_row: F::ZERO,
            is_last_row: F::ZERO,
            is_transition: F::ONE,
            public_values: &[],
            failures: vec![],
            scopes: vec![],
            constraint_count: 0,
        };
        chip.eval(&mut folder);
        folder.failures.len()
    }

    fn honest_row() -> Vec<F> {
        let trace = two_shape_trace();
        assert_eq!(trace.width(), NUM_MEMORY_LOCAL_INIT_COLS);
        trace.values[..NUM_MEMORY_LOCAL_INIT_COLS].to_vec()
    }

    /// Both shapes coexist on an honest row, and the trace generator really does produce them:
    /// entry 0 gets the sentinel, entry 1 the real clk. Without this the tampers below could all
    /// be passing vacuously.
    #[test]
    fn both_shapes_hold_on_an_honest_row() {
        let row = honest_row();
        assert_eq!(failures(&row), 0, "honest row violates a constraint");

        let cols: &MemoryLocalCols<F> = row.as_slice().borrow();
        let earlier = &cols.memory_local_entries[0];
        let here = &cols.memory_local_entries[1];
        assert_eq!(earlier.initial_in_chunk, F::ZERO);
        assert_eq!(earlier.initial_clk_regional, F::ZERO, "sentinel expected");
        assert_eq!(here.initial_in_chunk, F::ONE);
        assert_eq!(
            here.initial_clk_regional,
            F::from_u32(CHUNK_CLK_START),
            "real initial_clk expected"
        );
    }

    /// Claiming the in-chunk shape for an interval that started earlier. This is the tamper that
    /// would let a forged entry carry a real clk while pointing its Global receive at another
    /// chunk — the combination that would let an entry claim an unearned start.
    #[test]
    fn mislabelling_an_earlier_start_as_in_chunk_is_rejected() {
        let mut row = honest_row();
        let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();
        cols.memory_local_entries[0].initial_in_chunk = F::ONE;
        assert!(failures(&row) > 0);
    }

    /// An entry that starts in this chunk has to put its real `initial_clk` on the bus, not the
    /// sentinel: sharing the sentinel is what would make two intervals on one address
    /// indistinguishable there.
    #[test]
    fn in_chunk_entry_may_not_use_the_sentinel() {
        let mut row = honest_row();
        let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();
        cols.memory_local_entries[1].initial_clk_regional = F::ZERO;
        assert!(failures(&row) > 0);
    }

    /// ...and conversely an entry that starts earlier may not put a real clk there.
    #[test]
    fn earlier_start_may_not_use_a_real_clk() {
        let mut row = honest_row();
        let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();
        cols.memory_local_entries[0].initial_clk_regional = F::from_u32(9);
        assert!(failures(&row) > 0);
    }

    /// `initial_clk < final_clk` on the in-chunk shape, in both directions: equal timestamps
    /// (the entry whose two Global messages coincide) and a reversed interval.
    #[test]
    fn non_increasing_clk_on_an_in_chunk_entry_is_rejected() {
        for tamper in [F::from_u32(40), F::from_u32(41)] {
            let mut row = honest_row();
            let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();
            cols.memory_local_entries[1].initial_clk = tamper;
            cols.memory_local_entries[1].initial_clk_regional = tamper;
            assert!(
                failures(&row) > 0,
                "accepted initial_clk={tamper:?} against final_clk=40"
            );
        }
    }

    /// The chunk must strictly advance on the sentinel shape, as an integer.
    ///
    /// This one rides on a byte-table lookup, not on an algebraic constraint, so the folder used
    /// above is structurally blind to it (`EmptyLookupBuilder` makes every lookup a no-op). What
    /// is checked here instead is the value that lookup would carry: a chunk that fails to
    /// advance underflows in the field and lands far outside a 16-bit table, so the byte-table
    /// multiset cannot balance.
    ///
    /// The same blindness applies to the range half of `initial_clk < final_clk`. The test above
    /// catches a tampered `initial_clk` through the decomposition equality
    /// (`diff == limb16 + hi9 * 2^16`), which *is* algebraic; a prover that also rewrites the
    /// limbs to match an underflowed diff is caught by their range checks, on the same argument
    /// as here.
    #[test]
    fn non_advancing_chunk_on_a_sentinel_entry_underflows_its_range_check() {
        let row = honest_row();
        let cols: &MemoryLocalCols<F> = row.as_slice().borrow();
        let entry = &cols.memory_local_entries[0];
        assert_eq!(
            entry.initial_in_chunk,
            F::ZERO,
            "entry 0 must be the sentinel shape for this test to mean anything"
        );

        // Honest: chunk 1 -> 3, so the lookup carries 1 and the table has it.
        let honest = entry.final_chunk - entry.initial_chunk - F::ONE;
        assert!(honest.as_canonical_u32() < (1 << 16));

        // Equal chunks: the lookup would carry -1, i.e. p-1.
        let stalled = entry.initial_chunk - entry.initial_chunk - F::ONE;
        assert!(stalled.as_canonical_u32() >= (1 << 16));

        // Going backwards is worse still, and lands outside for the same reason.
        let backwards = entry.initial_chunk - entry.final_chunk - F::ONE;
        assert!(backwards.as_canonical_u32() >= (1 << 16));
    }

    /// One fresh entry (zero initial state, outside the default record's empty image) next to
    /// an inherited one: the trace generator clears `has_initial` on the first only, and the
    /// row satisfies every constraint including G4.
    fn fresh_and_inherited_row() -> Vec<F> {
        let entry = |ic, iclk, iv| MemoryLocalEvent {
            addr: 0x2_0000,
            initial_mem_access: MemoryRecord {
                chunk: ic,
                timestamp: iclk,
                value: iv,
            },
            final_mem_access: MemoryRecord {
                chunk: 3,
                timestamp: 40,
                value: 0x5555_6666_7777_8888,
            },
        };
        let mut record = EmulationRecord::default();
        record.cpu_local_memory_access = vec![
            entry(0, 0, 0),                     // fresh: first touch, starts at zero
            entry(1, 9, 0x1111_2222_3333_4444), // inherited from chunk 1
        ];
        let trace =
            MemoryLocalChip::<F>::default().generate_main(&record, &mut EmulationRecord::default());
        trace.values[..NUM_MEMORY_LOCAL_INIT_COLS].to_vec()
    }

    #[test]
    fn fresh_entry_declares_and_inherited_entry_receives() {
        let row = fresh_and_inherited_row();
        assert_eq!(failures(&row), 0, "honest row violates a constraint");
        let cols: &MemoryLocalCols<F> = row.as_slice().borrow();
        assert_eq!(cols.memory_local_entries[0].has_initial, F::ZERO);
        assert_eq!(cols.memory_local_entries[1].has_initial, F::ONE);
    }

    /// G4: an entry that does not receive its initial state may only declare zero, limb by
    /// limb. Claiming an inherited (nonzero) initial value while declaring is what would let a
    /// prover invent a predecessor state.
    #[test]
    fn declaring_entry_may_not_carry_a_nonzero_initial_value() {
        for limb in 0..4 {
            let mut row = fresh_and_inherited_row();
            let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();
            cols.memory_local_entries[0].initial_value.0[limb] = F::ONE;
            assert!(failures(&row) > 0, "limb {limb}");
        }
        // The same entry with `has_initial = 1` is free to carry it (the Global receive binds
        // it then), so the tamper above is caught by G4 and not by something else.
        let mut row = fresh_and_inherited_row();
        let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();
        cols.memory_local_entries[0].has_initial = F::ONE;
        cols.memory_local_entries[0].initial_value.0[0] = F::ONE;
        assert_eq!(failures(&row), 0);
    }

    /// G1: the receive multiplicity is boolean.
    #[test]
    fn has_initial_must_be_boolean() {
        let mut row = fresh_and_inherited_row();
        let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();
        cols.memory_local_entries[1].has_initial = F::from_u32(2);
        assert!(failures(&row) > 0);
    }

    /// G2: a padding entry may not receive. Only `has_initial` is set, so the G4 gate
    /// (`is_real - has_initial = -1`) is nonzero on an all-zero initial value and would not
    /// fire by itself; the failure has to come from G2.
    #[test]
    fn padding_may_not_receive_an_initial_state() {
        let mut row = vec![F::ZERO; NUM_MEMORY_LOCAL_INIT_COLS];
        let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();
        cols.memory_local_entries[2].has_initial = F::ONE;
        assert!(failures(&row) > 0);
    }

    /// A padding entry may not claim the in-chunk shape: `initial_in_chunk` doubles as a
    /// degree-1 lookup multiplicity, so it has to be zero wherever `is_real` is.
    ///
    /// The clk columns are set so the gap decomposition it un-gates is *satisfied*
    /// (`final_clk - initial_clk - 1 == 0` with zero limbs). Without that the tamper also breaks
    /// the range check, and this test would keep passing with its own target constraint deleted
    /// -- which is what it did before, and what `failures()` returning a bare count cannot show.
    #[test]
    fn padding_may_not_claim_the_in_chunk_shape() {
        let mut row = vec![F::ZERO; NUM_MEMORY_LOCAL_INIT_COLS];
        assert_eq!(failures(&row), 0, "an all-zero padding row must be valid");
        let cols: &mut MemoryLocalCols<F> = row.as_mut_slice().borrow_mut();
        let slot = &mut cols.memory_local_entries[0];
        slot.initial_in_chunk = F::ONE;
        slot.final_clk = F::ONE;
        assert!(failures(&row) > 0);
    }
}
