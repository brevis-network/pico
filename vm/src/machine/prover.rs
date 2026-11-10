//! GPU trace generation for the RISC-V machine: `BaseProver::gpu_generate_extra_record_and_main`
//! runs every chip's device trace generator in a fixed, memory-aware order and hands the row-major
//! device traces to the MLE backend (`mle::machine::riscv`). The FRI key setup / commit / prove
//! code that used to surround it was removed with the FRI proving path (tag `legacy-fri-last`).

use crate::{
    chips::{chips::byte::columns::NUM_BYTE_MULT_COLS, trace::TraceData},
    configs::config::StarkGenericConfig,
    cuda_adaptor::get_global_stream_pool,
    emulator::{record::RecordBehavior, riscv::record::EmulationRecord},
    instances::preparer::{
        gpu_allocate_and_copy_global_events, gpu_allocate_and_copy_poseidon2_events,
        gpu_allocate_byte_trace, gpu_finalize_byte_trace, PreallocatedGpuMemory, PreparedGpuEvents,
    },
    machine::chip::{ChipBehavior, GpuChipBehavior, MetaChip},
    mle::spans::device,
};
use cudart::stream::{CudaStream, CudaStreamCreateFlags};
use dashmap::DashMap;
use std::{cmp::Reverse, ops::RangeInclusive, time::Instant};
use tracing::debug;

pub struct BaseProver<SC, C> {
    _phantom: std::marker::PhantomData<(SC, C)>,
}

impl<SC, C> Clone for BaseProver<SC, C> {
    fn clone(&self) -> Self {
        Self {
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<SC, C> Default for BaseProver<SC, C> {
    fn default() -> Self {
        Self {
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<SC, C> BaseProver<SC, C> {
    pub fn new() -> Self {
        Self {
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<SC: StarkGenericConfig, C: GpuChipBehavior<SC::Val, Record = EmulationRecord>>
    BaseProver<SC, C>
where
    SC: StarkGenericConfig + 'static,
{
    pub fn gpu_generate_extra_record_and_main<'a>(
        &self,
        device_id: usize,
        chips: &'a [MetaChip<SC::Val, C>],
        record: &C::Record,
        prepared_gpu_events: &PreparedGpuEvents,
    ) -> Vec<(String, TraceData<'a, SC::Val>)> {
        // Processing order: Batch 1, Divrem, Add, Sub, Addw, Subw, Lt, Mul, Batch 2, Global, Poseidon2, Batch 3, Precompiles, Ecall, Host-tracegen precompiles, MemoryUnaligned, Byte.
        // The RISC-V chips read the chunk's execution history, whose upload is enqueued before
        // Batch 1 and not waited for: each chip that reads it makes its own streams wait on the
        // copies it reads (`HistoryReader`), so the CPU chip's slice kernels start as their slices
        // land, and every other reader once the whole fill has.
        // Batch 1: CPU, Program, and MemoryReadWrite chips.
        const BATCH_1_CHIP_INDICES: RangeInclusive<usize> = 0..=2;

        // Divrem writes the ADD rows it derives, which the Add chip reads after its own.
        const DIVREM_CHIP_INDEX: usize = 3;

        const ADD_CHIP_INDEX: usize = 4;
        const SUB_CHIP_INDEX: usize = 5;
        const ADDW_CHIP_INDEX: usize = 6;
        const SUBW_CHIP_INDEX: usize = 7;

        const LT_CHIP_INDEX: usize = 8;

        const MUL_CHIP_INDEX: usize = 9;

        // Batch 2: MemoryInitialize, MemoryFinalize, MemoryLocal, SyscallRiscv, and SyscallPrecompile chips.
        // Global event memory is allocated before running Batch 2.
        const BATCH_2_CHIP_INDICES: RangeInclusive<usize> = 10..=14;

        // Global event and Poseidon2 event memories are allocated before running Global chip.
        const GLOBAL_CHIP_INDEX: usize = 15;
        // Global event memory is released after running Global chip.

        const POSEIDON2_CHIP_INDEX: usize = 16;
        // Poseidon2 event memory is released after running Poseidon2 chip.

        // Batch 3: ShiftRight, ShiftLeft, and Bitwise chips.
        const BATCH_3_CHIP_INDICES: RangeInclusive<usize> = 17..=19;

        // All the Precompile chips.
        // Positional in `gpu_generate_extra_record_and_main_chips`: 25 precompile chips incl. the
        // ShaCompress/ShaExtend/Keccak control siblings.
        const PRECOMPILE_CHIP_INDICES: RangeInclusive<usize> = 20..=44;

        const BYTE_CHIP_INDEX: usize = 45;

        // Ecall chip: appended after Byte in the gpu chip list so the indices above
        // stay valid. A device kernel over the history's ecall list, so it needs no device event
        // buffers.
        const ECALL_CHIP_INDEX: usize = 46;

        // Poseidon2 precompile, Ed25519 add and Ed25519 decompress: host tracegen, appended after
        // Ecall for the same reason. Each adds its own byte lookups to the device byte table, so
        // they have to run before it is finalized.
        const HOST_TRACEGEN_PRECOMPILE_INDICES: RangeInclusive<usize> = 47..=49;

        // MemoryUnaligned: host tracegen, appended after them; its byte lookups go to the
        // device table the same way, so it runs before the table is finalized too.
        const MEMORY_UNALIGNED_CHIP_INDEX: usize = 50;

        // The sliced Keccak tables, appended last: a device kernel, no byte lookups.
        const KECCAK_TABLES_CHIP_INDEX: usize = 51;

        let durations = DashMap::new();
        let mut chip_names_traces = Vec::new();
        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();
        device::orchestrator_stream(stream);

        device::set_chip(|| chips[BYTE_CHIP_INDEX].name());
        let kernels = device::start(stream);
        let d_byte_trace = gpu_allocate_byte_trace(stream, device_id).unwrap();
        device::launched_step(kernels, stream, "init");
        device::clear_chip();
        // The byte table's allocation and zeroing land before any chip writes it: the writers are
        // the chips' kernels, on streams of their wrappers' own that wait on no event of this
        // stream. Waited for before the history's upload is enqueued, so it holds none of its
        // copies.
        device::wait(stream).unwrap();

        let d_history = record
            .gpu_upload_history(stream, device_id, prepared_gpu_events)
            .unwrap_or_else(|e| {
                panic!(
                    "chunk {}: uploading the execution history: {e}",
                    prepared_gpu_events.chunk_index
                )
            });

        let mut preallocated_gpu_memory = PreallocatedGpuMemory {
            d_byte_trace,
            d_history,
            ..Default::default()
        };

        // Per-chip byte_trace diagnostic (gated by BYTE_TRACE_DEBUG=1)
        use cudart::slice::CudaSlice;
        let byte_debug = std::env::var("BYTE_TRACE_DEBUG").is_ok();
        let mut gpu_per_chip_deltas: Vec<(String, [u64; NUM_BYTE_MULT_COLS])> = Vec::new();
        let mut bt_prev = [0u64; NUM_BYTE_MULT_COLS];

        let bt_snapshot = |mem: &PreallocatedGpuMemory| -> [u64; NUM_BYTE_MULT_COLS] {
            let mut sums = [0u64; NUM_BYTE_MULT_COLS];
            if let Some(ref d_bt) = mem.d_byte_trace {
                let n = d_bt.len();
                let nr = n / NUM_BYTE_MULT_COLS;
                let mut host = vec![0u32; n];
                unsafe {
                    let _ = cudart_sys::cudaDeviceSynchronize();
                    let _ = cudart_sys::cudaMemcpyAsync(
                        host.as_mut_ptr() as *mut std::ffi::c_void,
                        d_bt.as_c_void_ptr(),
                        n * 4,
                        cudart_sys::CudaMemoryCopyKind::DeviceToHost,
                        stream.into(),
                    );
                }
                stream.synchronize().unwrap();
                for row in 0..nr {
                    for col in 0..NUM_BYTE_MULT_COLS {
                        sums[col] += host[row * NUM_BYTE_MULT_COLS + col] as u64;
                    }
                }
            }
            sums
        };

        macro_rules! snap_after {
            ($idx:expr) => {
                if byte_debug && chips[$idx].is_active_for_extra_record(prepared_gpu_events) {
                    let cur = bt_snapshot(&preallocated_gpu_memory);
                    let mut delta = [0u64; NUM_BYTE_MULT_COLS];
                    for i in 0..NUM_BYTE_MULT_COLS {
                        delta[i] = cur[i] - bt_prev[i];
                    }
                    gpu_per_chip_deltas.push((chips[$idx].name(), delta));
                    bt_prev = cur;
                }
            };
        }

        let mut run_chip = |idx: usize, mem: &mut PreallocatedGpuMemory| {
            let chip = &chips[idx];
            // A pad shape lists every chip the proof must carry, events or not: a chip it
            // names is generated (as pure padding when it has no events). Without a shape,
            // or for a chip the shape leaves out, the event count decides as before.
            let listed = prepared_gpu_events
                .shape
                .as_ref()
                .is_some_and(|shape| shape.inner.contains_key(&chip.name()));
            let active = chip.is_active_for_extra_record(prepared_gpu_events);
            if !(listed || active) {
                return;
            }
            let begin = Instant::now();
            device::set_chip(|| chip.name());
            // A listed chip with no events takes the kernel like any other: the launchers pad
            // a zero-event trace on the device (DivRem / ShiftLeft / ShiftRight write their
            // non-zero padding row, the rest are zero-filled) and the wrappers tolerate an
            // absent event buffer.
            let trace = chip.gpu_generate_extra_record_and_main(
                device_id,
                record,
                prepared_gpu_events,
                mem,
            );
            device::clear_chip();
            durations.insert(chip.name(), begin.elapsed());
            chip_names_traces.push((chip.name(), trace));
        };

        // Batch 1
        for chip_index in BATCH_1_CHIP_INDICES {
            run_chip(chip_index, &mut preallocated_gpu_memory);
            snap_after!(chip_index);
        }
        // Divrem chip
        run_chip(DIVREM_CHIP_INDEX, &mut preallocated_gpu_memory);

        // Add, Sub, Addw, Subw chips
        run_chip(ADD_CHIP_INDEX, &mut preallocated_gpu_memory);
        snap_after!(ADD_CHIP_INDEX);
        run_chip(SUB_CHIP_INDEX, &mut preallocated_gpu_memory);
        snap_after!(SUB_CHIP_INDEX);
        run_chip(ADDW_CHIP_INDEX, &mut preallocated_gpu_memory);
        snap_after!(ADDW_CHIP_INDEX);
        run_chip(SUBW_CHIP_INDEX, &mut preallocated_gpu_memory);

        // Lt chip
        run_chip(LT_CHIP_INDEX, &mut preallocated_gpu_memory);
        snap_after!(LT_CHIP_INDEX);

        // Mul chip
        run_chip(MUL_CHIP_INDEX, &mut preallocated_gpu_memory);
        snap_after!(MUL_CHIP_INDEX);

        preallocated_gpu_memory.d_global_events =
            gpu_allocate_and_copy_global_events(stream, device_id, record, prepared_gpu_events)
                .unwrap();
        device::wait(stream).unwrap();

        // Batch 2
        for chip_index in BATCH_2_CHIP_INDICES {
            run_chip(chip_index, &mut preallocated_gpu_memory);
            snap_after!(chip_index);
        }

        preallocated_gpu_memory.d_poseidon2_events = gpu_allocate_and_copy_poseidon2_events(
            stream,
            device_id,
            &record.poseidon2_events,
            prepared_gpu_events,
        )
        .unwrap();
        device::wait(stream).unwrap();

        // Global chip
        run_chip(GLOBAL_CHIP_INDEX, &mut preallocated_gpu_memory);
        snap_after!(GLOBAL_CHIP_INDEX);
        preallocated_gpu_memory.d_global_events = None;

        // Poseidon2 chip
        run_chip(POSEIDON2_CHIP_INDEX, &mut preallocated_gpu_memory);
        snap_after!(POSEIDON2_CHIP_INDEX);
        preallocated_gpu_memory.d_poseidon2_events = None;

        // Batch 3
        for chip_index in BATCH_3_CHIP_INDICES {
            run_chip(chip_index, &mut preallocated_gpu_memory);
            snap_after!(chip_index);
        }

        // Precompile chips
        for chip_index in PRECOMPILE_CHIP_INDICES {
            run_chip(chip_index, &mut preallocated_gpu_memory);
            snap_after!(chip_index);
        }

        // Ecall chip: its kernel reads the history's ecall list and adds the chip's byte lookups
        // itself, so the snapshot after it carries them.
        run_chip(ECALL_CHIP_INDEX, &mut preallocated_gpu_memory);
        snap_after!(ECALL_CHIP_INDEX);

        // Host-tracegen precompile chips. Their byte-table update is a read-modify-write through
        // the host (`gpu_add_host_byte_lookups`), which is sound only because the chips run one
        // at a time and each one synchronizes its streams before returning -- keep it that way.
        for chip_index in HOST_TRACEGEN_PRECOMPILE_INDICES
            .chain([MEMORY_UNALIGNED_CHIP_INDEX, KECCAK_TABLES_CHIP_INDEX])
        {
            run_chip(chip_index, &mut preallocated_gpu_memory);
            snap_after!(chip_index);
        }

        // Byte chip
        let byte_timer = Instant::now();
        device::set_chip(|| chips[BYTE_CHIP_INDEX].name());
        let kernels = device::start(stream);
        gpu_finalize_byte_trace(stream, &mut preallocated_gpu_memory).unwrap();
        device::launched_step(kernels, stream, "finalize");
        device::clear_chip();
        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        device::wait(stream).unwrap();

        // === BYTE_TRACE_DEBUG: compare GPU vs CPU byte_trace per-opcode multiplicities ===
        // Enable with: BYTE_TRACE_DEBUG=1
        if std::env::var("BYTE_TRACE_DEBUG").is_ok() {
            use crate::chips::chips::byte::traces::{byte_lookup_row, NUM_ROWS as BYTE_NUM_ROWS};
            use p3_field::PrimeField32;
            use p3_koala_bear::KoalaBear;

            if let Some(ref d_bt) = preallocated_gpu_memory.d_byte_trace {
                let num_elements = d_bt.len();
                let num_rows = num_elements / NUM_BYTE_MULT_COLS;

                // D2H copy of the finalized GPU byte_trace
                use cudart::slice::CudaSlice;
                use cudart_sys::{cudaMemcpyAsync, CudaMemoryCopyKind};
                let mut gpu_host: Vec<KoalaBear> = vec![KoalaBear::default(); num_elements];
                unsafe {
                    let _ = cudaMemcpyAsync(
                        gpu_host.as_mut_ptr() as *mut std::ffi::c_void,
                        d_bt.as_c_void_ptr(),
                        num_elements * std::mem::size_of::<KoalaBear>(),
                        CudaMemoryCopyKind::DeviceToHost,
                        stream.into(),
                    );
                }
                stream.synchronize().unwrap();

                // Run complement_record on CPU to get the expected byte_lookups.
                // Must clone record and mutate it between chips (like complement_record_static)
                // because later chips (e.g. Global) read events produced by earlier chips.
                // SAFETY: C::Record = EmulationRecord in the RISCV pipeline.
                type EmuRecord = crate::emulator::riscv::record::EmulationRecord;
                let emu_ref: &EmuRecord =
                    unsafe { &*(record as *const C::Record as *const EmuRecord) };
                let mut cpu_record_emu = emu_ref.clone();
                let mut cpu_per_chip: Vec<(String, [u64; NUM_BYTE_MULT_COLS])> = Vec::new();
                for chip in chips.iter() {
                    let cpu_ref: &C::Record =
                        unsafe { &*(&cpu_record_emu as *const EmuRecord as *const C::Record) };
                    if chip.is_active(cpu_ref) {
                        let mut extra: C::Record = Default::default();
                        chip.extra_record(cpu_ref, &mut extra);
                        let extra_emu: &mut EmuRecord =
                            unsafe { &mut *(&mut extra as *mut C::Record as *mut EmuRecord) };
                        let mut opcode_counts = [0u64; NUM_BYTE_MULT_COLS];
                        for (event, mult) in extra_emu.byte_lookups.iter() {
                            let col = event.opcode as usize;
                            if col < NUM_BYTE_MULT_COLS {
                                opcode_counts[col] += *mult as u64;
                            }
                        }
                        if opcode_counts.iter().any(|&c| c > 0) {
                            cpu_per_chip.push((chip.name(), opcode_counts));
                        }
                        cpu_record_emu.append(extra_emu);
                        std::mem::forget(extra);
                    }
                }
                let emu_record = &cpu_record_emu;

                // Build a CPU byte_trace (same layout as GPU) from byte_lookups
                let mut cpu_trace = vec![0u32; BYTE_NUM_ROWS * NUM_BYTE_MULT_COLS];
                for (event, mult) in emu_record.byte_lookups.iter() {
                    let row_index = byte_lookup_row(event);
                    if row_index < BYTE_NUM_ROWS {
                        cpu_trace[row_index * NUM_BYTE_MULT_COLS + event.opcode as usize] +=
                            *mult as u32;
                    }
                }

                let opcode_names = [
                    "AND", "OR", "XOR", "SLL", "ShrCarry", "LTU", "MSB", "U8Range", "U16Range",
                    "BitRange",
                ];

                eprintln!(
                    "\n=== BYTE_TRACE_DEBUG (chunk {}) ===",
                    prepared_gpu_events.chunk_index
                );

                // Per-opcode column sums
                let mut gpu_sums = [0u64; NUM_BYTE_MULT_COLS];
                let mut cpu_sums = [0u64; NUM_BYTE_MULT_COLS];
                for row in 0..num_rows.min(BYTE_NUM_ROWS) {
                    for col in 0..NUM_BYTE_MULT_COLS {
                        gpu_sums[col] +=
                            gpu_host[row * NUM_BYTE_MULT_COLS + col].as_canonical_u32() as u64;
                        cpu_sums[col] += cpu_trace[row * NUM_BYTE_MULT_COLS + col] as u64;
                    }
                }

                eprintln!("--- Per-opcode comparison (CPU looking vs GPU looked) ---");
                let mut has_mismatch = false;
                for col in 0..NUM_BYTE_MULT_COLS {
                    let name = if col < opcode_names.len() {
                        opcode_names[col]
                    } else {
                        "?"
                    };
                    let diff = cpu_sums[col] as i64 - gpu_sums[col] as i64;
                    let marker = if diff != 0 { " *** MISMATCH ***" } else { "" };
                    if diff != 0 {
                        has_mismatch = true;
                    }
                    eprintln!(
                        "  [{col}] {name:>10}: cpu={:>10} gpu={:>10} diff={:>+10}{marker}",
                        cpu_sums[col], gpu_sums[col], diff
                    );
                }

                if has_mismatch {
                    eprintln!("\nColumn sum MISMATCH detected.");
                } else {
                    eprintln!("\nAll opcode column sums match between CPU and GPU.");
                }

                // Always check per-row mismatches (detects value-level differences
                // even when column totals happen to agree).
                {
                    let mut total_row_mismatches = 0usize;
                    eprintln!(
                        "\n--- Per-row byte trace comparison (first 30 mismatches per opcode) ---"
                    );
                    for col in 0..NUM_BYTE_MULT_COLS {
                        let name = if col < opcode_names.len() {
                            opcode_names[col]
                        } else {
                            "?"
                        };
                        let mut count = 0usize;
                        let mut col_mismatches = 0usize;
                        for row in 0..num_rows.min(BYTE_NUM_ROWS) {
                            let gpu_val =
                                gpu_host[row * NUM_BYTE_MULT_COLS + col].as_canonical_u32();
                            let cpu_val = cpu_trace[row * NUM_BYTE_MULT_COLS + col];
                            if gpu_val != cpu_val {
                                col_mismatches += 1;
                                if count < 30 {
                                    if count == 0 {
                                        eprintln!("  opcode [{col}] {name}:");
                                    }
                                    let b = row >> 8;
                                    let c = row & 0xFF;
                                    eprintln!(
                                        "    row={row:>6} (b={b:#06x}, c={c:#04x}): cpu={cpu_val} gpu={gpu_val} diff={:+}",
                                        cpu_val as i64 - gpu_val as i64
                                    );
                                    count += 1;
                                }
                            }
                        }
                        if col_mismatches > 30 {
                            eprintln!("    ... ({} more)", col_mismatches - 30);
                        }
                        total_row_mismatches += col_mismatches;
                    }
                    if total_row_mismatches == 0 {
                        eprintln!("  (all rows match — byte trace is fully consistent)");
                    } else {
                        eprintln!("  TOTAL row-level mismatches: {total_row_mismatches}");
                    }
                }

                // Per-chip CPU byte_lookup contributions
                eprintln!("\n--- Per-chip CPU byte lookup contributions (extra_record) ---");
                for (name, counts) in &cpu_per_chip {
                    let details: Vec<String> = counts
                        .iter()
                        .enumerate()
                        .filter(|(_, &c)| c > 0)
                        .map(|(i, &c)| {
                            let oname = if i < opcode_names.len() {
                                opcode_names[i]
                            } else {
                                "?"
                            };
                            format!("{}={}", oname, c)
                        })
                        .collect();
                    if !details.is_empty() {
                        eprintln!("  {:>20}: {}", name, details.join(", "));
                    }
                }

                // Per-chip GPU byte_trace contributions (from snapshots)
                eprintln!("\n--- Per-chip GPU byte_trace contributions (snapshots) ---");
                for (name, delta) in &gpu_per_chip_deltas {
                    let details: Vec<String> = delta
                        .iter()
                        .enumerate()
                        .filter(|(_, &d)| d > 0)
                        .map(|(i, &d)| {
                            let oname = if i < opcode_names.len() {
                                opcode_names[i]
                            } else {
                                "?"
                            };
                            format!("{}={}", oname, d)
                        })
                        .collect();
                    if !details.is_empty() {
                        eprintln!("  {:>20}: {}", name, details.join(", "));
                    }
                }

                // Per-chip comparison: find mismatched chips
                eprintln!("\n--- Per-chip MISMATCH (CPU - GPU) ---");
                let mut any_chip_mismatch = false;
                let all_chip_names: std::collections::HashSet<String> = cpu_per_chip
                    .iter()
                    .map(|(n, _)| n.clone())
                    .chain(gpu_per_chip_deltas.iter().map(|(n, _)| n.clone()))
                    .collect();
                for chip_name in &all_chip_names {
                    let cpu_counts = cpu_per_chip
                        .iter()
                        .find(|(n, _)| n == chip_name)
                        .map(|(_, c)| *c)
                        .unwrap_or([0u64; NUM_BYTE_MULT_COLS]);
                    let gpu_counts = gpu_per_chip_deltas
                        .iter()
                        .find(|(n, _)| n == chip_name)
                        .map(|(_, d)| *d)
                        .unwrap_or([0u64; NUM_BYTE_MULT_COLS]);
                    let diffs: Vec<String> = (0..NUM_BYTE_MULT_COLS)
                        .filter(|&i| cpu_counts[i] != gpu_counts[i])
                        .map(|i| {
                            let oname = if i < opcode_names.len() {
                                opcode_names[i]
                            } else {
                                "?"
                            };
                            format!(
                                "{}: cpu={} gpu={} diff={:+}",
                                oname,
                                cpu_counts[i],
                                gpu_counts[i],
                                cpu_counts[i] as i64 - gpu_counts[i] as i64
                            )
                        })
                        .collect();
                    if !diffs.is_empty() {
                        any_chip_mismatch = true;
                        eprintln!("  {:>20}: {}", chip_name, diffs.join(", "));
                    }
                }
                if !any_chip_mismatch {
                    eprintln!("  (no per-chip mismatches)");
                }

                eprintln!("=== END BYTE_TRACE_DEBUG ===\n");
            }
        }

        let d_byte_trace = preallocated_gpu_memory
            .d_byte_trace
            .take()
            .unwrap()
            .swap_stream(main_stream);
        device::wait(stream).unwrap();
        // Read once every reader's kernels have run: a set bit means some kernel read rows that
        // are not this chunk's history, and its trace cannot be trusted.
        if let Some(history) = preallocated_gpu_memory.d_history.take() {
            history.finish().unwrap_or_else(|e| {
                panic!(
                    "chunk {}: the execution history's readers: {e}",
                    prepared_gpu_events.chunk_index
                )
            });
        }
        chip_names_traces.push((
            chips[BYTE_CHIP_INDEX].name(),
            TraceData::<SC::Val>::Gpu(NUM_BYTE_MULT_COLS, d_byte_trace),
        ));
        durations.insert(chips[BYTE_CHIP_INDEX].name(), byte_timer.elapsed());

        chip_names_traces.sort_by_key(|(name, trace)| (Reverse(trace.height()), name.clone()));

        for cp in &chip_names_traces {
            debug!(
                "chunk {:<2} chip {:<17} | width {:<4} rows {:<8} cells {:<11} | in {:?}",
                prepared_gpu_events.chunk_index,
                cp.0,
                cp.1.width(),
                cp.1.height(),
                cp.1.len(),
                durations.get(&cp.0).unwrap().value()
            )
        }

        chip_names_traces
    }
}
