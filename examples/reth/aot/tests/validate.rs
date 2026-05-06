//! Validation test comparing AOT emulator against baseline interpreter.
//! Compares snapshots and memory images for every chunk to ensure identical outputs.

use pico_vm::{
    chips::chips::riscv_memory::event::MemoryRecord,
    compiler::riscv::compiler::{Compiler, SourceType},
    emulator::{
        opts::EmulatorOpts,
        riscv::{emulator::RiscvEmulator, state::RiscvEmulationState},
    },
    instances::configs::riscv_kb_config::StarkConfig as RiscvKBSC,
    machine::report::EmulationReport,
    primitives::consts::{DIGEST_SIZE, PV_DIGEST_NUM_WORDS},
};
use std::env;
use reth_aot::{AotRun, RethEmulator, recycle_snapshot_memory};
use reth_lib::{create_stdin, load_block_input, load_reth_elf};

fn maybe_debug_single_step(
    chunk_idx: usize,
    baseline_emu: &mut RiscvEmulator,
    aot_emu: &mut RethEmulator,
) {
    let target_chunk = env::var("PICO_DEBUG_RETH_CHUNK")
        .ok()
        .and_then(|value| value.parse::<usize>().ok());
    if target_chunk != Some(chunk_idx) {
        return;
    }

    let max_steps = env::var("PICO_DEBUG_RETH_STEPS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(50_000);
    let target_chunk_after = baseline_emu.state.current_chunk + 2;

    println!(
        "debug dispatch start: chunk={chunk_idx} baseline_pc=0x{:016x} aot_pc=0x{:016x}",
        baseline_emu.state.pc, aot_emu.pc
    );

    for step_idx in 0..max_steps {
        let aot_start_pc = aot_emu.pc;
        let aot_start_cycle = aot_emu.insn_count;
        if aot_emu.pc == 0 {
            panic!("debug reached halt before divergence");
        }
        if let Some(func) = aot_emu.lookup_block(aot_emu.pc) {
            let _ = func(aot_emu).expect("aot direct block debug step failed");
        } else {
            let _ = aot_emu
                .interpret_from_current_pc()
                .expect("aot fallback debug step failed");
        }
        let aot_delta = aot_emu.insn_count - aot_start_cycle;
        let mut baseline_done = false;
        for _ in 0..aot_delta {
            baseline_done = baseline_emu
                .debug_step_simple()
                .expect("baseline debug step failed");
        }

        if baseline_emu.state.pc != aot_emu.pc
            || baseline_emu.state.global_clk != aot_emu.insn_count
            || baseline_emu.state.current_chunk != aot_emu.current_chunk
            || baseline_emu.state.clk != u64::from(aot_emu.clk)
            || baseline_emu.chunk_split_state.num_memory_read_write_events
                != aot_emu.chunk_split_state.num_memory_read_write_events
            || baseline_emu.chunk_split_state.num_global_lookup_base
                != aot_emu.chunk_split_state.num_global_lookup_base
            || baseline_emu.chunk_split_state.num_syscall_memory_events
                != aot_emu.chunk_split_state.num_syscall_memory_events
        {
            panic!(
                "debug divergence after dispatch {step_idx}: aot_start_pc=0x{:016x} aot_delta={} baseline pc=0x{:016x} global_clk={} chunk={} clk={} mem_rw={} global={} syscall_mem={} | aot pc=0x{:016x} global_clk={} chunk={} clk={} mem_rw={} global={} syscall_mem={}",
                aot_start_pc,
                aot_delta,
                baseline_emu.state.pc,
                baseline_emu.state.global_clk,
                baseline_emu.state.current_chunk,
                baseline_emu.state.clk,
                baseline_emu.chunk_split_state.num_memory_read_write_events,
                baseline_emu.chunk_split_state.num_global_lookup_base,
                baseline_emu.chunk_split_state.num_syscall_memory_events,
                aot_emu.pc,
                aot_emu.insn_count,
                aot_emu.current_chunk,
                aot_emu.clk,
                aot_emu.chunk_split_state.num_memory_read_write_events,
                aot_emu.chunk_split_state.num_global_lookup_base,
                aot_emu.chunk_split_state.num_syscall_memory_events,
            );
        }

        if step_idx % 1_000 == 0 {
            println!(
                "debug dispatch progress: iter={} pc=0x{:016x} global_clk={} chunk={} clk={}",
                step_idx,
                baseline_emu.state.pc,
                baseline_emu.state.global_clk,
                baseline_emu.state.current_chunk,
                baseline_emu.state.clk,
            );
        }

        if baseline_emu.state.current_chunk >= target_chunk_after
            && aot_emu.current_chunk >= target_chunk_after
        {
            panic!(
                "debug reached target batch boundary without divergence: pc=0x{:016x} global_clk={} chunk={} clk={}",
                baseline_emu.state.pc,
                baseline_emu.state.global_clk,
                baseline_emu.state.current_chunk,
                baseline_emu.state.clk,
            );
        }

        if baseline_done {
            panic!("debug baseline reached halt before divergence");
        }
    }

    panic!(
        "debug dispatch completed {max_steps} iterations without divergence: pc=0x{:016x} global_clk={} chunk={} clk={}",
        baseline_emu.state.pc,
        baseline_emu.state.global_clk,
        baseline_emu.state.current_chunk,
        baseline_emu.state.clk,
    );
}

fn debug_target_chunk() -> Option<usize> {
    env::var("PICO_DEBUG_RETH_CHUNK")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
}

fn compare_snapshots(
    chunk_idx: usize,
    baseline: &RiscvEmulationState,
    aot: &RiscvEmulationState,
    compare_accessed_memory: bool,
) {
    assert_eq!(
        baseline.global_clk, aot.global_clk,
        "Chunk {}: global_clk mismatch",
        chunk_idx
    );
    assert_eq!(
        baseline.current_batch, aot.current_batch,
        "Chunk {}: current_batch mismatch",
        chunk_idx
    );
    assert_eq!(
        baseline.current_chunk, aot.current_chunk,
        "Chunk {}: current_chunk mismatch",
        chunk_idx
    );
    assert_eq!(baseline.clk, aot.clk, "Chunk {}: clk mismatch", chunk_idx);
    assert_eq!(baseline.pc, aot.pc, "Chunk {}: pc mismatch", chunk_idx);
    assert_eq!(
        baseline.input_stream, aot.input_stream,
        "Chunk {}: input_stream mismatch",
        chunk_idx
    );
    assert_eq!(
        baseline.input_stream_ptr, aot.input_stream_ptr,
        "Chunk {}: input_stream_ptr mismatch",
        chunk_idx
    );
    assert_eq!(
        baseline.public_values_stream, aot.public_values_stream,
        "Chunk {}: public_values_stream mismatch",
        chunk_idx
    );

    if compare_accessed_memory {
        compare_memory(chunk_idx, baseline, aot);
    }
    compare_uninitialized_memory(chunk_idx, baseline, aot);
}

fn compare_memory(chunk_idx: usize, baseline: &RiscvEmulationState, aot: &RiscvEmulationState) {
    for i in 0..32 {
        let baseline_reg = baseline.registers[i];
        let aot_reg = aot.registers[i];

        if baseline_reg == Default::default() && aot_reg == Default::default() {
            continue;
        }

        assert_eq!(
            baseline_reg.value, aot_reg.value,
            "Chunk {}: register x{} value mismatch",
            chunk_idx, i
        );
        assert_eq!(
            baseline_reg.chunk, aot_reg.chunk,
            "Chunk {}: register x{} chunk mismatch",
            chunk_idx, i
        );
        assert_eq!(
            baseline_reg.timestamp, aot_reg.timestamp,
            "Chunk {}: register x{} timestamp mismatch",
            chunk_idx, i
        );
    }

    for (addr, value, chunk, timestamp) in baseline.memory.iter_accessed_entries() {
        if addr < 32 {
            continue;
        }
        let baseline_rec = MemoryRecord {
            value,
            chunk,
            timestamp,
        };
        let aot_rec = aot.memory.get(addr);
        assert_eq!(
            baseline_rec.value, aot_rec.value,
            "Chunk {}: memory value mismatch at {:#x}",
            chunk_idx, addr
        );
        assert_eq!(
            baseline_rec.chunk, aot_rec.chunk,
            "Chunk {}: memory chunk mismatch at {:#x}",
            chunk_idx, addr
        );
        assert_eq!(
            baseline_rec.timestamp, aot_rec.timestamp,
            "Chunk {}: memory timestamp mismatch at {:#x}",
            chunk_idx, addr
        );
    }

    for (addr, value, chunk, timestamp) in aot.memory.iter_accessed_entries() {
        if addr < 32 {
            continue;
        }
        let aot_rec = MemoryRecord {
            value,
            chunk,
            timestamp,
        };
        let baseline_rec = baseline.memory.get(addr);
        assert_eq!(
            baseline_rec.value, aot_rec.value,
            "Chunk {}: extra memory in AOT at {:#x} (value)",
            chunk_idx, addr
        );
        assert_eq!(
            baseline_rec.chunk, aot_rec.chunk,
            "Chunk {}: extra memory in AOT at {:#x} (chunk)",
            chunk_idx, addr
        );
        assert_eq!(
            baseline_rec.timestamp, aot_rec.timestamp,
            "Chunk {}: extra memory in AOT at {:#x} (timestamp)",
            chunk_idx, addr
        );
    }
}

fn compare_uninitialized_memory(
    chunk_idx: usize,
    baseline: &RiscvEmulationState,
    aot: &RiscvEmulationState,
) {
    for i in 0..32 {
        let baseline_reg = baseline.uninitialized_memory.registers.get(i as u32);
        let aot_reg = aot.uninitialized_memory.registers.get(i as u32);
        assert_eq!(
            baseline_reg, aot_reg,
            "Chunk {}: uninitialized_memory register x{} mismatch",
            chunk_idx, i
        );
    }

    for addr in baseline.uninitialized_memory.page_table.keys() {
        let baseline_val = baseline.uninitialized_memory.page_table.get(addr).copied();
        let aot_val = aot.uninitialized_memory.page_table.get(addr).copied();
        assert_eq!(
            baseline_val, aot_val,
            "Chunk {}: uninitialized_memory mismatch at {:#x}",
            chunk_idx, addr
        );
    }

    for addr in aot.uninitialized_memory.page_table.keys() {
        let baseline_val = baseline.uninitialized_memory.page_table.get(addr).copied();
        let aot_val = aot.uninitialized_memory.page_table.get(addr).copied();
        assert_eq!(
            baseline_val, aot_val,
            "Chunk {}: uninitialized_memory extra entry at {:#x}",
            chunk_idx, addr
        );
    }
}

fn compare_reports(chunk_idx: usize, baseline: &EmulationReport, aot: &EmulationReport) {
    assert_eq!(
        baseline.current_cycle, aot.current_cycle,
        "Chunk {}: current_cycle mismatch",
        chunk_idx
    );
    assert_eq!(
        baseline.start_chunk, aot.start_chunk,
        "Chunk {}: start_chunk mismatch",
        chunk_idx
    );
    assert_eq!(
        baseline.done, aot.done,
        "Chunk {}: done flag mismatch",
        chunk_idx
    );
}

/// Runs baseline interpreter and AOT emulator together, comparing each chunk on the fly.
///
/// Bypasses `RiscvProver` / `ProvingWitness` to avoid chip `eval()` calls during
/// `MetaChip::new()` — some chips have pending u64 upgrade stubs that would panic.
fn run_and_compare_chunks(
    elf_bytes: &[u8],
    block_input: &[u8],
) -> ([u32; PV_DIGEST_NUM_WORDS], [u32; DIGEST_SIZE]) {
    use p3_koala_bear::KoalaBear;

    let opts = EmulatorOpts::test_opts();

    let program =
        Compiler::new(SourceType::RISCV, elf_bytes)
            .expect("failed to parse RISC-V ELF")
            .compile();

    // Set up baseline emulator directly.
    let stdin = create_stdin::<RiscvKBSC>(block_input).expect("Failed to create stdin");
    let mut baseline_emu =
        RiscvEmulator::new_single::<KoalaBear>(program.clone(), opts, None);
    baseline_emu.write_stdin(&stdin);

    // Set up AOT emulator.
    let stdin = create_stdin::<RiscvKBSC>(block_input).expect("Failed to create stdin");
    let input_stream = stdin.inputs.to_vec();
    let mut aot_emu = RethEmulator::new(program, input_stream);

    let mut chunk_idx = 0usize;
    loop {
        if debug_target_chunk() == Some(chunk_idx) {
            maybe_debug_single_step(chunk_idx, &mut baseline_emu, &mut aot_emu);
        }
        let (baseline_snapshot, baseline_report) = baseline_emu
            .emulate_state(true, &mut |_rec| {})
            .expect("baseline emulate_state failed");
        // NOTE: caller must recycle returned snapshot memory.
        let (aot_snapshot, aot_report) = aot_emu
            .next_state_batch(opts)
            .expect("AOT next_state_batch failed");
        if let Some(target_chunk) = debug_target_chunk() {
            if chunk_idx < target_chunk {
                recycle_snapshot_memory(baseline_snapshot);
                recycle_snapshot_memory(aot_snapshot);
                if baseline_report.done {
                    break;
                }
                chunk_idx += 1;
                continue;
            }
        }
        compare_snapshots(chunk_idx, &baseline_snapshot, &aot_snapshot, true);
        if baseline_report.current_cycle != aot_report.current_cycle {
            println!(
                "report mismatch chunk {chunk_idx}: baseline current_cycle={} aot current_cycle={}",
                baseline_report.current_cycle, aot_report.current_cycle
            );
            println!(
                "prestate: baseline pc=0x{:016x} chunk={} clk={} global_clk={} | aot pc=0x{:016x} chunk={} clk={} global_clk={}",
                baseline_snapshot.pc,
                baseline_snapshot.current_chunk,
                baseline_snapshot.clk,
                baseline_snapshot.global_clk,
                aot_snapshot.pc,
                aot_snapshot.current_chunk,
                aot_snapshot.clk,
                aot_snapshot.global_clk,
            );
            println!(
                "poststate: baseline pc=0x{:016x} chunk={} clk={} mem_rw={} global={} syscall_mem={} | aot pc=0x{:016x} chunk={} clk={} mem_rw={} global={} syscall_mem={}",
                baseline_emu.state.pc,
                baseline_emu.state.current_chunk,
                baseline_emu.state.clk,
                baseline_emu.chunk_split_state.num_memory_read_write_events,
                baseline_emu.chunk_split_state.num_global_lookup_base,
                baseline_emu.chunk_split_state.num_syscall_memory_events,
                aot_emu.pc,
                aot_emu.current_chunk,
                aot_emu.clk,
                aot_emu.chunk_split_state.num_memory_read_write_events,
                aot_emu.chunk_split_state.num_global_lookup_base,
                aot_emu.chunk_split_state.num_syscall_memory_events,
            );
        }
        compare_reports(chunk_idx, &baseline_report, &aot_report);
        let done = baseline_report.done;
        recycle_snapshot_memory(baseline_snapshot);
        recycle_snapshot_memory(aot_snapshot);

        if done {
            break;
        }
        chunk_idx += 1;
    }

    let committed_digest = baseline_emu
        .record
        .public_values
        .committed_value_digest;
    let deferred_digest = baseline_emu
        .record
        .public_values
        .deferred_proofs_digest;

    assert_eq!(
        committed_digest, aot_emu.committed_value_digest,
        "Final committed_value_digest mismatch"
    );
    assert_eq!(
        deferred_digest, aot_emu.deferred_proofs_digest,
        "Final deferred_proofs_digest mismatch"
    );

    (committed_digest, deferred_digest)
}

fn run_block(block_number: u32) {
    let elf_bytes = load_reth_elf().expect("Failed to load reth ELF");
    let block_input = load_block_input(block_number).expect("Failed to load block input");

    println!("\n=== AOT Reth Correctness Validation ===");
    println!("Block number: {}", block_number);

    run_and_compare_chunks(&elf_bytes, &block_input);
    println!("✓ All chunks validated successfully");
    println!("✓ Snapshots, memory records, and digests match exactly");
}

#[test]
#[ignore = "reth execution parity is expensive; run explicitly during Phase 5 validation"]
fn test_correctness_reth_17106222() {
    run_block(17106222);
}

#[test]
#[ignore = "reth execution parity is expensive; run explicitly during Phase 5 validation"]
fn test_correctness_reth_18884864() {
    run_block(18884864);
}

#[test]
#[ignore = "reth execution parity is expensive; run explicitly during Phase 5 validation"]
fn test_correctness_reth_23993050() {
    run_block(23993050);
}
