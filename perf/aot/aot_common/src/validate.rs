use pico_vm::{
    chips::chips::riscv_memory::event::MemoryRecord,
    emulator::riscv::{memory::GLOBAL_MEMORY_RECYCLER, state::RiscvEmulationState},
    machine::report::EmulationReport,
};

pub fn compare_snapshots(
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

pub fn compare_reports(chunk_idx: usize, baseline: &EmulationReport, aot: &EmulationReport) {
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

pub fn recycle_snapshot_memory(snapshot: RiscvEmulationState) {
    let RiscvEmulationState { memory, .. } = snapshot;
    let _ = GLOBAL_MEMORY_RECYCLER.send((memory, true));
}
