//! AOT factory glue for `bench --aot`.
//!
//! Registers an `AotSnapshotEmulator` factory backed by the generated
//! `pico-aot-dispatch` crate (repo-root `aot-generated`, produced by
//! `generate_crates`).
//!
//! Each consumer of the AOT prove path carries its own copy of this glue,
//! because the factory has to name the *generated* dispatch crate, and that
//! crate is regenerated per guest ELF. `cargo pico new` ships the same file as
//! `prover/src/aot_glue.rs` for downstream projects, and the AOT examples have
//! their own copy.

use std::sync::Arc;

use pico_aot_dispatch::AotEmulatorCore;
use pico_vm::{
    compiler::riscv::program::Program,
    emulator::{
        aot::{register_aot_factory, AotSnapshotEmulator},
        opts::EmulatorOpts,
        riscv::{
            chunk_split::ChunkSplitConfig, riscv_emulator::EmulationError,
            state::RiscvEmulationState,
        },
    },
    machine::report::EmulationReport,
};

fn next_state_batch_impl(
    emu: &mut AotEmulatorCore,
    opts: EmulatorOpts,
) -> Result<(RiscvEmulationState, EmulationReport), String> {
    let start_chunk = emu.current_chunk;
    let start_cycle = emu.insn_count;

    emu.batch_chunk_target = opts.chunk_batch_size;
    emu.batch_chunks_emulated = 0;
    emu.batch_stop = false;
    emu.chunk_split_config =
        ChunkSplitConfig::for_chunk_size(opts.chunk_size, emu.max_syscall_cycles);

    emu.save_batch_start_state();
    let mut snapshot = emu.build_snapshot_state();

    pico_aot_dispatch::run_aot(emu)?;

    let done = emu.pc == 0
        || emu.pc.wrapping_sub(emu.program_pc_base()).wrapping_div(4) >= emu.program_len() as u64;

    if !done {
        emu.current_batch = emu.current_batch.wrapping_add(1);
    }

    if done {
        emu.fill_snapshot_memory_full_prestate(&mut snapshot);
    } else {
        emu.fill_snapshot_memory_delta(&mut snapshot);
    }

    let report = EmulationReport {
        current_cycle: emu.insn_count,
        start_chunk,
        done,
        cycle_tracker: None,
        host_cycle_estimator: None,
    };

    if !done && emu.insn_count == start_cycle && emu.batch_chunk_target > 0 {
        return Err("AOT next_state_batch made no progress (possible yield bug)".to_string());
    }

    Ok((snapshot, report))
}

struct VmAotAdapter {
    core: AotEmulatorCore,
    opts: EmulatorOpts,
}

impl AotSnapshotEmulator for VmAotAdapter {
    fn next_state_batch(
        &mut self,
    ) -> Result<(RiscvEmulationState, EmulationReport), EmulationError> {
        next_state_batch_impl(&mut self.core, self.opts).map_err(|s| {
            tracing::error!(error = %s, "AOT adapter error");
            EmulationError::Aot(s)
        })
    }

    fn cycles(&self) -> u64 {
        self.core.insn_count
    }

    fn get_pv_stream(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.core.public_values_stream)
    }
}

fn aot_factory(
    program: Arc<Program>,
    input_stream: Vec<Vec<u8>>,
    opts: EmulatorOpts,
) -> Box<dyn AotSnapshotEmulator> {
    Box::new(VmAotAdapter {
        core: AotEmulatorCore::new(program, input_stream),
        opts,
    })
}

/// Register the AOT factory with the VM. Call once, before proving.
pub fn register_with_vm() {
    register_aot_factory(aot_factory);
}
