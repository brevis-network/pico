#[cfg(feature = "aot")]
use pico_aot_dispatch::AotEmulatorCore;
#[cfg(feature = "aot")]
use pico_vm::{
    compiler::riscv::program::Program,
    emulator::{
        aot::{register_aot_factory, AotSnapshotEmulator},
        opts::EmulatorOpts,
        riscv::{
            chunk_split::ChunkSplitConfig, memory::GLOBAL_MEMORY_RECYCLER,
            riscv_emulator::EmulationError, state::RiscvEmulationState,
        },
    },
    machine::report::EmulationReport,
};
#[cfg(feature = "aot")]
use std::sync::Arc;

#[cfg(feature = "aot")]
pub trait AotRun {
    fn run(&mut self) -> Result<(), String>;
    fn next_state_batch(
        &mut self,
        opts: EmulatorOpts,
    ) -> Result<(RiscvEmulationState, EmulationReport), String>;
}

#[cfg(feature = "aot")]
pub fn recycle_snapshot_memory(snapshot: RiscvEmulationState) {
    let RiscvEmulationState { memory, .. } = snapshot;
    let _ = GLOBAL_MEMORY_RECYCLER.send((memory, true));
}

#[cfg(feature = "aot")]
pub fn run_impl(emu: &mut AotEmulatorCore) -> Result<(), String> {
    emu.batch_chunk_target = 0;
    emu.batch_chunks_emulated = 0;
    emu.batch_stop = false;
    emu.chunk_split_config = ChunkSplitConfig::disabled(emu.max_syscall_cycles);
    pico_aot_dispatch::run_aot(emu)
}

#[cfg(feature = "aot")]
pub fn next_state_batch_impl(
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

#[cfg(feature = "aot")]
struct VmAotAdapter {
    core: AotEmulatorCore,
    opts: EmulatorOpts,
}

#[cfg(feature = "aot")]
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

#[cfg(feature = "aot")]
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

#[cfg(feature = "aot")]
pub fn register_with_vm() {
    register_aot_factory(aot_factory);
}

#[cfg(feature = "aot")]
impl AotRun for AotEmulatorCore {
    fn run(&mut self) -> Result<(), String> {
        run_impl(self)
    }

    fn next_state_batch(
        &mut self,
        opts: EmulatorOpts,
    ) -> Result<(RiscvEmulationState, EmulationReport), String> {
        next_state_batch_impl(self, opts)
    }
}
