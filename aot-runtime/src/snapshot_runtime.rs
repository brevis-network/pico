//! The VM side of AOT registration: the factories the snapshot pipeline asks for an AOT emulator,
//! one for its snapshot thread and one for its replay workers.
//!
//! The VM keeps one factory of each per process and the first install wins
//! (`pico_vm::emulator::aot::register_aot_factory` and `register_aot_replay_factory`, which say
//! whether a call was the one), and
//! generated code installs its block lookup the same way on its first run, without a word
//! (`set_lookup_block_fn`). So a process runs one AOT program. [`register`] keys the program by its
//! ELF digest, refuses code generated against another codegen stamp, and refuses anything that
//! would leave the slot holding another; [`register_interpreted`] installs the runtime with no
//! compiled code under the same one-per-process rule.

use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use pico_vm::{
    chips::chips::riscv_memory::event::MemoryRecord,
    compiler::riscv::program::Program,
    emulator::{
        aot::{
            is_aot_factory_registered, is_aot_replay_factory_registered, register_aot_factory,
            register_aot_replay_factory, split_segments, splits_batch, AotReplayEmulator,
            AotSnapshotEmulator,
        },
        opts::EmulatorOpts,
        riscv::{
            memory::ContiguousRiscvMemory, public_values::RecordFinalPvsState,
            record::EmulationRecord, riscv_emulator::EmulationError, state::RiscvEmulationState,
        },
        snapshot::SnapshotCounters,
    },
    machine::report::EmulationReport,
};

use crate::{
    program::{AotError, AotProgram, Sha256Hex},
    AotEmulatorCore,
};

// allow: domain-complex signature — tuple reflects prover data-flow structure
#[allow(clippy::type_complexity)]
static RUN_DISPATCH: OnceLock<fn(&mut AotEmulatorCore) -> Result<(), String>> = OnceLock::new();

/// The program [`register`] installed. Held locked for the whole of [`register`], so its checks
/// and its install are one step to any other caller of it.
static REGISTERED: Mutex<Option<&'static AotProgram>> = Mutex::new(None);

struct SharedSnapshotAot {
    emulator: AotEmulatorCore,
    opts: EmulatorOpts,
    run_dispatch: fn(&mut AotEmulatorCore) -> Result<(), String>,
    final_pvs_state: Arc<RecordFinalPvsState>,
    /// The ELF digest [`register`] recorded.
    elf_sha256: [u8; 32],
}

impl SharedSnapshotAot {
    /// The `[AOT]` banner prints for the interpreting stub too; a non-zero count is what shows
    /// compiled code ran.
    fn log_finished(&self) {
        let dispatches = self.emulator.compiled_block_dispatches();
        let cycles = self.emulator.insn_count;
        if self.elf_sha256 == AotProgram::STUB.elf_sha256() {
            log::info!(
                "AOT runtime finished interpreting every block (no compiled code): {cycles} cycles"
            );
        } else {
            log::info!(
                "AOT program for ELF {} finished: {dispatches} compiled-block dispatches in \
                 {cycles} cycles",
                Sha256Hex(&self.elf_sha256)
            );
        }
    }
}

impl AotSnapshotEmulator for SharedSnapshotAot {
    fn next_state_batch(
        &mut self,
    ) -> Result<(RiscvEmulationState, EmulationReport), EmulationError> {
        // Straight to the core's one-segment helper rather than through the trait method below,
        // which consults `split_segments()` and can hand back several: this returns a single
        // state, so every segment before the last would go out with the replay it stands for.
        // A caller that wants the split asks for segments.
        let (snapshot, report) = self
            .emulator
            .next_state_batch(self.opts, self.run_dispatch)?;
        if report.done {
            self.final_pvs_state.set_record_final_pvs(
                self.emulator.committed_value_digest,
                self.emulator.deferred_proofs_digest,
            );
            self.log_finished();
        }
        Ok((snapshot, report))
    }

    fn next_state_batch_segments(
        &mut self,
    ) -> Result<(Vec<(RiscvEmulationState, u64)>, EmulationReport), EmulationError> {
        // Only the leading chunks are worth splitting: after them the replay pool is saturated
        // and cutting a chunk just spreads the same work over more segments. The tail, whose
        // replay runs on a draining pool, is cut instead when `MLE_SPLIT_FROM_CHUNK` asks.
        let segments = if splits_batch(self.emulator.current_batch) {
            split_segments()
        } else {
            1
        };
        let (segments, report) =
            self.emulator
                .next_state_batch_segments(self.opts, self.run_dispatch, segments)?;
        if report.done {
            self.final_pvs_state.set_record_final_pvs(
                self.emulator.committed_value_digest,
                self.emulator.deferred_proofs_digest,
            );
            self.log_finished();
        }
        Ok((segments, report))
    }

    fn cycles(&self) -> u64 {
        self.emulator.insn_count
    }

    fn counters(&self) -> SnapshotCounters {
        let counts = &self.emulator.snapshot_counts;
        let entries = counts.first_touch_loads
            + counts.first_touch_partial_stores
            + counts.first_touch_full_stores;
        SnapshotCounters {
            dispatches: Some(self.emulator.compiled_block_dispatches()),
            prestate_entries: Some(entries),
            prestate_bytes: Some(entries * std::mem::size_of::<MemoryRecord>() as u64),
            first_touch_loads: Some(counts.first_touch_loads),
            first_touch_partial_stores: Some(counts.first_touch_partial_stores),
            first_touch_full_stores: Some(counts.first_touch_full_stores),
            first_touch_registers: Some(counts.first_touch_registers),
        }
    }

    fn get_pv_stream(&mut self) -> Vec<u8> {
        self.emulator.public_values_stream.clone()
    }
}

fn create_snapshot_aot(
    program: Arc<Program>,
    input_stream: Vec<Vec<u8>>,
    opts: EmulatorOpts,
    final_pvs_state: Arc<RecordFinalPvsState>,
) -> Box<dyn AotSnapshotEmulator> {
    Box::new(SharedSnapshotAot {
        emulator: AotEmulatorCore::new(program, input_stream),
        opts,
        run_dispatch: RUN_DISPATCH
            .get()
            .copied()
            .expect("AOT dispatch entrypoint not registered"),
        final_pvs_state,
        elf_sha256: REGISTERED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .expect("only `install` installs this factory, recording its program under the lock")
            .elf_sha256,
    })
}

/// A replay worker: the core recovered in place from each snapshot it is handed.
struct ReplayAot {
    emulator: AotEmulatorCore,
    run_dispatch: fn(&mut AotEmulatorCore) -> Result<(), String>,
}

impl AotReplayEmulator for ReplayAot {
    fn recover_in_place(
        &mut self,
        state: RiscvEmulationState,
        target_global_clk: u64,
        final_segment: bool,
    ) -> ContiguousRiscvMemory {
        self.emulator
            .recover_in_place(state, target_global_clk, final_segment)
    }

    fn replay(&mut self) -> Result<(EmulationRecord, EmulationReport), EmulationError> {
        let (chunk, report) = self.emulator.replay(self.run_dispatch)?;
        Ok((chunk.record, report))
    }

    fn postprocess(&self, record: &mut EmulationRecord) {
        self.emulator.postprocess(record);
    }

    fn compiled_block_dispatches(&self) -> u64 {
        self.emulator.compiled_block_dispatches()
    }

    fn fallback_insns(&self) -> u64 {
        self.emulator.fallback_insns()
    }

    fn replace_memory(&mut self, memory: ContiguousRiscvMemory) -> ContiguousRiscvMemory {
        std::mem::replace(&mut self.emulator.memory, memory)
    }

    fn into_memory(self: Box<Self>) -> ContiguousRiscvMemory {
        self.emulator.memory
    }
}

fn create_replay_aot(
    program: Arc<Program>,
    state: RiscvEmulationState,
    target_global_clk: u64,
    final_segment: bool,
) -> Box<dyn AotReplayEmulator> {
    let run_dispatch = RUN_DISPATCH
        .get()
        .copied()
        .expect("AOT dispatch entrypoint not registered");
    Box::new(ReplayAot {
        emulator: AotEmulatorCore::recover(program, state, target_global_clk, final_segment),
        run_dispatch,
    })
}

/// Registers `program` as this process's AOT code: what the snapshot pipeline runs when it is
/// asked for `SnapshotMainMode::Aot`, and what its replay workers run for `ReplayWorkers::Aot`.
///
/// One program per process, identified by its ELF digest. Registering the same program again is
/// `Ok`. Refused, with no factory installed: [`AotProgram::STUB`]; a program whose codegen stamp is
/// not [`AotProgram::CODEGEN_STAMP`]; a program other than the one already registered; and any
/// program while a factory installed without this function holds the slot, whether it got there
/// before the call or during it, since the program behind it cannot be known.
pub fn register(program: &'static AotProgram) -> Result<(), AotError> {
    if program.is_stub() {
        return Err(AotError::Stub);
    }
    if program.codegen_stamp != AotProgram::CODEGEN_STAMP {
        return Err(AotError::CodegenStamp {
            found: program.codegen_stamp,
            expected: AotProgram::CODEGEN_STAMP,
        });
    }
    install(program)
}

/// The runtime with no compiled code, which [`register_interpreted`] installs.
static INTERPRETED: AotProgram = AotProgram::STUB;

/// Registers the AOT runtime without compiled code: the snapshot thread, and the replay workers
/// when they run on the AOT runtime, interpret every block with the runtime's own interpreter and
/// precompile backends, for any ELF.
/// It runs no generated code and reports none (`0 compiled-block dispatches`). Same
/// one-per-process rule as [`register`]: a compiled program is refused once this is in, and this
/// once one is.
pub fn register_interpreted() -> Result<(), AotError> {
    install(&INTERPRETED)
}

fn install(program: &'static AotProgram) -> Result<(), AotError> {
    let mut registered = REGISTERED.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(current) = *registered {
        return if current.elf_sha256 == program.elf_sha256 {
            Ok(())
        } else {
            Err(AotError::Conflict {
                registered: current.elf_sha256,
                requested: program.elf_sha256,
            })
        };
    }
    // Refuse occupied slots before touching any OnceLock; a partial install cannot be undone.
    if RUN_DISPATCH.get().is_some()
        || is_aot_factory_registered()
        || is_aot_replay_factory_registered()
    {
        return Err(AotError::ForeignFactory);
    }
    if RUN_DISPATCH.set(program.run).is_err()
        || !register_aot_factory(create_snapshot_aot)
        || !register_aot_replay_factory(create_replay_aot)
    {
        return Err(AotError::ForeignFactory);
    }
    *registered = Some(program);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pico_vm::{
        compiler::riscv::program::Program,
        emulator::{
            aot::create_aot_emulator, opts::EmulatorOpts, riscv::public_values::RecordFinalPvsState,
        },
        primitives::consts::{DIGEST_SIZE, PV_DIGEST_NUM_WORDS},
    };

    use super::register;
    use crate::{AotEmulatorCore, AotProgram};

    fn run_dispatch_sets_done_and_final_pvs(emu: &mut AotEmulatorCore) -> Result<(), String> {
        emu.committed_value_digest = [7; PV_DIGEST_NUM_WORDS];
        emu.deferred_proofs_digest = [9; DIGEST_SIZE];
        emu.pc = 0;
        emu.insn_count = 11;
        Ok(())
    }

    #[test]
    fn registered_snapshot_factory_uses_shared_next_state_batch_and_sets_final_pvs() {
        static PROGRAM: AotProgram = AotProgram::stamped(
            [1; 32],
            AotProgram::CODEGEN_STAMP,
            run_dispatch_sets_done_and_final_pvs,
        );
        register(&PROGRAM).expect("a stamped program registers");

        let final_pvs_state = Arc::new(RecordFinalPvsState::default());
        let program = Arc::new(Program::new(Vec::new(), 0x1000, 0x1000));
        let mut emulator = create_aot_emulator(
            program,
            Vec::new(),
            EmulatorOpts::test_opts(),
            final_pvs_state.clone(),
        )
        .expect("AOT emulator factory should be registered");

        let (snapshot, report) = emulator
            .next_state_batch()
            .expect("shared snapshot AOT batch should succeed");

        assert!(report.done);
        assert_eq!(report.current_cycle, 11);
        assert_eq!(snapshot.global_clk, 0);
        assert_eq!(
            final_pvs_state.wait_for_final_committed_or_panic(),
            [7; PV_DIGEST_NUM_WORDS]
        );
        assert_eq!(
            final_pvs_state.wait_for_final_deferred_or_panic(),
            [9; DIGEST_SIZE]
        );
    }
}
