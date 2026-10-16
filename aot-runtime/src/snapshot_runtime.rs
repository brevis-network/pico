//! The VM side of AOT registration: the factory the snapshot pipeline asks for an AOT emulator.
//!
//! The VM keeps one factory per process and the first install wins
//! (`pico_vm::emulator::aot::register_aot_factory`, which says whether a call was the one), and
//! generated code installs its block lookup the same way on its first run, without a word
//! (`set_lookup_block_fn`). So a process runs one AOT program. [`register_snapshot_aot_factory`]
//! installs an entry point unchecked; [`register`] keys the program by its ELF digest and refuses
//! anything that would leave the slot holding another.

use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use pico_vm::{
    emulator::{
        aot::{register_aot_factory, split_chunks, split_segments, AotSnapshotEmulator},
        opts::EmulatorOpts,
        riscv::{
            public_values::RecordFinalPvsState, riscv_emulator::EmulationError,
            state::RiscvEmulationState,
        },
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
    /// The ELF digest [`register`] recorded; `None` behind [`register_snapshot_aot_factory`].
    elf_sha256: Option<[u8; 32]>,
}

impl SharedSnapshotAot {
    /// The `[AOT]` banner prints for the interpreting stub too; a non-zero count is what shows
    /// compiled code ran.
    fn log_finished(&self) {
        let dispatches = self.emulator.compiled_block_dispatches();
        let cycles = self.emulator.insn_count;
        match &self.elf_sha256 {
            Some(digest) => log::info!(
                "AOT program for ELF {} finished: {dispatches} compiled-block dispatches in \
                 {cycles} cycles",
                Sha256Hex(digest)
            ),
            None => log::info!(
                "AOT program finished: {dispatches} compiled-block dispatches in {cycles} cycles"
            ),
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
        // and cutting a chunk just spreads the same work over more segments.
        let segments = if self.emulator.current_batch < split_chunks() {
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

    fn get_pv_stream(&mut self) -> Vec<u8> {
        self.emulator.public_values_stream.clone()
    }
}

fn create_snapshot_aot(
    program: Arc<pico_vm::compiler::riscv::program::Program>,
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
            .map(|program| program.elf_sha256),
    })
}

/// Registers `program` as this process's AOT code: what the snapshot pipeline runs when it is
/// asked for `SnapshotMainMode::Aot`.
///
/// One program per process, identified by its ELF digest. Registering the same program again is
/// `Ok`. Refused, with no factory installed: [`AotProgram::STUB`]; a program other than the one
/// already registered; and any program while a factory installed without this function holds the
/// slot, whether it got there before the call or during it, since the program behind it cannot be
/// known.
pub fn register(program: &'static AotProgram) -> Result<(), AotError> {
    if program.is_stub() {
        return Err(AotError::Stub);
    }
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
    // Decided by the installs themselves, not by a look beforehand: the lock above does not hold
    // off the unchecked entry points, so either slot can be taken between a look and an install.
    if RUN_DISPATCH.set(program.run).is_err() || !register_aot_factory(create_snapshot_aot) {
        return Err(AotError::ForeignFactory);
    }
    *registered = Some(program);
    Ok(())
}

/// Installs `run_dispatch` as this process's AOT code, unchecked: the first entry point wins and
/// later ones are dropped without a word. [`register`] is the checked way in.
pub fn register_snapshot_aot_factory(run_dispatch: fn(&mut AotEmulatorCore) -> Result<(), String>) {
    let _ = RUN_DISPATCH.set(run_dispatch);
    register_aot_factory(create_snapshot_aot);
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

    use super::register_snapshot_aot_factory;
    use crate::AotEmulatorCore;

    fn run_dispatch_sets_done_and_final_pvs(emu: &mut AotEmulatorCore) -> Result<(), String> {
        emu.committed_value_digest = [7; PV_DIGEST_NUM_WORDS];
        emu.deferred_proofs_digest = [9; DIGEST_SIZE];
        emu.pc = 0;
        emu.insn_count = 11;
        Ok(())
    }

    #[test]
    fn registered_snapshot_factory_uses_shared_next_state_batch_and_sets_final_pvs() {
        register_snapshot_aot_factory(run_dispatch_sets_done_and_final_pvs);

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
