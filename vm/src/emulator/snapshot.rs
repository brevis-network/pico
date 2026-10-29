//! Shared contract for emulators that drive the snapshot-main thread in
//! `emulate_snapshot_pipeline`. Both the interpreter-backed `MetaEmulator`
//! and the feature-gated `AotMetaEmulator` implement this trait so the
//! snapshot-main loop can be written against one shape.

use crate::{
    emulator::riscv::{riscv_emulator::EmulationError, state::RiscvEmulationState},
    machine::report::EmulationReport,
};

pub trait SnapshotEmulator {
    /// Advance the emulator by one batch, returning the snapshot state and
    /// emulation report. `done` is encoded on the report.
    fn next_state_batch(
        &mut self,
    ) -> Result<(RiscvEmulationState, EmulationReport), EmulationError>;

    /// Total instruction cycles retired so far.
    fn cycles(&self) -> u64;

    /// Drain and return the public-values stream (called once after the
    /// loop observes a `done` report).
    fn get_pv_stream(&mut self) -> Vec<u8>;
}
