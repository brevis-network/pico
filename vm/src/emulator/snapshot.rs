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

    /// The batch's replay segments, in clock order, as `(start state, target global clock)`.
    ///
    /// One segment — this default — is the shipped shape, and the interpreter never hands back
    /// more. An implementation that can stop mid-chunk overrides it so one chunk's replay runs on
    /// several threads and still proves once.
    fn next_state_batch_segments(
        &mut self,
    ) -> Result<(Vec<(RiscvEmulationState, u64)>, EmulationReport), EmulationError> {
        let (state, report) = self.next_state_batch()?;
        let target = report.current_cycle;
        Ok((vec![(state, target)], report))
    }
}
