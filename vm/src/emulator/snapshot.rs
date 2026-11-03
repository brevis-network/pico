//! Shared contract for emulators that drive the snapshot-main thread in
//! `emulate_snapshot_pipeline`. Both the interpreter-backed `MetaEmulator`
//! and the feature-gated `AotMetaEmulator` implement this trait so the
//! snapshot-main loop can be written against one shape.

use crate::{
    emulator::riscv::{riscv_emulator::EmulationError, state::RiscvEmulationState},
    machine::report::EmulationReport,
};

/// Running totals a snapshot emulator keeps, read before and after each batch for the stage
/// ledger. `None` where the emulator keeps no such count — the interpreter keeps none of them,
/// and a count it does not keep must not read as zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SnapshotCounters {
    /// Compiled blocks entered: the field that proves an AOT run ran compiled code.
    pub dispatches: Option<u64>,
    /// Memory doublewords recorded on their first touch in a batch: the prestate the replay starts
    /// from.
    pub prestate_entries: Option<u64>,
    /// Those entries' bytes, at one access record each.
    pub prestate_bytes: Option<u64>,
    /// First touches by a load, which need the prior value.
    pub first_touch_loads: Option<u64>,
    /// First touches by a byte, halfword or word store, which need the prior value too: the store
    /// keeps the doubleword's other bytes.
    pub first_touch_partial_stores: Option<u64>,
    /// First touches by a doubleword store, which need only the record it overwrites.
    pub first_touch_full_stores: Option<u64>,
    /// Registers recorded on their first touch in a batch.
    pub first_touch_registers: Option<u64>,
}

impl SnapshotCounters {
    /// What accrued between `earlier` and `self`.
    pub fn since(&self, earlier: &Self) -> Self {
        let delta = |now: Option<u64>, then: Option<u64>| Some(now?.saturating_sub(then?));
        Self {
            dispatches: delta(self.dispatches, earlier.dispatches),
            prestate_entries: delta(self.prestate_entries, earlier.prestate_entries),
            prestate_bytes: delta(self.prestate_bytes, earlier.prestate_bytes),
            first_touch_loads: delta(self.first_touch_loads, earlier.first_touch_loads),
            first_touch_partial_stores: delta(
                self.first_touch_partial_stores,
                earlier.first_touch_partial_stores,
            ),
            first_touch_full_stores: delta(
                self.first_touch_full_stores,
                earlier.first_touch_full_stores,
            ),
            first_touch_registers: delta(self.first_touch_registers, earlier.first_touch_registers),
        }
    }
}

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

    /// The running totals of [`SnapshotCounters`] this emulator keeps; none by default.
    fn counters(&self) -> SnapshotCounters {
        SnapshotCounters::default()
    }
}
