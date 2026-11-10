//! Core runtime types for AOT emulation

use super::emulator::{AotEmulatorCore, Recorder};

/// Control flow decision for AOT execution.
///
/// Represents the next step after executing a block of code.
pub enum NextStep {
    /// Direct jump to a known block function
    Direct(fn(&mut AotEmulatorCore) -> Result<NextStep, String>),
    /// Dynamic jump to a PC (requires lookup or interpretation)
    Dynamic(u64),
    /// Halt execution
    Halt,
}

/// Function pointer type for AOT basic block handlers.
pub type BlockFn = fn(&mut AotEmulatorCore) -> Result<NextStep, String>;

/// [`NextStep`] between recording blocks: a direct step names a recording block, so a run that
/// lends them its sink never enters an ordinary block.
pub enum RecordStep {
    Direct(RecordBlockFn),
    Dynamic(u64),
    Halt,
}

/// A generated block's recording body: its instructions, their events written into the sink the
/// [`Recorder`] holds for the run.
pub type RecordBlockFn = fn(&mut AotEmulatorCore, &mut Recorder) -> Result<RecordStep, String>;
