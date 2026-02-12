//! Core runtime types for AOT emulation

use super::emulator::AotEmulatorCore;

/// Control flow decision for AOT execution.
///
/// Represents the next step after executing a block of code.
pub enum NextStep {
    /// Direct jump to a known block function
    Direct(fn(&mut AotEmulatorCore) -> Result<NextStep, String>),
    /// Dynamic jump to a PC (requires lookup or interpretation)
    Dynamic(u32),
    /// Halt execution
    Halt,
}

/// Function pointer type for AOT basic block handlers.
pub type BlockFn = fn(&mut AotEmulatorCore) -> Result<NextStep, String>;

/// Clock accumulator for batching instruction clock updates.
///
/// Generated AOT code uses this to batch multiple instruction clocks
/// into a single update, reducing overhead.
#[derive(Default)]
pub struct BlockClock {
    pending: u32,
}

impl BlockClock {
    /// Create a new block clock accumulator
    #[inline(always)]
    pub fn new() -> Self {
        Self { pending: 0 }
    }

    /// Accumulate clock cycles
    #[inline(always)]
    pub fn tick(&mut self, amount: u32) {
        self.pending = self.pending.wrapping_add(amount);
    }

    /// Flush accumulated cycles into emulator state
    #[inline(always)]
    pub fn flush_into(&mut self, emu: &mut AotEmulatorCore) {
        if self.pending != 0 {
            emu.bulk_update_clock(self.pending);
            self.pending = 0;
        }
    }
}

/// Trait for emulators that support bulk clock updates
pub trait ClockUpdate {
    /// Update clock by multiple instructions at once
    fn bulk_update_clock(&mut self, count: u32);
}
