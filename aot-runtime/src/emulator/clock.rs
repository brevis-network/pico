use crate::types::ClockUpdate;

use super::{constants::CLOCK_INCREMENT_PER_INSN, AotEmulatorCore};

impl AotEmulatorCore {
    // ========================================================================
    // Clock & Timing
    // ========================================================================

    /// Update instruction count and clock. Called after each instruction.
    #[inline(always)]
    pub fn update_insn_clock(&mut self) {
        self.insn_count += 1;
        self.clk = self.clk.wrapping_add(CLOCK_INCREMENT_PER_INSN);
    }

    /// Bulk update clock for multiple instructions at once.
    ///
    /// Used by generated AOT code to batch clock updates for performance.
    #[inline(always)]
    pub fn bulk_update_clock(&mut self, count: u32) {
        self.insn_count += count as u64;
        self.clk = self.clk.wrapping_add(count * CLOCK_INCREMENT_PER_INSN);
    }
}

impl ClockUpdate for AotEmulatorCore {
    #[inline(always)]
    fn bulk_update_clock(&mut self, count: u32) {
        AotEmulatorCore::bulk_update_clock(self, count);
    }
}
