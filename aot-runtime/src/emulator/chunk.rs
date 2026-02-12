use crate::types::{BlockClock, NextStep};

use super::{constants::CLOCK_INCREMENT_PER_INSN, AotEmulatorCore};

impl AotEmulatorCore {
    // ========================================================================
    // Chunk & Batch Boundaries
    // ========================================================================

    /// Check if we've crossed a chunk boundary and should yield.
    ///
    /// Note: Chunk boundary checks are skipped during unconstrained mode to match
    /// baseline behavior. The baseline emulator explicitly checks `!self.is_unconstrained()`
    /// before performing chunk boundary checks in `emulate_cycle`.
    #[inline(always)]
    pub fn check_chunk_boundary(&mut self) -> bool {
        // Skip chunk boundary checks during unconstrained mode (matches baseline)
        if self.is_unconstrained_mode() {
            return false;
        }
        let max_chunk_size = self.batch_chunk_size;
        let is_max_chunk_size = self.clk + self.max_syscall_cycles >= (max_chunk_size << 2);

        if is_max_chunk_size {
            self.chunk_split_state.clear();
            self.current_chunk = self.current_chunk.wrapping_add(1);
            self.clk = 0;
            self.batch_chunks_emulated = self.batch_chunks_emulated.wrapping_add(1);
            if self.batch_chunk_target > 0 && self.batch_chunks_emulated >= self.batch_chunk_target
            {
                self.batch_stop = true;
            }
            return true;
        }
        false
    }

    /// Fast-path chunk boundary check with early exit.
    ///
    /// When the clock is far from its threshold, we can skip the full
    /// check_chunk_boundary() entirely. This provides significant speedup since
    /// check_chunk_boundary() is called after every block/branch.
    #[inline(always)]
    pub fn check_chunk_boundary_fast(&mut self) -> bool {
        // Fast path: skip full check if clock is far from threshold
        if self.clk < self.batch_clk_fast_threshold {
            return false;
        }
        // Slow path: full check
        self.check_chunk_boundary()
    }

    /// Check if execution should yield.
    #[inline(always)]
    pub fn should_yield(&self) -> bool {
        self.batch_stop && self.pc != 0
    }

    /// Predict if a block with `count` instructions can fit in current chunk.
    #[inline(always)]
    pub fn can_fit_instructions(&self, count: u32) -> bool {
        let cost = count * CLOCK_INCREMENT_PER_INSN;
        let remaining = self.batch_clk_threshold.saturating_sub(self.clk);
        cost <= remaining
    }

    /// Finalize a block and check for yield.
    #[inline(always)]
    pub fn finalize_block(
        &mut self,
        clock: &mut BlockClock,
        next: NextStep,
    ) -> Result<NextStep, String> {
        clock.flush_into(self);
        self.check_chunk_boundary();
        if self.should_yield() {
            Ok(NextStep::Dynamic(self.pc))
        } else {
            Ok(next)
        }
    }

    /// Handle block failure with clock flush.
    #[inline(always)]
    pub fn fail_block(&mut self, clock: &mut BlockClock, err: String) -> Result<NextStep, String> {
        clock.flush_into(self);
        self.check_chunk_boundary();
        Err(err)
    }
}
