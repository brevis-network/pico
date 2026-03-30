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
        let num_memory_rw_events = self.chunk_split_state.num_memory_read_write_events;
        let num_global_lookup_base = self.chunk_split_state.num_global_lookup_base;
        let is_max_chunk_size = self.clk + self.max_syscall_cycles >= (max_chunk_size << 2);

        if is_max_chunk_size
            || (num_memory_rw_events > self.batch_memory_rw_threshold
                && num_global_lookup_base >= self.batch_global_lookup_base_threshold)
            || (num_memory_rw_events >= self.batch_memory_rw_threshold
                && num_global_lookup_base > self.batch_global_lookup_base_threshold)
        {
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
        // Fast path: skip full check if both clock and memory-RW counters are far from threshold.
        if self.clk < self.batch_clk_fast_threshold
            && self.chunk_split_state.num_memory_read_write_events < self.batch_event_fast_threshold
        {
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

    /// Predict if a block can fit in current chunk without crossing a split boundary.
    #[inline(always)]
    pub fn can_fit_block(
        &self,
        insn_count: u32,
        mem_rw_exact: usize,
        global_lookup_base_max: usize,
    ) -> bool {
        let cost = insn_count * CLOCK_INCREMENT_PER_INSN;
        let remaining = self.batch_clk_threshold.saturating_sub(self.clk);
        if cost > remaining {
            return false;
        }

        let projected_memory = self
            .chunk_split_state
            .num_memory_read_write_events
            .saturating_add(mem_rw_exact);
        if projected_memory < self.batch_memory_rw_threshold {
            return true;
        }

        let projected_global = self
            .chunk_split_state
            .num_global_lookup_base
            .saturating_add(global_lookup_base_max);

        !((projected_memory > self.batch_memory_rw_threshold
            && projected_global >= self.batch_global_lookup_base_threshold)
            || (projected_memory >= self.batch_memory_rw_threshold
                && projected_global > self.batch_global_lookup_base_threshold))
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

#[cfg(test)]
mod tests {
    use super::AotEmulatorCore;
    use pico_vm::compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program};
    use std::{collections::BTreeMap, sync::Arc};

    fn test_program() -> Arc<Program> {
        let mut program = Program::new(
            vec![Instruction::new(Opcode::ADD, 1, 0, 0, false, false)],
            0x1000,
            0x1000,
        );
        program.memory_image = Arc::new(BTreeMap::new());
        Arc::new(program)
    }

    fn test_emu() -> AotEmulatorCore {
        let mut emu = AotEmulatorCore::new(test_program(), Vec::new());
        emu.max_syscall_cycles = 0;
        emu.batch_chunk_size = 64;
        emu.batch_clk_threshold = 256;
        emu.batch_clk_fast_threshold = 240;
        emu.batch_memory_rw_threshold = 4;
        emu.batch_global_lookup_base_threshold = 2;
        emu.batch_event_fast_threshold = 3;
        emu
    }

    #[test]
    fn chunk_boundary_splits_on_cycle_limit() {
        let mut emu = test_emu();
        emu.clk = 256;

        assert!(emu.check_chunk_boundary());
        assert_eq!(emu.current_chunk, 2);
        assert_eq!(emu.clk, 0);
    }

    #[test]
    fn chunk_boundary_splits_on_mem_gt_global_eq_edge() {
        let mut emu = test_emu();
        emu.chunk_split_state.num_memory_read_write_events = 5;
        emu.chunk_split_state.num_global_lookup_base = 2;

        assert!(emu.check_chunk_boundary());
    }

    #[test]
    fn chunk_boundary_splits_on_mem_eq_global_gt_edge() {
        let mut emu = test_emu();
        emu.chunk_split_state.num_memory_read_write_events = 4;
        emu.chunk_split_state.num_global_lookup_base = 3;

        assert!(emu.check_chunk_boundary());
    }

    #[test]
    fn chunk_boundary_does_not_split_on_equal_thresholds() {
        let mut emu = test_emu();
        emu.chunk_split_state.num_memory_read_write_events = 4;
        emu.chunk_split_state.num_global_lookup_base = 2;

        assert!(!emu.check_chunk_boundary());
    }

    #[test]
    fn chunk_boundary_does_not_split_when_memory_is_below_threshold() {
        let mut emu = test_emu();
        emu.chunk_split_state.num_memory_read_write_events = 3;
        emu.chunk_split_state.num_global_lookup_base = 10;

        assert!(!emu.check_chunk_boundary());
    }

    #[test]
    fn chunk_boundary_is_skipped_in_unconstrained_mode() {
        let mut emu = test_emu();
        emu.enter_unconstrained_mode();
        emu.clk = 256;
        emu.chunk_split_state.num_memory_read_write_events = 5;
        emu.chunk_split_state.num_global_lookup_base = 3;

        assert!(!emu.check_chunk_boundary());
    }

    #[test]
    fn chunk_boundary_fast_skips_slow_path_when_far_from_limits() {
        let mut emu = test_emu();
        emu.clk = 128;
        emu.chunk_split_state.num_memory_read_write_events = 2;
        emu.chunk_split_state.num_global_lookup_base = 100;

        assert!(!emu.check_chunk_boundary_fast());
        assert_eq!(emu.current_chunk, 1);
    }

    #[test]
    fn chunk_boundary_fast_enters_slow_path_when_event_threshold_is_near() {
        let mut emu = test_emu();
        emu.clk = 128;
        emu.chunk_split_state.num_memory_read_write_events = 4;
        emu.chunk_split_state.num_global_lookup_base = 3;

        assert!(emu.check_chunk_boundary_fast());
        assert_eq!(emu.current_chunk, 2);
    }

    #[test]
    fn can_fit_block_rejects_when_clock_budget_is_exceeded() {
        let mut emu = test_emu();
        emu.clk = 252;

        assert!(!emu.can_fit_block(2, 0, 0));
    }

    #[test]
    fn can_fit_block_rejects_on_event_threshold_crossing() {
        let mut emu = test_emu();
        emu.chunk_split_state.num_memory_read_write_events = 3;
        emu.chunk_split_state.num_global_lookup_base = 1;

        assert!(!emu.can_fit_block(1, 2, 1));
    }

    #[test]
    fn can_fit_block_accepts_exact_threshold_without_strict_crossing() {
        let mut emu = test_emu();
        emu.chunk_split_state.num_memory_read_write_events = 3;
        emu.chunk_split_state.num_global_lookup_base = 1;

        assert!(emu.can_fit_block(1, 1, 1));
    }

    #[test]
    fn can_fit_block_rejects_superblock_aggregate_crossing() {
        let mut emu = test_emu();
        emu.chunk_split_state.num_memory_read_write_events = 2;
        emu.chunk_split_state.num_global_lookup_base = 1;

        assert!(!emu.can_fit_block(4, 3, 2));
    }
}
