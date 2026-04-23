use crate::types::{BlockClock, NextStep};
use pico_vm::emulator::riscv::chunk_split::should_check_fast;

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
        if self.chunk_split_state.should_split(
            self.clk,
            self.max_syscall_cycles,
            &self.chunk_split_config,
        ) {
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
        if !should_check_fast(self.clk, &self.chunk_split_state, &self.chunk_split_config) {
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
        non_register_global_lookup_base_max: usize,
        reg_write_mask: u32,
    ) -> bool {
        debug_assert_eq!(CLOCK_INCREMENT_PER_INSN, 4);
        self.chunk_split_state.can_fit_block(
            self.clk,
            insn_count,
            mem_rw_exact,
            non_register_global_lookup_base_max,
            reg_write_mask,
            &self.chunk_split_config,
        )
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
        emu.chunk_split_config = pico_vm::emulator::riscv::chunk_split::ChunkSplitConfig {
            chunk_size: 64,
            clk_threshold: 256,
            clk_fast_threshold: 240,
            memory_rw_threshold: 4,
            global_lookup_base_threshold: 2,
            event_fast_threshold: 3,
        };
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

        assert!(!emu.can_fit_block(2, 0, 0, 0));
    }

    #[test]
    fn can_fit_block_rejects_on_event_threshold_crossing() {
        let mut emu = test_emu();
        emu.chunk_split_state.num_memory_read_write_events = 3;
        emu.chunk_split_state.num_global_lookup_base = 1;

        assert!(!emu.can_fit_block(1, 2, 1, 0));
    }

    #[test]
    fn can_fit_block_accepts_exact_threshold_without_strict_crossing() {
        let mut emu = test_emu();
        emu.chunk_split_state.num_memory_read_write_events = 3;
        emu.chunk_split_state.num_global_lookup_base = 1;

        assert!(emu.can_fit_block(1, 1, 1, 0));
    }

    #[test]
    fn can_fit_block_rejects_superblock_aggregate_crossing() {
        let mut emu = test_emu();
        emu.chunk_split_state.num_memory_read_write_events = 2;
        emu.chunk_split_state.num_global_lookup_base = 1;

        assert!(!emu.can_fit_block(4, 3, 2, 0));
    }

    #[test]
    fn can_fit_block_does_not_charge_registers_already_written_in_chunk() {
        let mut emu = test_emu();
        emu.chunk_split_state.num_memory_read_write_events = 3;
        emu.chunk_split_state.track_address(1);
        emu.chunk_split_config.global_lookup_base_threshold = 1;

        assert!(emu.can_fit_block(1, 1, 0, 1 << 1));
        assert!(!emu.can_fit_block(1, 1, 0, 1 << 2));
    }
}
