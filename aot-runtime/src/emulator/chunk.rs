use pico_vm::{
    emulator::riscv::chunk_split::{maybe_debug_split_snapshot, should_check_fast},
    primitives::consts::CHUNK_CLK_START,
};

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
            // Report before `clear()` drops the counts this reads.
            maybe_debug_split_snapshot(
                self.current_chunk,
                self.clk,
                self.max_syscall_cycles,
                self.insn_count,
                &self.chunk_split_state,
                &self.chunk_split_config,
            );
            self.chunk_split_state.clear();
            self.cut_emitted_chunk();
            self.current_chunk = self
                .current_chunk
                .checked_add(1)
                .expect("the chunk counter fits u32");
            self.clk = CHUNK_CLK_START;
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

    /// Whether the generated dispatch should hand control back.
    ///
    /// The sub-yield rides here rather than on `check_chunk_boundary`, because that one sits
    /// behind a fast path that skips the whole check when the counters are far from their
    /// thresholds — a cut point expressed in instructions would be missed. This line runs once
    /// per block, and with split replay off the added comparison is against `u64::MAX`.
    ///
    /// It does have to borrow that one's unconstrained rule: the replaying interpreter only
    /// tests its target outside unconstrained mode, so a cut landing inside such a region would
    /// hand out a target the worker runs straight past — and the next segment would replay what
    /// it already did, silently.
    #[inline(always)]
    pub fn should_yield(&self) -> bool {
        let sub_yield = self.insn_count >= self.next_sub_yield && !self.is_unconstrained_mode();
        (self.batch_stop || sub_yield) && self.pc != 0
    }

    /// Predict if a block can fit in current chunk without crossing a split boundary, and, in a
    /// replay, without running past the replay's target: `insn_count` bounds the instructions the
    /// block runs, so one that fits ends at or before it. `memory_insns`, the block's loads and
    /// stores, bounds its misaligned accesses (`chunk_split::can_fit_block`).
    #[inline(always)]
    pub fn can_fit_block(
        &self,
        insn_count: u32,
        mem_rw_exact: usize,
        non_register_global_lookup_base_max: usize,
        reg_write_mask: u32,
        memory_insns: usize,
    ) -> bool {
        debug_assert_eq!(CLOCK_INCREMENT_PER_INSN, 4);
        self.insn_count + u64::from(insn_count) <= self.replay_target
            && self.chunk_split_state.can_fit_block(
                self.clk,
                insn_count,
                mem_rw_exact,
                non_register_global_lookup_base_max,
                reg_write_mask,
                memory_insns,
                &self.chunk_split_config,
            )
    }

    /// Adds a block's rows on one per-instruction chip (`chunk_split::LEAF_*`); the generated
    /// code tallies them per block at compile time.
    #[inline(always)]
    pub fn add_leaf_rows(&mut self, chip: usize, rows: u32) {
        self.chunk_split_state.add_leaf_rows(chip, rows);
    }
}

#[cfg(test)]
mod tests {
    use super::{AotEmulatorCore, CHUNK_CLK_START};
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
            commit_tail_reserve: 0,
            commit_tail_overrun: 0,
            leaf_cap: 0,
            misaligned_threshold: usize::MAX,
        };
        emu
    }

    #[test]
    fn chunk_boundary_waits_for_a_half_written_digest() {
        let mut emu = test_emu();
        emu.chunk_split_config.commit_tail_reserve = 16;
        emu.clk = 240;
        assert!(emu.check_chunk_boundary());

        let mut emu = test_emu();
        emu.chunk_split_config.commit_tail_reserve = 16;
        emu.chunk_split_state.commit_in_flight = true;
        emu.clk = 240;
        assert!(!emu.check_chunk_boundary());
        emu.clk = 256;
        assert!(emu.check_chunk_boundary());
        assert!(
            !emu.chunk_split_state.commit_in_flight,
            "the cut clears the flag"
        );
    }

    #[test]
    #[should_panic(expected = "the chunk counter fits u32")]
    fn a_cut_past_the_last_chunk_number_is_refused() {
        let mut emu = test_emu();
        emu.current_chunk = u32::MAX;
        emu.clk = 256;
        emu.check_chunk_boundary();
    }

    #[test]
    fn chunk_boundary_splits_on_cycle_limit() {
        let mut emu = test_emu();
        emu.clk = 256;

        assert!(emu.check_chunk_boundary());
        assert_eq!(emu.current_chunk, 2);
        assert_eq!(emu.clk, CHUNK_CLK_START);
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

        assert!(!emu.can_fit_block(2, 0, 0, 0, 0));
    }

    #[test]
    fn can_fit_block_rejects_on_event_threshold_crossing() {
        let mut emu = test_emu();
        emu.chunk_split_state.num_memory_read_write_events = 3;
        emu.chunk_split_state.num_global_lookup_base = 1;

        assert!(!emu.can_fit_block(1, 2, 1, 0, 0));
    }

    #[test]
    fn can_fit_block_accepts_exact_threshold_without_strict_crossing() {
        let mut emu = test_emu();
        emu.chunk_split_state.num_memory_read_write_events = 3;
        emu.chunk_split_state.num_global_lookup_base = 1;

        assert!(emu.can_fit_block(1, 1, 1, 0, 0));
    }

    #[test]
    fn can_fit_block_rejects_multi_instruction_aggregate_crossing() {
        let mut emu = test_emu();
        emu.chunk_split_state.num_memory_read_write_events = 2;
        emu.chunk_split_state.num_global_lookup_base = 1;

        assert!(!emu.can_fit_block(4, 3, 2, 0, 0));
    }

    #[test]
    fn can_fit_block_does_not_charge_registers_already_written_in_chunk() {
        let mut emu = test_emu();
        emu.chunk_split_state.num_memory_read_write_events = 3;
        emu.chunk_split_state.track_address(1);
        emu.chunk_split_config.global_lookup_base_threshold = 1;

        assert!(emu.can_fit_block(1, 1, 0, 1 << 1, 0));
        assert!(!emu.can_fit_block(1, 1, 0, 1 << 2, 0));
    }

    #[test]
    fn chunk_boundary_fast_cuts_at_the_misaligned_cap() {
        let mut emu = test_emu();
        emu.chunk_split_config.misaligned_threshold = 3;
        emu.clk = 128;
        emu.chunk_split_state.num_misaligned = 2;
        assert!(!emu.check_chunk_boundary_fast());

        emu.chunk_split_state.num_misaligned = 3;
        assert!(emu.check_chunk_boundary_fast());
        assert_eq!(emu.current_chunk, 2);
        assert_eq!(
            emu.chunk_split_state.num_misaligned, 0,
            "the cut starts a new count"
        );
    }

    #[test]
    fn can_fit_block_keeps_the_blocks_loads_and_stores_below_the_cap() {
        let mut emu = test_emu();
        emu.chunk_split_config.misaligned_threshold = 3;
        emu.chunk_split_state.num_misaligned = 1;

        assert!(emu.can_fit_block(1, 1, 1, 0, 1));
        assert!(!emu.can_fit_block(2, 2, 2, 0, 2));
    }

    #[test]
    fn a_misaligned_access_counts_toward_the_cap_outside_unconstrained_mode() {
        let mut emu = test_emu();
        emu.write_mem_dword(0x2_0000, 0x1122_3344_5566_7788);
        emu.misaligned_load(Opcode::LW, 0x2_0002, 4).unwrap();
        assert_eq!(emu.chunk_split_state.num_misaligned, 1);
        assert_eq!(emu.misaligned_accesses, 1);

        emu.enter_unconstrained_mode();
        emu.misaligned_load(Opcode::LW, 0x2_0002, 4).unwrap();
        assert_eq!(emu.chunk_split_state.num_misaligned, 1);
    }
}
