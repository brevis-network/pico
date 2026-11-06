//! The sink a replay worker's recording blocks write into, lent to them once per dispatch run
//! ([`AotEmulatorCore::run_record_blocks`]) rather than once per instruction.
//!
//! A recording block ([`RecordBlockFn`]) writes the rows of every instruction but `ECALL` directly,
//! through an entry here (`alu_direct_rec`, `load_direct_rec` and the like) to which the generated
//! code hands the program's instruction at its pc, its ALU list and whether it writes `x0`, all
//! constants. The entry appends the rows itself ([`HistoryRows`]): no cycle buffer, slot test,
//! operand rule or program fetch. A branch or `JAL` whose target no row holds (rows hold pcs as
//! `u32`) goes through its emitting body (a `_rec` entry) instead: such a target is outside the
//! program, so `check_jump_target` ends the run at the jump, before any cut. A `JALR`'s entry
//! checks its target before it writes anything, as the interpreter does, so one no row holds
//! fails there.
//!
//! The rows must be the interpreter's. Registers are read `c`, `b`, then `a` for a store or a
//! branch, at the clock plus the slot (`c` 1, `b` 2, `a` 3); `x0` reads and commits 0 and is still
//! recorded. A load or a store accesses its dword at the clock itself through
//! `read_and_update_metadata` or `write_and_capture_prev`, which set the accessed bit the
//! finalisation reads; a narrow store merges into the dword `peek_dword` finds and records that
//! dword as the value it replaced. An access the memory guard refuses (`guard::access_fault`)
//! fails as the emitting body's does, after the register reads and before memory is touched. A
//! misaligned one is counted as the emitting body counts it and goes to the unaligned table rather
//! than the memory list; when it runs into the next dword, it accesses that one at the clock plus
//! `C`, a local event and the table's next-dword access.
//!
//! A direct entry skips what only the snapshot thread reads: the touched-register mark, the
//! first-touch memory store and the chunk-split estimate and counts (`track_chunk_split_address`,
//! a misaligned store's next-dword write). That holds
//! only on a replay worker, which [`AotEmulatorCore::run_record_blocks`] asserts: it hands out no
//! snapshot, and `recover_in_place` turns its chunk split off (`ChunkSplitConfig::disabled`), so
//! neither `can_fit_block` nor `should_split` depends on the skipped counts and the replay stops
//! only at its target.
//!
//! **Operand exceptions.** [`ExecutionHistory::operands`] rebuilds `b` and `c` from exactly what
//! the entries take, and `a` as `pc + 4` for a jump and the `a` slot's value otherwise. Only an ALU
//! instruction, `AUIPC` or a load into `x0` can compute an `a` other than the 0 its slot commits,
//! so only those entries compare `a` with 0.
//!
//! The core holds no sink while the recorder does, so the fallback interpreter and `ECALL` run
//! inside [`AotEmulatorCore::with_sink_on_core`]; the sink is back on the core however the run
//! ends. A recording block tests no chunk boundary, since the replay's split is off. A block
//! reserves its direct rows' room once ([`AotEmulatorCore::reserve_rows_rec`]), and one that stops
//! part way leaves only the rows of the instructions it completed.
//!
//! No recording block runs inside an unconstrained region or past the replay's target
//! ([`AotEmulatorCore::can_run_record_block`]): a direct write keeps nothing for a region's
//! rollback, and the fallback, which writes nothing inside a region, runs a chunk's tail to the
//! target one instruction at a time.
//!
//! With `recorder-check`, every direct step is also closed by the shared writer's generic code, and
//! the run panics where the two differ or an instruction is not the program's at its pc. Both see
//! the same values, so only comparing records with the interpreter's catches a wrong value.
//!
//! The entries are calls: inlined, a block of a few thousand instructions becomes one function the
//! code generator takes minutes to optimise, and the replay runs slower, not faster.
//!
//! [`RecordBlockFn`]: crate::RecordBlockFn
//! [`HistoryRows`]: pico_vm::emulator::riscv::sink::HistoryRows
//! [`ExecutionHistory::operands`]: pico_vm::emulator::riscv::history::ExecutionHistory::operands

use pico_vm::{
    chips::chips::riscv_memory::event::{MemoryAccessPosition, MemoryRecord},
    compiler::riscv::{instruction::Instruction, opcode::Opcode},
    emulator::riscv::{
        history::{Access, ReadAccess},
        record::AluStream,
        riscv_emulator::{
            guard::access_width,
            util::{dword_bytes, splice_dword, straddling_bytes},
        },
        sink::BlockRows,
    },
};

/// The chip list a direct step also goes into, besides the CPU's.
#[derive(Clone, Copy)]
enum ChipList {
    None,
    Alu(AluStream),
    Memory,
    /// A misaligned load or store, with its next-dword access when it crosses into that dword.
    Unaligned(Option<Access>),
    Branch,
}

use super::{
    sink::{AotSink, LentSink},
    types::RegisterRecord,
    AotEmulatorCore,
};
use crate::types::{NextStep, RecordStep};

/// The core's sink, held for one dispatch run of recording blocks.
pub struct Recorder {
    /// Off while [`AotEmulatorCore::with_sink_on_core`] has the sink on the core, and on a core
    /// that records nothing.
    sink: AotSink,
}

impl Recorder {
    #[inline(always)]
    pub(crate) fn sink(&mut self) -> LentSink<'_> {
        match &mut self.sink {
            AotSink::Recording(sink) => Some(&mut **sink),
            AotSink::Off => None,
        }
    }
}

pub(crate) struct RecordingRun<'a> {
    pub(crate) core: &'a mut AotEmulatorCore,
    pub(crate) recorder: Recorder,
}

impl<'a> RecordingRun<'a> {
    pub(crate) fn new(core: &'a mut AotEmulatorCore) -> Self {
        let sink = std::mem::take(&mut core.sink);
        Self {
            core,
            recorder: Recorder { sink },
        }
    }
}

/// An unwind out of [`AotEmulatorCore::with_sink_on_core`] leaves the sink on the core, so only a
/// sink the recorder still holds goes back.
impl Drop for RecordingRun<'_> {
    fn drop(&mut self) {
        if matches!(self.recorder.sink, AotSink::Recording(_)) {
            self.core.sink = std::mem::take(&mut self.recorder.sink);
        }
    }
}

impl AotEmulatorCore {
    /// Runs `code` with the recorder's sink back on the core. A `NextStep::Direct` names an
    /// ordinary block, so its pc goes back to the dispatch run to be looked up among the recording
    /// blocks.
    #[inline(always)]
    pub fn with_sink_on_core(
        &mut self,
        rec: &mut Recorder,
        code: impl FnOnce(&mut Self) -> Result<NextStep, String>,
    ) -> Result<RecordStep, String> {
        Ok(match self.on_core_sink(rec, code)? {
            NextStep::Direct(_) => RecordStep::Dynamic(self.pc),
            NextStep::Dynamic(pc) => RecordStep::Dynamic(pc),
            NextStep::Halt => RecordStep::Halt,
        })
    }

    #[inline(always)]
    fn on_core_sink<R>(&mut self, rec: &mut Recorder, code: impl FnOnce(&mut Self) -> R) -> R {
        std::mem::swap(&mut self.sink, &mut rec.sink);
        let result = code(self);
        std::mem::swap(&mut self.sink, &mut rec.sink);
        result
    }

    /// Whether a recording block of `insn_count` instructions runs rather than falling back: only
    /// outside an unconstrained region, and only if it ends by the replay's target. The target
    /// alone decides, since a replay worker's chunk split is off (the module header); a debug
    /// build checks that the split's estimate agrees.
    #[inline(always)]
    pub fn can_run_record_block(
        &self,
        insn_count: u32,
        mem_rw_exact: usize,
        non_register_global_lookup_base_max: usize,
        reg_write_mask: u32,
        memory_insns: usize,
    ) -> bool {
        let fits = self.insn_count + u64::from(insn_count) <= self.replay_target;
        debug_assert!(
            !fits
                || self.chunk_split_state.can_fit_block(
                    self.clk,
                    insn_count,
                    mem_rw_exact,
                    non_register_global_lookup_base_max,
                    reg_write_mask,
                    memory_insns,
                    &self.chunk_split_config,
                ),
            "the chunk split refuses a recording block of {insn_count} instruction(s) at clk {} \
             that the replay's target admits",
            self.clk
        );
        fits && !self.is_unconstrained_mode()
    }

    /// Counts a recording block past [`Self::can_run_record_block`]: `insns` run, `direct` of them
    /// written directly.
    #[inline(always)]
    pub fn count_recorder_block(&mut self, insns: u32, direct: u32) {
        self.recorder_body_dispatches += 1;
        self.recorder_body_insns += u64::from(insns);
        self.recorder_direct_insns += u64::from(direct);
    }

    /// Recording blocks that ran their instructions: unlike
    /// [`Self::compiled_block_dispatches`], none that fell back on entry.
    pub fn recorder_body_dispatches(&self) -> u64 {
        self.recorder_body_dispatches
    }

    /// Instructions recording blocks ran; with [`Self::fallback_insns`], every instruction of a
    /// recording run.
    pub fn recorder_body_insns(&self) -> u64 {
        self.recorder_body_insns
    }

    /// Of [`Self::recorder_body_insns`], those written directly: not the `ECALL`s, nor a branch or
    /// `JAL` left to its emitting body.
    pub fn recorder_direct_insns(&self) -> u64 {
        self.recorder_direct_insns
    }
}

impl AotEmulatorCore {
    /// Reserves table room for a recording block's direct rows, once per block.
    #[inline(always)]
    pub fn reserve_rows_rec(&mut self, rec: &mut Recorder, room: BlockRows) {
        if let Some(sink) = rec.sink() {
            sink.history_rows().reserve(&room);
        }
    }

    /// Runs the ALU instruction `insn`, the program's at `pc`, whose destination is not `x0`, and
    /// writes its rows, its event in `stream`'s list.
    #[inline(never)]
    pub fn alu_direct_rec(
        &mut self,
        rec: &mut Recorder,
        pc: u32,
        insn: Instruction,
        stream: AluStream,
    ) {
        debug_assert_ne!(insn.op_a, 0, "{insn:?} writes x0");
        self.alu_direct(rec, pc, insn, Some(stream), false);
    }

    /// [`Self::alu_direct_rec`] for an `x0` destination: no ALU event, and an operand exception
    /// when the value computed is not the 0 committed.
    #[inline(never)]
    pub fn alu_x0_direct_rec(&mut self, rec: &mut Recorder, pc: u32, insn: Instruction) {
        debug_assert_eq!(insn.op_a, 0, "{insn:?} does not write x0");
        self.alu_direct(rec, pc, insn, None, true);
    }

    /// [`Self::alu_direct_rec`] for `AUIPC`, which writes no ALU event.
    #[inline(never)]
    pub fn auipc_direct_rec(&mut self, rec: &mut Recorder, pc: u32, insn: Instruction) {
        debug_assert_ne!(insn.op_a, 0, "{insn:?} writes x0");
        self.auipc_direct(rec, pc, insn, false);
    }

    /// [`Self::auipc_direct_rec`] for an `x0` destination: an operand exception when `pc + op_b`
    /// is not 0.
    #[inline(never)]
    pub fn auipc_x0_direct_rec(&mut self, rec: &mut Recorder, pc: u32, insn: Instruction) {
        debug_assert_eq!(insn.op_a, 0, "{insn:?} does not write x0");
        self.auipc_direct(rec, pc, insn, true);
    }

    /// Reads `c` before `b`, the interpreter's order, so a register in both slots is read at
    /// rising timestamps.
    #[inline(always)]
    fn alu_direct(
        &mut self,
        rec: &mut Recorder,
        pc: u32,
        insn: Instruction,
        alu: Option<AluStream>,
        x0: bool,
    ) {
        use MemoryAccessPosition::{A, B, C};
        let mut sink = rec.sink();
        let rd = usize::from(insn.op_a);
        let list = alu.map_or(ChipList::None, ChipList::Alu);
        if !insn.imm_c {
            let (c, read_c) = self.read_reg_direct(sink.as_deref_mut(), insn.op_c as usize, C);
            let (b, read_b) = self.read_reg_direct(sink.as_deref_mut(), insn.op_b as usize, B);
            let a = Self::alu_value(insn.opcode, b, c);
            let write = self.write_reg_direct(sink.as_deref_mut(), rd, a);
            let reads = [(B, read_b), (C, read_c)];
            self.close_direct(sink, pc, insn, reads, [(A, write)], list, x0, [a, b, c]);
        } else if !insn.imm_b {
            let (b, read_b) = self.read_reg_direct(sink.as_deref_mut(), insn.op_b as usize, B);
            let c = insn.op_c;
            let a = Self::alu_value(insn.opcode, b, c);
            let write = self.write_reg_direct(sink.as_deref_mut(), rd, a);
            let reads = [(B, read_b)];
            self.close_direct(sink, pc, insn, reads, [(A, write)], list, x0, [a, b, c]);
        } else {
            let (b, c) = (insn.op_b, insn.op_c);
            let a = Self::alu_value(insn.opcode, b, c);
            let write = self.write_reg_direct(sink.as_deref_mut(), rd, a);
            self.close_direct(sink, pc, insn, [], [(A, write)], list, x0, [a, b, c]);
        }
    }

    /// `b` and `c` are both `op_b`, as in the interpreter's event.
    #[inline(always)]
    fn auipc_direct(&mut self, rec: &mut Recorder, pc: u32, insn: Instruction, x0: bool) {
        let mut sink = rec.sink();
        let imm = insn.op_b;
        let a = u64::from(pc).wrapping_add(imm);
        let write = self.write_reg_direct(sink.as_deref_mut(), usize::from(insn.op_a), a);
        let writes = [(MemoryAccessPosition::A, write)];
        self.close_direct(
            sink,
            pc,
            insn,
            [],
            writes,
            ChipList::None,
            x0,
            [a, imm, imm],
        );
    }

    /// Runs the load `insn`, the program's at `pc`, whose destination is not `x0`, and writes its
    /// rows.
    ///
    /// # Errors
    ///
    /// The emitting body's, on an access the memory guard refuses.
    #[inline(never)]
    pub fn load_direct_rec(
        &mut self,
        rec: &mut Recorder,
        pc: u32,
        insn: Instruction,
    ) -> Result<(), String> {
        debug_assert_ne!(insn.op_a, 0, "{insn:?} writes x0");
        self.load_direct(rec, pc, insn, false)
    }

    /// [`Self::load_direct_rec`] for an `x0` destination: an operand exception when the value
    /// loaded is not 0.
    ///
    /// # Errors
    ///
    /// As [`Self::load_direct_rec`].
    #[inline(never)]
    pub fn load_x0_direct_rec(
        &mut self,
        rec: &mut Recorder,
        pc: u32,
        insn: Instruction,
    ) -> Result<(), String> {
        debug_assert_eq!(insn.op_a, 0, "{insn:?} does not write x0");
        self.load_direct(rec, pc, insn, true)
    }

    /// Runs the store `insn`, the program's at `pc`, and writes its rows.
    ///
    /// # Errors
    ///
    /// The emitting body's, on an access the memory guard refuses.
    #[inline(never)]
    pub fn store_direct_rec(
        &mut self,
        rec: &mut Recorder,
        pc: u32,
        insn: Instruction,
    ) -> Result<(), String> {
        use MemoryAccessPosition::{Memory, A, B};
        let mut sink = rec.sink();
        let (b, read_b) = self.read_reg_direct(sink.as_deref_mut(), insn.op_b as usize, B);
        let (a, read_a) = self.read_reg_direct(sink.as_deref_mut(), usize::from(insn.op_a), A);
        let c = insn.op_c;
        let addr = b.wrapping_add(c);
        self.check_access(insn.opcode, addr)?;
        let (store, list) = if addr.is_multiple_of(access_width(insn.opcode)) {
            let dword_addr = Self::dword_addr(addr);
            let store =
                self.write_mem_direct(sink.as_deref_mut(), dword_addr, |dword| match insn.opcode {
                    Opcode::SB => Self::write_u8_into_word(dword, addr, a),
                    Opcode::SH => Self::write_u16_into_word(dword, addr, a),
                    Opcode::SW => Self::insert_word(dword, addr, a),
                    Opcode::SD => a,
                    other => unreachable!("{other:?} is not a store"),
                });
            (store, ChipList::Memory)
        } else {
            self.misaligned_store_direct(sink.as_deref_mut(), insn.opcode, addr, a)?
        };
        let (reads, writes) = ([(A, read_a), (B, read_b)], [(Memory, store)]);
        self.close_direct(sink, pc, insn, reads, writes, list, false, [a, b, c]);
        Ok(())
    }

    /// Writes the rows of the branch `insn`, the program's at `pc`, and returns whether it is
    /// taken. The generated code moves the pc and the clock, as for the emitting body.
    #[inline(never)]
    pub fn branch_direct_rec(&mut self, rec: &mut Recorder, pc: u32, insn: Instruction) -> bool {
        use MemoryAccessPosition::{A, B};
        let mut sink = rec.sink();
        let (b, read_b) = self.read_reg_direct(sink.as_deref_mut(), insn.op_b as usize, B);
        let (a, read_a) = self.read_reg_direct(sink.as_deref_mut(), usize::from(insn.op_a), A);
        let c = insn.op_c;
        let taken = match insn.opcode {
            Opcode::BEQ => a == b,
            Opcode::BNE => a != b,
            Opcode::BLT => (a as i64) < (b as i64),
            Opcode::BGE => (a as i64) >= (b as i64),
            Opcode::BLTU => a < b,
            Opcode::BGEU => a >= b,
            other => unreachable!("{other:?} is not a branch"),
        };
        let next_pc = if taken {
            Self::target_row_pc(pc, c)
        } else {
            Self::fall_through(pc)
        };
        let reads = [(A, read_a), (B, read_b)];
        self.write_direct(
            sink,
            pc,
            next_pc,
            insn,
            reads,
            [],
            ChipList::Branch,
            false,
            [a, b, c],
        );
        taken
    }

    /// Runs `JAL`, the program's `insn` at `pc`, and writes its rows. The generated code moves the
    /// pc and the clock, as for the emitting body.
    #[inline(never)]
    pub fn jal_direct_rec(&mut self, rec: &mut Recorder, pc: u32, insn: Instruction) {
        let mut sink = rec.sink();
        let a = u64::from(Self::fall_through(pc));
        let write = self.write_reg_direct(sink.as_deref_mut(), usize::from(insn.op_a), a);
        let imm = insn.op_b;
        let next_pc = Self::target_row_pc(pc, imm);
        let writes = [(MemoryAccessPosition::A, write)];
        self.write_direct(
            sink,
            pc,
            next_pc,
            insn,
            [],
            writes,
            ChipList::None,
            false,
            [a, imm, 0],
        );
    }

    /// Runs `JALR`, the program's `insn` at `pc`: checks its target, `(rs1 + imm) & !1`, and only
    /// then writes the link and its rows, so a bad jump leaves `rd` as the interpreter does, `rs1`
    /// the same register or not. Returns the target; the generated code moves the pc and the
    /// clock, as for the emitting body.
    ///
    /// # Errors
    ///
    /// [`Self::check_jump_target`]'s, for a misaligned target or one outside the program; every
    /// target no row holds is outside it.
    #[inline(never)]
    pub fn jalr_direct_rec(
        &mut self,
        rec: &mut Recorder,
        pc: u32,
        insn: Instruction,
    ) -> Result<u64, String> {
        use MemoryAccessPosition::{A, B};
        let (rd, rs1, imm) = (usize::from(insn.op_a), insn.op_b as usize, insn.op_c);
        let target = self.read_reg_unsafe(rs1).wrapping_add(imm) & !1;
        self.check_jump_target(u64::from(pc), target)?;
        let next_pc = u32::try_from(target).expect("a target inside the program is a row's pc");
        let mut sink = rec.sink();
        let (b, read_b) = self.read_reg_direct(sink.as_deref_mut(), rs1, B);
        let a = u64::from(Self::fall_through(pc));
        let write = self.write_reg_direct(sink.as_deref_mut(), rd, a);
        let (reads, writes) = ([(B, read_b)], [(A, write)]);
        self.write_direct(
            sink,
            pc,
            next_pc,
            insn,
            reads,
            writes,
            ChipList::None,
            false,
            [a, b, imm],
        );
        Ok(target)
    }

    #[inline(always)]
    fn load_direct(
        &mut self,
        rec: &mut Recorder,
        pc: u32,
        insn: Instruction,
        x0: bool,
    ) -> Result<(), String> {
        use MemoryAccessPosition::{Memory, A, B};
        let mut sink = rec.sink();
        let (b, read_b) = self.read_reg_direct(sink.as_deref_mut(), insn.op_b as usize, B);
        let c = insn.op_c;
        let addr = b.wrapping_add(c);
        self.check_access(insn.opcode, addr)?;
        let aligned = addr.is_multiple_of(access_width(insn.opcode));
        if !aligned {
            self.misaligned(insn.opcode, addr)?;
        }
        let (dword, read_memory) =
            self.read_mem_direct(sink.as_deref_mut(), Self::dword_addr(addr));
        let (a, list) = if aligned {
            let a = match insn.opcode {
                Opcode::LB => Self::read_u8_from_word(dword, addr) as i8 as i64 as u64,
                Opcode::LBU => u64::from(Self::read_u8_from_word(dword, addr)),
                Opcode::LH => (Self::read_u16_from_word(dword, addr) as i16) as i64 as u64,
                Opcode::LHU => u64::from(Self::read_u16_from_word(dword, addr)),
                Opcode::LW => (Self::extract_word(dword, addr) as u32 as i32) as i64 as u64,
                Opcode::LWU => Self::extract_word(dword, addr),
                Opcode::LD => dword,
                other => unreachable!("{other:?} is not a load"),
            };
            (a, ChipList::Memory)
        } else {
            self.misaligned_load_direct(sink.as_deref_mut(), insn.opcode, addr, dword)
        };
        let write = self.write_reg_direct(sink.as_deref_mut(), usize::from(insn.op_a), a);
        let (reads, writes) = ([(B, read_b), (Memory, read_memory)], [(A, write)]);
        self.close_direct(sink, pc, insn, reads, writes, list, x0, [a, b, c]);
        Ok(())
    }

    /// The value a misaligned load at `addr` puts in its register, extended as `opcode` says,
    /// `dword` being the aligned dword it read; the next dword is read too when the load runs
    /// into it, as the emitting body reads it.
    #[cold]
    #[inline(never)]
    fn misaligned_load_direct(
        &mut self,
        sink: LentSink<'_>,
        opcode: Opcode,
        addr: u64,
        dword: u64,
    ) -> (u64, ChipList) {
        let (offset, width) = (addr % 8, access_width(opcode));
        let (bytes, next) = if offset + width <= 8 {
            (dword_bytes(dword, offset, width), None)
        } else {
            let (next, access) = self.read_next_dword_direct(sink, Self::dword_addr(addr) + 8);
            (straddling_bytes(dword, next, offset, width), Some(access))
        };
        let a = match opcode {
            Opcode::LH => bytes as u16 as i16 as i64 as u64,
            Opcode::LW => bytes as u32 as i32 as i64 as u64,
            Opcode::LHU | Opcode::LWU | Opcode::LD => bytes,
            other => unreachable!("{other:?} is not a load that can be misaligned"),
        };
        (a, ChipList::Unaligned(next))
    }

    /// Writes the low bytes of `value` at a misaligned `addr`, as the emitting body writes them:
    /// the aligned dword's access, the step's memory access, and the next dword's when the store
    /// runs into it.
    #[cold]
    #[inline(never)]
    fn misaligned_store_direct(
        &mut self,
        mut sink: LentSink<'_>,
        opcode: Opcode,
        addr: u64,
        value: u64,
    ) -> Result<(Access, ChipList), String> {
        self.misaligned(opcode, addr)?;
        let (offset, width) = (addr % 8, access_width(opcode));
        let low = width.min(8 - offset);
        let dword_addr = Self::dword_addr(addr);
        let store = self.write_mem_direct(sink.as_deref_mut(), dword_addr, |dword| {
            splice_dword(dword, offset, low, value)
        });
        let next = (low < width).then(|| {
            self.write_next_dword_direct(sink, dword_addr + 8, width - low, value >> (8 * low))
        });
        Ok((store, ChipList::Unaligned(next)))
    }

    /// Reads the dword at `addr`, the one after a misaligned load's aligned dword, at the clock
    /// plus `C`.
    fn read_next_dword_direct(&mut self, sink: LentSink<'_>, addr: u64) -> (u64, Access) {
        let (value, read) = self.read_mem_direct_at(sink, addr, self.clk + 1);
        let access = Access {
            value,
            prev_value: value,
            prev_chunk: read.prev_chunk,
            prev_timestamp: read.prev_timestamp,
        };
        (value, access)
    }

    /// Replaces the low `width` bytes of the dword at `addr`, the one after a misaligned store's
    /// aligned dword, with those of `value`, at the clock plus `C`.
    fn write_next_dword_direct(
        &mut self,
        sink: LentSink<'_>,
        addr: u64,
        width: u64,
        value: u64,
    ) -> Access {
        self.write_mem_direct_at(sink, addr, self.clk + 1, |found| {
            splice_dword(found, 0, width, value)
        })
    }

    #[inline(always)]
    fn target_row_pc(pc: u32, offset: u64) -> u32 {
        u32::try_from(u64::from(pc).wrapping_add(offset))
            .expect("the code generator writes a jump's rows directly only to a target a row holds")
    }

    #[inline(always)]
    fn fall_through(pc: u32) -> u32 {
        pc.checked_add(4)
            .expect("the code generator writes direct rows only below a pc of 2^32 - 4")
    }

    /// The interpreter's ALU arithmetic, which the ordinary helpers each repeat in their own body.
    #[inline(always)]
    fn alu_value(opcode: Opcode, b: u64, c: u64) -> u64 {
        let word = |value: u32| Self::sign_extend_word_result_u64(u64::from(value));
        let (lhs, rhs) = (b as u32, c as u32);
        match opcode {
            Opcode::ADD => b.wrapping_add(c),
            Opcode::SUB => b.wrapping_sub(c),
            Opcode::XOR => b ^ c,
            Opcode::OR => b | c,
            Opcode::AND => b & c,
            Opcode::SLL => b.wrapping_shl(Self::shift_amount_u32(c)),
            Opcode::SRL => b.wrapping_shr(Self::shift_amount_u32(c)),
            Opcode::SRA => (b as i64).wrapping_shr(Self::shift_amount_u32(c)) as u64,
            Opcode::SLT => u64::from((b as i64) < (c as i64)),
            Opcode::SLTU => u64::from(b < c),
            Opcode::MUL => b.wrapping_mul(c),
            Opcode::MULH => Self::rv64_mulh_result_u64(b, c),
            Opcode::MULHU => Self::rv64_mulhu_result_u64(b, c),
            Opcode::MULHSU => Self::rv64_mulhsu_result_u64(b, c),
            Opcode::DIV => Self::rv64_div_result_u64(b, c),
            Opcode::DIVU => Self::rv64_divu_result_u64(b, c),
            Opcode::REM => Self::rv64_rem_result_u64(b, c),
            Opcode::REMU => Self::rv64_remu_result_u64(b, c),
            Opcode::ADDW => word(lhs.wrapping_add(rhs)),
            Opcode::SUBW => word(lhs.wrapping_sub(rhs)),
            Opcode::SLLW => word(lhs.wrapping_shl(Self::word_shift_amount_u32(c))),
            Opcode::SRLW => word(lhs.wrapping_shr(Self::word_shift_amount_u32(c))),
            Opcode::SRAW => word((lhs as i32).wrapping_shr(Self::word_shift_amount_u32(c)) as u32),
            Opcode::MULW => word(lhs.wrapping_mul(rhs)),
            Opcode::DIVW => {
                let (lhs, rhs) = (lhs as i32, rhs as i32);
                word(if rhs == 0 {
                    u32::MAX
                } else if lhs == i32::MIN && rhs == -1 {
                    lhs as u32
                } else {
                    lhs.wrapping_div(rhs) as u32
                })
            }
            Opcode::DIVUW => word(lhs.checked_div(rhs).unwrap_or(u32::MAX)),
            Opcode::REMW => {
                let (lhs, rhs) = (lhs as i32, rhs as i32);
                word(if rhs == 0 {
                    lhs as u32
                } else if lhs == i32::MIN && rhs == -1 {
                    0
                } else {
                    lhs.wrapping_rem(rhs) as u32
                })
            }
            Opcode::REMUW => word(lhs.checked_rem(rhs).unwrap_or(lhs)),
            other => unreachable!("{other:?} is not an ALU instruction"),
        }
    }

    #[inline(always)]
    fn read_reg_direct(
        &mut self,
        sink: LentSink<'_>,
        reg: usize,
        position: MemoryAccessPosition,
    ) -> (u64, ReadAccess) {
        let (chunk, timestamp) = (self.current_chunk, self.clk.wrapping_add(position as u32));
        let prev = self.registers[reg];
        self.registers[reg] = RegisterRecord {
            chunk,
            timestamp,
            value: prev.value,
        };
        let value = if reg == 0 { 0 } else { prev.value };
        if let Some(sink) = sink {
            sink.local_register_event(
                reg,
                MemoryRecord {
                    value,
                    chunk: prev.chunk,
                    timestamp: prev.timestamp,
                },
                MemoryRecord {
                    value,
                    chunk,
                    timestamp,
                },
            );
        }
        let read = ReadAccess {
            value,
            prev_chunk: prev.chunk,
            prev_timestamp: prev.timestamp,
        };
        (value, read)
    }

    #[inline(always)]
    fn write_reg_direct(&mut self, sink: LentSink<'_>, reg: usize, value: u64) -> Access {
        let timestamp = self.clk.wrapping_add(MemoryAccessPosition::A as u32);
        let (chunk, prev) = (self.current_chunk, self.registers[reg]);
        let (prev_value, written) = if reg == 0 {
            (0, 0)
        } else {
            (prev.value, value)
        };
        self.registers[reg] = RegisterRecord {
            chunk,
            timestamp,
            value: written,
        };
        if let Some(sink) = sink {
            sink.local_register_event(
                reg,
                MemoryRecord {
                    value: prev_value,
                    chunk: prev.chunk,
                    timestamp: prev.timestamp,
                },
                MemoryRecord {
                    value: written,
                    chunk,
                    timestamp,
                },
            );
        }
        Access {
            value: written,
            prev_value,
            prev_chunk: prev.chunk,
            prev_timestamp: prev.timestamp,
        }
    }

    #[inline(always)]
    fn read_mem_direct(&mut self, sink: LentSink<'_>, addr: u64) -> (u64, ReadAccess) {
        self.read_mem_direct_at(sink, addr, self.clk)
    }

    /// [`Self::read_mem_direct`] at `timestamp`.
    #[inline(always)]
    fn read_mem_direct_at(
        &mut self,
        sink: LentSink<'_>,
        addr: u64,
        timestamp: u32,
    ) -> (u64, ReadAccess) {
        let chunk = self.current_chunk;
        let (value, prev_chunk, prev_timestamp) =
            self.memory.read_and_update_metadata(addr, chunk, timestamp);
        if let Some(sink) = sink {
            sink.local_event(
                addr,
                MemoryRecord {
                    value,
                    chunk: prev_chunk,
                    timestamp: prev_timestamp,
                },
                MemoryRecord {
                    value,
                    chunk,
                    timestamp,
                },
            );
        }
        let read = ReadAccess {
            value,
            prev_chunk,
            prev_timestamp,
        };
        (value, read)
    }

    /// The row records the dword found, before `merge`, as the value the write replaced.
    #[inline(always)]
    fn write_mem_direct(
        &mut self,
        sink: LentSink<'_>,
        addr: u64,
        merge: impl FnOnce(u64) -> u64,
    ) -> Access {
        self.write_mem_direct_at(sink, addr, self.clk, merge)
    }

    /// [`Self::write_mem_direct`] at `timestamp`.
    #[inline(always)]
    fn write_mem_direct_at(
        &mut self,
        sink: LentSink<'_>,
        addr: u64,
        timestamp: u32,
        merge: impl FnOnce(u64) -> u64,
    ) -> Access {
        let chunk = self.current_chunk;
        let found = self.memory.peek_dword(addr);
        let value = merge(found);
        let (_, prev_chunk, prev_timestamp) = self
            .memory
            .write_and_capture_prev(addr, value, chunk, timestamp);
        if let Some(sink) = sink {
            sink.local_event(
                addr,
                MemoryRecord {
                    value: found,
                    chunk: prev_chunk,
                    timestamp: prev_timestamp,
                },
                MemoryRecord {
                    value,
                    chunk,
                    timestamp,
                },
            );
        }
        Access {
            value,
            prev_value: found,
            prev_chunk,
            prev_timestamp,
        }
    }

    /// Appends the step, its entry in `list` and any `x0` operand exception. `reads` and `writes`
    /// must each be in slot order.
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(not(feature = "recorder-check"), allow(unused_variables))]
    fn write_direct<const READS: usize, const WRITES: usize>(
        &mut self,
        sink: LentSink<'_>,
        pc: u32,
        next_pc: u32,
        insn: Instruction,
        reads: [(MemoryAccessPosition, ReadAccess); READS],
        writes: [(MemoryAccessPosition, Access); WRITES],
        list: ChipList,
        x0: bool,
        operands: [u64; 3],
    ) {
        let Some(sink) = sink else {
            return;
        };
        let mut rows = sink.history_rows();
        let step = rows.step(
            self.current_chunk,
            self.clk,
            pc,
            next_pc,
            reads.map(|(_, read)| read),
            writes.map(|(_, write)| write),
        );
        match list {
            ChipList::None => {}
            ChipList::Alu(stream) => rows.alu(stream, step),
            ChipList::Memory => rows.memory(step),
            ChipList::Unaligned(next) => rows.unaligned(step, next),
            ChipList::Branch => rows.branch(step),
        }
        let [a, ..] = operands;
        if x0 && a != 0 {
            rows.operand_exception(step, MemoryAccessPosition::A, a);
        }
        #[cfg(feature = "recorder-check")]
        self.check_direct(
            &rows, step, pc, next_pc, insn, &reads, &writes, list, operands,
        );
    }

    /// [`Self::write_direct`] for an instruction that falls through, then the pc and the clock
    /// move on.
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    fn close_direct<const READS: usize, const WRITES: usize>(
        &mut self,
        sink: LentSink<'_>,
        pc: u32,
        insn: Instruction,
        reads: [(MemoryAccessPosition, ReadAccess); READS],
        writes: [(MemoryAccessPosition, Access); WRITES],
        list: ChipList,
        x0: bool,
        operands: [u64; 3],
    ) {
        let next_pc = Self::fall_through(pc);
        self.write_direct(sink, pc, next_pc, insn, reads, writes, list, x0, operands);
        self.pc = u64::from(next_pc);
        self.update_insn_clock();
    }

    /// Compares the step just written with the generic close's for the same accesses, and `insn`
    /// with the program's at `pc`.
    #[cfg(feature = "recorder-check")]
    #[cold]
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn check_direct(
        &self,
        rows: &pico_vm::emulator::riscv::sink::HistoryRows<'_>,
        step: u32,
        pc: u32,
        next_pc: u32,
        insn: Instruction,
        reads: &[(MemoryAccessPosition, ReadAccess)],
        writes: &[(MemoryAccessPosition, Access)],
        list: ChipList,
        operands: [u64; 3],
    ) {
        use pico_vm::chips::chips::riscv_memory::event::{
            MemoryReadRecord, MemoryRecordEnum, MemoryWriteRecord,
        };
        let fetched = self.program.fetch(u64::from(pc));
        assert!(
            insn == fetched,
            "the recording block's instruction at {pc:#x}, {insn:?}, is not the program's, \
             {fetched:?}"
        );
        let (chunk, clk) = (self.current_chunk, self.clk);
        let at = |position: MemoryAccessPosition| clk.wrapping_add(position as u32);
        let read_records = reads.iter().map(|&(position, read)| {
            let record = MemoryReadRecord::new(
                read.value,
                chunk,
                at(position),
                read.prev_chunk,
                read.prev_timestamp,
            );
            (position, MemoryRecordEnum::from(record))
        });
        let write_records = writes.iter().map(|&(position, write)| {
            let record = MemoryWriteRecord::new(
                write.value,
                chunk,
                at(position),
                write.prev_value,
                write.prev_chunk,
                write.prev_timestamp,
            );
            (position, MemoryRecordEnum::from(record))
        });
        let accesses: Vec<_> = read_records.chain(write_records).collect();
        // The next dword's access, at the clock plus `C`: a store writes it, a load reads it.
        let next = match list {
            ChipList::Unaligned(Some(next))
                if matches!(
                    fetched.opcode,
                    Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD
                ) =>
            {
                Some(
                    MemoryWriteRecord::new(
                        next.value,
                        chunk,
                        clk + 1,
                        next.prev_value,
                        next.prev_chunk,
                        next.prev_timestamp,
                    )
                    .into(),
                )
            }
            ChipList::Unaligned(Some(next)) => Some(
                MemoryReadRecord::new(
                    next.value,
                    chunk,
                    clk + 1,
                    next.prev_chunk,
                    next.prev_timestamp,
                )
                .into(),
            ),
            _ => None,
        };
        // As an ordinary helper decides it, from the program's instruction.
        let alu = fetched.is_alu_instruction() && fetched.op_a != 0;
        rows.check_step(
            step,
            chunk,
            u64::from(clk),
            u64::from(pc),
            u64::from(next_pc),
            &accesses,
            next,
            alu,
            operands,
            &fetched,
        );
    }
}

#[cfg(test)]
mod tests {
    use std::{
        panic::{catch_unwind, AssertUnwindSafe},
        process::Command,
        sync::Arc,
    };

    use p3_koala_bear::KoalaBear;
    use pico_vm::{
        chips::chips::riscv_memory::event::MemoryAccessPosition,
        compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
        emulator::{
            opts::EmulatorOpts,
            riscv::{
                history::Slots,
                history_arena::Table,
                public_values::RecordFinalPvsState,
                record::{AluStream, EmulationRecord},
                record_digest::{field_digests, first_difference, is_compared},
                record_slots::{hold_records_unbounded, init_record_slots},
                riscv_emulator::{EmulationDeferredState, RiscvEmulator},
                sink::BlockRows,
                state::RiscvEmulationState,
                syscalls::SyscallCode,
            },
        },
    };

    use super::Recorder;
    use crate::{
        emulator::EmittedChunk, AotEmulatorCore, BlockFn, NextStep, RecordBlockFn, RecordStep,
    };

    const HALT: u32 = SyscallCode::HALT as u32;
    const ECALL: Instruction = Instruction::new(Opcode::ECALL, 5, 10, 11, false, false);

    const fn addi(rd: u8, rs1: u64, imm: u64) -> Instruction {
        Instruction::new(Opcode::ADD, rd, rs1, imm, false, true)
    }

    /// `ADDI x5, x0, code`, `ADDI x1, x1, 1`, then an `ECALL` of syscall `code` with `a0 = 0`.
    fn program(code: u32) -> Arc<Program> {
        Arc::new(Program::new(
            vec![addi(5, 0, u64::from(code)), addi(1, 1, 1), ECALL],
            0x1000,
            0x1000,
        ))
    }

    /// `ADDI x5, x0, ED_ADD`, `ADDI x10, x0, p`, then the `ECALL`: the precompile panics on its
    /// misaligned point `p`, where the memory guard would let it read.
    fn unwinding_program() -> Arc<Program> {
        Arc::new(Program::new(
            vec![
                addi(5, 0, SyscallCode::ED_ADD as u64),
                addi(10, 0, BASE + 1),
                ECALL,
            ],
            0x1000,
            0x1000,
        ))
    }

    fn is_load(insn: &Instruction) -> bool {
        insn.is_memory_instruction() && Slots::of(insn).writes(MemoryAccessPosition::A)
    }

    /// One instruction as the code generator writes it into a recording block. A branch or a jump
    /// returns its next pc, its target checked where the generated code checks it: a `JAL`'s
    /// before its link, a `JALR`'s in its entry.
    fn direct(
        emu: &mut AotEmulatorCore,
        rec: &mut Recorder,
        pc: u32,
        insn: Instruction,
    ) -> Result<Option<u64>, String> {
        let x0 = insn.op_a == 0;
        let pc_plus = |offset: u64| u64::from(pc).wrapping_add(offset);
        match insn.opcode {
            Opcode::AUIPC if x0 => emu.auipc_x0_direct_rec(rec, pc, insn),
            Opcode::AUIPC => emu.auipc_direct_rec(rec, pc, insn),
            Opcode::JAL => {
                emu.check_jump_target(u64::from(pc), pc_plus(insn.op_b))?;
                emu.jal_direct_rec(rec, pc, insn);
                return Ok(Some(pc_plus(insn.op_b)));
            }
            Opcode::JALR => return Ok(Some(emu.jalr_direct_rec(rec, pc, insn)?)),
            _ if insn.is_branch_instruction() => {
                let taken = emu.branch_direct_rec(rec, pc, insn);
                if taken {
                    emu.check_jump_target(u64::from(pc), pc_plus(insn.op_c))?;
                }
                return Ok(Some(pc_plus(if taken { insn.op_c } else { 4 })));
            }
            _ if is_load(&insn) && x0 => emu.load_x0_direct_rec(rec, pc, insn)?,
            _ if is_load(&insn) => emu.load_direct_rec(rec, pc, insn)?,
            _ if insn.is_memory_instruction() => emu.store_direct_rec(rec, pc, insn)?,
            _ if x0 => emu.alu_x0_direct_rec(rec, pc, insn),
            opcode => emu.alu_direct_rec(rec, pc, insn, AluStream::of(opcode)),
        }
        Ok(None)
    }

    /// The room the code generator reserves for `insns`' direct rows.
    fn room(insns: &[Instruction]) -> BlockRows {
        let mut room = BlockRows::default();
        for insn in insns {
            let slots = Slots::of(insn);
            room.steps += 1;
            room.reads += slots.len() - slots.write_count();
            room.writes += slots.write_count();
            let computes_a =
                insn.is_alu_instruction() || insn.opcode == Opcode::AUIPC || is_load(insn);
            if insn.op_a == 0 && computes_a {
                room.operand_exceptions += 1;
            }
            if insn.is_alu_instruction() && insn.op_a != 0 {
                *room.alu_mut(AluStream::of(insn.opcode)) += 1;
            }
            if insn.is_memory_instruction() {
                room.memory += 1;
            } else if insn.is_branch_instruction() {
                room.branch += 1;
            }
        }
        room
    }

    fn ends_block(insn: &Instruction) -> bool {
        insn.is_branch_instruction()
            || matches!(insn.opcode, Opcode::JAL | Opcode::JALR | Opcode::ECALL)
    }

    /// The block at the core's pc as the code generator writes its recording body: every
    /// instruction direct but a closing `ECALL`, and the fallback where the block may not run.
    fn recording_block(
        emu: &mut AotEmulatorCore,
        rec: &mut Recorder,
    ) -> Result<RecordStep, String> {
        let program = emu.program.clone();
        let first = usize::try_from((emu.pc - program.pc_base) / 4).expect("an instruction index");
        let rest = &program.instructions[first..];
        let block = &rest[..rest
            .iter()
            .position(ends_block)
            .map_or(rest.len(), |end| end + 1)];
        let insns = block.len() as u32;
        if !emu.can_run_record_block(insns, 0, 0, 0, 0) {
            return emu.with_sink_on_core(rec, AotEmulatorCore::interpret_from_current_pc);
        }
        let (body, ecall) = match block.split_last() {
            Some((last, body)) if last.opcode == Opcode::ECALL => (body, true),
            _ => (block, false),
        };
        emu.count_recorder_block(insns, body.len() as u32);
        emu.reserve_rows_rec(rec, room(body));
        for &insn in body {
            let pc = u32::try_from(emu.pc).expect("a test program's pc fits a row");
            if let Some(next_pc) = direct(emu, rec, pc, insn)? {
                emu.pc = next_pc;
                emu.update_insn_clock();
            }
        }
        if ecall {
            let pc = emu.pc;
            return emu.with_sink_on_core(rec, |emu| emu.interpret_ecall(pc));
        }
        Ok(RecordStep::Dynamic(emu.pc))
    }

    /// [`recording_block`] failing part way, the sink in the recorder: room reserved for its whole
    /// body, the first instruction written, then a panic.
    fn failing_block(emu: &mut AotEmulatorCore, rec: &mut Recorder) -> Result<RecordStep, String> {
        let program = emu.program.clone();
        let body = &program.instructions[..program.instructions.len() - 1];
        emu.count_recorder_block(body.len() as u32 + 1, body.len() as u32);
        emu.reserve_rows_rec(rec, room(body));
        direct(emu, rec, 0x1000, body[0])?;
        panic!("the block fails")
    }

    /// A recording block of the one instruction at the core's pc.
    fn one_instruction_block(
        emu: &mut AotEmulatorCore,
        rec: &mut Recorder,
    ) -> Result<RecordStep, String> {
        let pc = emu.pc;
        let insn = emu.program.fetch(pc);
        if !emu.can_run_record_block(1, 0, 0, 0, 0) {
            return emu.with_sink_on_core(rec, AotEmulatorCore::interpret_from_current_pc);
        }
        if insn.opcode == Opcode::ECALL {
            emu.count_recorder_block(1, 0);
            return emu.with_sink_on_core(rec, |emu| emu.interpret_ecall(pc));
        }
        emu.count_recorder_block(1, 1);
        emu.reserve_rows_rec(rec, room(&[insn]));
        let row_pc = u32::try_from(pc).expect("a test program's pc fits a row");
        if let Some(next_pc) = direct(emu, rec, row_pc, insn)? {
            emu.pc = next_pc;
            emu.update_insn_clock();
        }
        Ok(RecordStep::Dynamic(emu.pc))
    }

    /// `program` run by one-instruction recording blocks: the run's result, its chunk and the core.
    fn recorded_one_by_one(
        program: Arc<Program>,
    ) -> (Result<(), String>, EmittedChunk, AotEmulatorCore) {
        let mut emu = recorder_core(program);
        let block: RecordBlockFn = one_instruction_block;
        let ran = emu.run_record_blocks(|_| Some(block));
        assert!(emu.is_emitting(), "the sink is back on the core");
        let recorded = cut(&mut emu);
        (ran, recorded, emu)
    }

    /// [`interpreted`], with the run's memory initialize and finalize events.
    fn interpreted_to_the_end(program: Arc<Program>) -> (EmulationRecord, AotEmulatorCore) {
        let (mut record, emu) = interpreted(program);
        emu.postprocess(&mut record);
        (record, emu)
    }

    /// Where the memory tests load and store.
    const BASE: u64 = 0x2_0000;

    /// Every load and store width, over dwords written whole, merged into and only read; a base
    /// register the load overwrites and one the store also stores; loads into `x0` of non-zero and
    /// of zero; a store of `x0`. Then each branch taken and not, a loop, `JAL` and `JALR` with a
    /// link and into `x0`, a `JALR` to an odd address, and a halt.
    fn memory_control_program() -> Arc<Program> {
        use Opcode::*;
        let folded = |rd, value| Instruction::new(ADD, rd, value, 0, true, true);
        let load = |opcode, rd, rs1, imm| Instruction::new(opcode, rd, rs1, imm, false, true);
        let store = |opcode, rs2, rs1, imm| Instruction::new(opcode, rs2, rs1, imm, false, true);
        let branch = |opcode, rs1, rs2, offset: i64| {
            Instruction::new(opcode, rs1, rs2, offset as u64, false, true)
        };
        let jal = |rd, offset: i64| Instruction::new(JAL, rd, offset as u64, 0, true, true);
        let jalr = |rd, rs1, imm| Instruction::new(JALR, rd, rs1, imm, false, true);
        let mut insns = vec![
            addi(1, 0, BASE),
            folded(2, 0x1122_3344_5566_7788),
            folded(3, 0xffff_ffff_8765_4321),
            store(SD, 2, 1, 0),
            // The other word of the dword stays: a store that did not merge would zero it.
            store(SW, 3, 1, 4),
            load(LD, 4, 1, 0),
            load(LW, 5, 1, 4),
            load(LWU, 6, 1, 4),
            load(LH, 7, 1, 6),
            load(LHU, 8, 1, 2),
            load(LB, 9, 1, 7),
            load(LBU, 18, 1, 7),
            // A dword first touched by narrow stores, merged byte by byte and halfword by halfword.
            store(SB, 3, 1, 9),
            store(SH, 3, 1, 14),
            store(SW, 0, 1, 8),
            load(LD, 19, 1, 8),
            // Into `x0`: a non-zero word and byte, which the rule needs an exception for, and the
            // zero of a dword never written, which it does not.
            load(LW, 0, 1, 4),
            load(LB, 0, 1, 0),
            load(LD, 0, 1, 16),
            store(SD, 1, 1, 24),
            load(LD, 1, 1, 24),
            load(LD, 1, 1, 0),
            addi(1, 0, BASE),
            branch(BEQ, 4, 4, 8),
            addi(12, 0, 1),
            branch(BNE, 4, 4, 8),
            branch(BLT, 3, 0, 8),
            addi(12, 12, 2),
            branch(BGE, 0, 3, 8),
            addi(12, 12, 4),
            branch(BLTU, 3, 0, 8),
            branch(BGEU, 3, 0, 8),
            addi(12, 12, 8),
            addi(17, 0, 3),
            addi(17, 17, (-1_i64) as u64),
            branch(BNE, 17, 0, -4),
            jal(13, 8),
            addi(12, 12, 16),
            jal(0, 8),
            addi(12, 12, 32),
        ];
        // `JALR` past the next instruction through an odd address, then into `x0` past the next.
        let at = |index: usize| 0x1000 + 4 * index as u64;
        let next_but_one = at(insns.len() + 3);
        insns.extend([
            addi(14, 0, next_but_one + 1),
            jalr(15, 14, 0),
            addi(12, 12, 64),
        ]);
        let halt = at(insns.len() + 3);
        insns.extend([
            addi(16, 0, halt - 8),
            jalr(0, 16, 8),
            addi(12, 12, 128),
            addi(5, 0, u64::from(HALT)),
            self::ECALL,
        ]);
        Arc::new(Program::new(insns, 0x1000, 0x1000))
    }

    /// The memory finalize events, which read the accessed bits, are held to the AOT fallback's
    /// only: pico-vm hands them out in a record of their own.
    #[test]
    fn direct_rows_are_the_interpreters_for_loads_stores_branches_and_jumps() {
        hold_records_unbounded();
        let program = memory_control_program();
        let (ran, recorded, emu) = recorded_one_by_one(program.clone());
        ran.expect("the guest halts");
        let mut to_the_end = recorded.record.clone();
        emu.postprocess(&mut to_the_end);
        let (reference, interpreter) = interpreted_to_the_end(program.clone());

        assert_eq!(first_difference(&reference, &to_the_end), None);
        assert_eq!(emu.registers, interpreter.registers);
        let (vm, vm_registers) =
            vm_replayed(program.clone(), recorded.cycles).expect("pico-vm's replay halts");
        assert_eq!(
            differences_from_vm(&vm, &recorded.record),
            Vec::<String>::new()
        );
        assert_eq!(emu.registers.0.map(|register| register.value), vm_registers);
        assert_eq!(emu.registers[12].value, 0, "a skipped instruction ran");
        let history = recorded.record.history.as_ref().expect("a history");
        let steps = history.steps.len() as u64;
        assert_eq!(
            (recorded.recorder_body_insns, recorded.recorder_direct_insns),
            (steps, steps - 1)
        );
        // `LW x0` and `LB x0` load what `x0` does not hold; `LD x0` loads 0.
        assert_eq!(history.operand_exceptions.len(), 2);
        let (loads_and_stores, branches) =
            program
                .instructions
                .iter()
                .fold((0, 0), |(memory, branch), insn| {
                    (
                        memory + usize::from(insn.is_memory_instruction()),
                        branch + usize::from(insn.is_branch_instruction()),
                    )
                });
        assert_eq!(history.chip_steps.memory.len(), loads_and_stores);
        // The loop's branch runs three times.
        assert_eq!(history.chip_steps.branch.len(), branches + 2);
        assert!(!reference.memory_finalize_events.is_empty());
    }

    /// A block of the one instruction at the core's pc as the code generator writes its plain
    /// body, emitting: a load or a store through its `_no_count` helper, anything else through
    /// the fallback.
    fn emitting_block(emu: &mut AotEmulatorCore) -> Result<NextStep, String> {
        use Opcode::*;
        let (pc, insn) = (emu.pc, emu.program.fetch(emu.pc));
        let emitting = emu.is_emitting();
        let (a, b, c, next_pc) = (
            usize::from(insn.op_a),
            insn.op_b as usize,
            insn.op_c,
            pc + 4,
        );
        match insn.opcode {
            LB => emu.lb_no_count(emitting, a, b, c, next_pc)?,
            LBU => emu.lbu_no_count(emitting, a, b, c, next_pc)?,
            LH => emu.lh_no_count(emitting, a, b, c, next_pc)?,
            LHU => emu.lhu_no_count(emitting, a, b, c, next_pc)?,
            LW => emu.lw_no_count(emitting, a, b, c, next_pc)?,
            LWU => emu.lwu_no_count(emitting, a, b, c, next_pc)?,
            LD => emu.ld_no_count(emitting, a, b, c, next_pc)?,
            SB => emu.sb_no_count(emitting, a, b, c, next_pc)?,
            SH => emu.sh_no_count(emitting, a, b, c, next_pc)?,
            SW => emu.sw_no_count(emitting, a, b, c, next_pc)?,
            SD => emu.sd_no_count(emitting, a, b, c, next_pc)?,
            _ => emu.debug_interpret_single_step()?,
        }
        Ok(NextStep::Dynamic(emu.pc))
    }

    /// `program` run by [`emitting_block`]s: the run's result, its chunk and the core.
    fn emitted_one_by_one(
        program: Arc<Program>,
    ) -> (Result<(), String>, EmittedChunk, AotEmulatorCore) {
        let mut emu = recorder_core(program);
        let block: BlockFn = emitting_block;
        let ran = emu.run_blocks(|_| Some(block));
        let emitted = cut(&mut emu);
        (ran, emitted, emu)
    }

    /// Runs `program` through the recording blocks and through the emitting bodies, and checks
    /// that both end the same way and leave the same rows, the unaligned table's included, the
    /// same registers and the same count of misaligned accesses. Returns the recorded run.
    fn recorded_as_emitted(
        program: Arc<Program>,
        what: &str,
    ) -> (Result<(), String>, EmittedChunk, AotEmulatorCore) {
        let (ran, recorded, emu) = recorded_one_by_one(program.clone());
        let (emitted_ran, emitted, emitting) = emitted_one_by_one(program);
        assert_eq!(ran, emitted_ran, "{what}: how the run ended");
        assert_eq!(
            format!("{:?}", emu.fault),
            format!("{:?}", emitting.fault),
            "{what}: the fault"
        );
        let history = |chunk: &EmittedChunk| chunk.record.history.clone().expect("a history");
        let (recorded_history, emitted_history) = (history(&recorded), history(&emitted));
        assert_eq!(
            recorded_history.unaligned.as_slice(),
            emitted_history.unaligned.as_slice(),
            "{what}: the unaligned table"
        );
        assert_eq!(
            first_difference(&emitted.record, &recorded.record),
            None,
            "{what}"
        );
        assert_eq!(emu.registers, emitting.registers, "{what}: the registers");
        assert_eq!(
            (
                emu.misaligned_accesses,
                emu.chunk_split_state.num_misaligned
            ),
            (
                emitting.misaligned_accesses,
                emitting.chunk_split_state.num_misaligned
            ),
            "{what}: the misaligned accesses counted"
        );
        (ran, recorded, emu)
    }

    /// Every load and store width at a misaligned address, within its dword and running into the
    /// next, over dwords whose high bits are set so the sign fill shows; a crossing load into `x0`;
    /// crossing stores into a dword written whole, one merged into and one never written; then
    /// each dword read back whole, and a halt.
    fn misaligned_program() -> Arc<Program> {
        use Opcode::*;
        let folded = |rd, value| Instruction::new(ADD, rd, value, 0, true, true);
        let load = |opcode, rd, rs1, imm| Instruction::new(opcode, rd, rs1, imm, false, true);
        let store = |opcode, rs2, rs1, imm| Instruction::new(opcode, rs2, rs1, imm, false, true);
        let insns = vec![
            addi(1, 0, BASE),
            folded(2, 0x8899_aabb_ccdd_eeff),
            folded(3, 0xf0e1_d2c3_b4a5_9687),
            store(SD, 2, 1, 0),
            store(SD, 3, 1, 8),
            // Within the dword.
            load(LH, 4, 1, 1),
            load(LHU, 5, 1, 3),
            load(LW, 6, 1, 2),
            load(LWU, 7, 1, 1),
            load(LB, 8, 1, 7),
            load(LBU, 9, 1, 5),
            // Into the next dword; `a0` and `a1` stay clear for the halt.
            load(LH, 20, 1, 7),
            load(LHU, 21, 1, 7),
            load(LW, 12, 1, 5),
            load(LWU, 13, 1, 6),
            load(LD, 14, 1, 3),
            load(LD, 15, 1, 9),
            load(LW, 0, 1, 6),
            // Stores within the dword, then into the next: one written whole, one merged into, and
            // one never written.
            store(SH, 3, 1, 1),
            store(SW, 3, 1, 10),
            store(SH, 2, 1, 7),
            store(SW, 2, 1, 14),
            store(SD, 3, 1, 4),
            store(SD, 2, 1, 21),
            store(SB, 3, 1, 3),
            load(LD, 16, 1, 0),
            load(LD, 17, 1, 8),
            load(LD, 18, 1, 16),
            load(LD, 19, 1, 24),
            addi(5, 0, u64::from(HALT)),
            self::ECALL,
        ];
        Arc::new(Program::new(insns, 0x1000, 0x1000))
    }

    /// A recording block runs a misaligned load or store natively, as the emitting body does:
    /// the same rows, an unaligned step with its next dword's access where it crosses, the same
    /// values and the same count. pico-vm's interpreter agrees.
    #[test]
    fn misaligned_accesses_record_as_the_emitting_body_does() {
        hold_records_unbounded();
        let program = misaligned_program();
        let (ran, recorded, emu) = recorded_as_emitted(program.clone(), "misaligned");
        ran.expect("the guest halts");
        let history = recorded.record.history.as_ref().expect("a history");
        let crossing = history
            .unaligned
            .iter()
            .filter(|unaligned| unaligned.crosses != 0)
            .count();
        // Four loads and two stores within their dword; seven loads and four stores across.
        assert_eq!((history.unaligned.len(), crossing), (17, 11));
        assert_eq!(emu.misaligned_accesses, 17);
        assert_eq!(history.operand_exceptions.len(), 1, "the crossing `LW x0`");
        assert_eq!(
            emu.registers[4].value, 0xffff_ffff_ffff_ddee,
            "LH sign-extends"
        );
        assert_eq!(
            emu.registers[12].value, 0xffff_ffff_8788_99aa,
            "LW sign-extends"
        );

        let (reference, _) = interpreted(program.clone());
        assert_eq!(first_difference(&reference, &recorded.record), None);
        let (vm, vm_registers) =
            vm_replayed(program, recorded.cycles).expect("pico-vm's replay halts");
        assert_eq!(
            differences_from_vm(&vm, &recorded.record),
            Vec::<String>::new()
        );
        assert_eq!(emu.registers.0.map(|register| register.value), vm_registers);
    }

    /// The same accesses in one recording block, its rows reserved for the whole body as the code
    /// generator reserves them: the steps land where the interpreter puts them.
    #[test]
    fn a_block_of_misaligned_accesses_records_as_the_interpreter_does() {
        hold_records_unbounded();
        let program = misaligned_program();
        let mut emu = recorder_core(program.clone());
        let block: RecordBlockFn = recording_block;
        emu.run_record_blocks(|_| Some(block))
            .expect("the guest halts");
        // Every instruction but the closing `ECALL` ran direct, none through the fallback.
        assert_eq!(
            emu.recorder_direct_insns(),
            program.instructions.len() as u64 - 1
        );
        let recorded = cut(&mut emu);
        let history = recorded.record.history.as_ref().expect("a history");
        assert_eq!(history.unaligned.len(), 17);
        assert_eq!(emu.misaligned_accesses, 17);
        let (reference, _) = interpreted(program);
        assert_eq!(first_difference(&reference, &recorded.record), None);
    }

    /// A load or store the memory guard refuses ends the run where the emitting body ends it,
    /// with the same fault, after the same register reads and before memory is touched: below the
    /// floor, in the stack guard, into the code and past the top of memory, each width.
    #[test]
    fn a_refused_access_fails_as_the_emitting_body_does() {
        use pico_vm::primitives::layout::{HEAP_END, MEMORY_SIZE};
        use Opcode::*;
        hold_records_unbounded();
        // Above the floor, so its code can be stored into.
        const CODE: u64 = 0x3_0000;
        let (null, stack, top, code) = (
            "null access",
            "stack overflow",
            "invalid memory access",
            "store into code",
        );
        let accesses = [
            (null, 0x100, [LB, LHU, LW, SB, SH, SD]),
            (stack, HEAP_END, [LBU, LH, LD, SB, SW, SD]),
            // Its last byte past the top.
            (top, MEMORY_SIZE - 1, [LH, LHU, LWU, LD, SH, SW]),
        ];
        let mut cases: Vec<_> = accesses
            .into_iter()
            .flat_map(|(kind, addr, opcodes)| opcodes.map(|opcode| (kind, addr, opcode)))
            .collect();
        // Crossing into the stack guard from below, a byte at the top, and a store into the code.
        cases.extend([(stack, HEAP_END - 2, LW), (stack, HEAP_END - 4, SD)]);
        cases.extend([(top, MEMORY_SIZE, LB), (top, MEMORY_SIZE, SB)]);
        cases.extend([SB, SH, SW, SD].map(|opcode| (code, CODE + 4, opcode)));
        // A load from the code is no fault.
        cases.extend([LB, LD].map(|opcode| ("", CODE + 4, opcode)));
        for (kind, addr, opcode) in cases {
            let access = Instruction::new(opcode, 4, 1, 0, false, true);
            let program = Arc::new(Program::new(
                vec![
                    Instruction::new(ADD, 1, 0, addr, true, true),
                    access,
                    addi(5, 0, u64::from(HALT)),
                    self::ECALL,
                ],
                CODE,
                CODE,
            ));
            let what = format!("{kind}: {access:?} at {addr:#x}");
            let (ran, recorded, emu) = recorded_as_emitted(program.clone(), &what);
            if kind.is_empty() {
                ran.expect(&what);
                continue;
            }
            let error = ran.expect_err(&what);
            assert!(error.contains(kind), "{what}: {error}");
            assert!(emu.is_emitting(), "{what}: the sink is back on the core");
            assert_eq!(
                table_rows(&recorded.record),
                (1, 0, 1, 0),
                "{what}: rows past the first instruction"
            );
            let (reference, interpreter) = interpreted(program);
            assert_eq!(
                first_difference(&reference, &recorded.record),
                None,
                "{what}"
            );
            assert_eq!(
                format!("{:?}", emu.fault),
                format!("{:?}", interpreter.fault),
                "{what}: the interpreter's fault"
            );
        }
    }

    /// A `JALR` to 2^32, a target no row holds, fails the replay at the jump as pico-vm's run
    /// fails, whether the replay's target is the jump or past it.
    #[test]
    fn a_jalr_past_every_row_fails_the_replay_closed() {
        hold_records_unbounded();
        let program = Arc::new(Program::new(
            vec![
                addi(1, 0, 1 << 32),
                Instruction::new(Opcode::JALR, 0, 1, 0, false, true),
                addi(5, 0, u64::from(HALT)),
                self::ECALL,
            ],
            0x1000,
            0x1000,
        ));
        vm_replayed(program.clone(), 2).expect_err("pico-vm refuses a run ending at 2^32");
        for target in [2, 3] {
            let start = RiscvEmulationState::new(0x1000);
            let mut emu = AotEmulatorCore::recover(program.clone(), start, target, true);
            let block: RecordBlockFn = recording_block;
            let Err(error) =
                emu.replay(|emu| emu.run_record_blocks(|pc| (pc == 0x1000).then_some(block)))
            else {
                panic!("target {target}: a record was cut past the jump");
            };
            assert!(
                error.to_string().contains("outside the program"),
                "target {target}: {error}"
            );
            assert!(emu.take_emitted_chunks().is_empty(), "target {target}");
        }
    }

    /// A `JALR` whose target fails its check, misaligned, outside the program or past every row,
    /// fails with the interpreter's error and leaves `rd` as it was, whether `rd` is `rs1` or not:
    /// through the recording entry, and through the ordinary helper, emitting or not.
    #[test]
    fn a_bad_jalr_leaves_its_link_unwritten() {
        hold_records_unbounded();
        const KEPT: u64 = 0x5eed;
        let (link, base_reg) = (6_u8, 1_u8);
        for base in [0x1002, 0x2000, 1 << 32] {
            for rd in [link, base_reg] {
                let jalr = Instruction::new(Opcode::JALR, rd, u64::from(base_reg), 0, false, true);
                let program = Arc::new(Program::new(
                    vec![
                        addi(link, 0, KEPT),
                        addi(base_reg, 0, base),
                        jalr,
                        addi(5, 0, u64::from(HALT)),
                        self::ECALL,
                    ],
                    0x1000,
                    0x1000,
                ));
                let kept = |emu: &AotEmulatorCore| {
                    let value = |reg: u8| emu.registers[usize::from(reg)].value;
                    (value(link), value(base_reg))
                };
                // Both, whichever the JALR would have written.
                let before = (KEPT, base);
                let case = format!("x{rd} <- JALR x{base_reg} = {base:#x}");

                let mut interpreter = recorder_core(program.clone());
                let theirs = interpreter
                    .run_blocks(|_| None)
                    .expect_err("the interpreter fails the jump");
                assert_eq!(kept(&interpreter), before, "{case}: the interpreter");

                let (ours, _, recorded) = recorded_one_by_one(program.clone());
                assert_eq!(ours, Err(theirs.clone()), "{case}: the recording entry");
                assert_eq!(kept(&recorded), before, "{case}: the recording entry");

                for emitting in [false, true] {
                    let mut emu = recorder_core(program.clone());
                    emu.write_reg(usize::from(link), KEPT);
                    emu.write_reg(usize::from(base_reg), base);
                    emu.update_insn_clock();
                    let ours = emu.jalr_no_count(
                        emitting,
                        usize::from(rd),
                        usize::from(base_reg),
                        0x1008,
                        0,
                    );
                    assert_eq!(ours, Err(theirs.clone()), "{case}: the helper, {emitting}");
                    assert_eq!(kept(&emu), before, "{case}: the helper, {emitting}");
                }
            }
        }
    }

    /// A replay worker, the only core recording blocks run on, with a target no test reaches.
    fn recorder_core(program: Arc<Program>) -> AotEmulatorCore {
        let start = RiscvEmulationState::new(program.pc_start);
        AotEmulatorCore::recover(program, start, u64::MAX - 1, true)
    }

    fn cut(emu: &mut AotEmulatorCore) -> EmittedChunk {
        emu.finish_emitted_chunk();
        let mut chunks = emu.take_emitted_chunks();
        assert_eq!(chunks.len(), 1);
        chunks.pop().expect("one chunk")
    }

    /// The record the AOT core's fallback interpreter writes for `program`, up to its halt or
    /// panic, and the core it left: the reference where pico-vm's ([`vm_replayed`]) cannot be.
    fn interpreted(program: Arc<Program>) -> (EmulationRecord, AotEmulatorCore) {
        let mut emu = recorder_core(program);
        let _ = catch_unwind(AssertUnwindSafe(|| emu.run_blocks(|_| None)));
        (cut(&mut emu).record, emu)
    }

    /// pico-vm's interpreter as a replay worker, run from `program`'s start to global clock
    /// `target`: the chunk's record and the register values it left, or its error.
    fn vm_replayed(
        program: Arc<Program>,
        target: u64,
    ) -> Result<(EmulationRecord, [u64; 32]), String> {
        let deferred = EmulationDeferredState::shared(
            program.clone(),
            Arc::new(RecordFinalPvsState::default()),
        );
        let start = RiscvEmulationState::new(program.pc_start);
        let opts = EmulatorOpts::default();
        let mut vm =
            RiscvEmulator::recover::<KoalaBear>(program, start, opts, deferred, target, true);
        let mut records = Vec::new();
        vm.emulate_batch(&mut |record: EmulationRecord| records.push(record))
            .map_err(|error| error.to_string())?;
        let chunk = records
            .into_iter()
            .find(|record| record.history.is_some())
            .expect("the replay cuts its chunk");
        Ok((chunk, vm.registers()))
    }

    /// Every field the record digest compares on which `recorded` differs from pico-vm's
    /// `reference`, the public values aside: pico-vm's deferred state stamps them at the cut, and
    /// the AOT replay leaves them to the sequencer.
    fn differences_from_vm(reference: &EmulationRecord, recorded: &EmulationRecord) -> Vec<String> {
        let (theirs, ours) = (field_digests(reference), field_digests(recorded));
        assert_eq!(theirs.len(), ours.len(), "a history on one side only");
        theirs
            .iter()
            .zip(&ours)
            .filter(|((field, ..), _)| is_compared(field) && *field != "public_values")
            .filter(|(theirs, ours)| theirs != ours)
            .map(|((field, len, digest), (_, our_len, our_digest))| {
                format!("{field}: {len} vs {our_len}, {digest:#x} vs {our_digest:#x}")
            })
            .collect()
    }

    fn table_rows(record: &EmulationRecord) -> (usize, usize, usize, usize) {
        let history = record.history.as_ref().expect("a history sink's record");
        (
            history.steps.len(),
            history.reads.len(),
            history.writes.len(),
            history.syscalls.len(),
        )
    }

    #[test]
    fn a_recording_block_writes_the_interpreters_rows_its_ecall_through_the_core() {
        hold_records_unbounded();
        let mut emu = recorder_core(program(HALT));
        let block: RecordBlockFn = recording_block;
        emu.run_record_blocks(|pc| (pc == 0x1000).then_some(block))
            .expect("the guest halts");
        assert!(emu.is_emitting(), "the sink is back on the core");
        let recorded = cut(&mut emu);
        let (reference, _) = interpreted(program(HALT));

        assert_eq!(first_difference(&reference, &recorded.record), None);
        assert_eq!(table_rows(&recorded.record), (3, 4, 3, 0));
        let history = recorded.record.history.as_ref().expect("a history");
        assert_eq!(history.chip_steps.ecall, [2]);
        assert_eq!(
            (
                recorded.cycles,
                recorded.compiled_block_dispatches,
                recorded.recorder_body_dispatches,
                recorded.recorder_body_insns,
                recorded.recorder_direct_insns,
                recorded.fallback_insns
            ),
            (3, 1, 1, 3, 2, 0)
        );
    }

    /// With no recording block to run, the fallback runs every instruction.
    #[test]
    fn the_fallback_writes_through_the_core_sink() {
        hold_records_unbounded();
        let mut emu = recorder_core(program(HALT));
        emu.run_record_blocks(|_| None).expect("the guest halts");
        let interpreted_only = cut(&mut emu);
        assert_eq!(
            first_difference(&interpreted(program(HALT)).0, &interpreted_only.record),
            None
        );
        assert_eq!(
            (
                interpreted_only.recorder_body_insns,
                interpreted_only.recorder_direct_insns,
                interpreted_only.fallback_insns
            ),
            (0, 0, 3)
        );
    }

    /// Out of a recording block, the sink in the recorder, and out of a precompile, the sink on
    /// the core. Either way the tables hold only the completed instructions' rows, not the room
    /// the block reserved for the rest.
    #[test]
    fn a_recording_run_that_unwinds_leaves_the_sink_on_the_core() {
        hold_records_unbounded();
        let mut emu = recorder_core(unwinding_program());
        let block: RecordBlockFn = failing_block;
        let unwound = catch_unwind(AssertUnwindSafe(|| {
            emu.run_record_blocks(|pc| (pc == 0x1000).then_some(block))
        }));
        assert!(unwound.is_err());
        assert!(emu.is_emitting(), "the recorder gave the sink back");
        assert_eq!(table_rows(&cut(&mut emu).record), (1, 1, 1, 0));

        let mut emu = recorder_core(unwinding_program());
        let block: RecordBlockFn = recording_block;
        let unwound = catch_unwind(AssertUnwindSafe(|| {
            emu.run_record_blocks(|pc| (pc == 0x1000).then_some(block))
        }));
        let message = unwound.expect_err("the precompile refuses its point");
        assert!(
            message
                .downcast_ref::<String>()
                .is_some_and(|m| m.contains("must be 8-byte aligned")),
            "the precompile's own panic"
        );
        assert!(emu.is_emitting(), "the sink stayed on the core");
        let recorded = cut(&mut emu).record;
        let (reference, _) = interpreted(unwinding_program());
        assert_eq!(table_rows(&recorded), (2, 2, 2, 1));
        assert_eq!(first_difference(&reference, &recorded), None);
    }

    /// Set in the child process that runs
    /// [`in_a_history_slot_a_recording_run_leaves_only_the_rows_it_wrote`] bounded.
    const BOUNDED_CHILD: &str = "PICO_RECORDER_BOUNDED_CHILD";

    fn assert_in_slot(record: &EmulationRecord, what: &str) {
        let history = record.history.as_ref().expect("a history sink's record");
        assert!(
            history.holds_slot() && history.is_in_slot(Table::Steps),
            "{what}: the history is not in a slot"
        );
    }

    /// [`a_recording_run_that_unwinds_leaves_the_sink_on_the_core`] and the `ECALL` hand-back with
    /// records bounded, so a history's tables are a slot's fixed-size regions and a reservation is
    /// room in them, not heap capacity. Runs in a child process: the bound is process-wide, and
    /// every other test here holds its records unbounded.
    #[test]
    fn in_a_history_slot_a_recording_run_leaves_only_the_rows_it_wrote() {
        const MARKER: &str = "[recorder-slot] each history held only the rows written";
        if std::env::var_os(BOUNDED_CHILD).is_none() {
            let test = "emulator::recorder::tests::\
                        in_a_history_slot_a_recording_run_leaves_only_the_rows_it_wrote";
            let output = Command::new(std::env::current_exe().expect("the test binary"))
                .args(["--exact", test, "--nocapture", "--test-threads=1"])
                .env(BOUNDED_CHILD, "1")
                .output()
                .expect("re-run this test binary");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                output.status.success() && stdout.contains(MARKER),
                "the bounded child failed ({}):\n{stdout}\n{stderr}",
                output.status
            );
            return;
        }
        // Two slots: a run's record and its reference held at once.
        assert_eq!(init_record_slots(2), 2);

        let mut emu = recorder_core(unwinding_program());
        let block: RecordBlockFn = failing_block;
        let unwound = catch_unwind(AssertUnwindSafe(|| {
            emu.run_record_blocks(|pc| (pc == 0x1000).then_some(block))
        }));
        assert!(unwound.is_err());
        assert!(emu.is_emitting(), "the recorder gave the sink back");
        let recorded = cut(&mut emu).record;
        assert_in_slot(&recorded, "the unwound block");
        assert_eq!(table_rows(&recorded), (1, 1, 1, 0), "rows past the first");
        drop(recorded);

        let mut emu = recorder_core(unwinding_program());
        let block: RecordBlockFn = recording_block;
        let unwound = catch_unwind(AssertUnwindSafe(|| {
            emu.run_record_blocks(|pc| (pc == 0x1000).then_some(block))
        }));
        assert!(unwound.is_err(), "the precompile refuses its point");
        let recorded = cut(&mut emu).record;
        let (reference, _) = interpreted(unwinding_program());
        assert_in_slot(&recorded, "the unwound precompile");
        assert_eq!(table_rows(&recorded), (2, 2, 2, 1));
        assert_eq!(first_difference(&reference, &recorded), None);
        drop((recorded, reference));

        for (shape, program) in [
            ("the hand-back", program(HALT)),
            ("every ALU form", alu_program()),
        ] {
            let mut emu = recorder_core(program.clone());
            let block: RecordBlockFn = recording_block;
            emu.run_record_blocks(|pc| (pc == 0x1000).then_some(block))
                .expect("the guest halts");
            let recorded = cut(&mut emu);
            let (reference, _) = interpreted(program);
            assert_in_slot(&recorded.record, shape);
            assert_in_slot(&reference, shape);
            assert!(recorded.recorder_direct_insns > 0, "{shape}: no direct row");
            assert_eq!(
                first_difference(&reference, &recorded.record),
                None,
                "{shape}"
            );
        }
        println!("{MARKER}");
    }

    /// An error out of [`AotEmulatorCore::with_sink_on_core`], here a `HALT` with exit code 1,
    /// leaves the sink on the core and only the completed instructions' rows. The generated
    /// `ECALL` sequence runs only in a generated crate (`perf/aot/record_parity.sh`).
    #[test]
    fn an_error_inside_the_hand_back_leaves_the_sink_on_the_core() {
        hold_records_unbounded();
        let failing_halt = Arc::new(Program::new(
            vec![addi(5, 0, u64::from(HALT)), addi(10, 0, 1), self::ECALL],
            0x1000,
            0x1000,
        ));
        let mut emu = recorder_core(failing_halt.clone());
        let block: RecordBlockFn = recording_block;
        let ran = emu.run_record_blocks(|pc| (pc == 0x1000).then_some(block));
        let vm_error = vm_replayed(failing_halt.clone(), 3).expect_err("a non-zero exit code");
        assert_eq!(ran, Err(vm_error));
        assert!(emu.is_emitting(), "the hand-back gave the sink back");
        let recorded = cut(&mut emu).record;
        assert_eq!(table_rows(&recorded), (2, 2, 2, 0));
        assert_eq!(
            first_difference(&interpreted(failing_halt).0, &recorded),
            None
        );
    }

    /// Every ALU opcode in each operand form and `AUIPC`, on edge-case operands (division by zero,
    /// the signed overflow, shifts past the word, negative immediates), with aliased sources and
    /// destinations and `x0` destinations; then a halt.
    fn alu_program() -> Arc<Program> {
        use Opcode::*;
        let folded = |opcode, rd, b, c| Instruction::new(opcode, rd, b, c, true, true);
        let registers = |opcode, rd, rs1, rs2| Instruction::new(opcode, rd, rs1, rs2, false, false);
        let immediate = |opcode, rd, rs1, imm| Instruction::new(opcode, rd, rs1, imm, false, true);
        let mut insns = vec![
            folded(ADD, 6, 0xffff_ffff_8000_0001, 0),
            folded(SLL, 8, 1, 63),
            folded(SUB, 9, 0, 1),
            folded(ADDW, 12, 0x7fff_ffff, 1),
        ];
        let all = [
            ADD, SUB, XOR, OR, AND, SLL, SRL, SRA, SLT, SLTU, MUL, MULH, MULHU, MULHSU, DIV, DIVU,
            REM, REMU, ADDW, SUBW, SLLW, SRLW, SRAW, MULW, DIVW, DIVUW, REMW, REMUW,
        ];
        for opcode in all {
            insns.extend([
                registers(opcode, 13, 6, 8),
                registers(opcode, 14, 8, 9),
                registers(opcode, 15, 12, 0),
                registers(opcode, 16, 16, 16),
                registers(opcode, 22, 12, 9),
            ]);
        }
        // The forms with immediates programs carry: the code generator refuses the others.
        let with_immediates = [
            ADD, XOR, OR, AND, SLL, SRL, SRA, SLT, SLTU, ADDW, SLLW, SRLW, SRAW,
        ];
        for opcode in with_immediates {
            insns.extend([
                immediate(opcode, 18, 6, 0xffff_ffff_ffff_f801),
                immediate(opcode, 19, 12, 33),
                folded(opcode, 17, 0xffff_ffff_8765_4321, 0x25),
            ]);
        }
        insns.extend([
            registers(ADD, 0, 6, 8),
            registers(SUB, 0, 6, 6),
            immediate(XOR, 0, 6, 5),
            folded(SUB, 0, 0, 1),
            immediate(ADD, 0, 0, 0),
            registers(OR, 20, 0, 0),
            Instruction::new(
                AUIPC,
                21,
                0xffff_ffff_ffff_f000,
                0xffff_ffff_ffff_f000,
                true,
                true,
            ),
            Instruction::new(AUIPC, 0, 0x2000, 0x2000, true, true),
            addi(5, 0, u64::from(HALT)),
            self::ECALL,
        ]);
        Arc::new(Program::new(insns, 0x1000, 0x1000))
    }

    #[test]
    fn direct_rows_are_the_interpreters_for_every_alu_form() {
        hold_records_unbounded();
        let program = alu_program();
        let mut emu = recorder_core(program.clone());
        let block: RecordBlockFn = recording_block;
        emu.run_record_blocks(|pc| (pc == 0x1000).then_some(block))
            .expect("the guest halts");
        let recorded = cut(&mut emu);
        let (reference, interpreter) = interpreted(program.clone());

        assert_eq!(first_difference(&reference, &recorded.record), None);
        assert_eq!(emu.registers, interpreter.registers);
        let (vm, vm_registers) =
            vm_replayed(program.clone(), recorded.cycles).expect("pico-vm's replay halts");
        assert_eq!(
            differences_from_vm(&vm, &recorded.record),
            Vec::<String>::new()
        );
        assert_eq!(emu.registers.0.map(|register| register.value), vm_registers);
        let insns = program.instructions.len() as u64;
        assert_eq!(
            (recorded.recorder_body_insns, recorded.recorder_direct_insns),
            (insns, insns - 1)
        );
        let history = recorded.record.history.as_ref().expect("a history");
        // `ADD x0, x6, x8`, `XOR x0, x6, 5`, `SUB x0, 0, 1` and `AUIPC x0` compute what `x0`
        // does not hold; `SUB x0, x6, x6` and `ADDI x0, x0, 0` compute 0.
        assert_eq!(history.operand_exceptions.len(), 4);
        let lists = &history.chip_steps;
        for (stream, list) in [
            &lists.add,
            &lists.sub,
            &lists.mul,
            &lists.bitwise,
            &lists.shift_left,
            &lists.shift_right,
            &lists.lt,
            &lists.divrem,
        ]
        .into_iter()
        .enumerate()
        {
            assert!(!list.is_empty(), "ALU list {stream} holds no step");
        }
    }

    #[test]
    fn a_recording_block_runs_where_it_ends_by_the_target_outside_an_unconstrained_block() {
        hold_records_unbounded();
        let mut emu =
            AotEmulatorCore::recover(program(HALT), RiscvEmulationState::new(0x1000), 3, true);
        assert!(
            emu.can_run_record_block(3, 0, 0, 0, 0),
            "a block ending at the target"
        );
        assert!(
            !emu.can_run_record_block(4, 0, 0, 0, 0),
            "a block crossing it"
        );
        emu.enter_unconstrained_mode();
        assert!(
            !emu.can_run_record_block(1, 0, 0, 0, 0),
            "a block inside an unconstrained one"
        );
    }

    /// The recorder runs only where the split is off, so its fit test does not ask the split.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "the chunk split refuses a recording block")]
    fn a_debug_build_fails_a_recording_block_the_split_would_refuse() {
        hold_records_unbounded();
        let mut emu = recorder_core(program(HALT));
        emu.chunk_split_config.clk_threshold = emu.clk;
        let _ = emu.can_run_record_block(1, 0, 0, 0, 0);
    }

    /// `ADDI x1, x1, 1` twice and a `JAL` to the next block; `ADDI x2, x2, 1` twice and a halt.
    fn two_blocks() -> Arc<Program> {
        Arc::new(Program::new(
            vec![
                addi(1, 1, 1),
                addi(1, 1, 1),
                Instruction::new(Opcode::JAL, 0, 4, 0, true, true),
                addi(2, 2, 1),
                addi(2, 2, 1),
                addi(5, 0, u64::from(HALT)),
                self::ECALL,
            ],
            0x1000,
            0x1000,
        ))
    }

    /// A target inside a block hands that block to the fallback, which runs it to the target; a
    /// block that ends at the target runs.
    #[test]
    fn a_recording_block_past_the_target_leaves_the_chunk_tail_to_the_fallback() {
        hold_records_unbounded();
        for (target, recorder_insns, fallback_insns) in [(5, 3, 2), (7, 7, 0)] {
            let start = RiscvEmulationState::new(0x1000);
            let mut emu = AotEmulatorCore::recover(two_blocks(), start, target, true);
            let (recorded, _) = emu
                .replay(|emu| emu.run_record_blocks(|_| Some(recording_block as RecordBlockFn)))
                .expect("the replay reaches its target");
            let (reference, _) = vm_replayed(two_blocks(), target).expect("pico-vm's replay");
            assert_eq!(
                differences_from_vm(&reference, &recorded.record),
                Vec::<String>::new(),
                "target {target}"
            );
            assert_eq!(
                (
                    recorded.cycles,
                    recorded.recorder_body_insns,
                    recorded.fallback_insns
                ),
                (target, recorder_insns, fallback_insns),
                "target {target}"
            );
        }
    }

    /// `ENTER_UNCONSTRAINED`, then, inside the block it opens, a register write and a store over
    /// a dword stored before it; `EXIT_UNCONSTRAINED` resumes after the `ENTER_UNCONSTRAINED` with
    /// `t0 = 0`, which branches past the block to a load of that dword, then a halt.
    fn unconstrained_program() -> Arc<Program> {
        use Opcode::*;
        let enter = SyscallCode::ENTER_UNCONSTRAINED as u32;
        let exit = SyscallCode::EXIT_UNCONSTRAINED as u32;
        Arc::new(Program::new(
            vec![
                addi(1, 0, BASE),
                addi(2, 0, 7),
                Instruction::new(SD, 2, 1, 0, false, true),
                addi(5, 0, u64::from(enter)),
                self::ECALL,
                Instruction::new(BEQ, 5, 0, 20, false, true),
                addi(2, 0, 99),
                Instruction::new(SD, 2, 1, 0, false, true),
                addi(5, 0, u64::from(exit)),
                self::ECALL,
                Instruction::new(LD, 3, 1, 0, false, true),
                addi(5, 0, u64::from(HALT)),
                self::ECALL,
            ],
            0x1000,
            0x1000,
        ))
    }

    /// The fallback runs an unconstrained block and its writes roll back, whether each instruction
    /// is a recording block of its own or the blocks run straight through.
    #[test]
    fn an_unconstrained_block_runs_in_the_fallback_and_rolls_back() {
        hold_records_unbounded();
        // The block and its two `ECALL`s count as one cycle.
        const CYCLES: u64 = 9;
        let program = unconstrained_program();
        let (reference, registers) =
            vm_replayed(program.clone(), CYCLES).expect("pico-vm's replay halts");
        assert_eq!(registers[3], 7, "the store rolled back");
        let blocks: [RecordBlockFn; 2] = [one_instruction_block, recording_block];
        for (shape, block) in ["one by one", "straight through"].into_iter().zip(blocks) {
            let start = RiscvEmulationState::new(0x1000);
            let mut emu = AotEmulatorCore::recover(program.clone(), start, CYCLES, true);
            let (recorded, report) = emu
                .replay(|emu| emu.run_record_blocks(|_| Some(block)))
                .expect("the replay halts");
            assert!(report.done, "{shape}");
            assert_eq!(
                differences_from_vm(&reference, &recorded.record),
                Vec::<String>::new(),
                "{shape}"
            );
            let ours: Vec<u64> = (0..32).map(|reg| emu.read_reg_unsafe(reg)).collect();
            assert_eq!(ours, registers, "{shape}");
            assert_eq!(
                recorded.recorder_body_insns + recorded.fallback_insns,
                recorded.cycles,
                "{shape}"
            );
            assert!(
                recorded.compiled_block_dispatches > recorded.recorder_body_dispatches,
                "{shape}: no recording block fell back"
            );
        }
    }

    /// The instruction check fails a block even where its rows agree with the generic close's.
    #[cfg(feature = "recorder-check")]
    #[test]
    #[should_panic(expected = "is not the program's")]
    fn the_checking_build_refuses_an_instruction_that_is_not_the_programs() {
        hold_records_unbounded();
        fn misnamed_block(
            emu: &mut AotEmulatorCore,
            rec: &mut Recorder,
        ) -> Result<RecordStep, String> {
            emu.count_recorder_block(3, 2);
            direct(emu, rec, 0x1000, addi(5, 0, u64::from(HALT)))?;
            direct(emu, rec, 0x1004, addi(1, 0, 1))?;
            emu.with_sink_on_core(rec, |emu| emu.interpret_ecall(0x1008))
        }
        let mut emu = recorder_core(program(HALT));
        let block: RecordBlockFn = misnamed_block;
        let _ = emu.run_record_blocks(|pc| (pc == 0x1000).then_some(block));
    }
}
