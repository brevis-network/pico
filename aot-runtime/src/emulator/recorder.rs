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
                history::{Slots, UnalignedStep},
                history_arena::Table,
                memory::ContiguousRiscvMemory,
                public_values::RecordFinalPvsState,
                record::{AluStream, EmulationRecord},
                record_digest::{field_digests, first_difference, is_compared},
                record_slots::{hold_records_unbounded, init_record_slots},
                riscv_emulator::{
                    guard::access_width, AbnormalTermination, EmulationDeferredState,
                    EmulationError, RiscvEmulator, RiscvEmulatorMode, TerminationReason,
                },
                sink::BlockRows,
                state::RiscvEmulationState,
                syscalls::SyscallCode,
            },
        },
        primitives::layout::{HEAP_END, MEMORY_SIZE, MIN_SEGMENT_ADDR, STACK_BOTTOM},
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
    /// As in a generated crate, no block answers a pc outside the program.
    fn recorded_one_by_one(
        program: Arc<Program>,
    ) -> (Result<(), String>, EmittedChunk, AotEmulatorCore) {
        let code = program.code();
        let mut emu = recorder_core(program);
        let block: RecordBlockFn = one_instruction_block;
        let ran = emu.run_record_blocks(|pc| code.contains(&pc).then_some(block));
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
    /// body: a load, a store, a jump or a branch through its `_no_count` helper, a jump's target
    /// checked where the generated code checks it, and anything else through the fallback, as
    /// everything inside an unconstrained region is.
    fn emitting_block(emu: &mut AotEmulatorCore) -> Result<NextStep, String> {
        use Opcode::*;
        if emu.is_unconstrained_mode() {
            emu.debug_interpret_single_step()?;
            return Ok(NextStep::Dynamic(emu.pc));
        }
        let (pc, insn) = (emu.pc, emu.program.fetch(emu.pc));
        let emitting = emu.is_emitting();
        let (a, b, c, next_pc) = (
            usize::from(insn.op_a),
            insn.op_b as usize,
            insn.op_c,
            pc + 4,
        );
        let target = match insn.opcode {
            JAL => {
                let target = pc.wrapping_add(insn.op_b);
                emu.check_jump_target(pc, target)?;
                emu.jal_no_count(emitting, a, pc, insn.op_b);
                target
            }
            JALR => emu.jalr_no_count(emitting, a, b, pc, c)?,
            BEQ | BNE | BLT | BGE | BLTU | BGEU => {
                let taken = match insn.opcode {
                    BEQ => emu.beq_no_count(emitting, a, b, pc, c),
                    BNE => emu.bne_no_count(emitting, a, b, pc, c),
                    BLT => emu.blt_no_count(emitting, a, b, pc, c),
                    BGE => emu.bge_no_count(emitting, a, b, pc, c),
                    BLTU => emu.bltu_no_count(emitting, a, b, pc, c),
                    _ => emu.bgeu_no_count(emitting, a, b, pc, c),
                };
                if taken {
                    emu.check_jump_target(pc, pc.wrapping_add(c))?;
                    pc.wrapping_add(c)
                } else {
                    next_pc
                }
            }
            _ => {
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
                return Ok(NextStep::Dynamic(emu.pc));
            }
        };
        emu.pc = target;
        emu.update_insn_clock();
        Ok(NextStep::Dynamic(target))
    }

    /// `program` run by [`emitting_block`]s on a replay worker: the run's result, its chunk and the
    /// core.
    fn emitted_one_by_one(
        program: Arc<Program>,
    ) -> (Result<(), String>, EmittedChunk, AotEmulatorCore) {
        let code = program.code();
        let mut emu = recorder_core(program);
        let block: BlockFn = emitting_block;
        let ran = emu.run_blocks(|pc| code.contains(&pc).then_some(block));
        let emitted = cut(&mut emu);
        (ran, emitted, emu)
    }

    /// `program` run by [`recording_block`]s, each block whole: the run's result, its chunk and the
    /// core.
    fn recorded_in_blocks(
        program: Arc<Program>,
    ) -> (Result<(), String>, EmittedChunk, AotEmulatorCore) {
        let code = program.code();
        let mut emu = recorder_core(program);
        let block: RecordBlockFn = recording_block;
        let ran = emu.run_record_blocks(|pc| code.contains(&pc).then_some(block));
        assert!(emu.is_emitting(), "the sink is back on the core");
        let recorded = cut(&mut emu);
        (ran, recorded, emu)
    }

    /// `program` run by the AOT core's fallback interpreter alone, on a replay worker: the run's
    /// result, its chunk and the core.
    fn fallback_run(program: Arc<Program>) -> (Result<(), String>, EmittedChunk, AotEmulatorCore) {
        let mut emu = recorder_core(program);
        let ran = emu.run_blocks(|_| None);
        let chunk = cut(&mut emu);
        (ran, chunk, emu)
    }

    /// One instruction case, which every engine runs ([`assert_engines_agree`]).
    struct Case {
        what: String,
        program: Arc<Program>,
        /// `None` for a run that halts.
        fault: Option<TerminationReason>,
        /// Register values every engine leaves.
        registers: Vec<(usize, u64)>,
        /// The misaligned accesses a run that halts counts.
        misaligned: u64,
        /// What a case that halts pins in the chunk its whole recording blocks cut, besides that
        /// count.
        pins: fn(&EmittedChunk),
    }

    /// A case at 0x1000 that runs `insns`, then halts.
    fn halting(
        what: &str,
        mut insns: Vec<Instruction>,
        registers: Vec<(usize, u64)>,
        misaligned: u64,
    ) -> Case {
        insns.extend([addi(5, 0, u64::from(HALT)), self::ECALL]);
        Case {
            what: what.to_string(),
            program: Arc::new(Program::new(insns, 0x1000, 0x1000)),
            fault: None,
            registers,
            misaligned,
            pins: |_| {},
        }
    }

    fn folded(rd: u8, value: u64) -> Instruction {
        Instruction::new(Opcode::ADD, rd, value, 0, true, true)
    }

    /// A load into `rd`, or a store of it, at `rs1 + imm`.
    fn access(opcode: Opcode, rd: u8, rs1: u64, imm: u64) -> Instruction {
        Instruction::new(opcode, rd, rs1, imm, false, true)
    }

    fn branch(opcode: Opcode, rs1: u8, rs2: u64, offset: i64) -> Instruction {
        Instruction::new(opcode, rs1, rs2, offset as u64, false, true)
    }

    fn jal(rd: u8, offset: i64) -> Instruction {
        Instruction::new(Opcode::JAL, rd, offset as u64, 0, true, true)
    }

    fn jalr(rd: u8, rs1: u64, imm: i64) -> Instruction {
        Instruction::new(Opcode::JALR, rd, rs1, imm as u64, false, true)
    }

    /// Where each jump case's jump is; its target is relative to it.
    const JUMP_PC: u64 = 0x1008;
    /// What `x6` holds before the jump: a link a jump that fails leaves alone.
    const KEPT: u64 = 0x5eed;

    /// `x6 = KEPT` and `x5 = base`, then `jump` at [`JUMP_PC`], `x7 = 1` and a halt.
    fn jump_program(base: u64, jump: Instruction) -> Arc<Program> {
        Arc::new(Program::new(
            vec![
                folded(6, KEPT),
                folded(5, base),
                jump,
                addi(7, 0, 1),
                addi(5, 0, u64::from(HALT)),
                self::ECALL,
            ],
            0x1000,
            0x1000,
        ))
    }

    /// A jump that fails for `reason` writes nothing: its `rd` keeps what it held.
    fn jump_fails(what: &str, base: u64, jump: Instruction, reason: TerminationReason) -> Case {
        let rd = usize::from(jump.op_a);
        let held = match rd {
            5 => base,
            6 => KEPT,
            _ => 0,
        };
        Case {
            what: format!("{what}: {jump:?}, x5 = {base:#x}"),
            program: jump_program(base, jump),
            fault: Some(reason),
            registers: vec![(5, base), (6, KEPT), (rd, held)],
            misaligned: 0,
            pins: |_| {},
        }
    }

    /// A jump that lands, leaving its link in `x1` and the marker `x7` as given.
    fn jump_lands(what: &str, base: u64, jump: Instruction, link: u64, marker: u64) -> Case {
        Case {
            what: format!("{what}: {jump:?}, x5 = {base:#x}"),
            program: jump_program(base, jump),
            fault: None,
            registers: vec![(1, link), (7, marker)],
            misaligned: 0,
            pins: |_| {},
        }
    }

    fn jump_cases() -> Vec<Case> {
        use Opcode::{BEQ, BNE};
        use TerminationReason::{MisalignedJumpTarget, OutsideProgram};
        let misaligned = |target| MisalignedJumpTarget {
            pc: JUMP_PC,
            target,
        };
        let outside = |pc| OutsideProgram { pc };
        let (marker, end) = (JUMP_PC + 4, JUMP_PC + 16);
        let nop = Instruction::new(Opcode::ADD, 0, 0, 0, false, false);
        let mut cases = vec![
            jump_fails(
                "a JAL to a misaligned target",
                0,
                jal(1, 6),
                misaligned(JUMP_PC + 6),
            ),
            jump_fails(
                "a taken branch to one",
                0,
                branch(BEQ, 0, 0, 2),
                misaligned(JUMP_PC + 2),
            ),
            // JALR clears bit 0 only: bit 1 left set is misaligned, not rounded down.
            jump_fails(
                "a JALR to one",
                JUMP_PC + 6,
                jalr(1, 5, 0),
                misaligned(JUMP_PC + 6),
            ),
            jump_fails(
                "a JAL past the program",
                0,
                jal(1, 0x100),
                outside(JUMP_PC + 0x100),
            ),
            jump_fails("a JAL below it", 0, jal(1, -12), outside(0x1000 - 4)),
            jump_fails(
                "a taken branch to its end",
                0,
                branch(BEQ, 0, 0, 16),
                outside(end),
            ),
            // Only HALT ends a run at 0.
            jump_fails("a JALR to 0", 0, jalr(1, 0, 0), outside(0)),
            // Past the pcs a CPU row holds, and the last one it holds: the run ends before a cut
            // on the jump's clock would encode the target.
            jump_fails("a JALR to 2^48", 1 << 48, jalr(0, 5, 0), outside(1 << 48)),
            jump_fails(
                "a JALR to 2^32 - 4",
                1 << 32,
                jalr(0, 5, -4),
                outside((1 << 32) - 4),
            ),
            jump_lands("a JALR clears bit 0", marker + 1, jalr(1, 5, 0), marker, 1),
            jump_lands(
                "a JALR clears bit 0 after adding its immediate",
                JUMP_PC + 3,
                jalr(1, 5, 2),
                marker,
                1,
            ),
            jump_lands(
                "a JALR past the marker",
                marker + 4,
                jalr(1, 5, 1),
                marker,
                0,
            ),
            jump_lands(
                "a branch not taken checks no target",
                0,
                branch(BNE, 0, 0, 2),
                0,
                1,
            ),
            Case {
                what: "running past the last instruction".to_string(),
                program: Arc::new(Program::new(vec![nop, nop], 0x1000, 0x1000)),
                fault: Some(outside(0x1008)),
                registers: Vec::new(),
                misaligned: 0,
                pins: |_| {},
            },
        ];
        // Whether its link is its base, another register or `x0`.
        for (base, reason) in [
            (0x1002, misaligned(0x1002)),
            (0x2000, outside(0x2000)),
            (1 << 32, outside(1 << 32)),
        ] {
            for rd in [0, 5, 6] {
                cases.push(jump_fails(
                    "a JALR whose target fails its check",
                    base,
                    jalr(rd, 5, 0),
                    reason,
                ));
            }
        }
        cases
    }

    fn misaligned_cases() -> Vec<Case> {
        use Opcode::*;
        const LOW: u64 = 0x1122_3344_5566_7788;
        const HIGH: u64 = 0x99aa_bbcc_ddee_ff00;
        let mut every_width = halting(
            "every width at a misaligned address, within its dword and into the next",
            vec![
                addi(1, 0, BASE),
                folded(2, 0x8899_aabb_ccdd_eeff),
                folded(3, 0xf0e1_d2c3_b4a5_9687),
                access(SD, 2, 1, 0),
                access(SD, 3, 1, 8),
                // Within the dword, over high bits set so the sign fill shows.
                access(LH, 4, 1, 1),
                access(LHU, 5, 1, 3),
                access(LW, 6, 1, 2),
                access(LWU, 7, 1, 1),
                access(LB, 8, 1, 7),
                access(LBU, 9, 1, 5),
                // Into the next dword; `a0` and `a1` stay clear for the halt.
                access(LH, 20, 1, 7),
                access(LHU, 21, 1, 7),
                access(LW, 12, 1, 5),
                access(LWU, 13, 1, 6),
                access(LD, 14, 1, 3),
                access(LD, 15, 1, 9),
                access(LW, 0, 1, 6),
                // Stores within the dword, then into the next: one written whole, one merged
                // into, and one never written.
                access(SH, 3, 1, 1),
                access(SW, 3, 1, 10),
                access(SH, 2, 1, 7),
                access(SW, 2, 1, 14),
                access(SD, 3, 1, 4),
                access(SD, 2, 1, 21),
                access(SB, 3, 1, 3),
                access(LD, 16, 1, 0),
                access(LD, 17, 1, 8),
                access(LD, 18, 1, 16),
                access(LD, 19, 1, 24),
            ],
            // LH and LW sign-extend.
            vec![(4, 0xffff_ffff_ffff_ddee), (12, 0xffff_ffff_8788_99aa)],
            17,
        );
        every_width.pins = |chunk| {
            // Every instruction but the closing `ECALL` ran direct, none through the fallback.
            assert_eq!(chunk.recorder_direct_insns, chunk.cycles - 1);
            let history = chunk.record.history.as_ref().expect("a history");
            let crossing = history
                .unaligned
                .iter()
                .filter(|unaligned| unaligned.crosses != 0)
                .count();
            // Four loads and two stores within their dword; seven loads and four stores across.
            assert_eq!(crossing, 11);
            assert_eq!(history.operand_exceptions.len(), 1, "the crossing `LW x0`");
        };
        let over_words = halting(
            "misaligned accesses over words stored aligned, and read back",
            vec![
                addi(1, 0, BASE),
                addi(2, 0, 0x7654_3210),
                addi(3, 0, (-0x1234_5679_i64) as u64),
                access(SW, 2, 1, 0),
                access(SW, 3, 1, 4),
                access(SW, 2, 1, 8),
                access(SW, 3, 1, 12),
                access(LH, 4, 1, 1),
                access(LHU, 5, 1, 7),
                access(LW, 6, 1, 2),
                access(LWU, 7, 1, 6),
                access(LD, 8, 1, 3),
                access(SH, 2, 1, 9),
                access(SH, 3, 1, 15),
                access(SW, 3, 1, 13),
                access(SW, 2, 1, 17),
                access(SD, 8, 1, 21),
                access(LD, 9, 1, 8),
                access(LD, 10, 1, 16),
                access(LD, 11, 1, 24),
                access(LW, 12, 1, 23),
                access(LD, 13, 1, 26),
                // The halt's exit code.
                addi(10, 0, 0),
            ],
            Vec::new(),
            12,
        );
        let one_dword_across = halting(
            "an LD and an SD across a dword boundary",
            vec![
                addi(1, 0, BASE),
                folded(2, 0x8877_6655_4433_2211),
                access(SD, 2, 1, 0),
                folded(2, 0xffee_ddcc_bbaa_9900),
                access(SD, 2, 1, 8),
                folded(2, 0x0123_4567_89ab_cdef),
                access(LD, 3, 1, 4),
                access(SD, 2, 1, 4),
                access(LD, 7, 1, 0),
                access(LD, 8, 1, 8),
            ],
            vec![
                (3, 0xbbaa_9900_8877_6655),
                (7, 0x89ab_cdef_4433_2211),
                (8, 0xffee_ddcc_0123_4567),
            ],
            2,
        );
        // Inside the region a value other than the one expected branches to a misaligned target,
        // which ends the run; `EXIT_UNCONSTRAINED` resumes at the branch past the region with
        // `t0 = 0`. A store across into a dword never written rolls back as one across into a
        // dword written before the region does.
        let region = [
            access(SD, 2, 1, 5),
            access(LW, 4, 1, 5),
            branch(BNE, 4, 13, 2),
            access(LD, 15, 1, 8),
            branch(BNE, 15, 16, 2),
            access(SD, 2, 1, 0x15),
            addi(5, 0, SyscallCode::EXIT_UNCONSTRAINED as u64),
            self::ECALL,
        ];
        let mut unconstrained = vec![
            addi(1, 0, BASE),
            folded(2, LOW),
            access(SD, 2, 1, 0),
            folded(2, HIGH),
            access(SD, 2, 1, 8),
            folded(2, 0xdead_beef_cafe_f00d),
            folded(13, 0xffff_ffff_cafe_f00d),
            folded(16, 0x99aa_bbde_adbe_efca),
            addi(5, 0, SyscallCode::ENTER_UNCONSTRAINED as u64),
            self::ECALL,
            branch(BEQ, 5, 0, 4 * (region.len() as i64 + 1)),
        ];
        unconstrained.extend(region);
        unconstrained.extend([
            access(LD, 17, 1, 0),
            access(LD, 18, 1, 8),
            access(LD, 19, 1, 0x18),
        ]);
        let unconstrained = halting(
            "misaligned accesses in an unconstrained region, rolled back and not counted",
            unconstrained,
            vec![(4, 0), (15, 0), (17, LOW), (18, HIGH), (19, 0)],
            0,
        );
        vec![every_width, over_words, one_dword_across, unconstrained]
    }

    /// The pc base of the guarded access cases, above the memory floor so their code can be
    /// stored into.
    const CODE: u64 = 0x3_0000;
    /// Where those programs' code ends: five instructions on.
    const CODE_END: u64 = CODE + 4 * 5;
    /// What `x4` holds before the access: what a store writes and a refused load leaves.
    const STORED: u64 = 0x1234;

    /// `x1 = addr` and `x4 = STORED`, then `opcode` at `x1`, a load into `x4` or a store of it, and
    /// a halt: refused for `reason`, or run.
    fn guarded_access(opcode: Opcode, addr: u64, reason: Option<TerminationReason>) -> Case {
        let insn = access(opcode, 4, 1, 0);
        let mut registers = vec![(1, addr)];
        if reason.is_some() {
            registers.push((4, STORED));
        }
        Case {
            what: format!("{insn:?} at {addr:#x}"),
            program: Arc::new(Program::new(
                vec![
                    folded(1, addr),
                    folded(4, STORED),
                    insn,
                    addi(5, 0, u64::from(HALT)),
                    self::ECALL,
                ],
                CODE,
                CODE,
            )),
            fault: reason,
            registers,
            misaligned: u64::from(!addr.is_multiple_of(access_width(opcode))),
            pins: |_| {},
        }
    }

    /// Below the floor, in the stack guard, past the top of memory and, for a store, into the
    /// code, at each width, where the access starts and where it only runs into the region; and
    /// beside each, where the access may land.
    fn guarded_access_cases() -> Vec<Case> {
        use Opcode::*;
        type Reason = fn(Opcode, u64) -> TerminationReason;
        let null: Reason = |opcode, addr| TerminationReason::NullAccess { opcode, addr };
        let guard: Reason = |opcode, addr| TerminationReason::StackOverflow { opcode, addr };
        let past: Reason = |opcode, addr| TerminationReason::InvalidMemoryAccess { opcode, addr };
        let code: Reason = |opcode, addr| TerminationReason::StoreToCode { opcode, addr };
        let mut refused: Vec<(Opcode, u64, Reason)> = Vec::new();
        refused.extend([LB, LHU, LW, SB, SH, SD].map(|opcode| (opcode, 0x100, null)));
        refused.extend([LBU, LH, LD, SB, SW, SD].map(|opcode| (opcode, HEAP_END, guard)));
        refused.extend([LH, LHU, LWU, LD, SH, SW].map(|opcode| (opcode, MEMORY_SIZE - 1, past)));
        refused.extend([SB, SH, SW, SD].map(|opcode| (opcode, CODE + 4, code)));
        refused.extend([
            (SB, 0, null),
            (LW, MIN_SEGMENT_ADDR - 4, null),
            (LD, MIN_SEGMENT_ADDR - 2, null),
            (LW, HEAP_END - 2, guard),
            (SD, HEAP_END - 4, guard),
            (LB, STACK_BOTTOM - 1, guard),
            (LD, MEMORY_SIZE - 4, past),
            (LB, MEMORY_SIZE, past),
            (SB, MEMORY_SIZE, past),
            (SW, CODE + 8, code),
            (SH, CODE - 1, code),
            (SD, CODE_END - 4, code),
        ]);
        // A load from the code is no fault.
        let allowed = [
            (LB, CODE + 4),
            (LD, CODE + 4),
            (LW, CODE),
            (SW, CODE - 4),
            (SW, CODE_END),
            (LD, MIN_SEGMENT_ADDR),
            (SD, HEAP_END - 8),
            (SB, STACK_BOTTOM),
            (SD, MEMORY_SIZE - 8),
        ];
        refused
            .into_iter()
            .map(|(opcode, addr, reason)| guarded_access(opcode, addr, Some(reason(opcode, addr))))
            .chain(
                allowed
                    .into_iter()
                    .map(|(opcode, addr)| guarded_access(opcode, addr, None)),
            )
            .collect()
    }

    /// How a run ends: at its `HALT`, or abnormally.
    type Ending = Result<(), AbnormalTermination>;

    fn termination(error: &EmulationError) -> AbnormalTermination {
        *error
            .abnormal_termination()
            .unwrap_or_else(|| panic!("not an abnormal termination: {error}"))
    }

    /// The opcode and address of the access a fault refused, if it refused one.
    fn refused_access(reason: &TerminationReason) -> Option<(Opcode, u64)> {
        use TerminationReason::*;
        match *reason {
            NullAccess { opcode, addr }
            | InvalidMemoryAccess { opcode, addr }
            | StackOverflow { opcode, addr }
            | StoreToCode { opcode, addr } => Some((opcode, addr)),
            _ => None,
        }
    }

    /// What a run of pico-vm's interpreter left, `clocks` the instructions it completed.
    struct VmRun {
        ended: Ending,
        message: Option<String>,
        registers: [u64; 32],
        misaligned: u64,
        clocks: u64,
    }

    /// `program` run by pico-vm's interpreter in `mode` from its start until it ends, the chunk
    /// cut on global clock `cut_at` when given.
    fn vm_run(program: &Arc<Program>, mode: RiscvEmulatorMode, cut_at: Option<u64>) -> VmRun {
        let opts = EmulatorOpts {
            chunk_size: 1 << 22,
            chunk_batch_size: 1,
            max_cycles: Some(1 << 20),
            ..EmulatorOpts::test_opts()
        };
        let mut vm = RiscvEmulator::new_single::<KoalaBear>(
            program.clone(),
            Arc::new(RecordFinalPvsState::default()),
            opts,
        );
        vm.mode = mode;
        vm.update_mode_deps();
        vm.target_global_clk = cut_at;
        let error = loop {
            match vm.emulate_batch(&mut |_| {}) {
                Ok(report) if report.done => break None,
                Ok(_) => {}
                Err(error) => break Some(error),
            }
        };
        VmRun {
            ended: error
                .as_ref()
                .map_or(Ok(()), |error| Err(termination(error))),
            message: error.map(|error| error.to_string()),
            registers: vm.registers(),
            misaligned: vm.state.misaligned_accesses,
            clocks: vm.state.global_clk,
        }
    }

    /// What a run leaves in the core besides its records: what the next instruction, the snapshot
    /// and the chunk split read.
    fn core_state(emu: &AotEmulatorCore) -> String {
        let cells = |memory: &ContiguousRiscvMemory| {
            let mut addrs: Vec<_> = memory.accessed_keys().collect();
            addrs.sort_unstable();
            addrs
                .into_iter()
                .map(|addr| (addr, memory.get(addr)))
                .collect::<Vec<_>>()
        };
        let split = &emu.chunk_split_state;
        format!(
            "{:?} {:?} {:?} {:?} {:?} {:#x} {} {} {}",
            emu.registers,
            emu.touched_registers,
            cells(&emu.memory),
            cells(&emu.memory_snapshot),
            (
                emu.misaligned_accesses,
                split.num_misaligned,
                split.num_syscall_events,
                split.num_syscall_memory_events,
                split.num_memory_read_write_events,
                split.num_global_lookup_base,
            ),
            emu.pc,
            emu.clk,
            emu.insn_count,
            emu.current_chunk,
        )
    }

    fn unaligned(record: &EmulationRecord) -> &[UnalignedStep] {
        record
            .history
            .as_ref()
            .expect("a history")
            .unaligned
            .as_slice()
    }

    /// That the AOT core's run ended as pico-vm's did, with its message and register values, its
    /// misaligned accesses counted where it halts, and without touching the memory of an access
    /// it refused.
    fn assert_ends_as(
        case: &Case,
        vm: &VmRun,
        engine: &str,
        ran: &Result<(), String>,
        emu: &AotEmulatorCore,
    ) {
        let what = &case.what;
        assert_eq!(ran.as_ref().err(), vm.message.as_ref(), "{what}: {engine}");
        let ended = emu
            .fault
            .as_ref()
            .map_or(Ok(()), |fault| Err(termination(fault)));
        assert_eq!(ended, vm.ended, "{what}: {engine}");
        assert_eq!(
            emu.registers.0.map(|register| register.value),
            vm.registers,
            "{what}: {engine}'s registers"
        );
        if case.fault.is_none() {
            assert_eq!(
                emu.misaligned_accesses, case.misaligned,
                "{what}: {engine}'s misaligned accesses"
            );
        }
        if let Some((opcode, addr)) = case.fault.as_ref().and_then(refused_access) {
            let end = addr.saturating_add(access_width(opcode));
            assert!(
                emu.memory
                    .accessed_keys()
                    .all(|dword| dword + 8 <= addr || dword >= end),
                "{what}: {engine} touched the memory it refused"
            );
        }
    }

    /// Runs `case` on every engine: pico-vm's interpreter recording a trace, which the others are
    /// held to, and in simple mode; the AOT core's fallback interpreter, its plain body and its
    /// recording body, one instruction a block and whole blocks, on a replay worker; and the
    /// fallback and the plain body on a core with no sink, which a halting run has to leave as it
    /// does with one. Where the run halts or an access is refused, every AOT record is the
    /// fallback's, and where it halts, pico-vm's replay worker's too. A jump that fails is not
    /// compared row by row: the generated code writes a branch's row before it checks the target,
    /// the fallback checks first, and the run fails, so neither row is read.
    fn assert_engines_agree(case: &Case) {
        let (what, program) = (case.what.as_str(), &case.program);
        let halts = case.fault.is_none();

        let vm = vm_run(program, RiscvEmulatorMode::Trace, None);
        assert_eq!(
            vm.ended.err().map(|end| end.reason),
            case.fault,
            "{what}: pico-vm, {:?}",
            vm.message
        );
        for &(reg, value) in &case.registers {
            assert_eq!(vm.registers[reg], value, "{what}: pico-vm's x{reg}");
        }
        if halts {
            assert_eq!(vm.misaligned, case.misaligned, "{what}: pico-vm's count");
        }
        if let (Err(end), Some(_)) = (vm.ended, case.fault.as_ref().and_then(refused_access)) {
            assert_eq!(end.exit_code, 139, "{what}: SIGSEGV's code");
        }
        // A run that fails does so before a cut on the clock of the instruction that fails.
        let last = if halts { vm.clocks } else { vm.clocks + 1 };
        let simple = vm_run(program, RiscvEmulatorMode::Simple, (!halts).then_some(last));
        assert_eq!(
            (simple.ended, &simple.message, simple.registers),
            (vm.ended, &vm.message, vm.registers),
            "{what}: pico-vm in simple mode"
        );
        if halts {
            assert_eq!(simple.misaligned, vm.misaligned, "{what}: in simple mode");
        }
        let replayed = vm_replayed(program.clone(), last);

        let (fallback_ran, fallback_chunk, fallback) = fallback_run(program.clone());
        let (plain_ran, plain_chunk, plain) = emitted_one_by_one(program.clone());
        let (recorded_ran, recorded_chunk, recorded) = recorded_one_by_one(program.clone());
        let (blocks_ran, blocks_chunk, blocks) = recorded_in_blocks(program.clone());
        let others = [
            ("the plain body", &plain_ran, &plain_chunk, &plain),
            (
                "the recording body",
                &recorded_ran,
                &recorded_chunk,
                &recorded,
            ),
            (
                "whole recording blocks",
                &blocks_ran,
                &blocks_chunk,
                &blocks,
            ),
        ];
        assert_ends_as(case, &vm, "the fallback", &fallback_ran, &fallback);
        for (engine, ran, _, emu) in others {
            assert_ends_as(case, &vm, engine, ran, emu);
        }
        assert_eq!(
            (
                recorded.misaligned_accesses,
                recorded.chunk_split_state.num_misaligned
            ),
            (
                plain.misaligned_accesses,
                plain.chunk_split_state.num_misaligned
            ),
            "{what}: the misaligned accesses the recording body counted, then the plain body"
        );

        assert!(
            recorded_chunk.recorder_direct_insns > 0 && blocks_chunk.recorder_direct_insns > 0,
            "{what}: the recording body wrote no row itself"
        );

        let reference = &fallback_chunk.record;
        let refused = case.fault.as_ref().and_then(refused_access).is_some();
        if halts || refused {
            for (engine, _, chunk, _) in others {
                assert_eq!(
                    first_difference(reference, &chunk.record),
                    None,
                    "{what}: {engine}, the fallback's record first"
                );
                assert_eq!(
                    unaligned(reference),
                    unaligned(&chunk.record),
                    "{what}: {engine}'s unaligned table"
                );
            }
            assert_eq!(
                recorded.registers, plain.registers,
                "{what}: the recording body's register records"
            );
        }
        if refused {
            assert_eq!(
                table_rows(reference),
                (2, 0, 2, 0),
                "{what}: the two constants' rows, and none for the refused access"
            );
        }
        if halts {
            let (vm_record, vm_registers) =
                replayed.unwrap_or_else(|error| panic!("{what}: pico-vm's replay: {error}"));
            assert_eq!(vm_registers, vm.registers, "{what}: pico-vm's replay");
            assert_eq!(
                differences_from_vm(&vm_record, reference),
                Vec::<String>::new(),
                "{what}"
            );
            assert_eq!(recorded.registers, fallback.registers, "{what}");
            assert_eq!(
                unaligned(reference).len() as u64,
                case.misaligned,
                "{what}: the unaligned steps"
            );
            (case.pins)(&blocks_chunk);
        } else {
            assert_eq!(replayed.err(), vm.message, "{what}: pico-vm's replay");
        }

        for (body, block) in [
            ("the fallback", None),
            ("the plain body", Some(emitting_block as BlockFn)),
        ] {
            let code = program.code();
            let run = |emitting: bool| {
                let mut emu = AotEmulatorCore::new(program.clone(), Vec::new());
                if emitting {
                    emu.emit_records();
                }
                let ran = emu.run_blocks(|pc| block.filter(|_| code.contains(&pc)));
                (ran, emu)
            };
            let (quiet_ran, quiet) = run(false);
            assert_ends_as(case, &vm, &format!("{body}, no sink"), &quiet_ran, &quiet);
            if halts {
                assert_eq!(
                    core_state(&run(true).1),
                    core_state(&quiet),
                    "{what}: {body}, the run with a sink first"
                );
            }
        }
    }

    #[test]
    fn a_jump_ends_or_lands_alike_on_every_engine() {
        hold_records_unbounded();
        let cases = jump_cases();
        assert_eq!(cases.len(), 23, "the jump table lost or gained a case");
        for case in cases {
            assert_engines_agree(&case);
        }
    }

    #[test]
    fn a_misaligned_access_runs_alike_on_every_engine() {
        hold_records_unbounded();
        let cases = misaligned_cases();
        assert_eq!(cases.len(), 4, "the misaligned table lost or gained a case");
        for case in cases {
            assert_engines_agree(&case);
        }
    }

    #[test]
    fn a_guarded_access_ends_or_runs_alike_on_every_engine() {
        hold_records_unbounded();
        let cases = guarded_access_cases();
        assert_eq!(
            cases.len(),
            43,
            "the guarded-access table lost or gained a case"
        );
        for case in cases {
            assert_engines_agree(&case);
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
