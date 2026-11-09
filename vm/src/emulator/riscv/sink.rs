use crate::{
    chips::chips::{
        events::{MemoryAccessPosition, MemoryLocalEvent},
        riscv_memory::event::MemoryRecordEnum,
    },
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
    emulator::riscv::{
        emulator::guard::access_width,
        event_types::{RvAddr, RvChunk, RvClk, RvValue},
        history::{
            ruled_operands, Access, ExecutionHistory, OperandException, ReadAccess, Slots, Step,
            UnalignedStep,
        },
        history_arena,
        public_values_compat::encode_public_value_pc_limbs,
        record::{AluStream, EmulationRecord},
        record_slots,
        syscalls::SyscallEvent,
    },
};
use hashbrown::HashMap;
use std::sync::Arc;

/// Where a cut chunk started and where it hands over: the chunk's `start_pc` and `next_pc` public
/// values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkBoundary {
    /// The pc of the chunk's first instruction.
    pub start_pc: RvAddr,
    /// The pc the next chunk starts at: the last instruction's next pc.
    pub next_pc: RvAddr,
}

/// Where the interpreter writes the events of each instruction it executes.
///
/// The trait carries the cycle's operand accesses, its ALU, CPU and syscall events, the chunk cut
/// and the unconstrained block's rollback. An implementation only writes: whether an event is
/// written at all is the emulator mode's decision, taken before the call.
///
/// Four writes do not go through it: a precompile's events and the CPU windows it closes, the
/// digest words a COMMIT or COMMIT_DEFERRED_PROOFS stores in the public values, the local-memory
/// windows the emulator updates on every access (per address in a map, per register in an
/// array), and `postprocess`'s memory initialize and finalize events. Those reach the current
/// record through [`Sink::record_mut`], [`Sink::local_memory_access_mut`] and
/// [`Sink::register_local_access_mut`], so every sink still holds an [`EmulationRecord`] and both
/// kinds of window.
pub trait ExecutionSink {
    /// A cycle starts; the previous cycle's operand accesses are forgotten.
    fn begin_cycle(&mut self);

    /// This cycle's access in operand slot `position`: a register for `A`, `B` and `C`, memory
    /// for `Memory`.
    fn access(&mut self, position: MemoryAccessPosition, record: MemoryRecordEnum);

    /// This cycle's access to the dword after the one its load or store starts in, which a
    /// misaligned access that runs into it makes at the `C` position. It fills no slot:
    /// a load's or a store's `c` is an immediate.
    fn next_dword(&mut self, record: MemoryRecordEnum);

    fn alu(&mut self, clk: RvClk, opcode: Opcode, a: RvValue, b: RvValue, c: RvValue, is_imm: bool);

    /// The cycle ends; its accesses are the ones reported since [`Self::begin_cycle`].
    #[allow(clippy::too_many_arguments)]
    fn end_cycle(
        &mut self,
        chunk: RvChunk,
        clk: RvClk,
        pc: RvAddr,
        next_pc: RvAddr,
        exit_code: u32,
        a: RvValue,
        b: RvValue,
        c: RvValue,
        instruction: Instruction,
        memory_store_value: Option<RvValue>,
    );

    fn syscall(&mut self, event: SyscallEvent);

    /// An unconstrained block opens. Whatever is written from here to
    /// [`Self::exit_unconstrained`] is discarded there: the block's state is rolled back, so no
    /// record may carry its events.
    fn enter_unconstrained(&mut self);

    /// The unconstrained block closes, and the sink is as [`Self::enter_unconstrained`] left it.
    fn exit_unconstrained(&mut self);

    /// Whether the open chunk holds a step: an [`Self::end_cycle`] since the last cut that no
    /// unconstrained block rolled back. The emulator cuts its last chunk on it.
    fn holds_steps(&self) -> bool;

    /// Closes the chunk and returns its record, with every window the sink holds drained into it
    /// and, on a CPU chunk, `boundary` written into its public values, which are the only place
    /// the public-value readers take the chunk's pcs from. The next record is `program`'s and
    /// starts with this one's public values.
    ///
    /// Never called inside an unconstrained block.
    fn cut_chunk(&mut self, program: Arc<Program>, boundary: ChunkBoundary) -> EmulationRecord;
}

/// The record half of [`ExecutionSink::cut_chunk`]: writes `boundary` into a CPU chunk's public
/// values, swaps in `program`'s next record with the same public values, and returns the closed
/// one.
fn close_record(
    record: &mut EmulationRecord,
    program: Arc<Program>,
    boundary: ChunkBoundary,
) -> EmulationRecord {
    if record.is_cpu_chunk {
        let public_values = &mut record.public_values;
        public_values.start_pc = encode_public_value_pc_limbs(boundary.start_pc);
        public_values.next_pc = encode_public_value_pc_limbs(boundary.next_pc);
    }
    let next = EmulationRecord::new(program);
    let finished = std::mem::replace(record, next);
    record.public_values = finished.public_values;
    finished
}

/// The history a sink writes apart from its record, and the cycle in progress.
///
/// A step is written only for a cycle [`ExecutionSink::begin_cycle`] opened, which the emulator
/// does only while it traces events. Outside tracing it still ends the cycle of the ECALL closing
/// an unconstrained block, so the chunk boundary also tracks untraced cycle ends.
///
/// A chunk's history takes its slot of the process's history arena with its first write, so that
/// write waits while the process holds its bound of records ([`record_slots`]) and, on a pipeline
/// replay, until every earlier chunk of the run holds one ([`history_arena::order`]); a process
/// with no bound writes on the heap. An unconstrained block's history is dropped at its end, so it
/// takes none.
#[derive(Default)]
struct HistoryWriter {
    history: ExecutionHistory,
    /// Whether the chunk's history has looked for its slot: set by the first write, and inside an
    /// unconstrained block.
    slot_sought: bool,
    cycle: Cycle,
    /// An [`ExecutionSink::end_cycle`] since the last cut, traced or not: what
    /// [`ExecutionSink::holds_steps`] reports for the chunk cut.
    ended: bool,
    /// The next pc of a step left unwritten because it does not fit a row: no pc that far is in a
    /// program, so the run ends on that step with the emulator's own error, and no chunk is cut on
    /// it. A cut refuses the history if one is.
    unfit_next_pc: Option<RvAddr>,
    /// The history, `slot_sought`, the cycle and `ended` as an unconstrained block found them.
    unconstrained: Option<(ExecutionHistory, bool, Cycle, bool)>,
}

/// The accesses of the cycle in progress, by [`MemoryAccessPosition`].
#[derive(Clone, Copy, Default)]
struct Cycle {
    /// Meaningful only in the slots `filled` has the bit of.
    accesses: [Access; 4],
    filled: u8,
    traced: bool,
    /// The access to the next dword, of a misaligned load or store that runs into it.
    next: Option<Access>,
}

/// `value` as the `u32` a history row stores. Checked in every build: a clock, pc or index cut
/// short still names a plausible row, and nothing downstream would notice.
#[inline(always)]
fn narrow(value: u64, what: &'static str) -> u32 {
    match u32::try_from(value) {
        Ok(narrowed) => narrowed,
        Err(_) => too_wide(what, value),
    }
}

#[cold]
#[inline(never)]
fn too_wide(what: &str, value: u64) -> ! {
    panic!("{what} {value:#x} does not fit the history's u32")
}

impl HistoryWriter {
    /// Before a row is written: the chunk's first write moves its history into a slot, once the
    /// process bounds its records.
    #[inline(always)]
    fn before_write(&mut self) {
        if !self.slot_sought {
            self.seek_slot();
        }
    }

    #[cold]
    #[inline(never)]
    fn seek_slot(&mut self) {
        self.slot_sought = true;
        if let Some(arena) = record_slots::history_arena() {
            let history = &self.history;
            assert!(
                history.steps.is_empty() && history.syscalls.is_empty(),
                "a history moved to a slot after its first write"
            );
            let chunk = history.chunk;
            let taken = history_arena::order::with_turn(|turn| match turn {
                Some(turn) => arena.take_in_turn(chunk, turn),
                None => Some(arena.take(chunk)),
            });
            // None once the run has failed: the history stays on the heap, and the replay ends.
            if let Some(taken) = taken {
                self.history = taken;
            }
        }
    }

    #[inline]
    fn begin_cycle(&mut self) {
        self.cycle.filled = 0;
        self.cycle.traced = true;
        self.cycle.next = None;
    }

    #[inline]
    fn access(&mut self, position: MemoryAccessPosition, record: MemoryRecordEnum) {
        let slot = position as usize;
        self.cycle.accesses[slot] = record.into();
        self.cycle.filled |= 1 << slot;
    }

    #[inline]
    fn next_dword(&mut self, record: MemoryRecordEnum) {
        debug_assert!(self.cycle.next.is_none(), "a second next-dword access");
        self.cycle.next = Some(record.into());
    }

    /// The step in progress writes an ALU event.
    #[inline]
    fn alu(&mut self, opcode: Opcode) {
        debug_assert!(self.cycle.traced, "an ALU event outside a traced cycle");
        self.before_write();
        let history = &mut self.history;
        let index = narrow(history.steps.len() as u64, "step index");
        history
            .chip_steps
            .alu_mut(AluStream::of(opcode))
            .push(index);
    }

    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn end_cycle(
        &mut self,
        chunk: RvChunk,
        clk: RvClk,
        pc: RvAddr,
        next_pc: RvAddr,
        a: RvValue,
        b: RvValue,
        c: RvValue,
        instruction: &Instruction,
    ) {
        self.ended = true;
        if !std::mem::take(&mut self.cycle.traced) {
            return;
        }
        let Ok(next_pc) = u32::try_from(next_pc) else {
            self.unfit_next_pc = Some(next_pc);
            return;
        };
        self.before_write();
        let history = &mut self.history;
        let index = narrow(history.steps.len() as u64, "step index");
        if index == 0 {
            history.chunk = chunk;
        }
        debug_assert_eq!(history.chunk, chunk, "a step of another chunk");
        let pc = narrow(pc, "pc");
        history.steps.push(Step {
            clk: narrow(clk, "clk"),
            pc,
            next_pc,
            first_read: narrow(history.reads.len() as u64, "read index"),
            first_write: narrow(history.writes.len() as u64, "write index"),
        });
        let cycle = &self.cycle;
        let filled = |position: MemoryAccessPosition| cycle.filled & (1 << position as u8) != 0;
        // The readers pair rows with slots by the instruction, so the table follows from it too,
        // and a cycle that filled other slots would be paired wrongly in every build.
        let slots = Slots::of(instruction);
        assert_eq!(
            cycle.filled,
            slots.bits(),
            "step {index}'s accesses fill other slots than {instruction:?} names"
        );
        for position in Slots::ORDER {
            if filled(position) {
                let access = cycle.accesses[position as usize];
                if slots.writes(position) {
                    history.writes.push(access);
                } else {
                    debug_assert_eq!(
                        access.prev_value, access.value,
                        "step {index}'s {position:?} read changed the state"
                    );
                    history.reads.push(access.into());
                }
            }
        }
        let ruled = ruled_operands(instruction, pc, |position| {
            filled(position).then(|| cycle.accesses[position as usize].value)
        });
        for (slot, (seen, ruled)) in Slots::ORDER
            .into_iter()
            .zip([a, b, c].into_iter().zip(ruled))
        {
            if seen != ruled {
                history.operand_exceptions.push(OperandException {
                    step: index,
                    slot: slot as u32,
                    value: seen,
                });
            }
        }
        debug_assert_eq!(
            history.operands(index as usize, instruction),
            (a, b, c),
            "step {index}'s operands as the readers rebuild them"
        );
        if instruction.is_memory_instruction() {
            // A load or store whose address is not a multiple of its width goes to the unaligned
            // table, with the next dword's access, which it has exactly when it runs into that
            // dword.
            let (addr, width) = (b.wrapping_add(c), access_width(instruction.opcode));
            let crosses = addr % 8 + width > 8;
            assert_eq!(
                cycle.next.is_some(),
                crosses,
                "step {index}'s {:?} at 0x{addr:x} and its next dword's access",
                instruction.opcode
            );
            if addr.is_multiple_of(width) {
                history.chip_steps.memory.push(index);
            } else {
                history.unaligned.push(UnalignedStep {
                    step: index,
                    crosses: u32::from(crosses),
                    next: cycle.next.unwrap_or_default(),
                });
            }
            return;
        }
        let chip_steps = &mut history.chip_steps;
        if instruction.is_branch_instruction() {
            chip_steps.branch.push(index);
        } else if instruction.is_ecall_instruction() {
            chip_steps.ecall.push(index);
        }
    }

    #[inline]
    fn syscall(&mut self, event: SyscallEvent) {
        self.before_write();
        self.history.syscalls.push(event);
    }

    fn enter_unconstrained(&mut self) {
        let saved = (
            std::mem::take(&mut self.history),
            std::mem::replace(&mut self.slot_sought, true),
            std::mem::take(&mut self.cycle),
            std::mem::take(&mut self.ended),
        );
        assert!(
            self.unconstrained.replace(saved).is_none(),
            "an unconstrained block opens inside another"
        );
    }

    fn exit_unconstrained(&mut self) {
        (self.history, self.slot_sought, self.cycle, self.ended) = self
            .unconstrained
            .take()
            .expect("an unconstrained block closes that never opened");
    }

    /// The chunk's history, leaving an empty one for the next, which seeks its own slot.
    fn cut(&mut self) -> ExecutionHistory {
        if let Some(next_pc) = self.unfit_next_pc {
            too_wide("next pc", next_pc);
        }
        self.ended = false;
        self.slot_sought = false;
        std::mem::take(&mut self.history)
    }
}

/// Per-table row counts a block reserves through [`HistoryRows::reserve`] before its steps.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockRows {
    pub steps: usize,
    pub reads: usize,
    pub writes: usize,
    /// An upper bound: whether an exception is written depends on the operand's value.
    pub operand_exceptions: usize,
    /// Indexed by [`AluStream`] discriminant.
    pub alu: [usize; 8],
    pub memory: usize,
    pub branch: usize,
}

impl BlockRows {
    /// In discriminant order, matching the indexing of [`Self::alu`].
    const ALU_STREAMS: [AluStream; 8] = [
        AluStream::Add,
        AluStream::Sub,
        AluStream::Mul,
        AluStream::Bitwise,
        AluStream::ShiftLeft,
        AluStream::ShiftRight,
        AluStream::Lt,
        AluStream::DivRem,
    ];

    pub fn alu_mut(&mut self, stream: AluStream) -> &mut usize {
        &mut self.alu[stream as usize]
    }
}

/// The history's tables, for a writer that closes its steps itself instead of through
/// [`ExecutionSink::end_cycle`]: the AOT core's recording blocks.
///
/// Each step must be, row for row, the one `end_cycle` writes for the same cycle: reads in
/// [`Slots::ORDER`], then the write, the chip list entries, and an operand exception wherever the
/// rule of [`ExecutionHistory::operands`] misses. Nothing here checks it; `check_step` (test
/// builds) compares one step against `end_cycle`, which catches a wrong layout but not a value the
/// writer gets wrong consistently.
///
/// Rows go through `end_cycle`'s first-write path, so the chunk takes its arena slot, and a table
/// spills or refuses, at the same row. Steps are written between cycles: the emulator's open cycle
/// must hold no access.
pub struct HistoryRows<'a> {
    writer: &'a mut HistoryWriter,
}

impl HistoryRows<'_> {
    /// Takes the chunk's slot first, so the room is reserved in the tables the rows go into. Writes
    /// no row, so a block that stops part way leaves only the steps it wrote.
    #[inline]
    pub fn reserve(&mut self, room: &BlockRows) {
        let writer = &mut *self.writer;
        writer.before_write();
        let history = &mut writer.history;
        history.steps.reserve(room.steps);
        history.reads.reserve(room.reads);
        history.writes.reserve(room.writes);
        history.operand_exceptions.reserve(room.operand_exceptions);
        for (stream, entries) in BlockRows::ALU_STREAMS.into_iter().zip(room.alu) {
            if entries > 0 {
                history.chip_steps.alu_mut(stream).reserve(entries);
            }
        }
        history.chip_steps.memory.reserve(room.memory);
        history.chip_steps.branch.reserve(room.branch);
    }

    /// Writes one step and its rows, `reads` in [`Slots::ORDER`]. Returns the step's index.
    ///
    /// # Panics
    ///
    /// If an index does not fit a `u32`.
    #[inline(always)]
    pub fn step<const READS: usize, const WRITES: usize>(
        &mut self,
        chunk: RvChunk,
        clk: u32,
        pc: u32,
        next_pc: u32,
        reads: [ReadAccess; READS],
        writes: [Access; WRITES],
    ) -> u32 {
        let writer = &mut *self.writer;
        debug_assert!(
            writer.cycle.traced && writer.cycle.filled == 0,
            "a step written while a cycle holds accesses"
        );
        writer.ended = true;
        writer.before_write();
        let history = &mut writer.history;
        let index = narrow(history.steps.len() as u64, "step index");
        if index == 0 {
            history.chunk = chunk;
        }
        debug_assert_eq!(history.chunk, chunk, "a step of another chunk");
        let first_read = narrow(history.reads.len() as u64, "read index");
        let first_write = narrow(history.writes.len() as u64, "write index");
        history.steps.push(Step {
            clk,
            pc,
            next_pc,
            first_read,
            first_write,
        });
        history.reads.extend(reads);
        history.writes.extend(writes);
        index
    }

    /// This and the list and exception writers below must follow their step's [`Self::step`],
    /// which took the chunk's slot.
    #[inline(always)]
    pub fn alu(&mut self, stream: AluStream, step: u32) {
        self.writer.history.chip_steps.alu_mut(stream).push(step);
    }

    #[inline(always)]
    pub fn memory(&mut self, step: u32) {
        self.writer.history.chip_steps.memory.push(step);
    }

    #[inline(always)]
    pub fn branch(&mut self, step: u32) {
        self.writer.history.chip_steps.branch.push(step);
    }

    /// A misaligned load or store, in the unaligned table rather than the memory list, with its
    /// access to the next dword when it runs into it.
    #[inline(always)]
    pub fn unaligned(&mut self, step: u32, next: Option<Access>) {
        self.writer.history.unaligned.push(UnalignedStep {
            step,
            crosses: u32::from(next.is_some()),
            next: next.unwrap_or_default(),
        });
    }

    /// Operand `slot` held `value`, which the rule does not give.
    #[inline(always)]
    pub fn operand_exception(&mut self, step: u32, slot: MemoryAccessPosition, value: RvValue) {
        self.writer
            .history
            .operand_exceptions
            .push(OperandException {
                step,
                slot: slot as u32,
                value,
            });
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl HistoryRows<'_> {
    /// Panics unless the step at `index`, the last written, holds exactly the rows
    /// [`ExecutionSink::end_cycle`] writes for the cycle that made `accesses` (in the order made),
    /// the next-dword access `next` and an ALU event if `alu`. The emulator's open cycle must hold
    /// no access.
    #[allow(clippy::too_many_arguments)]
    pub fn check_step(
        &self,
        index: u32,
        chunk: RvChunk,
        clk: RvClk,
        pc: RvAddr,
        next_pc: RvAddr,
        accesses: &[(MemoryAccessPosition, MemoryRecordEnum)],
        next: Option<MemoryRecordEnum>,
        alu: bool,
        operands: [RvValue; 3],
        instruction: &Instruction,
    ) {
        let writer = &*self.writer;
        assert!(
            writer.cycle.traced && writer.cycle.filled == 0,
            "step {index} at {pc:#x} was written while a cycle held accesses"
        );
        // On the heap: the comparison's own history must not take a slot of the arena.
        let mut generic = HistoryWriter {
            slot_sought: true,
            ..HistoryWriter::default()
        };
        generic.begin_cycle();
        for &(position, record) in accesses {
            generic.access(position, record);
        }
        if let Some(next) = next {
            generic.next_dword(next);
        }
        if alu {
            generic.alu(instruction.opcode);
        }
        let [a, b, c] = operands;
        generic.end_cycle(chunk, clk, pc, next_pc, a, b, c, instruction);
        let (expected, written) = (&generic.history, &writer.history);
        let at = index as usize;
        let what = |table: &str| format!("step {index} at {pc:#x} ({instruction:?}): {table}");
        assert_eq!(written.steps.len(), at + 1, "{}", what("not the last step"));
        assert_eq!(
            expected.steps.len(),
            1,
            "{}",
            what("end_cycle wrote no step")
        );
        assert!(writer.ended, "{}", what("the chunk holds no step"));
        assert_eq!(written.chunk, chunk, "{}", what("chunk"));
        let (step, generic_step) = (written.steps[at], expected.steps[0]);
        assert_eq!(
            (step.clk, step.pc, step.next_pc),
            (generic_step.clk, generic_step.pc, generic_step.next_pc),
            "{}",
            what("clock and pcs")
        );
        assert_eq!(
            &written.reads[step.first_read as usize..],
            &expected.reads[..],
            "{}",
            what("reads")
        );
        assert_eq!(
            &written.writes[step.first_write as usize..],
            &expected.writes[..],
            "{}",
            what("writes")
        );
        let first_exception = written
            .operand_exceptions
            .partition_point(|exception| exception.step < index);
        let rebased: Vec<_> = expected
            .operand_exceptions
            .iter()
            .map(|exception| OperandException {
                step: index,
                ..*exception
            })
            .collect();
        assert_eq!(
            &written.operand_exceptions[first_exception..],
            &rebased[..],
            "{}",
            what("operand exceptions")
        );
        let first_unaligned = written
            .unaligned
            .partition_point(|unaligned| unaligned.step < index);
        let rebased: Vec<_> = expected
            .unaligned
            .iter()
            .map(|unaligned| UnalignedStep {
                step: index,
                ..*unaligned
            })
            .collect();
        assert_eq!(
            &written.unaligned[first_unaligned..],
            &rebased[..],
            "{}",
            what("unaligned steps")
        );
        let lists = written.chip_steps.all().into_iter();
        for (list, (written_list, expected_list)) in
            lists.zip(expected.chip_steps.all()).enumerate()
        {
            assert_eq!(
                written_list.last() == Some(&index),
                expected_list == [0],
                "{}",
                what(&format!("chip list {list}"))
            );
        }
        assert_eq!(
            written.operands(at, instruction),
            (a, b, c),
            "{}",
            what("operands as the readers rebuild them")
        );
    }
}

/// The execution history, with no per-chip event stream: the record carries only what reaches it
/// around [`ExecutionSink`], the chunk's windows and the history, and with the history the slot it
/// was written into.
pub struct HistorySink {
    record: EmulationRecord,
    /// The chunk's first and last access to each memory address it touched.
    local_memory_access: HashMap<u64, MemoryLocalEvent>,
    /// The same windows for the registers, indexed rather than hashed: registers are touched
    /// about three times a cycle, and the map's entry lookup was the emulator's hottest cost.
    /// Boxed so the array does not widen the emulator, which holds the sink inline. Register
    /// addresses (0..32) sit below every memory address, so both kinds drain into one list.
    register_local_access: Box<[Option<MemoryLocalEvent>; 32]>,
    history: HistoryWriter,
    /// The record as an unconstrained block found it.
    unconstrained: Option<EmulationRecord>,
}

impl HistorySink {
    #[must_use]
    pub fn new(record: EmulationRecord) -> Self {
        Self {
            record,
            local_memory_access: HashMap::default(),
            register_local_access: Box::new(core::array::from_fn(|_| None)),
            history: HistoryWriter::default(),
            unconstrained: None,
        }
    }
}

impl ExecutionSink for HistorySink {
    #[inline]
    fn begin_cycle(&mut self) {
        self.history.begin_cycle();
    }

    #[inline]
    fn access(&mut self, position: MemoryAccessPosition, record: MemoryRecordEnum) {
        self.history.access(position, record);
    }

    #[inline]
    fn next_dword(&mut self, record: MemoryRecordEnum) {
        self.history.next_dword(record);
    }

    #[inline]
    fn alu(
        &mut self,
        _clk: RvClk,
        opcode: Opcode,
        _a: RvValue,
        _b: RvValue,
        _c: RvValue,
        _is_imm: bool,
    ) {
        self.history.alu(opcode);
    }

    #[inline]
    fn end_cycle(
        &mut self,
        chunk: RvChunk,
        clk: RvClk,
        pc: RvAddr,
        next_pc: RvAddr,
        _exit_code: u32,
        a: RvValue,
        b: RvValue,
        c: RvValue,
        instruction: Instruction,
        _memory_store_value: Option<RvValue>,
    ) {
        self.history
            .end_cycle(chunk, clk, pc, next_pc, a, b, c, &instruction);
    }

    #[inline]
    fn syscall(&mut self, event: SyscallEvent) {
        self.history.syscall(event);
    }

    fn enter_unconstrained(&mut self) {
        assert!(
            self.unconstrained
                .replace(std::mem::take(&mut self.record))
                .is_none(),
            "an unconstrained block opens inside another"
        );
        self.history.enter_unconstrained();
    }

    fn exit_unconstrained(&mut self) {
        self.record = self
            .unconstrained
            .take()
            .expect("an unconstrained block closes that never opened");
        self.history.exit_unconstrained();
    }

    fn holds_steps(&self) -> bool {
        self.history.ended
    }

    fn cut_chunk(&mut self, program: Arc<Program>, boundary: ChunkBoundary) -> EmulationRecord {
        let windows = &mut self.record.cpu_local_memory_access;
        windows.extend(self.local_memory_access.drain().map(|(_, event)| event));
        windows.extend(
            self.register_local_access
                .iter_mut()
                .filter_map(Option::take),
        );
        self.record.history = Some(self.history.cut());
        close_record(&mut self.record, program, boundary)
    }
}

/// The executed operations and accesses for one chunk, counted without writing an event.
///
/// These count executed operations, not trace heights: the ALU events and byte lookups chips add in
/// `extra_record`, the global and Poseidon2 events, and `postprocess`'s memory initialize and
/// finalize events are not counted.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChunkCounts {
    /// One per `end_cycle`.
    pub steps: usize,
    /// The access slots filled at `end_cycle`, by slot: a, b, c, memory.
    pub accesses: [usize; 4],
    pub add: usize,
    pub sub: usize,
    pub mul: usize,
    pub bitwise: usize,
    pub shift_left: usize,
    pub shift_right: usize,
    pub lt: usize,
    pub divrem: usize,
    pub syscalls: usize,
    pub memory_instructions: usize,
    pub ecalls: usize,
    /// The chunk's local-memory windows of the emulator's own accesses: those left in the sink's
    /// map and register array at the cut, and those a precompile's `SyscallContext::postprocess`
    /// moved out of the map into the record. The next access to a moved address opens another
    /// window, so a precompile-heavy chunk holds many windows per address.
    pub windows: usize,
}

#[cfg(any(test, feature = "test-utils"))]
impl std::ops::AddAssign for ChunkCounts {
    fn add_assign(&mut self, other: Self) {
        let Self {
            steps,
            accesses,
            add,
            sub,
            mul,
            bitwise,
            shift_left,
            shift_right,
            lt,
            divrem,
            syscalls,
            memory_instructions,
            ecalls,
            windows,
        } = other;
        self.steps += steps;
        for (sum, n) in self.accesses.iter_mut().zip(accesses) {
            *sum += n;
        }
        self.add += add;
        self.sub += sub;
        self.mul += mul;
        self.bitwise += bitwise;
        self.shift_left += shift_left;
        self.shift_right += shift_right;
        self.lt += lt;
        self.divrem += divrem;
        self.syscalls += syscalls;
        self.memory_instructions += memory_instructions;
        self.ecalls += ecalls;
        self.windows += windows;
    }
}

/// Counts executed operations and accesses without writing their history.
///
/// The record keeps only what reaches it around the trait, through [`Sink::record_mut`]: the
/// public values a COMMIT writes, a precompile's events and the emulator's windows it moved,
/// `postprocess`'s memory initialize and finalize events.
#[cfg(any(test, feature = "test-utils"))]
pub struct CountingSink {
    record: EmulationRecord,
    /// Which of the cycle's access slots are filled, in [`ChunkCounts::accesses`]'s order.
    accessed: [bool; 4],
    /// Full window maps, not counts: the emulator and a precompile's `postprocess` read and write
    /// them directly through [`Sink::local_memory_access_mut`] and
    /// [`Sink::register_local_access_mut`], around the trait.
    local_memory_access: HashMap<u64, MemoryLocalEvent>,
    register_local_access: Box<[Option<MemoryLocalEvent>; 32]>,
    chunk: ChunkCounts,
    counts: Vec<ChunkCounts>,
    /// The record, the cycle's accesses and the chunk's counts as an unconstrained block found
    /// them, so counts roll back with the emulated state.
    unconstrained: Option<(EmulationRecord, [bool; 4], ChunkCounts)>,
    /// Kept through cuts and rollbacks, so a run shows whether the rollback was exercised.
    unconstrained_blocks: usize,
}

#[cfg(any(test, feature = "test-utils"))]
impl CountingSink {
    #[must_use]
    pub fn new(record: EmulationRecord) -> Self {
        Self {
            record,
            accessed: [false; 4],
            local_memory_access: HashMap::default(),
            register_local_access: Box::new(core::array::from_fn(|_| None)),
            chunk: ChunkCounts::default(),
            counts: Vec::new(),
            unconstrained: None,
            unconstrained_blocks: 0,
        }
    }

    /// The counts of every chunk cut since the last call, in cut order: one per `cut_chunk`, so a
    /// finished Trace-mode run ends on `postprocess`'s cut, which holds no step.
    pub fn take_counts(&mut self) -> Vec<ChunkCounts> {
        std::mem::take(&mut self.counts)
    }

    /// The unconstrained blocks entered since the sink was built.
    #[must_use]
    pub fn unconstrained_blocks(&self) -> usize {
        self.unconstrained_blocks
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl ExecutionSink for CountingSink {
    #[inline]
    fn begin_cycle(&mut self) {
        self.accessed = [false; 4];
    }

    #[inline]
    fn access(&mut self, position: MemoryAccessPosition, _record: MemoryRecordEnum) {
        let slot = match position {
            MemoryAccessPosition::A => 0,
            MemoryAccessPosition::B => 1,
            MemoryAccessPosition::C => 2,
            MemoryAccessPosition::Memory => 3,
        };
        self.accessed[slot] = true;
    }

    /// Not counted: it fills no slot.
    #[inline]
    fn next_dword(&mut self, _record: MemoryRecordEnum) {}

    #[inline]
    fn alu(
        &mut self,
        _clk: RvClk,
        opcode: Opcode,
        _a: RvValue,
        _b: RvValue,
        _c: RvValue,
        _is_imm: bool,
    ) {
        let count = match AluStream::of(opcode) {
            AluStream::Add => &mut self.chunk.add,
            AluStream::Sub => &mut self.chunk.sub,
            AluStream::Mul => &mut self.chunk.mul,
            AluStream::Bitwise => &mut self.chunk.bitwise,
            AluStream::ShiftLeft => &mut self.chunk.shift_left,
            AluStream::ShiftRight => &mut self.chunk.shift_right,
            AluStream::Lt => &mut self.chunk.lt,
            AluStream::DivRem => &mut self.chunk.divrem,
        };
        *count += 1;
    }

    #[inline]
    fn end_cycle(
        &mut self,
        _chunk: RvChunk,
        _clk: RvClk,
        _pc: RvAddr,
        _next_pc: RvAddr,
        _exit_code: u32,
        _a: RvValue,
        _b: RvValue,
        _c: RvValue,
        instruction: Instruction,
        _memory_store_value: Option<RvValue>,
    ) {
        for (count, accessed) in self.chunk.accesses.iter_mut().zip(self.accessed) {
            *count += usize::from(accessed);
        }
        self.chunk.steps += 1;
        self.chunk.memory_instructions += usize::from(instruction.is_memory_instruction());
        self.chunk.ecalls += usize::from(instruction.is_ecall_instruction());
    }

    #[inline]
    fn syscall(&mut self, _event: SyscallEvent) {
        self.chunk.syscalls += 1;
    }

    fn enter_unconstrained(&mut self) {
        let saved = (
            std::mem::take(&mut self.record),
            std::mem::take(&mut self.accessed),
            self.chunk,
        );
        assert!(
            self.unconstrained.replace(saved).is_none(),
            "an unconstrained block opens inside another"
        );
        self.unconstrained_blocks += 1;
    }

    fn exit_unconstrained(&mut self) {
        let (record, accessed, chunk) = self
            .unconstrained
            .take()
            .expect("an unconstrained block closes that never opened");
        self.record = record;
        self.accessed = accessed;
        self.chunk = chunk;
    }

    fn holds_steps(&self) -> bool {
        self.chunk.steps > 0
    }

    fn cut_chunk(&mut self, program: Arc<Program>, boundary: ChunkBoundary) -> EmulationRecord {
        self.chunk.windows = self.local_memory_access.len()
            + self.register_local_access.iter().flatten().count()
            + self.record.cpu_local_memory_access.len();
        self.local_memory_access.clear();
        self.register_local_access.fill(None);
        self.counts.push(std::mem::take(&mut self.chunk));
        close_record(&mut self.record, program, boundary)
    }
}

/// The sink an emulator writes through.
///
/// An enum rather than a type parameter on the emulator, so adding a sink touches neither the
/// emulator's signature nor anything generic over it.
#[allow(clippy::large_enum_variant)]
pub enum Sink {
    History(HistorySink),
    #[cfg(any(test, feature = "test-utils"))]
    Counting(CountingSink),
}

impl Sink {
    /// The open chunk's record. It holds the chunk's events only if the sink writes them:
    /// a counting or history sink's holds just what reaches it through [`Self::record_mut`].
    #[inline]
    pub fn record(&self) -> &EmulationRecord {
        match self {
            Self::History(sink) => &sink.record,
            #[cfg(any(test, feature = "test-utils"))]
            Self::Counting(sink) => &sink.record,
        }
    }

    /// The open chunk's first pc and last next pc as the steps written since the last cut hold
    /// them, for the cut to check its boundary against; `None` while no step is written.
    pub fn written_boundary(&self) -> Option<ChunkBoundary> {
        let steps = match self {
            Self::History(sink) => &sink.history.history.steps,
            #[cfg(any(test, feature = "test-utils"))]
            Self::Counting(_) => return None,
        };
        Some(ChunkBoundary {
            start_pc: u64::from(steps.first()?.pc),
            next_pc: u64::from(steps.last()?.next_pc),
        })
    }

    /// For the writes [`ExecutionSink`] does not carry.
    #[inline]
    pub fn record_mut(&mut self) -> &mut EmulationRecord {
        match self {
            Self::History(sink) => &mut sink.record,
            #[cfg(any(test, feature = "test-utils"))]
            Self::Counting(sink) => &mut sink.record,
        }
    }

    /// The emulator's own memory windows, as opposed to a syscall's.
    #[inline]
    pub fn local_memory_access_mut(&mut self) -> &mut HashMap<u64, MemoryLocalEvent> {
        match self {
            Self::History(sink) => &mut sink.local_memory_access,
            #[cfg(any(test, feature = "test-utils"))]
            Self::Counting(sink) => &mut sink.local_memory_access,
        }
    }

    /// See [`HistoryRows`].
    ///
    /// # Panics
    ///
    /// On a counting sink, which keeps none.
    #[inline]
    pub fn history_rows(&mut self) -> HistoryRows<'_> {
        match self {
            Self::History(sink) => HistoryRows {
                writer: &mut sink.history,
            },
            #[cfg(any(test, feature = "test-utils"))]
            Self::Counting(_) => panic!("a counting sink keeps no history rows"),
        }
    }

    /// The emulator's register windows, indexed by register.
    #[inline]
    pub fn register_local_access_mut(&mut self) -> &mut [Option<MemoryLocalEvent>; 32] {
        match self {
            Self::History(sink) => &mut sink.register_local_access,
            #[cfg(any(test, feature = "test-utils"))]
            Self::Counting(sink) => &mut sink.register_local_access,
        }
    }

    /// Starts a replay over on `program`'s empty record, with no cycle accesses, no windows, no
    /// history and no open unconstrained block. The sink keeps its kind.
    pub fn restart(&mut self, program: Arc<Program>) {
        match self {
            Self::History(sink) => {
                sink.record = EmulationRecord::new(program);
                sink.local_memory_access.clear();
                sink.register_local_access.fill(None);
                sink.history = HistoryWriter::default();
                sink.unconstrained = None;
            }
            #[cfg(any(test, feature = "test-utils"))]
            Self::Counting(sink) => {
                sink.record = EmulationRecord::new(program);
                sink.accessed = [false; 4];
                sink.local_memory_access.clear();
                sink.register_local_access.fill(None);
                sink.chunk = ChunkCounts::default();
                sink.unconstrained = None;
            }
        }
    }
}

impl ExecutionSink for Sink {
    #[inline]
    fn begin_cycle(&mut self) {
        match self {
            Self::History(sink) => sink.begin_cycle(),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Counting(sink) => sink.begin_cycle(),
        }
    }

    #[inline]
    fn access(&mut self, position: MemoryAccessPosition, record: MemoryRecordEnum) {
        match self {
            Self::History(sink) => sink.access(position, record),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Counting(sink) => sink.access(position, record),
        }
    }

    #[inline]
    fn next_dword(&mut self, record: MemoryRecordEnum) {
        match self {
            Self::History(sink) => sink.next_dword(record),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Counting(sink) => sink.next_dword(record),
        }
    }

    #[inline]
    fn alu(
        &mut self,
        clk: RvClk,
        opcode: Opcode,
        a: RvValue,
        b: RvValue,
        c: RvValue,
        is_imm: bool,
    ) {
        match self {
            Self::History(sink) => sink.alu(clk, opcode, a, b, c, is_imm),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Counting(sink) => sink.alu(clk, opcode, a, b, c, is_imm),
        }
    }

    #[inline]
    fn end_cycle(
        &mut self,
        chunk: RvChunk,
        clk: RvClk,
        pc: RvAddr,
        next_pc: RvAddr,
        exit_code: u32,
        a: RvValue,
        b: RvValue,
        c: RvValue,
        instruction: Instruction,
        memory_store_value: Option<RvValue>,
    ) {
        match self {
            Self::History(sink) => sink.end_cycle(
                chunk,
                clk,
                pc,
                next_pc,
                exit_code,
                a,
                b,
                c,
                instruction,
                memory_store_value,
            ),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Counting(sink) => sink.end_cycle(
                chunk,
                clk,
                pc,
                next_pc,
                exit_code,
                a,
                b,
                c,
                instruction,
                memory_store_value,
            ),
        }
    }

    #[inline]
    fn syscall(&mut self, event: SyscallEvent) {
        match self {
            Self::History(sink) => sink.syscall(event),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Counting(sink) => sink.syscall(event),
        }
    }

    fn enter_unconstrained(&mut self) {
        match self {
            Self::History(sink) => sink.enter_unconstrained(),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Counting(sink) => sink.enter_unconstrained(),
        }
    }

    fn exit_unconstrained(&mut self) {
        match self {
            Self::History(sink) => sink.exit_unconstrained(),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Counting(sink) => sink.exit_unconstrained(),
        }
    }

    fn holds_steps(&self) -> bool {
        match self {
            Self::History(sink) => sink.holds_steps(),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Counting(sink) => sink.holds_steps(),
        }
    }

    fn cut_chunk(&mut self, program: Arc<Program>, boundary: ChunkBoundary) -> EmulationRecord {
        match self {
            Self::History(sink) => sink.cut_chunk(program, boundary),
            #[cfg(any(test, feature = "test-utils"))]
            Self::Counting(sink) => sink.cut_chunk(program, boundary),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chips::chips::riscv_memory::event::{MemoryReadRecord, MemoryRecord, MemoryWriteRecord},
        emulator::riscv::{
            history::ReadAccess,
            history_arena::{HistoryArena, HistoryCapacity, SpillPolicy, Table},
            record_digest::field_digests,
        },
    };
    use std::num::NonZeroUsize;

    fn syscall(clk: RvClk) -> SyscallEvent {
        SyscallEvent {
            chunk: 1,
            clk,
            syscall_id: 0,
            arg1: 0,
            arg2: 0,
        }
    }

    fn window(addr: u64, timestamp: u32) -> MemoryLocalEvent {
        let access = MemoryRecord {
            chunk: 1,
            timestamp,
            value: addr,
        };
        MemoryLocalEvent {
            addr,
            initial_mem_access: access,
            final_mem_access: access,
        }
    }

    #[test]
    fn exit_unconstrained_discards_what_the_block_wrote() {
        let mut sink = HistorySink::new(EmulationRecord::default());
        add_cycle(&mut sink);
        sink.syscall(syscall(8));
        let before = field_digests(&sink.record);
        let history_before = sink.history.history.digest();

        sink.enter_unconstrained();
        add_cycle(&mut sink);
        sink.syscall(syscall(12));
        sink.record.public_values.committed_value_digest[0] = 1;
        sink.exit_unconstrained();

        assert_eq!(field_digests(&sink.record), before);
        assert_eq!(sink.history.history.digest(), history_before);
    }

    #[test]
    fn cut_chunk_writes_the_boundary_and_hands_it_on() {
        let program = Arc::new(Program::default());
        let mut sink = HistorySink::new(EmulationRecord::new(program.clone()));
        let boundary = ChunkBoundary {
            start_pc: 0x1010,
            next_pc: 0x100c,
        };

        let cut = sink.cut_chunk(program, boundary);

        for public_values in [&cut.public_values, &sink.record.public_values] {
            assert_eq!(public_values.start_pc, encode_public_value_pc_limbs(0x1010));
            assert_eq!(public_values.next_pc, encode_public_value_pc_limbs(0x100c));
        }
    }

    #[test]
    fn cut_chunk_leaves_a_non_cpu_record_unstamped() {
        let program = Arc::new(Program::default());
        let mut record = EmulationRecord::new(program.clone());
        record.is_cpu_chunk = false;
        let mut sink = HistorySink::new(record);
        let boundary = ChunkBoundary {
            start_pc: 0x1010,
            next_pc: 0x100c,
        };

        let cut = sink.cut_chunk(program, boundary);

        assert_eq!(cut.public_values.start_pc, [0; 3]);
        assert_eq!(cut.public_values.next_pc, [0; 3]);
    }

    #[test]
    fn cut_chunk_drains_memory_then_register_windows() {
        let program = Arc::new(Program::default());
        let mut sink = HistorySink::new(EmulationRecord::new(program.clone()));
        sink.local_memory_access.insert(0x100, window(0x100, 8));
        sink.register_local_access[2] = Some(window(2, 12));
        sink.register_local_access[5] = Some(window(5, 16));
        let boundary = ChunkBoundary {
            start_pc: 0x1000,
            next_pc: 0x1004,
        };

        let cut = sink.cut_chunk(program, boundary);

        let addrs: Vec<u64> = cut
            .cpu_local_memory_access
            .iter()
            .map(|event| event.addr)
            .collect();
        assert_eq!(addrs, [0x100, 2, 5]);
        assert!(sink.local_memory_access.is_empty());
        assert!(sink.register_local_access.iter().all(Option::is_none));
    }

    #[test]
    fn exit_unconstrained_discards_what_the_block_counted() {
        let mut sink = CountingSink::new(EmulationRecord::default());
        sink.alu(8, Opcode::ADD, 3, 1, 2, false);
        sink.syscall(syscall(8));
        let before = sink.chunk;

        sink.enter_unconstrained();
        sink.alu(12, Opcode::MUL, 2, 1, 2, false);
        sink.syscall(syscall(12));
        sink.exit_unconstrained();

        assert_eq!(sink.chunk, before);
    }

    const ADD: Instruction = Instruction::new(Opcode::ADD, 3, 1, 2, false, false);
    const LD: Instruction = Instruction::new(Opcode::LD, 4, 1, 0, false, true);
    const ECALL: Instruction = Instruction::new(Opcode::ECALL, 5, 10, 11, false, false);

    fn read(value: RvValue, prev_timestamp: u32) -> MemoryRecordEnum {
        MemoryRecordEnum::Read(MemoryReadRecord {
            value,
            chunk: 2,
            timestamp: prev_timestamp + 4,
            prev_chunk: 1,
            prev_timestamp,
        })
    }

    fn write(value: RvValue, prev_value: RvValue, prev_timestamp: u32) -> MemoryRecordEnum {
        MemoryRecordEnum::Write(MemoryWriteRecord {
            value,
            chunk: 2,
            timestamp: prev_timestamp + 4,
            prev_value,
            prev_chunk: 1,
            prev_timestamp,
        })
    }

    /// `ADD x3, x1, x2` at clock 8, its accesses reported in the emulator's order: c, b, a.
    fn add_cycle(sink: &mut impl ExecutionSink) {
        sink.begin_cycle();
        sink.access(MemoryAccessPosition::C, read(2, 5));
        sink.access(MemoryAccessPosition::B, read(1, 6));
        sink.access(MemoryAccessPosition::A, write(3, 9, 7));
        sink.alu(8, Opcode::ADD, 3, 1, 2, false);
        sink.end_cycle(2, 8, 0x1000, 0x1004, 0, 3, 1, 2, ADD, None);
    }

    /// A jump past every pc a row holds ends the run on the emulator's own error, so the sink
    /// writes no step for it and leaves the error to the emulator; a cut on it is refused.
    #[test]
    fn a_step_whose_next_pc_no_row_holds_is_left_unwritten_and_never_cut() {
        let program = Arc::new(Program::default());
        let mut sink = HistorySink::new(EmulationRecord::new(program.clone()));
        add_cycle(&mut sink);
        sink.begin_cycle();
        sink.access(MemoryAccessPosition::A, write(0x1008, 0, 9));
        let jal = Instruction::new(Opcode::JAL, 1, 0, 0, true, true);
        sink.end_cycle(2, 12, 0x1004, 1 << 32, 0, 0x1008, 0, 0, jal, None);
        assert!(sink.holds_steps());
        assert_eq!(sink.history.history.steps.len(), 1);

        let boundary = ChunkBoundary {
            start_pc: 0x1000,
            next_pc: 1 << 32,
        };
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sink.cut_chunk(program, boundary)
        }));
        assert!(refused.is_err(), "a chunk was cut on the unwritten step");
    }

    #[test]
    fn history_sink_stores_each_step_and_its_accesses_in_slot_order() {
        let mut sink = HistorySink::new(EmulationRecord::default());
        add_cycle(&mut sink);
        // `LD x4, 0(x1)` at clock 12, x1 holding 8: b, memory, a.
        sink.begin_cycle();
        sink.access(MemoryAccessPosition::B, read(8, 10));
        sink.access(MemoryAccessPosition::Memory, read(0x55, 3));
        sink.access(MemoryAccessPosition::A, write(0x55, 0, 11));
        sink.end_cycle(2, 12, 0x1004, 0x1008, 0, 0x55, 8, 0, LD, Some(0x55));

        let history = &sink.history.history;
        assert_eq!(history.chunk, 2);
        assert_eq!(
            history.steps,
            [
                Step {
                    clk: 8,
                    pc: 0x1000,
                    next_pc: 0x1004,
                    first_read: 0,
                    first_write: 0,
                },
                Step {
                    clk: 12,
                    pc: 0x1004,
                    next_pc: 0x1008,
                    first_read: 2,
                    first_write: 1,
                },
            ]
        );
        let access = |value, prev_value, prev_timestamp| Access {
            value,
            prev_value,
            prev_chunk: 1,
            prev_timestamp,
        };
        use MemoryAccessPosition::{Memory, A, B, C};
        assert_eq!(
            history.accesses_of(0, &ADD).collect::<Vec<_>>(),
            [
                (A, access(3, 9, 7)),
                (B, access(1, 1, 6)),
                (C, access(2, 2, 5))
            ]
        );
        assert_eq!(
            history.accesses_of(1, &LD).collect::<Vec<_>>(),
            [
                (A, access(0x55, 0, 11)),
                (B, access(8, 8, 10)),
                (Memory, access(0x55, 0x55, 3))
            ]
        );
        assert_eq!(history.writes, [access(3, 9, 7), access(0x55, 0, 11)]);
        assert_eq!(history.reads.len(), 4);
        assert_eq!(history.chip_steps.add, [0]);
        assert_eq!(history.chip_steps.memory, [1]);
        assert!(history.operand_exceptions.is_empty());
        assert_eq!(history.operands(0, &ADD), (3, 1, 2));
        assert_eq!(history.operands(1, &LD), (0x55, 8, 0));

        let record = &sink.record;
        assert!(record.add_events.is_empty());
    }

    /// `ADD x3, x1, x2` without its `c` read: its rows would be paired with the wrong slots.
    #[test]
    #[should_panic(expected = "step 0's accesses fill other slots than")]
    fn a_cycle_that_fills_other_slots_than_its_instruction_names_is_refused() {
        let mut sink = HistorySink::new(EmulationRecord::default());
        sink.begin_cycle();
        sink.access(MemoryAccessPosition::B, read(1, 6));
        sink.access(MemoryAccessPosition::A, write(3, 9, 7));
        sink.end_cycle(2, 8, 0x1000, 0x1004, 0, 3, 1, 2, ADD, None);
    }

    /// A load whose address is not a multiple of its width goes to the unaligned table rather than
    /// the memory chip's list, with the next dword's access when it runs into that one;
    /// an aligned one stays in the list.
    #[test]
    fn a_misaligned_load_goes_to_the_unaligned_table_with_its_next_dword() {
        let lw = Instruction::new(Opcode::LW, 4, 1, 0, false, true);
        let mut sink = HistorySink::new(EmulationRecord::default());
        // `LD x4, 0(x1)` with x1 = 0x1_0005: it runs into the next dword, read at the C position.
        let cycle = |sink: &mut HistorySink, base, instruction, next: Option<MemoryRecordEnum>| {
            sink.begin_cycle();
            sink.access(MemoryAccessPosition::B, read(base, 10));
            sink.access(MemoryAccessPosition::Memory, read(0x55, 3));
            if let Some(next) = next {
                sink.next_dword(next);
            }
            sink.access(MemoryAccessPosition::A, write(0x77, 0, 11));
            sink.end_cycle(2, 12, 0x1004, 0x1008, 0, 0x77, base, 0, instruction, None);
        };
        cycle(&mut sink, 0x1_0005, LD, Some(read(0x66, 4)));
        cycle(&mut sink, 0x1_0002, lw, None);
        cycle(&mut sink, 0x1_0008, LD, None);

        let history = &sink.history.history;
        assert_eq!(history.chip_steps.memory, [2]);
        let next = Access {
            value: 0x66,
            prev_value: 0x66,
            prev_chunk: 1,
            prev_timestamp: 4,
        };
        assert_eq!(
            history.unaligned,
            [
                UnalignedStep {
                    step: 0,
                    crosses: 1,
                    next,
                },
                UnalignedStep {
                    step: 1,
                    crosses: 0,
                    next: Access::default(),
                },
            ]
        );
        // The next dword's access fills no slot: the steps' rows are as an aligned load's.
        assert_eq!(history.reads.len(), 6);
        assert_eq!(history.writes.len(), 3);
    }

    /// A load that runs into the next dword without that dword's access was traced wrongly.
    #[test]
    #[should_panic(expected = "step 0's LD at 0x10005 and its next dword's access")]
    fn a_crossing_load_without_its_next_dword_is_refused() {
        let mut sink = HistorySink::new(EmulationRecord::default());
        sink.begin_cycle();
        sink.access(MemoryAccessPosition::B, read(0x1_0005, 10));
        sink.access(MemoryAccessPosition::Memory, read(0x55, 3));
        sink.access(MemoryAccessPosition::A, write(0x77, 0, 11));
        sink.end_cycle(2, 12, 0x1004, 0x1008, 0, 0x77, 0x1_0005, 0, LD, None);
    }

    /// A store reads `a` and writes memory, and a branch writes nothing: each access goes to the
    /// table of the kind its instruction gives the slot.
    #[test]
    fn a_store_writes_its_memory_and_a_branch_writes_nothing() {
        let sd = Instruction::new(Opcode::SD, 2, 1, 8, false, true);
        let beq = Instruction::new(Opcode::BEQ, 1, 2, 8, false, true);
        let mut sink = HistorySink::new(EmulationRecord::default());
        sink.begin_cycle();
        sink.access(MemoryAccessPosition::Memory, write(9, 4, 3));
        sink.access(MemoryAccessPosition::B, read(0x2000, 6));
        sink.access(MemoryAccessPosition::A, read(9, 5));
        sink.end_cycle(2, 8, 0x1000, 0x1004, 0, 9, 0x2000, 8, sd, Some(9));
        sink.begin_cycle();
        sink.access(MemoryAccessPosition::B, read(1, 10));
        sink.access(MemoryAccessPosition::A, read(1, 9));
        sink.end_cycle(2, 12, 0x1004, 0x1008, 0, 1, 1, 8, beq, None);

        let history = &sink.history.history;
        let first_rows: Vec<_> = history
            .steps
            .iter()
            .map(|step| (step.first_read, step.first_write))
            .collect();
        assert_eq!(first_rows, [(0, 0), (2, 1)]);
        let read_row = |value, prev_timestamp| ReadAccess {
            value,
            prev_chunk: 1,
            prev_timestamp,
        };
        assert_eq!(
            history.reads,
            [
                read_row(9, 5),
                read_row(0x2000, 6),
                read_row(1, 9),
                read_row(1, 10)
            ]
        );
        assert_eq!(
            history.writes,
            [Access {
                value: 9,
                prev_value: 4,
                prev_chunk: 1,
                prev_timestamp: 3,
            }]
        );
        assert_eq!(history.operands(0, &sd), (9, 0x2000, 8));
        assert_eq!(history.operands(1, &beq), (1, 1, 8));
    }

    /// `ADD x0, x1, x2` commits 0 while the instruction saw the sum: the sum goes in the exception
    /// table, and the rebuilt operands are the ones seen.
    #[test]
    fn a_write_to_x0_excepts_the_operand_the_instruction_saw() {
        let add_x0 = Instruction::new(Opcode::ADD, 0, 1, 2, false, false);
        let mut sink = HistorySink::new(EmulationRecord::default());
        sink.begin_cycle();
        sink.access(MemoryAccessPosition::C, read(2, 5));
        sink.access(MemoryAccessPosition::B, read(1, 6));
        sink.access(MemoryAccessPosition::A, write(0, 0, 7));
        sink.end_cycle(2, 8, 0x1000, 0x1004, 0, 3, 1, 2, add_x0, None);

        let history = &sink.history.history;
        assert_eq!(
            history.operand_exceptions,
            [OperandException {
                step: 0,
                slot: MemoryAccessPosition::A as u32,
                value: 3,
            }]
        );
        assert_eq!(history.operands(0, &add_x0), (3, 1, 2));
    }

    /// A jump's `a` is its pc + 4 by rule, so `jal x0` needs no exception.
    #[test]
    fn a_jump_to_x0_needs_no_exception() {
        let jal_x0 = Instruction::new(Opcode::JAL, 0, 0x20, 0, true, true);
        let mut sink = HistorySink::new(EmulationRecord::default());
        sink.begin_cycle();
        sink.access(MemoryAccessPosition::A, write(0, 0, 7));
        sink.end_cycle(2, 8, 0x1000, 0x1020, 0, 0x1004, 0x20, 0, jal_x0, None);

        let history = &sink.history.history;
        assert!(history.operand_exceptions.is_empty());
        assert_eq!(history.operands(0, &jal_x0), (0x1004, 0x20, 0));
    }

    #[test]
    fn exit_unconstrained_discards_what_the_block_wrote_to_the_history() {
        let mut sink = HistorySink::new(EmulationRecord::default());
        add_cycle(&mut sink);
        sink.syscall(syscall(8));
        let before = sink.history.history.clone();

        sink.enter_unconstrained();
        assert!(!sink.holds_steps());
        add_cycle(&mut sink);
        sink.syscall(syscall(12));
        sink.record.public_values.committed_value_digest[0] = 1;
        sink.exit_unconstrained();

        let after = &sink.history.history;
        assert_eq!(after.steps, before.steps);
        assert_eq!(after.reads, before.reads);
        assert_eq!(after.writes, before.writes);
        assert_eq!(after.chip_steps, before.chip_steps);
        assert_eq!(after.syscalls.len(), before.syscalls.len());
        assert_eq!(sink.record.public_values.committed_value_digest[0], 0);
        assert!(sink.holds_steps());
    }

    /// The ECALL closing a block finishes the cycle of the one that opened it, whose register
    /// reads came before the block; its own operands are what the block left in x10 and x11.
    #[test]
    fn the_ecall_closing_an_unconstrained_block_keeps_the_reads_made_before_it() {
        let mut sink = HistorySink::new(EmulationRecord::default());
        sink.begin_cycle();
        sink.access(MemoryAccessPosition::C, read(0, 5));
        sink.access(MemoryAccessPosition::B, read(0, 6));
        sink.enter_unconstrained();
        sink.exit_unconstrained();
        sink.access(MemoryAccessPosition::A, write(0, 0xf0, 7));
        sink.end_cycle(2, 8, 0x1000, 0x1004, 0, 0, 7, 9, ECALL, None);

        let history = &sink.history.history;
        assert_eq!(history.steps.len(), 1);
        let values: Vec<_> = history
            .accesses_of(0, &ECALL)
            .map(|(_, access)| (access.value, access.prev_value))
            .collect();
        assert_eq!(values, [(0, 0xf0), (0, 0), (0, 0)]);
        let exception = |slot: MemoryAccessPosition, value| OperandException {
            step: 0,
            slot: slot as u32,
            value,
        };
        assert_eq!(
            history.operand_exceptions,
            [
                exception(MemoryAccessPosition::B, 7),
                exception(MemoryAccessPosition::C, 9)
            ]
        );
        assert_eq!(history.operands(0, &ECALL), (0, 7, 9));
        assert_eq!(history.chip_steps.ecall, [0]);
    }

    /// The closing ECALL still ends a cycle outside tracing, so the chunk is cut.
    #[test]
    fn an_untraced_cycle_writes_no_step_but_holds_the_chunk() {
        let program = Arc::new(Program::default());
        let mut sink = HistorySink::new(EmulationRecord::new(program.clone()));
        assert!(!sink.holds_steps());

        sink.end_cycle(2, 8, 0x1000, 0x1004, 0, 0, 0, 0, ECALL, None);
        assert!(sink.holds_steps());

        let boundary = ChunkBoundary {
            start_pc: 0x1000,
            next_pc: 0x1004,
        };
        let mut cut = sink.cut_chunk(program, boundary);
        assert!(!sink.holds_steps());
        assert!(cut
            .history
            .take()
            .expect("a history sink's record")
            .steps
            .is_empty());
    }

    #[test]
    fn cut_chunk_hands_over_the_history_and_the_windows() {
        let program = Arc::new(Program::default());
        let mut sink = HistorySink::new(EmulationRecord::new(program.clone()));
        add_cycle(&mut sink);
        sink.local_memory_access.insert(0x100, window(0x100, 8));
        sink.register_local_access[3] = Some(window(3, 11));
        let boundary = ChunkBoundary {
            start_pc: 0x1000,
            next_pc: 0x1004,
        };

        let cut = sink.cut_chunk(program, boundary);

        let history = cut.history.as_ref().expect("a history sink's record");
        assert_eq!((history.chunk, history.steps.len()), (2, 1));
        let addrs: Vec<u64> = cut
            .cpu_local_memory_access
            .iter()
            .map(|event| event.addr)
            .collect();
        assert_eq!(addrs, [0x100, 3]);
        assert!(sink.history.history.steps.is_empty());
        assert!(sink.local_memory_access.is_empty());
        assert!(sink.register_local_access.iter().all(Option::is_none));
    }

    #[test]
    #[should_panic(expected = "pc 0x100000000 does not fit the history's u32")]
    fn a_pc_past_u32_is_refused() {
        let mut sink = HistorySink::new(EmulationRecord::default());
        sink.begin_cycle();
        sink.end_cycle(2, 8, 1 << 32, 0x1004, 0, 0, 0, 0, ECALL, None);
    }

    #[test]
    #[should_panic(expected = "clk 0x100000000 does not fit the history's u32")]
    fn a_clock_past_u32_is_refused() {
        let mut sink = HistorySink::new(EmulationRecord::default());
        sink.begin_cycle();
        sink.end_cycle(2, 1 << 32, 0x1000, 0x1004, 0, 0, 0, 0, ECALL, None);
    }

    #[test]
    fn restart_drops_the_history() {
        let program = Arc::new(Program::default());
        let mut sink = Sink::History(HistorySink::new(EmulationRecord::new(program.clone())));
        if let Sink::History(history) = &mut sink {
            add_cycle(history);
            assert!(history.holds_steps());
        }
        sink.restart(program);
        let Sink::History(history) = &sink else {
            unreachable!("a restart keeps the sink's kind");
        };
        assert!(history.history.history.steps.is_empty());
        assert!(!history.holds_steps());
    }

    /// `add_cycle`'s rows, written directly. An `x0` destination writes 0, so the computed 3 is an
    /// operand exception and there is no ALU entry.
    fn add_rows(sink: &mut Sink, rd: u8) -> u32 {
        sink.begin_cycle();
        let read = |value, prev_timestamp| ReadAccess {
            value,
            prev_chunk: 1,
            prev_timestamp,
        };
        let written = if rd == 0 { 0 } else { 3 };
        let write = Access {
            value: written,
            prev_value: 9,
            prev_chunk: 1,
            prev_timestamp: 7,
        };
        let mut rows = sink.history_rows();
        let step = rows.step(2, 8, 0x1000, 0x1004, [read(1, 6), read(2, 5)], [write]);
        if rd == 0 {
            rows.operand_exception(step, MemoryAccessPosition::A, 3);
        } else {
            rows.alu(AluStream::Add, step);
        }
        step
    }

    fn written_history(sink: &Sink) -> &ExecutionHistory {
        let Sink::History(sink) = sink else {
            unreachable!("a history sink");
        };
        &sink.history.history
    }

    /// `add_cycle`'s accesses, for `check_step`.
    fn add_accesses(rd_written: RvValue) -> [(MemoryAccessPosition, MemoryRecordEnum); 3] {
        [
            (MemoryAccessPosition::C, read(2, 5)),
            (MemoryAccessPosition::B, read(1, 6)),
            (MemoryAccessPosition::A, write(rd_written, 9, 7)),
        ]
    }

    #[test]
    fn a_step_written_directly_is_the_one_end_cycle_writes() {
        let mut generic = HistorySink::new(EmulationRecord::default());
        add_cycle(&mut generic);
        let mut direct = Sink::History(HistorySink::new(EmulationRecord::default()));
        let step = add_rows(&mut direct, 3);
        assert_eq!(step, 0);
        assert!(direct.holds_steps());
        assert_eq!(
            written_history(&direct).digest(),
            generic.history.history.digest()
        );
        direct.history_rows().check_step(
            step,
            2,
            8,
            0x1000,
            0x1004,
            &add_accesses(3),
            None,
            true,
            [3, 1, 2],
            &ADD,
        );

        // The next instruction's accesses go into the cycle the first left open.
        add_cycle(&mut generic);
        if let Sink::History(direct) = &mut direct {
            direct.access(MemoryAccessPosition::C, read(2, 5));
            direct.access(MemoryAccessPosition::B, read(1, 6));
            direct.access(MemoryAccessPosition::A, write(3, 9, 7));
            direct.alu(8, Opcode::ADD, 3, 1, 2, false);
            direct.end_cycle(2, 8, 0x1000, 0x1004, 0, 3, 1, 2, ADD, None);
        }
        assert_eq!(
            written_history(&direct).digest(),
            generic.history.history.digest()
        );
    }

    #[test]
    fn check_step_takes_the_operand_exception_end_cycle_writes() {
        let add_x0 = Instruction::new(Opcode::ADD, 0, 1, 2, false, false);
        let mut direct = Sink::History(HistorySink::new(EmulationRecord::default()));
        let step = add_rows(&mut direct, 0);
        assert_eq!(
            written_history(&direct).operand_exceptions,
            [OperandException {
                step,
                slot: MemoryAccessPosition::A as u32,
                value: 3,
            }]
        );
        let rows = direct.history_rows();
        rows.check_step(
            step,
            2,
            8,
            0x1000,
            0x1004,
            &add_accesses(0),
            None,
            false,
            [3, 1, 2],
            &add_x0,
        );
    }

    #[test]
    #[should_panic(expected = "reads")]
    fn check_step_refuses_reads_out_of_slot_order() {
        let mut direct = Sink::History(HistorySink::new(EmulationRecord::default()));
        direct.begin_cycle();
        let read = |value, prev_timestamp| ReadAccess {
            value,
            prev_chunk: 1,
            prev_timestamp,
        };
        let write = Access {
            value: 3,
            prev_value: 9,
            prev_chunk: 1,
            prev_timestamp: 7,
        };
        let mut rows = direct.history_rows();
        let step = rows.step(2, 8, 0x1000, 0x1004, [read(2, 5), read(1, 6)], [write]);
        rows.alu(AluStream::Add, step);
        rows.check_step(
            step,
            2,
            8,
            0x1000,
            0x1004,
            &add_accesses(3),
            None,
            true,
            [3, 1, 2],
            &ADD,
        );
    }

    #[test]
    fn reserving_room_writes_no_row() {
        let mut sink = Sink::History(HistorySink::new(EmulationRecord::default()));
        let mut room = BlockRows {
            steps: 4,
            reads: 6,
            writes: 4,
            operand_exceptions: 1,
            ..BlockRows::default()
        };
        *room.alu_mut(AluStream::ShiftRight) = 3;
        room.memory = 2;
        room.branch = 1;
        sink.history_rows().reserve(&room);
        let history = written_history(&sink);
        assert!(history.steps.capacity() >= 4 && history.chip_steps.shift_right.capacity() >= 3);
        assert!(history.chip_steps.memory.capacity() >= 2);
        assert!(history.chip_steps.branch.capacity() >= 1);
        assert_eq!(history.digest(), ExecutionHistory::default().digest());
        assert!(!sink.holds_steps());
    }

    /// `LD x4, 0(x1)` then a taken `BNE x4, x1, -8`, as in
    /// `history_sink_stores_each_step_and_its_accesses_in_slot_order`.
    #[test]
    fn a_load_and_a_branch_written_directly_are_the_ones_end_cycle_writes() {
        let bne = Instruction::new(Opcode::BNE, 4, 1, (-8_i64) as u64, false, true);
        let mut generic = HistorySink::new(EmulationRecord::default());
        generic.begin_cycle();
        generic.access(MemoryAccessPosition::B, read(8, 10));
        generic.access(MemoryAccessPosition::Memory, read(0x55, 3));
        generic.access(MemoryAccessPosition::A, write(0x55, 0, 11));
        generic.end_cycle(2, 12, 0x1004, 0x1008, 0, 0x55, 8, 0, LD, Some(0x55));
        generic.begin_cycle();
        generic.access(MemoryAccessPosition::B, read(8, 14));
        generic.access(MemoryAccessPosition::A, read(0x55, 15));
        generic.end_cycle(2, 16, 0x1008, 0x1000, 0, 0x55, 8, bne.op_c, bne, None);

        let as_read = |record: MemoryRecordEnum| ReadAccess::from(Access::from(record));
        let mut direct = Sink::History(HistorySink::new(EmulationRecord::default()));
        direct.begin_cycle();
        let mut rows = direct.history_rows();
        let load = rows.step(
            2,
            12,
            0x1004,
            0x1008,
            [as_read(read(8, 10)), as_read(read(0x55, 3))],
            [Access::from(write(0x55, 0, 11))],
        );
        rows.memory(load);
        let branch = rows.step(
            2,
            16,
            0x1008,
            0x1000,
            [as_read(read(0x55, 15)), as_read(read(8, 14))],
            [],
        );
        rows.branch(branch);
        assert_eq!((load, branch), (0, 1));
        assert_eq!(
            written_history(&direct).digest(),
            generic.history.history.digest()
        );
        let rows = direct.history_rows();
        rows.check_step(
            branch,
            2,
            16,
            0x1008,
            0x1000,
            &[
                (MemoryAccessPosition::B, read(8, 14)),
                (MemoryAccessPosition::A, read(0x55, 15)),
            ],
            None,
            false,
            [0x55, 8, bne.op_c],
            &bne,
        );
    }

    /// An arena with `rows` rows a table. Built with `cuda`, its slots are pinned and need a CUDA
    /// driver.
    fn small_arena(slots: usize, rows: usize, policy: SpillPolicy) -> HistoryArena {
        let capacity = Table::ALL
            .into_iter()
            .fold(HistoryCapacity::CENSUS, |capacity, table| {
                capacity.with_rows(table, rows)
            });
        let slots = NonZeroUsize::new(slots).expect("at least one slot");
        HistoryArena::pin(slots, capacity.chunk_size(), capacity, policy).expect("an arena")
    }

    /// A history sink holding a slot of `arena`, as its first write takes one when records are
    /// bounded.
    fn history_sink_in_a_slot(arena: &HistoryArena) -> HistorySink {
        let mut sink = HistorySink::new(EmulationRecord::default());
        let chunk = sink.history.history.chunk;
        sink.history.history = arena.take(chunk);
        sink.history.slot_sought = true;
        sink
    }

    fn in_slot(history: &ExecutionHistory) -> Vec<bool> {
        Table::ALL
            .into_iter()
            .map(|table| history.is_in_slot(table))
            .collect()
    }

    /// Reserving past a region's room under a refusing policy neither refuses nor moves it.
    #[test]
    fn reserving_room_in_a_slot_writes_no_row_and_leaves_its_regions_in_place() {
        let arena = small_arena(1, 2, SpillPolicy::Refuse);
        let mut sink = Sink::History(history_sink_in_a_slot(&arena));
        let mut room = BlockRows {
            steps: 16,
            reads: 32,
            writes: 16,
            operand_exceptions: 16,
            memory: 16,
            branch: 16,
            ..BlockRows::default()
        };
        *room.alu_mut(AluStream::Add) = 16;
        let taken = written_history(&sink).digest();
        sink.history_rows().reserve(&room);
        let history = written_history(&sink);
        assert!(history.holds_slot());
        assert_eq!(in_slot(history), [true; 16]);
        assert_eq!(history.steps.capacity(), 2);
        assert_eq!(history.bytes(), 0, "a reservation published rows");
        assert_eq!(history.digest(), taken);
        assert!(!sink.holds_steps());

        let mut generic = HistorySink::new(EmulationRecord::default());
        add_cycle(&mut generic);
        add_rows(&mut sink, 3);
        let history = written_history(&sink);
        assert_eq!(history.digest(), generic.history.history.digest());
        assert!(history.is_in_slot(Table::Steps) && history.is_in_slot(Table::Add));
    }

    /// The arena is process-wide, so this checks the seeking, not a slot taken.
    #[test]
    fn a_direct_step_seeks_the_chunks_slot_as_end_cycle_does() {
        let program = Arc::new(Program::default());
        let sink = HistorySink::new(EmulationRecord::new(program.clone()));
        assert!(!sink.history.slot_sought);
        let mut lent = Sink::History(sink);
        add_rows(&mut lent, 3);
        let Sink::History(mut sink) = lent else {
            unreachable!("a history sink");
        };
        assert!(sink.history.slot_sought);
        let boundary = ChunkBoundary {
            start_pc: 0x1000,
            next_pc: 0x1004,
        };
        let _ = sink.cut_chunk(program, boundary);
        assert!(!sink.history.slot_sought);
    }

    /// At three rows a table, the two-read steps spill their reads on the second step and the
    /// other tables on the fourth.
    #[test]
    fn direct_rows_fill_and_spill_a_slot_where_end_cycle_does() {
        let arena = small_arena(2, 3, SpillPolicy::Spill);
        let mut generic = history_sink_in_a_slot(&arena);
        let mut direct = Sink::History(history_sink_in_a_slot(&arena));
        for steps in 1..=4 {
            add_cycle(&mut generic);
            add_rows(&mut direct, 3);
            let (expected, written) = (&generic.history.history, written_history(&direct));
            assert_eq!(written.digest(), expected.digest(), "after {steps} step(s)");
            assert_eq!(in_slot(written), in_slot(expected), "after {steps} step(s)");
        }
        let written = written_history(&direct);
        assert!(!written.is_in_slot(Table::Reads) && !written.is_in_slot(Table::Steps));
        assert!(written.is_in_slot(Table::Sub) && written.holds_slot());
    }
}
