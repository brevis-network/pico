//! Where the AOT core writes the events of the instructions it runs.
//!
//! The interpreter writes an instruction's events as it runs it: each operand and memory access as
//! it happens, the ALU event, then the CPU event, through `ExecutionSink`. The AOT core does the same
//! from all three places that run instructions — the runtime's `_no_count` helpers, the code
//! generated around them, and the fallback interpreter — in the interpreter's order, with the same
//! records: an access's timestamp is the instruction's clock plus its position (memory 0, `c` 1,
//! `b` 2, `a` 3), and a write carries the value, chunk and timestamp it overwrote.
//!
//! Inside an unconstrained block nothing is written, and the sink rolls the block back as the
//! interpreter's does: on the way in it sets aside the record and the accesses the entering `ECALL`
//! has made, and on the way out puts both back, so those accesses go out with the exiting `ECALL`'s
//! event. No chunk is cut inside the block, no sink is set inside one, and the record after a cut
//! is the core's program's.
//!
//! A cut hands the interpreter's chunk boundary to the record: the chunk starts at the pc the core
//! stood at when the sink was set or at the last cut, and ends at the pc the last instruction left.
//!
//! The snapshot thread runs every guest instruction with the sink off, so a compiled block pays one
//! test of the sink and nothing per instruction. Each helper's body is generic over whether it
//! writes events, and `by_sink!` runs the plain body inline and the emitting one out of line. The
//! generated code reads the sink once per block and hands that flag to every helper: only a caller
//! holding the core between runs sets the sink, so it cannot change while a block runs, and one
//! flag tested by every helper lets the compiler lay the block's plain bodies out back to back,
//! with no test and no reload between them. The fallback interpreter and `ECALL` test the sink at
//! each access.

use std::sync::Arc;

use pico_vm::{
    chips::chips::{
        events::{MemoryAccessPosition, MemoryLocalEvent},
        riscv_memory::event::{MemoryReadRecord, MemoryRecord, MemoryWriteRecord},
    },
    compiler::{addr::fits_pc, riscv::program::Program},
    emulator::riscv::{
        record::EmulationRecord,
        sink::{ChunkBoundary, ExecutionSink, HistorySink, Sink},
        syscalls::{SyscallCode, SyscallEvent},
    },
};

use super::{types::RegisterRecord, AotEmulatorCore};

/// `$emu.$body::<false>(..)` inline when `$emitting` is false, and `$emu.$body::<true>(..)` out of
/// line through [`AotEmulatorCore::emitting`] when it is true; without `$emitting`, the sink as the
/// core holds it.
macro_rules! by_sink {
    ($emu:ident.$body:ident($($arg:expr),* $(,)?)) => {
        by_sink!($emu.is_emitting(), $emu.$body($($arg),*))
    };
    ($emitting:expr, $emu:ident.$body:ident($($arg:expr),* $(,)?)) => {
        if $emitting {
            $emu.emitting(move |emu| emu.$body::<true>($($arg),*))
        } else {
            $emu.$body::<false>($($arg),*)
        }
    };
}
pub(crate) use by_sink;

/// Where the AOT core writes the events of the instructions it runs.
///
/// `Off` unless a caller asks for records: the snapshot thread hands out states, not records, and
/// must not pay for a sink it does not read.
#[derive(Default)]
pub enum AotSink {
    #[default]
    Off,
    /// The execution history and chunk-local memory windows.
    Recording(Box<RecordingAotSink>),
}

impl AotSink {
    /// The execution history, into records of `program`.
    pub fn recording(program: Arc<Program>) -> Self {
        Self::Recording(Box::new(RecordingAotSink::new(program)))
    }
}

/// The history sink, with what the interpreter keeps beside it.
pub struct RecordingAotSink {
    /// Behind `Sink`, which gives out the record being written and the chunk's local-memory
    /// windows, registers included.
    events: Sink,
    /// Chunks cut and not yet taken.
    chunks: Vec<EmittedChunk>,
    /// The core's counters when the current chunk began.
    chunk_start: ChunkCounters,
    /// The pc of the current chunk's first instruction.
    chunk_start_pc: u64,
}

impl RecordingAotSink {
    fn new(program: Arc<Program>) -> Self {
        let chunk_start_pc = program.pc_start;
        Self {
            events: Sink::History(HistorySink::new(EmulationRecord::new(program))),
            chunks: Vec::new(),
            chunk_start: ChunkCounters::default(),
            chunk_start_pc,
        }
    }

    /// The interpreter's `add_memory_local_event`: the first access to `addr` in the chunk opens its
    /// window at the state it found, every later one moves the window's end.
    #[inline(always)]
    fn local_event(&mut self, addr: u64, prev: MemoryRecord, now: MemoryRecord) {
        self.events
            .local_memory_access_mut()
            .entry(addr)
            .and_modify(|event| event.final_mem_access = now)
            .or_insert(MemoryLocalEvent {
                addr,
                initial_mem_access: prev,
                final_mem_access: now,
            });
    }
}

/// One chunk's record as the AOT core cut it, with what ran the chunk: per chunk, because a chunk
/// that fell back to interpreting hides inside a run's totals.
pub struct EmittedChunk {
    pub record: EmulationRecord,
    /// Instructions the chunk ran.
    pub cycles: u64,
    /// Compiled blocks entered while it ran.
    pub compiled_block_dispatches: u64,
    /// Its instructions the fallback interpreter ran.
    pub fallback_insns: u64,
}

#[derive(Clone, Copy, Default)]
struct ChunkCounters {
    cycles: u64,
    compiled_block_dispatches: u64,
    fallback_insns: u64,
}

impl AotEmulatorCore {
    /// Sends the events of every instruction from here on to `sink`.
    ///
    /// # Panics
    ///
    /// Inside an unconstrained block. The `ECALL` that closes a block writes its row with the `b`
    /// and `c` reads the opening one made before the block, as the interpreter's does: a sink set
    /// inside the block never saw them. The interpreter has no such row to agree with, since its
    /// sink is fixed before the run and a replay never resumes inside a block.
    pub fn set_sink(&mut self, sink: AotSink) {
        assert!(
            !self.is_unconstrained_mode(),
            "a sink is set inside an unconstrained block"
        );
        self.sink = sink;
        let (start, pc) = (self.chunk_counters(), self.pc);
        if let AotSink::Recording(sink) = &mut self.sink {
            sink.chunk_start = start;
            sink.chunk_start_pc = pc;
            // Every later cycle is opened by the one before it ending, in `end_instruction`; a
            // history sink writes no step for a cycle nothing opened.
            sink.events.begin_cycle();
        }
    }

    /// Writes the execution history of every instruction from here on, into records of the guest
    /// this core runs.
    pub fn emit_records(&mut self) {
        self.set_sink(AotSink::recording(self.program.clone()));
    }

    /// Whether the instructions' events are being written anywhere.
    #[inline(always)]
    pub fn is_emitting(&self) -> bool {
        !matches!(self.sink, AotSink::Off)
    }

    /// Runs `instruction` with its events written, out of line, so the code that tests the sink
    /// before calling it holds none of the emitting work.
    #[cold]
    #[inline(never)]
    pub(crate) fn emitting<R>(&mut self, instruction: impl FnOnce(&mut Self) -> R) -> R {
        instruction(self)
    }

    /// The chunks cut since the last call, in order; none while the sink is off.
    pub fn take_emitted_chunks(&mut self) -> Vec<EmittedChunk> {
        match &mut self.sink {
            AotSink::Off => Vec::new(),
            AotSink::Recording(sink) => std::mem::take(&mut sink.chunks),
        }
    }

    /// Closes the chunk the guest halted in, unless it ran nothing since the last cut: a halt ends
    /// the run without crossing a chunk boundary, so nothing else closes it. A run the interpreter
    /// refuses where it ends, inside an unconstrained block or at a pc the CPU trace cannot hold,
    /// closes none: the batch returns that error instead.
    pub fn finish_emitted_chunk(&mut self) {
        let ran = match &self.sink {
            AotSink::Off => false,
            AotSink::Recording(sink) => self.insn_count > sink.chunk_start.cycles,
        };
        if ran && self.run_end_error().is_none() {
            self.close_emitted_chunk();
        }
    }

    /// Closes the chunk's record where the chunk boundary is crossed, before the chunk counter
    /// moves on.
    #[inline(always)]
    pub(crate) fn cut_emitted_chunk(&mut self) {
        if self.is_emitting() {
            self.close_emitted_chunk();
        }
    }

    #[inline(never)]
    fn close_emitted_chunk(&mut self) {
        // Inside the block the record is the one `events` holds in its place, and the windows
        // would drain into it.
        assert!(
            !self.is_unconstrained_mode(),
            "a chunk is cut inside an unconstrained block"
        );
        let (now, next_pc) = (self.chunk_counters(), self.pc);
        // No pc this far is in the program, so the run ended on that jump, and the batch refuses
        // it; a chunk boundary crossed on the same instruction cuts nothing.
        if !fits_pc(next_pc) {
            return;
        }
        let AotSink::Recording(sink) = &mut self.sink else {
            return;
        };
        // Every cut follows a completed instruction, which leaves the pc at its next pc.
        let boundary = ChunkBoundary {
            start_pc: std::mem::replace(&mut sink.chunk_start_pc, next_pc),
            next_pc,
        };
        let record = sink.events.cut_chunk(self.program.clone(), boundary);
        let start = std::mem::replace(&mut sink.chunk_start, now);
        sink.chunks.push(EmittedChunk {
            record,
            cycles: now.cycles - start.cycles,
            compiled_block_dispatches: now.compiled_block_dispatches
                - start.compiled_block_dispatches,
            fallback_insns: now.fallback_insns - start.fallback_insns,
        });
    }

    fn chunk_counters(&self) -> ChunkCounters {
        ChunkCounters {
            cycles: self.insn_count,
            compiled_block_dispatches: self.compiled_block_dispatches,
            fallback_insns: self.fallback_insns,
        }
    }

    /// An unconstrained block opens: the sink sets aside what it holds until the block closes.
    pub(crate) fn sink_enter_unconstrained(&mut self) {
        if let AotSink::Recording(sink) = &mut self.sink {
            sink.events.enter_unconstrained();
        }
    }

    /// The unconstrained block closes, and the sink is as [`Self::sink_enter_unconstrained`] left
    /// it.
    pub(crate) fn sink_exit_unconstrained(&mut self) {
        if let AotSink::Recording(sink) = &mut self.sink {
            sink.events.exit_unconstrained();
        }
    }

    /// The sink, when the current instruction's events are written: one is set, and no
    /// unconstrained block is running.
    #[inline(always)]
    fn writing(&mut self) -> Option<&mut RecordingAotSink> {
        match &mut self.sink {
            AotSink::Recording(sink) if self.unconstrained_state.is_none() => Some(sink),
            _ => None,
        }
    }

    /// A read of register `reg` in operand `position` at `timestamp`; `prev` is the register's
    /// record before it.
    #[inline(never)]
    pub(crate) fn record_reg_read(
        &mut self,
        reg: usize,
        position: MemoryAccessPosition,
        value: u64,
        prev: RegisterRecord,
        timestamp: u32,
    ) {
        let chunk = self.current_chunk;
        let Some(sink) = self.writing() else {
            return;
        };
        let record = MemoryReadRecord::new(value, chunk, timestamp, prev.chunk, prev.timestamp);
        sink.events.access(position, record.into());
        sink.local_event(
            reg as u64,
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

    /// A write of `value` to register `reg`, operand `a`, at `timestamp`, over `prev_value` and
    /// its record `prev`.
    #[inline(always)]
    pub(crate) fn record_reg_write(
        &mut self,
        reg: usize,
        value: u64,
        prev_value: u64,
        prev: RegisterRecord,
        timestamp: u32,
    ) {
        let prev = MemoryRecord {
            value: prev_value,
            chunk: prev.chunk,
            timestamp: prev.timestamp,
        };
        self.record_write(reg as u64, MemoryAccessPosition::A, value, prev, timestamp);
    }

    /// [`Self::record_mem_read`] when the sink is on.
    #[inline(always)]
    pub(crate) fn emit_mem_read(&mut self, addr: u64, value: u64, prev: MemoryRecord) {
        if self.is_emitting() {
            self.record_mem_read(addr, value, prev);
        }
    }

    /// A read of the dword at `addr`, at the instruction's own clock.
    #[inline(never)]
    pub(crate) fn record_mem_read(&mut self, addr: u64, value: u64, prev: MemoryRecord) {
        let (chunk, timestamp) = (self.current_chunk, self.clk);
        let Some(sink) = self.writing() else {
            return;
        };
        let record = MemoryReadRecord::new(value, chunk, timestamp, prev.chunk, prev.timestamp);
        sink.events
            .access(MemoryAccessPosition::Memory, record.into());
        sink.local_event(
            addr,
            prev,
            MemoryRecord {
                value,
                chunk,
                timestamp,
            },
        );
    }

    /// [`Self::record_mem_write`] when the sink is on.
    #[inline(always)]
    pub(crate) fn emit_mem_write(&mut self, addr: u64, value: u64, prev: MemoryRecord) {
        if self.is_emitting() {
            self.record_mem_write(addr, value, prev);
        }
    }

    /// A write of `value` to the dword at `addr`, over `prev`, at the instruction's own clock.
    #[inline(always)]
    pub(crate) fn record_mem_write(&mut self, addr: u64, value: u64, prev: MemoryRecord) {
        let timestamp = self.clk;
        self.record_write(addr, MemoryAccessPosition::Memory, value, prev, timestamp);
    }

    #[inline(never)]
    fn record_write(
        &mut self,
        addr: u64,
        position: MemoryAccessPosition,
        value: u64,
        prev: MemoryRecord,
        timestamp: u32,
    ) {
        let chunk = self.current_chunk;
        let Some(sink) = self.writing() else {
            return;
        };
        let record = MemoryWriteRecord::new(
            value,
            chunk,
            timestamp,
            prev.value,
            prev.chunk,
            prev.timestamp,
        );
        sink.events.access(position, record.into());
        sink.local_event(
            addr,
            prev,
            MemoryRecord {
                value,
                chunk,
                timestamp,
            },
        );
    }

    /// The CPU event of the instruction at `pc`, which went on to `next_pc`. `a`, `b` and `c` are
    /// the operand values the interpreter's event carries: the result or the value stored, the
    /// first source, and the second source or immediate.
    #[inline(always)]
    pub fn emit_cpu(&mut self, pc: u64, next_pc: u64, a: u64, b: u64, c: u64) {
        if self.is_emitting() {
            self.end_instruction(pc, pc, next_pc, [a, b, c], None, false);
        }
    }

    /// [`Self::emit_cpu`] for an ALU instruction, which falls through, and its ALU event: none
    /// when it writes `x0`, which the CPU chip sends no ALU lookup for.
    #[inline(always)]
    pub fn emit_alu(&mut self, pc: u64, a: u64, b: u64, c: u64) {
        if self.is_emitting() {
            self.end_instruction(pc, pc, pc.wrapping_add(4), [a, b, c], None, true);
        }
    }

    /// [`Self::emit_cpu`] for a load or a store, with the dword it read or wrote.
    #[inline(always)]
    pub(crate) fn emit_memory(&mut self, pc: u64, a: u64, b: u64, c: u64, dword: u64) {
        if self.is_emitting() {
            self.end_instruction(pc, pc, pc.wrapping_add(4), [a, b, c], Some(dword), false);
        }
    }

    /// [`Self::emit_cpu`] for the `ECALL` at `pc`, once its syscall has run. The event goes out at
    /// the pc and clock the syscall left: its own, except after an exit from unconstrained mode,
    /// which puts back the entering `ECALL`'s.
    #[inline(always)]
    pub fn emit_ecall(&mut self, pc: u64, next_pc: u64, a: u64, b: u64, c: u64) {
        if self.is_emitting() {
            let event_pc = self.pc;
            self.end_instruction(pc, event_pc, next_pc, [a, b, c], None, false);
        }
    }

    #[inline(never)]
    fn end_instruction(
        &mut self,
        instruction_pc: u64,
        pc: u64,
        next_pc: u64,
        [a, b, c]: [u64; 3],
        memory_store_value: Option<u64>,
        alu: bool,
    ) {
        let (chunk, clk) = (self.current_chunk, u64::from(self.clk));
        // `writing`, field by field, so the instruction is fetched only when its event is written.
        let AotSink::Recording(sink) = &mut self.sink else {
            return;
        };
        if self.unconstrained_state.is_some() {
            return;
        }
        let instruction = self.program.fetch(instruction_pc);
        if alu && instruction.op_a != 0 {
            sink.events
                .alu(clk, instruction.opcode, a, b, c, instruction.imm_c);
        }
        sink.events.end_cycle(
            chunk,
            clk,
            pc,
            next_pc,
            0,
            a,
            b,
            c,
            instruction,
            memory_store_value,
        );
        // The core has no hook where an instruction starts, so the next one's cycle opens here.
        sink.events.begin_cycle();
    }

    /// The record the current instruction's events go into; none while nothing is written.
    pub(crate) fn emitting_record_mut(&mut self) -> Option<&mut EmulationRecord> {
        self.writing().map(|sink| sink.events.record_mut())
    }

    /// Takes the CPU's open window on `addr` out of the chunk's map, as a syscall that touches it
    /// closes it.
    pub(crate) fn take_cpu_window(&mut self, addr: u64) -> Option<MemoryLocalEvent> {
        self.writing()
            .and_then(|sink| sink.events.local_memory_access_mut().remove(&addr))
    }

    /// The `SyscallEvent` of an `ECALL` whose syscall the syscall chip receives, at the
    /// instruction's clock, before the syscall runs.
    #[inline(always)]
    pub(crate) fn emit_syscall(&mut self, code: SyscallCode, arg1: u64, arg2: u64) {
        if self.is_emitting() {
            let event = SyscallEvent {
                chunk: self.current_chunk,
                clk: u64::from(self.clk),
                syscall_id: code.syscall_id(),
                arg1,
                arg2,
            };
            if let Some(sink) = self.writing() {
                sink.events.syscall(event);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::types::RegisterRecord, AotEmulatorCore};
    use pico_vm::{
        chips::chips::events::MemoryAccessPosition,
        compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
        emulator::riscv::{
            record_slots::hold_records_unbounded, riscv_emulator::EmulationError,
            syscalls::SyscallCode,
        },
    };
    use std::sync::Arc;

    fn core() -> AotEmulatorCore {
        let program = Program::new(
            vec![Instruction::new(Opcode::ADD, 1, 0, 0, false, false)],
            0x1000,
            0x1000,
        );
        AotEmulatorCore::new(Arc::new(program), Vec::new())
    }

    #[test]
    #[should_panic(expected = "a chunk is cut inside an unconstrained block")]
    fn a_chunk_is_never_cut_inside_an_unconstrained_block() {
        let mut emu = core();
        emu.emit_records();
        emu.enter_unconstrained_mode();
        emu.insn_count += 1;
        emu.cut_emitted_chunk();
    }

    /// A halt inside an unconstrained block ends a run the interpreter refuses, so the finish
    /// closes no chunk and leaves the error to the batch.
    #[test]
    fn a_run_ending_inside_an_unconstrained_block_closes_no_chunk() {
        let mut emu = core();
        emu.emit_records();
        emu.enter_unconstrained_mode();
        emu.insn_count += 1;
        emu.pc = 0;
        emu.finish_emitted_chunk();
        assert!(emu.take_emitted_chunks().is_empty());
        assert!(matches!(
            emu.run_end_error(),
            Some(EmulationError::UnconstrainedEnd)
        ));
    }

    /// The program's `ADD x1, x0, x0` as the core runs it with its sink set just before: its reads
    /// of `c` and `b`, its write of `a` and its events, then the halt's cut.
    fn add_after_setting() -> pico_vm::emulator::riscv::record::EmulationRecord {
        let mut emu = core();
        emu.emit_records();
        let clk = emu.clk;
        let before = RegisterRecord::default();
        emu.record_reg_read(0, MemoryAccessPosition::C, 0, before, clk + 1);
        emu.record_reg_read(0, MemoryAccessPosition::B, 0, before, clk + 2);
        emu.record_reg_write(1, 0, 0, before, clk + 3);
        emu.emit_alu(0x1000, 0, 0, 0);
        emu.insn_count += 1;
        emu.pc = 0x1004;
        emu.finish_emitted_chunk();
        let mut chunks = emu.take_emitted_chunks();
        assert_eq!(chunks.len(), 1);
        chunks.pop().expect("one chunk").record
    }

    /// Nothing ends a cycle before the first instruction after the sink is set, so the sink opens
    /// that one itself: a history sink writes no step for a cycle nothing opened.
    #[test]
    fn the_first_instruction_after_the_sink_is_set_is_written() {
        hold_records_unbounded();
        let record = add_after_setting();
        let history = record.history.as_ref().expect("a history sink's record");
        assert_eq!(
            (
                history.steps.len(),
                history.reads.len(),
                history.writes.len()
            ),
            (1, 2, 1)
        );
        assert_eq!(history.chip_steps.add, [0]);
        assert!(record.add_events.is_empty());
        let step = &history.steps[0];
        assert_eq!((step.pc, step.next_pc), (0x1000, 0x1004));
        let add = Instruction::new(Opcode::ADD, 1, 0, 0, false, false);
        assert_eq!(history.operands(0, &add), (0, 0, 0));
    }

    /// The `ECALL` closing a block writes its row with the `b` and `c` reads the opening one made
    /// before the block, as the interpreter's does: a sink set inside the block never saw them,
    /// and the row it would write is one the interpreter never writes.
    #[test]
    #[should_panic(expected = "a sink is set inside an unconstrained block")]
    fn a_sink_is_never_set_inside_an_unconstrained_block() {
        hold_records_unbounded();
        let program = Program::new(
            vec![Instruction::new(Opcode::ECALL, 5, 10, 11, false, false)],
            0x1000,
            0x1000,
        );
        let mut emu = AotEmulatorCore::new(Arc::new(program), Vec::new());
        emu.enter_unconstrained_mode();
        emu.emit_records();
        emu.write_reg(5, SyscallCode::EXIT_UNCONSTRAINED as u64);
        let _ = emu.interpret_ecall(0x1000);
    }
}
