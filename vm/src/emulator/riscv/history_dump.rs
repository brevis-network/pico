//! A dump: one chunk's [`Fill`], the program table it was made against and the event streams the
//! host's accessors rebuild from the same history ([`HostStreams`]), so the device's loaders can be
//! checked against the host's reading away from the prover, on the host by the kernel repository's
//! loader tests or on a card by its self-test.
//!
//! The file is a header and sections, little-endian. The header is the magic [`DUMP_MAGIC`], then
//! four `u32`s: [`DUMP_VERSION`], [`HISTORY_LAYOUT`], the chunk and the section count. A section is
//! a `u32` [`Section`] tag, a `u32` row size and a `u64` row count, then its rows, zero-padded to a
//! multiple of 8. The fill, the program table and the syscall rows are in the device's layouts;
//! the CPU and ALU events are canonical rows ([`CPU_ROW`], [`ALU_ROW`]), every padding byte zero,
//! since the Rust structs' memory holds padding no reader may compare.
//!
//! The streams are the events the emulator records, before the augment pass appends to any. The
//! comparison behind each branch, which the less-than chip proves after its own rows, is a section
//! of its own, built from the CPU events in execution order.

use std::{
    borrow::Cow,
    io::{self, Read, Write},
};

use crate::{
    chips::{
        chips::{
            alu::{divrem::utils::derived_add_rows, event::AluEvent},
            riscv_cpu::{branch::traces::branch_compare, event::CpuEvent},
            riscv_memory::event::MemoryRecordEnum,
        },
        ffi::FfiOption,
    },
    compiler::riscv::{opcode::Opcode, program::Program},
    emulator::riscv::{
        history::ExecutionHistory,
        history_fill::{
            program_key, program_rows, syscall_row, DerivedRows, Fill, HISTORY_LAYOUT,
            INSTRUCTION_ROW, SYSCALL_ROW,
        },
        history_view::{history_of, AluOps},
        record::{AluStream, EmulationRecord},
        syscalls::SyscallEvent,
    },
};

pub const DUMP_MAGIC: [u8; 8] = *b"PICOHDMP";
pub const DUMP_VERSION: u32 = 1;

/// The nonce of every dump's fill.
pub const DUMP_NONCE: u64 = 1;
/// The CPU chip's slice in a dump's fill, in steps: a fib chunk is one slice, a production chunk
/// many.
pub const DUMP_CPU_SLICE_STEPS: u32 = 1 << 16;

/// A CPU event's canonical row: `chunk` `u32` at 0, `exit_code` `u32` at 4, then `u64`s `clk`,
/// `pc`, `next_pc`, `a`, `b`, `c` from 8; the instruction's `opcode`, `op_a`, `imm_b`, `imm_c` bytes
/// at 56 and its `op_b`, `op_c` at 64 and 72; the `a`, `b`, `c` and memory records from 80,
/// [`RECORD_ROW`] bytes each; the memory value's presence `u32` at 240 and the value at 248.
pub const CPU_ROW: usize = 256;
/// A memory record's canonical row: `u32`s kind (0 none, 1 read, 2 write), `chunk`, `timestamp`,
/// `prev_chunk`, `prev_timestamp` from 0, then `u64`s `value` at 24 and `prev_value` at 32, which
/// is 0 for a read.
pub const RECORD_ROW: usize = 40;
/// An ALU event's canonical row: `u64`s `clk`, `a`, `b`, `c` from 0, then the `opcode`, `is_imm`
/// and `is_cmp` bytes at 32.
pub const ALU_ROW: usize = 40;

/// What a section holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Section {
    /// The fill, byte by byte.
    Fill = 1,
    /// The program table, [`INSTRUCTION_ROW`] bytes each.
    Program = 2,
    /// Two `u64`s: the program's `pc_base` and the key the fill names.
    ProgramBase = 3,
    CpuEvents = 10,
    /// The indices into the CPU events of the loads and stores, `u64` each.
    MemoryIndices = 11,
    AddSub = 12,
    Mul = 13,
    Bitwise = 14,
    ShiftLeft = 15,
    ShiftRight = 16,
    DivRem = 17,
    Lt = 18,
    Syscalls = 19,
    BranchCompares = 20,
}

/// The stream sections in the order the kernel library's `history_check` numbers the streams, with
/// its names for them.
pub const STREAMS: [(Section, &str); 11] = [
    (Section::CpuEvents, "cpu"),
    (Section::MemoryIndices, "memory"),
    (Section::AddSub, "add_sub"),
    (Section::Mul, "mul"),
    (Section::Bitwise, "bitwise"),
    (Section::ShiftLeft, "shift_left"),
    (Section::ShiftRight, "shift_right"),
    (Section::DivRem, "divrem"),
    (Section::Lt, "lt"),
    (Section::Syscalls, "syscall"),
    (Section::BranchCompares, "branch_compare"),
];

impl Section {
    pub const ALL: [Self; 14] = [
        Self::Fill,
        Self::Program,
        Self::ProgramBase,
        Self::CpuEvents,
        Self::MemoryIndices,
        Self::AddSub,
        Self::Mul,
        Self::Bitwise,
        Self::ShiftLeft,
        Self::ShiftRight,
        Self::DivRem,
        Self::Lt,
        Self::Syscalls,
        Self::BranchCompares,
    ];

    fn of(tag: u32) -> Option<Self> {
        Self::ALL.into_iter().find(|section| *section as u32 == tag)
    }
}

/// One record's event streams.
pub struct StreamEvents<'a> {
    pub cpu: &'a [CpuEvent],
    pub memory_indices: &'a [usize],
    pub add_sub: &'a [AluEvent],
    pub mul: &'a [AluEvent],
    pub bitwise: &'a [AluEvent],
    pub shift_left: &'a [AluEvent],
    pub shift_right: &'a [AluEvent],
    pub divrem: &'a [AluEvent],
    pub lt: &'a [AluEvent],
    pub syscalls: &'a [SyscallEvent],
}

/// A record's event streams as the host's accessors rebuild them from its history: every list in
/// its own order, the add and sub lists merged in step order, as the device buffer the add/sub
/// chips once shared held them.
pub struct HostStreams {
    cpu: Vec<CpuEvent>,
    memory_indices: Vec<usize>,
    add_sub: Vec<AluEvent>,
    mul: Vec<AluEvent>,
    bitwise: Vec<AluEvent>,
    shift_left: Vec<AluEvent>,
    shift_right: Vec<AluEvent>,
    divrem: Vec<AluEvent>,
    lt: Vec<AluEvent>,
    syscalls: Vec<SyscallEvent>,
}

impl HostStreams {
    /// # Panics
    ///
    /// On a CPU chunk's record without a history, as every host accessor.
    #[must_use]
    pub fn of(record: &EmulationRecord) -> Self {
        let history = history_of(record);
        // The list's own rows only: the augment pass appends after them.
        let recorded = |stream: AluStream| -> Vec<(u32, AluEvent)> {
            let ops = AluOps::recorded(record, stream);
            let steps = history.chip_steps.alu(stream);
            steps
                .iter()
                .enumerate()
                .map(|(row, &step)| (step, ops.get(row)))
                .collect()
        };
        let events = |stream: AluStream| -> Vec<AluEvent> {
            recorded(stream)
                .into_iter()
                .map(|(_, event)| event)
                .collect()
        };
        let mut add_sub = recorded(AluStream::Add);
        add_sub.extend(recorded(AluStream::Sub));
        add_sub.sort_unstable_by_key(|&(step, _)| step);
        Self {
            cpu: record.cpu_steps().iter().map(Cow::into_owned).collect(),
            memory_indices: history
                .chip_steps
                .memory
                .iter()
                .map(|&step| step as usize)
                .collect(),
            add_sub: add_sub.into_iter().map(|(_, event)| event).collect(),
            mul: events(AluStream::Mul),
            bitwise: events(AluStream::Bitwise),
            shift_left: events(AluStream::ShiftLeft),
            shift_right: events(AluStream::ShiftRight),
            divrem: events(AluStream::DivRem),
            lt: events(AluStream::Lt),
            syscalls: history.syscalls.to_vec(),
        }
    }

    #[must_use]
    pub fn events(&self) -> StreamEvents<'_> {
        StreamEvents {
            cpu: &self.cpu,
            memory_indices: &self.memory_indices,
            add_sub: &self.add_sub,
            mul: &self.mul,
            bitwise: &self.bitwise,
            shift_left: &self.shift_left,
            shift_right: &self.shift_right,
            divrem: &self.divrem,
            lt: &self.lt,
            syscalls: &self.syscalls,
        }
    }
}

/// The rows [`DerivedRows::of`] counts from a history, tallied from the event streams instead: the
/// add/sub stream's events by opcode, and div/rem's ADD rows from each of its events.
#[must_use]
pub fn stream_derived_rows(streams: &StreamEvents<'_>) -> DerivedRows {
    let count = |opcode: Opcode| {
        let events = streams
            .add_sub
            .iter()
            .filter(|event| event.opcode == opcode);
        u32::try_from(events.count()).expect("the add/sub stream outgrows a u32")
    };
    let divrem_add: usize = streams
        .divrem
        .iter()
        .map(|event| derived_add_rows(event.opcode, event.b, event.c))
        .sum();
    DerivedRows {
        divrem_add: u32::try_from(divrem_add).expect("div/rem's ADD rows outgrow a u32"),
        add: count(Opcode::ADD),
        addw: count(Opcode::ADDW),
        sub: count(Opcode::SUB),
        subw: count(Opcode::SUBW),
    }
}

/// Writes the dump of `history`, made by `program`, beside `streams`, the event streams of the same
/// record.
///
/// # Errors
///
/// If the rows the fill's descriptor derives from the history are not the ones the streams tally
/// ([`stream_derived_rows`]), before anything is written; otherwise what writing to `out` returns.
pub fn write(
    out: &mut impl Write,
    history: &ExecutionHistory,
    program: &Program,
    streams: &StreamEvents<'_>,
) -> io::Result<()> {
    let derived = DerivedRows::of(history, program);
    let tallied = stream_derived_rows(streams);
    if derived != tallied {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "chunk {}: the history derives {derived:?}, the event streams {tallied:?}",
                history.chunk
            ),
        ));
    }
    let rows = program_rows(program);
    let key = program_key(&rows);
    let fill = Fill::encode(history, derived, DUMP_NONCE, key, DUMP_CPU_SLICE_STEPS);
    out.write_all(&DUMP_MAGIC)?;
    for word in [
        DUMP_VERSION,
        HISTORY_LAYOUT,
        history.chunk,
        Section::ALL.len() as u32,
    ] {
        out.write_all(&word.to_le_bytes())?;
    }
    section(out, Section::Fill, 1, &fill.bytes)?;
    section(out, Section::Program, INSTRUCTION_ROW, &rows)?;
    let base = [program.pc_base.to_le_bytes(), key.to_le_bytes()].concat();
    section(out, Section::ProgramBase, 8, &base)?;
    let cpu = rows_of(streams.cpu, CPU_ROW, cpu_row);
    section(out, Section::CpuEvents, CPU_ROW, &cpu)?;
    let indices = rows_of(streams.memory_indices, 8, |index, row| {
        row.copy_from_slice(&(*index as u64).to_le_bytes());
    });
    section(out, Section::MemoryIndices, 8, &indices)?;
    for (tag, events) in [
        (Section::AddSub, streams.add_sub),
        (Section::Mul, streams.mul),
        (Section::Bitwise, streams.bitwise),
        (Section::ShiftLeft, streams.shift_left),
        (Section::ShiftRight, streams.shift_right),
        (Section::DivRem, streams.divrem),
        (Section::Lt, streams.lt),
    ] {
        section(out, tag, ALU_ROW, &rows_of(events, ALU_ROW, alu_row))?;
    }
    let syscalls = rows_of(streams.syscalls, SYSCALL_ROW, syscall_row);
    section(out, Section::Syscalls, SYSCALL_ROW, &syscalls)?;
    let compares: Vec<AluEvent> = streams
        .cpu
        .iter()
        .filter(|event| event.instruction.is_branch_instruction())
        .map(|event| branch_compare(event.instruction.opcode, event.clk, event.a, event.b))
        .collect();
    section(
        out,
        Section::BranchCompares,
        ALU_ROW,
        &rows_of(&compares, ALU_ROW, alu_row),
    )
}

/// A dump read back.
pub struct Dump {
    pub chunk: u32,
    /// Each section's row size and bytes, by [`Section`] order.
    sections: Vec<Option<(usize, Vec<u8>)>>,
}

impl Dump {
    /// # Errors
    ///
    /// If `input` is not a dump of this version and layout, or holds a section twice or a tag no
    /// [`Section`] names.
    pub fn read(input: &mut impl Read) -> io::Result<Self> {
        let invalid = |what: String| io::Error::new(io::ErrorKind::InvalidData, what);
        let mut magic = [0u8; 8];
        input.read_exact(&mut magic)?;
        if magic != DUMP_MAGIC {
            return Err(invalid("not a history dump".into()));
        }
        let [version, layout, chunk, count] = [(); 4].map(|()| read_u32(input));
        let (version, layout, chunk, count) = (version?, layout?, chunk?, count?);
        if version != DUMP_VERSION || layout != HISTORY_LAYOUT {
            return Err(invalid(format!(
                "a dump of version {version}, layout {layout:#x}; this reader takes version \
                 {DUMP_VERSION}, layout {HISTORY_LAYOUT:#x}"
            )));
        }
        let mut sections = vec![None; Section::ALL.len()];
        for _ in 0..count {
            let tag = read_u32(input)?;
            let row_bytes = read_u32(input)? as usize;
            let mut rows = [0u8; 8];
            input.read_exact(&mut rows)?;
            let bytes = usize::try_from(u64::from_le_bytes(rows))
                .ok()
                .and_then(|rows| rows.checked_mul(row_bytes))
                .ok_or_else(|| invalid(format!("section {tag} outgrows memory")))?;
            let section = Section::of(tag).ok_or_else(|| invalid(format!("no section {tag}")))?;
            let slot = Section::ALL
                .iter()
                .position(|known| *known == section)
                .expect("every section is listed");
            let mut data = vec![0u8; bytes.next_multiple_of(8)];
            input.read_exact(&mut data)?;
            data.truncate(bytes);
            if sections[slot].replace((row_bytes, data)).is_some() {
                return Err(invalid(format!("section {section:?} twice")));
            }
        }
        Ok(Self { chunk, sections })
    }

    /// The rows of `section`, and their size, if the dump holds it.
    #[must_use]
    pub fn section(&self, section: Section) -> Option<(usize, &[u8])> {
        let slot = Section::ALL
            .iter()
            .position(|known| *known == section)
            .expect("every section is listed");
        self.sections[slot]
            .as_ref()
            .map(|(row_bytes, bytes)| (*row_bytes, bytes.as_slice()))
    }
}

fn read_u32(input: &mut impl Read) -> io::Result<u32> {
    let mut word = [0u8; 4];
    input.read_exact(&mut word)?;
    Ok(u32::from_le_bytes(word))
}

fn section(out: &mut impl Write, tag: Section, row_bytes: usize, bytes: &[u8]) -> io::Result<()> {
    debug_assert_eq!(bytes.len() % row_bytes, 0, "{tag:?}'s rows");
    out.write_all(&(tag as u32).to_le_bytes())?;
    out.write_all(&(row_bytes as u32).to_le_bytes())?;
    out.write_all(&((bytes.len() / row_bytes) as u64).to_le_bytes())?;
    out.write_all(bytes)?;
    out.write_all(&[0u8; 8][..bytes.len().next_multiple_of(8) - bytes.len()])
}

fn rows_of<T>(items: &[T], row_bytes: usize, row: impl Fn(&T, &mut [u8])) -> Vec<u8> {
    let mut bytes = vec![0u8; items.len() * row_bytes];
    for (item, out) in items.iter().zip(bytes.chunks_exact_mut(row_bytes)) {
        row(item, out);
    }
    bytes
}

fn put_u32(row: &mut [u8], at: usize, value: u32) {
    row[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(row: &mut [u8], at: usize, value: u64) {
    row[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn cpu_row(event: &CpuEvent, row: &mut [u8]) {
    put_u32(row, 0, event.chunk);
    put_u32(row, 4, event.exit_code);
    for (word, value) in [
        event.clk,
        event.pc,
        event.next_pc,
        event.a,
        event.b,
        event.c,
    ]
    .into_iter()
    .enumerate()
    {
        put_u64(row, 8 + 8 * word, value);
    }
    let instruction = &event.instruction;
    row[56] = instruction.opcode as u8;
    row[57] = instruction.op_a;
    row[58] = u8::from(instruction.imm_b);
    row[59] = u8::from(instruction.imm_c);
    put_u64(row, 64, instruction.op_b);
    put_u64(row, 72, instruction.op_c);
    for (slot, record) in [
        &event.a_record,
        &event.b_record,
        &event.c_record,
        &event.memory_record,
    ]
    .into_iter()
    .enumerate()
    {
        record_row(record, &mut row[80 + RECORD_ROW * slot..][..RECORD_ROW]);
    }
    if let FfiOption::Some(value) = event.memory {
        put_u32(row, 240, 1);
        put_u64(row, 248, value);
    }
}

fn record_row(record: &FfiOption<MemoryRecordEnum>, row: &mut [u8]) {
    let FfiOption::Some(record) = record else {
        return;
    };
    let (kind, chunk, timestamp, prev_chunk, prev_timestamp, value, prev_value) = match record {
        MemoryRecordEnum::Read(read) => (
            1,
            read.chunk,
            read.timestamp,
            read.prev_chunk,
            read.prev_timestamp,
            read.value,
            0,
        ),
        MemoryRecordEnum::Write(write) => (
            2,
            write.chunk,
            write.timestamp,
            write.prev_chunk,
            write.prev_timestamp,
            write.value,
            write.prev_value,
        ),
    };
    for (word, value) in [kind, chunk, timestamp, prev_chunk, prev_timestamp]
        .into_iter()
        .enumerate()
    {
        put_u32(row, 4 * word, value);
    }
    put_u64(row, 24, value);
    put_u64(row, 32, prev_value);
}

fn alu_row(event: &AluEvent, row: &mut [u8]) {
    for (word, value) in [event.clk, event.a, event.b, event.c]
        .into_iter()
        .enumerate()
    {
        put_u64(row, 8 * word, value);
    }
    row[32] = event.opcode as u8;
    row[33] = u8::from(event.is_imm);
    row[34] = u8::from(event.is_cmp);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compiler::riscv::instruction::Instruction,
        emulator::riscv::history::{Access, ReadAccess, Step},
    };

    /// One `ADD x1, x2, x3` step on its add list, and the write of its dump beside `add_sub`.
    fn write_one_add(add_sub: &[AluEvent]) -> io::Result<()> {
        let program = Program::new(
            vec![Instruction::new(Opcode::ADD, 1, 2, 3, false, false)],
            0x1000,
            0x1000,
        );
        let mut history = ExecutionHistory {
            chunk: 1,
            steps: vec![Step {
                pc: 0x1000,
                next_pc: 0x1004,
                ..Step::default()
            }]
            .into(),
            reads: vec![ReadAccess::default(); 2].into(),
            writes: vec![Access::default()].into(),
            ..ExecutionHistory::default()
        };
        history.chip_steps.add = vec![0].into();
        let streams = StreamEvents {
            cpu: &[],
            memory_indices: &[],
            add_sub,
            mul: &[],
            bitwise: &[],
            shift_left: &[],
            shift_right: &[],
            divrem: &[],
            lt: &[],
            syscalls: &[],
        };
        write(&mut Vec::new(), &history, &program, &streams)
    }

    #[test]
    fn a_dump_refuses_derived_rows_its_streams_do_not_tally() {
        let add = AluEvent::new(0, Opcode::ADD, 0, 0, 0, false);
        assert!(write_one_add(&[add]).is_ok());
        let addw = AluEvent::new(0, Opcode::ADDW, 0, 0, 0, false);
        let refused = write_one_add(&[addw]).expect_err("an ADDW tallied for an ADD step");
        assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
        assert!(
            refused.to_string().contains("the history derives"),
            "{refused}"
        );
    }
}
