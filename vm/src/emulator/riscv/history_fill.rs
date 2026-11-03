//! The execution history as a device holds it: one buffer per chunk, its fill. A
//! [`FillDescriptor`] opens the buffer and the operand exceptions follow it, so one copy carries
//! both ahead of the rest; every other table sits where the descriptor places it, and the
//! completion word, the fill's nonce, lands last. The layout is the kernel library's
//! (`tracegen/riscv/history.cuh`), asserted there and here field by field, and [`HISTORY_LAYOUT`]
//! names it.
//!
//! Rows are written field by field, little-endian, every padding byte zero.

use std::{
    ffi::c_void,
    mem::{offset_of, size_of},
};

use crate::{
    chips::chips::{
        alu::divrem::utils::derived_add_rows, riscv_memory::event::MemoryAccessPosition,
    },
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
    emulator::riscv::{
        history::{Access, ExecutionHistory, OperandException, ReadAccess, Step},
        syscalls::SyscallEvent,
    },
    iter::{IntoPicoRefIterator, PicoIterator},
};

/// The chip lists, in `ChipSteps`'s field order.
pub const LISTS: usize = 11;

/// The rows, the list order and the launch arguments the kernel library reads; a fill, a dump and
/// every launch carry it.
pub const HISTORY_LAYOUT: u32 = 0x4853_0000 | ((LISTS as u32) << 8) | 2;

/// The bits of the error word the loaders set, named in bit order.
pub const ERRORS: [&str; 13] = [
    "layout",
    "identity",
    "program",
    "incomplete",
    "step",
    "read",
    "write",
    "rows",
    "list",
    "pc",
    "exception",
    "syscall",
    "slice",
];

/// The names of the bits set in `word`, an error word the loaders wrote.
#[must_use]
pub fn describe_errors(word: u32) -> String {
    let mut names: Vec<&str> = ERRORS
        .iter()
        .enumerate()
        .filter(|(bit, _)| word & (1 << bit) != 0)
        .map(|(_, name)| *name)
        .collect();
    if word >> ERRORS.len() != 0 {
        names.push("unknown");
    }
    names.join(", ")
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FillIdentity {
    pub chunk: u32,
    pub steps: u32,
    /// Never zero and never reused on a device: the completion word equals it, so a word an
    /// earlier fill of the same memory left cannot pass for this fill's.
    pub nonce: u64,
}

const _: () = assert!(size_of::<FillIdentity>() == 16);
const _: () = assert!(offset_of!(FillIdentity, chunk) == 0);
const _: () = assert!(offset_of!(FillIdentity, steps) == 4);
const _: () = assert!(offset_of!(FillIdentity, nonce) == 8);

/// The immutable part of a fill's header, at its offset 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FillDescriptor {
    pub layout: u32,
    pub descriptor_bytes: u32,
    pub identity: FillIdentity,
    /// The key the program table is held under on the device; a launch names it too.
    pub program_key: u64,
    /// Every table and the completion word end inside the buffer.
    pub buffer_bytes: u64,
    pub reads: u32,
    pub writes: u32,
    pub exceptions: u32,
    pub syscalls: u32,
    /// List `l`'s entries are `entries[list_start[l]..list_start[l + 1]]`.
    pub list_start: [u32; LISTS + 1],
    /// The rows no list holds, so that every chip's height is known before any kernel runs.
    pub divrem_add_rows: u32,
    pub add_rows: u32,
    pub addw_rows: u32,
    pub sub_rows: u32,
    pub subw_rows: u32,
    /// Slice `k` of the CPU chip holds steps `k * cpu_slice_steps..(k + 1) * cpu_slice_steps`,
    /// the last one cut at the step count.
    pub cpu_slice_steps: u32,
    /// Byte offsets from the start of the buffer, each a multiple of 8.
    pub steps_at: u64,
    pub reads_at: u64,
    pub writes_at: u64,
    pub exceptions_at: u64,
    pub entries_at: u64,
    pub syscalls_at: u64,
    pub completion_at: u64,
}

const _: () = assert!(size_of::<FillDescriptor>() == 184);
const _: () = assert!(offset_of!(FillDescriptor, layout) == 0);
const _: () = assert!(offset_of!(FillDescriptor, descriptor_bytes) == 4);
const _: () = assert!(offset_of!(FillDescriptor, identity) == 8);
const _: () = assert!(offset_of!(FillDescriptor, program_key) == 24);
const _: () = assert!(offset_of!(FillDescriptor, buffer_bytes) == 32);
const _: () = assert!(offset_of!(FillDescriptor, reads) == 40);
const _: () = assert!(offset_of!(FillDescriptor, writes) == 44);
const _: () = assert!(offset_of!(FillDescriptor, exceptions) == 48);
const _: () = assert!(offset_of!(FillDescriptor, syscalls) == 52);
const _: () = assert!(offset_of!(FillDescriptor, list_start) == 56);
const _: () = assert!(offset_of!(FillDescriptor, divrem_add_rows) == 104);
const _: () = assert!(offset_of!(FillDescriptor, add_rows) == 108);
const _: () = assert!(offset_of!(FillDescriptor, addw_rows) == 112);
const _: () = assert!(offset_of!(FillDescriptor, sub_rows) == 116);
const _: () = assert!(offset_of!(FillDescriptor, subw_rows) == 120);
const _: () = assert!(offset_of!(FillDescriptor, cpu_slice_steps) == 124);
const _: () = assert!(offset_of!(FillDescriptor, steps_at) == 128);
const _: () = assert!(offset_of!(FillDescriptor, reads_at) == 136);
const _: () = assert!(offset_of!(FillDescriptor, writes_at) == 144);
const _: () = assert!(offset_of!(FillDescriptor, exceptions_at) == 152);
const _: () = assert!(offset_of!(FillDescriptor, entries_at) == 160);
const _: () = assert!(offset_of!(FillDescriptor, syscalls_at) == 168);
const _: () = assert!(offset_of!(FillDescriptor, completion_at) == 176);

/// A program's instructions on a device, rows of [`Instruction`]'s own layout.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ProgramTable {
    pub instructions: *const c_void,
    pub count: u64,
    pub pc_base: u64,
    /// Compared with the fill's `program_key`.
    pub key: u64,
}

const _: () = assert!(size_of::<ProgramTable>() == 32);
const _: () = assert!(offset_of!(ProgramTable, instructions) == 0);
const _: () = assert!(offset_of!(ProgramTable, count) == 8);
const _: () = assert!(offset_of!(ProgramTable, pc_base) == 16);
const _: () = assert!(offset_of!(ProgramTable, key) == 24);

/// What a kernel reading the history is launched with: device pointers, and the identity of the
/// fill it was launched for, which the kernel compares with the descriptor on the device.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct HistoryArgs {
    pub fill: *const u8,
    pub expected: FillIdentity,
    pub program: ProgramTable,
    /// The bitmap lookup's index of the exceptions; null for the binary search.
    pub exception_bits: *const u32,
    pub exception_first: *const u32,
    pub error: *mut u32,
    /// The bytes allocated at `fill`: the descriptor's own `buffer_bytes` is part of what the
    /// kernel checks, so it cannot bound the kernel's reads.
    pub fill_bytes: u64,
}

const _: () = assert!(size_of::<HistoryArgs>() == 88);
const _: () = assert!(offset_of!(HistoryArgs, fill) == 0);
const _: () = assert!(offset_of!(HistoryArgs, expected) == 8);
const _: () = assert!(offset_of!(HistoryArgs, program) == 24);
const _: () = assert!(offset_of!(HistoryArgs, exception_bits) == 56);
const _: () = assert!(offset_of!(HistoryArgs, exception_first) == 64);
const _: () = assert!(offset_of!(HistoryArgs, error) == 72);
const _: () = assert!(offset_of!(HistoryArgs, fill_bytes) == 80);

// The rows the device reads in place, as `history.cuh` asserts them.
const _: () = assert!(size_of::<Step>() == 20);
const _: () = assert!(offset_of!(Step, clk) == 0);
const _: () = assert!(offset_of!(Step, pc) == 4);
const _: () = assert!(offset_of!(Step, next_pc) == 8);
const _: () = assert!(offset_of!(Step, first_read) == 12);
const _: () = assert!(offset_of!(Step, first_write) == 16);
const _: () = assert!(size_of::<ReadAccess>() == 16);
const _: () = assert!(offset_of!(ReadAccess, value) == 0);
const _: () = assert!(offset_of!(ReadAccess, prev_chunk) == 8);
const _: () = assert!(offset_of!(ReadAccess, prev_timestamp) == 12);
const _: () = assert!(size_of::<Access>() == 24);
const _: () = assert!(offset_of!(Access, value) == 0);
const _: () = assert!(offset_of!(Access, prev_value) == 8);
const _: () = assert!(offset_of!(Access, prev_chunk) == 16);
const _: () = assert!(offset_of!(Access, prev_timestamp) == 20);
const _: () = assert!(size_of::<OperandException>() == 16);
const _: () = assert!(offset_of!(OperandException, step) == 0);
const _: () = assert!(offset_of!(OperandException, slot) == 4);
const _: () = assert!(offset_of!(OperandException, value) == 8);
const _: () = assert!(size_of::<SyscallEvent>() == SYSCALL_ROW);
const _: () = assert!(offset_of!(SyscallEvent, chunk) == 0);
const _: () = assert!(offset_of!(SyscallEvent, clk) == 8);
const _: () = assert!(offset_of!(SyscallEvent, syscall_id) == 16);
const _: () = assert!(offset_of!(SyscallEvent, arg1) == 24);
const _: () = assert!(offset_of!(SyscallEvent, arg2) == 32);
const _: () = assert!(size_of::<Instruction>() == INSTRUCTION_ROW);
const _: () = assert!(offset_of!(Instruction, opcode) == 0);
const _: () = assert!(offset_of!(Instruction, op_a) == 1);
const _: () = assert!(offset_of!(Instruction, op_b) == 8);
const _: () = assert!(offset_of!(Instruction, op_c) == 16);
const _: () = assert!(offset_of!(Instruction, imm_b) == 24);
const _: () = assert!(offset_of!(Instruction, imm_c) == 25);

pub const SYSCALL_ROW: usize = 40;
pub const INSTRUCTION_ROW: usize = 32;

/// Every table after the exceptions starts on a multiple of this, a segment the device reads
/// whole.
pub const TABLE_ALIGN: usize = 256;

/// The rows the chip lists do not hold, which the descriptor carries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DerivedRows {
    /// The ADD rows div/rem derives, zero, one or two per step.
    pub divrem_add: u32,
    pub add: u32,
    pub addw: u32,
    pub sub: u32,
    pub subw: u32,
}

impl DerivedRows {
    /// Counted from `history` and `program`, the program it ran: the add and sub lists split by
    /// opcode, and div/rem's ADD rows from each of its steps' rebuilt operands, as its chip counts
    /// them from its events.
    ///
    /// # Panics
    ///
    /// If the add or the sub list holds a step of another opcode, or a count does not fit a `u32`.
    #[must_use]
    pub fn of(history: &ExecutionHistory, program: &Program) -> Self {
        let opcode = |step: u32| {
            program
                .fetch(u64::from(history.steps[step as usize].pc))
                .opcode
        };
        // The add list is a chunk's longest, millions of entries on a block, so it is split in
        // parallel; a list entry of neither opcode is looked for only once the split misses it.
        let split = |list: &[u32], one: Opcode, other: Opcode, name: &str| -> (u32, u32) {
            let (ones, others) = list
                .pico_iter()
                .map(|&step| {
                    let opcode = opcode(step);
                    (u32::from(opcode == one), u32::from(opcode == other))
                })
                .pico_reduce(|| (0, 0), |(a, b), (c, d)| (a + c, b + d));
            if (ones + others) as usize != list.len() {
                let step = list
                    .iter()
                    .find(|&&step| ![one, other].contains(&opcode(step)))
                    .expect("an entry of neither opcode");
                panic!("step {step} of the {name} list is a {:?}", opcode(*step));
            }
            (ones, others)
        };
        let lists = &history.chip_steps;
        let (add, addw) = split(&lists.add, Opcode::ADD, Opcode::ADDW, "add");
        let (sub, subw) = split(&lists.sub, Opcode::SUB, Opcode::SUBW, "sub");
        let divrem_add = lists
            .divrem
            .iter()
            .map(|&step| {
                let instruction = program.fetch(u64::from(history.steps[step as usize].pc));
                let (_, b, c) = history.operands(step as usize, &instruction);
                derived_add_rows(instruction.opcode, b, c)
            })
            .sum::<usize>();
        Self {
            divrem_add: u32::try_from(divrem_add).expect("div/rem's ADD rows outgrow a u32"),
            add,
            addw,
            sub,
            subw,
        }
    }
}

/// The rows of each table of one fill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FillRows {
    pub steps: usize,
    pub reads: usize,
    pub writes: usize,
    pub exceptions: usize,
    pub syscalls: usize,
    /// In `ChipSteps`'s field order.
    pub lists: [usize; LISTS],
}

/// Where each table of a fill starts, in bytes from its start: the descriptor, the exceptions
/// right behind it, every other table on a [`TABLE_ALIGN`] boundary, the completion word last.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FillLayout {
    pub exceptions_at: usize,
    pub steps_at: usize,
    pub reads_at: usize,
    pub writes_at: usize,
    pub entries_at: usize,
    pub syscalls_at: usize,
    pub completion_at: usize,
    /// The fill's length: the completion word's end.
    pub buffer_bytes: usize,
    /// List `l`'s entries are `entries[list_start[l]..list_start[l + 1]]`.
    pub list_start: [u32; LISTS + 1],
    counts: [u32; 5],
}

impl FillLayout {
    /// # Panics
    ///
    /// If a table's row count does not fit a `u32`.
    #[must_use]
    pub fn of(rows: &FillRows) -> Self {
        let count = |rows: usize| u32::try_from(rows).expect("a history table outgrows a u32");
        let mut list_start = [0u32; LISTS + 1];
        for (list, &entries) in rows.lists.iter().enumerate() {
            list_start[list + 1] = list_start[list]
                .checked_add(count(entries))
                .expect("the chip lists outgrow a u32");
        }
        let mut layout = Layout(size_of::<FillDescriptor>());
        let exceptions_at = layout.table(rows.exceptions * 16, 8);
        let steps_at = layout.table(rows.steps * 20, TABLE_ALIGN);
        let reads_at = layout.table(rows.reads * 16, TABLE_ALIGN);
        let writes_at = layout.table(rows.writes * 24, TABLE_ALIGN);
        let entries_at = layout.table(list_start[LISTS] as usize * 4, TABLE_ALIGN);
        let syscalls_at = layout.table(rows.syscalls * SYSCALL_ROW, TABLE_ALIGN);
        let completion_at = layout.table(8, 8);
        Self {
            exceptions_at,
            steps_at,
            reads_at,
            writes_at,
            entries_at,
            syscalls_at,
            completion_at,
            buffer_bytes: layout.0,
            list_start,
            counts: [
                count(rows.steps),
                count(rows.reads),
                count(rows.writes),
                count(rows.exceptions),
                count(rows.syscalls),
            ],
        }
    }

    /// The descriptor of a fill laid out so, `identity`'s step count being the layout's.
    ///
    /// # Panics
    ///
    /// If `identity` holds another step count than the layout was made for.
    #[must_use]
    pub fn descriptor(
        &self,
        identity: FillIdentity,
        program_key: u64,
        derived: DerivedRows,
        cpu_slice_steps: u32,
    ) -> FillDescriptor {
        let [steps, reads, writes, exceptions, syscalls] = self.counts;
        assert_eq!(
            identity.steps, steps,
            "a fill's identity names its step count"
        );
        FillDescriptor {
            layout: HISTORY_LAYOUT,
            descriptor_bytes: size_of::<FillDescriptor>() as u32,
            identity,
            program_key,
            buffer_bytes: self.buffer_bytes as u64,
            reads,
            writes,
            exceptions,
            syscalls,
            list_start: self.list_start,
            divrem_add_rows: derived.divrem_add,
            add_rows: derived.add,
            addw_rows: derived.addw,
            sub_rows: derived.sub,
            subw_rows: derived.subw,
            cpu_slice_steps,
            steps_at: self.steps_at as u64,
            reads_at: self.reads_at as u64,
            writes_at: self.writes_at as u64,
            exceptions_at: self.exceptions_at as u64,
            entries_at: self.entries_at as u64,
            syscalls_at: self.syscalls_at as u64,
            completion_at: self.completion_at as u64,
        }
    }
}

/// One chunk's fill.
pub struct Fill {
    pub descriptor: FillDescriptor,
    pub bytes: Vec<u8>,
}

impl Fill {
    /// The fill of `history`, made against the program table `program_key` names.
    ///
    /// # Panics
    ///
    /// If a table's row count does not fit a `u32`, `nonce` is zero, or an operand exception is not
    /// where the device's lookups search for it ([`check_exceptions`]).
    #[must_use]
    pub fn encode(
        history: &ExecutionHistory,
        derived: DerivedRows,
        nonce: u64,
        program_key: u64,
        cpu_slice_steps: u32,
    ) -> Self {
        assert_ne!(nonce, 0, "a fill's nonce is never zero");
        check_exceptions(&history.operand_exceptions, history.steps.len());
        let lists = lists(history);
        let layout = FillLayout::of(&FillRows {
            steps: history.steps.len(),
            reads: history.reads.len(),
            writes: history.writes.len(),
            exceptions: history.operand_exceptions.len(),
            syscalls: history.syscalls.len(),
            lists: lists.map(<[u32]>::len),
        });
        let descriptor = layout.descriptor(
            FillIdentity {
                chunk: history.chunk,
                steps: history.steps.len() as u32,
                nonce,
            },
            program_key,
            derived,
            cpu_slice_steps,
        );
        let FillLayout {
            exceptions_at,
            steps_at,
            reads_at,
            writes_at,
            entries_at,
            syscalls_at,
            completion_at,
            buffer_bytes,
            ..
        } = layout;
        let mut bytes = Bytes(vec![0; buffer_bytes]);
        bytes.descriptor(&descriptor);
        for (row, exception) in history.operand_exceptions.iter().enumerate() {
            let at = exceptions_at + 16 * row;
            bytes.u32(at, exception.step);
            bytes.u32(at + 4, exception.slot);
            bytes.u64(at + 8, exception.value);
        }
        for (row, step) in history.steps.iter().enumerate() {
            let at = steps_at + 20 * row;
            let Step {
                clk,
                pc,
                next_pc,
                first_read,
                first_write,
            } = *step;
            for (word, value) in [clk, pc, next_pc, first_read, first_write]
                .into_iter()
                .enumerate()
            {
                bytes.u32(at + 4 * word, value);
            }
        }
        for (row, read) in history.reads.iter().enumerate() {
            let at = reads_at + 16 * row;
            bytes.u64(at, read.value);
            bytes.u32(at + 8, read.prev_chunk);
            bytes.u32(at + 12, read.prev_timestamp);
        }
        for (row, write) in history.writes.iter().enumerate() {
            let at = writes_at + 24 * row;
            bytes.u64(at, write.value);
            bytes.u64(at + 8, write.prev_value);
            bytes.u32(at + 16, write.prev_chunk);
            bytes.u32(at + 20, write.prev_timestamp);
        }
        for (entry, &step) in lists.iter().flat_map(|list| list.iter()).enumerate() {
            bytes.u32(entries_at + 4 * entry, step);
        }
        for (row, event) in history.syscalls.iter().enumerate() {
            let at = syscalls_at + SYSCALL_ROW * row;
            syscall_row(event, &mut bytes.0[at..at + SYSCALL_ROW]);
        }
        bytes.u64(completion_at, nonce);
        Self {
            descriptor,
            bytes: bytes.0,
        }
    }
}

/// Checks that the operand `exceptions` of a history of `steps` steps are where the device's
/// lookups search for them, both a search over the table sorted: each on one of the history's
/// steps, in an operand slot, and after the one before it by step and, within a step, in `a`, `b`,
/// `c` order, which is the slots' descending order.
///
/// # Panics
///
/// At the first exception that is not.
pub fn check_exceptions(exceptions: &[OperandException], steps: usize) {
    let operand = MemoryAccessPosition::C as u32..=MemoryAccessPosition::A as u32;
    for (row, exception) in exceptions.iter().enumerate() {
        assert!(
            (exception.step as usize) < steps && operand.contains(&exception.slot),
            "operand exception {row} names step {} slot {} of a history of {steps} steps",
            exception.step,
            exception.slot,
        );
        if let Some(before) = row.checked_sub(1).map(|row| exceptions[row]) {
            assert!(
                (before.step, std::cmp::Reverse(before.slot))
                    < (exception.step, std::cmp::Reverse(exception.slot)),
                "operand exception {row} (step {}, slot {}) is not after the one before it (step \
                 {}, slot {})",
                exception.step,
                exception.slot,
                before.step,
                before.slot
            );
        }
    }
}

/// `history`'s chip lists, in `ChipSteps`'s field order.
#[must_use]
pub fn lists(history: &ExecutionHistory) -> [&[u32]; LISTS] {
    let lists = &history.chip_steps;
    [
        &lists.add,
        &lists.sub,
        &lists.mul,
        &lists.bitwise,
        &lists.shift_left,
        &lists.shift_right,
        &lists.lt,
        &lists.divrem,
        &lists.memory,
        &lists.ecall,
        &lists.branch,
    ]
}

/// `program`'s instructions as the device reads them, [`INSTRUCTION_ROW`] bytes each.
#[must_use]
pub fn program_rows(program: &Program) -> Vec<u8> {
    let mut bytes = Bytes(vec![0; program.instructions.len() * INSTRUCTION_ROW]);
    for (row, instruction) in program.instructions.iter().enumerate() {
        let at = INSTRUCTION_ROW * row;
        bytes.0[at] = instruction.opcode as u8;
        bytes.0[at + 1] = instruction.op_a;
        bytes.u64(at + 8, instruction.op_b);
        bytes.u64(at + 16, instruction.op_c);
        bytes.0[at + 24] = u8::from(instruction.imm_b);
        bytes.0[at + 25] = u8::from(instruction.imm_c);
    }
    bytes.0
}

/// `event` in the device's layout of [`SyscallEvent`], [`SYSCALL_ROW`] bytes with its padding zero.
pub fn syscall_row(event: &SyscallEvent, row: &mut [u8]) {
    let mut put = |at: usize, value: &[u8]| row[at..at + value.len()].copy_from_slice(value);
    put(offset_of!(SyscallEvent, chunk), &event.chunk.to_le_bytes());
    put(offset_of!(SyscallEvent, clk), &event.clk.to_le_bytes());
    put(
        offset_of!(SyscallEvent, syscall_id),
        &event.syscall_id.to_le_bytes(),
    );
    put(offset_of!(SyscallEvent, arg1), &event.arg1.to_le_bytes());
    put(offset_of!(SyscallEvent, arg2), &event.arg2.to_le_bytes());
}

/// A key for program rows: 64-bit FNV-1a over them. A fill and the table it was made against carry
/// the same key; what the device caches its tables under is its own.
#[must_use]
pub fn program_key(rows: &[u8]) -> u64 {
    rows.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// The end of the tables laid out so far.
struct Layout(usize);

impl Layout {
    /// Places a table of `bytes` at the next multiple of `align`, returning its offset.
    fn table(&mut self, bytes: usize, align: usize) -> usize {
        let at = self.0.next_multiple_of(align);
        self.0 = at + bytes;
        at
    }
}

struct Bytes(Vec<u8>);

impl Bytes {
    fn u32(&mut self, at: usize, value: u32) {
        self.0[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, at: usize, value: u64) {
        self.0[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn descriptor(&mut self, descriptor: &FillDescriptor) {
        macro_rules! put {
            ($width:ident, $field:ident) => {
                self.$width(offset_of!(FillDescriptor, $field), descriptor.$field)
            };
        }
        put!(u32, layout);
        put!(u32, descriptor_bytes);
        let identity = offset_of!(FillDescriptor, identity);
        self.u32(
            identity + offset_of!(FillIdentity, chunk),
            descriptor.identity.chunk,
        );
        self.u32(
            identity + offset_of!(FillIdentity, steps),
            descriptor.identity.steps,
        );
        self.u64(
            identity + offset_of!(FillIdentity, nonce),
            descriptor.identity.nonce,
        );
        put!(u64, program_key);
        put!(u64, buffer_bytes);
        put!(u32, reads);
        put!(u32, writes);
        put!(u32, exceptions);
        put!(u32, syscalls);
        for (list, &start) in descriptor.list_start.iter().enumerate() {
            self.u32(offset_of!(FillDescriptor, list_start) + 4 * list, start);
        }
        put!(u32, divrem_add_rows);
        put!(u32, add_rows);
        put!(u32, addw_rows);
        put!(u32, sub_rows);
        put!(u32, subw_rows);
        put!(u32, cpu_slice_steps);
        put!(u64, steps_at);
        put!(u64, reads_at);
        put!(u64, writes_at);
        put!(u64, exceptions_at);
        put!(u64, entries_at);
        put!(u64, syscalls_at);
        put!(u64, completion_at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulator::riscv::history::Slots;

    /// A program of ADD, ADDW, SUB and SUBW at 0x1000, 0x1004, 0x1008 and 0x100c, and a history
    /// whose add and sub lists name `add` and `sub` of its steps, one step per instruction.
    fn split(add: Vec<u32>, sub: Vec<u32>) -> DerivedRows {
        let opcodes = [Opcode::ADD, Opcode::ADDW, Opcode::SUB, Opcode::SUBW];
        let program = Program::new(
            opcodes
                .map(|opcode| Instruction::new(opcode, 1, 2, 3, false, false))
                .to_vec(),
            0x1000,
            0x1000,
        );
        let mut history = ExecutionHistory {
            steps: (0..4)
                .map(|i| Step {
                    pc: 0x1000 + 4 * i,
                    ..Step::default()
                })
                .collect(),
            ..ExecutionHistory::default()
        };
        history.chip_steps.add = add.into();
        history.chip_steps.sub = sub.into();
        DerivedRows::of(&history, &program)
    }

    #[test]
    fn the_coarse_lists_split_by_opcode() {
        assert_eq!(
            split(vec![0, 1, 0, 0], vec![3, 2, 3]),
            DerivedRows {
                divrem_add: 0,
                add: 3,
                addw: 1,
                sub: 1,
                subw: 2,
            }
        );
    }

    #[test]
    #[should_panic(expected = "step 2 of the add list is a SUB")]
    fn a_list_entry_of_another_opcode_is_refused() {
        split(vec![0, 2], Vec::new());
    }

    /// Appends a step of `instruction` at `pc` whose accesses hold `values`, one per slot present
    /// in `Slots::ORDER`, each read from or written to its table.
    fn push_step(
        history: &mut ExecutionHistory,
        pc: u32,
        instruction: &Instruction,
        values: &[u64],
    ) {
        let slots = Slots::of(instruction);
        assert_eq!(slots.len(), values.len());
        history.steps.push(Step {
            pc,
            first_read: history.reads.len() as u32,
            first_write: history.writes.len() as u32,
            ..Step::default()
        });
        for (position, &value) in slots.iter().zip(values) {
            if slots.writes(position) {
                history.writes.push(Access {
                    value,
                    prev_value: value,
                    ..Access::default()
                });
            } else {
                history.reads.push(ReadAccess {
                    value,
                    ..ReadAccess::default()
                });
            }
        }
    }

    /// Every opcode of the two coarse lists once, and div/rem steps whose divisor or remainder a
    /// signed operation finds negative: 1 row for `7 / -2`, 2 for `-7 / -2` and for `remw` of the
    /// words `-7` and `-2`, none for an unsigned divisor of all ones, and 1 for a divisor of 3
    /// that an operand exception makes `-3`, since the rows follow the operands the step saw.
    #[test]
    fn the_derived_rows_count_the_coarse_opcodes_and_negative_div_rem_operands() {
        let negative = |value: i64| value as u64;
        let reg = |opcode| Instruction::new(opcode, 1, 2, 3, false, false);
        let steps: [(Opcode, [u64; 3]); 9] = [
            (Opcode::ADD, [5, 2, 3]),
            (Opcode::ADDW, [5, 2, 3]),
            (Opcode::SUB, [1, 3, 2]),
            (Opcode::SUBW, [1, 3, 2]),
            (Opcode::DIV, [0, 7, negative(-2)]),
            (Opcode::DIV, [0, negative(-7), negative(-2)]),
            (Opcode::REMW, [0, negative(-7), 0xffff_fffe]),
            (Opcode::DIVU, [0, 7, u64::MAX]),
            (Opcode::DIV, [0, 9, 3]),
        ];
        let program = Program::new(
            steps.iter().map(|&(opcode, _)| reg(opcode)).collect(),
            0x1000,
            0x1000,
        );
        let mut history = ExecutionHistory::default();
        for (index, (opcode, values)) in (0u32..).zip(steps) {
            push_step(&mut history, 0x1000 + 4 * index, &reg(opcode), &values);
        }
        history.operand_exceptions.push(OperandException {
            step: 8,
            slot: MemoryAccessPosition::C as u32,
            value: negative(-3),
        });
        history.chip_steps.add = vec![0, 1].into();
        history.chip_steps.sub = vec![2, 3].into();
        history.chip_steps.divrem = vec![4, 5, 6, 7, 8].into();
        assert_eq!(
            DerivedRows::of(&history, &program),
            DerivedRows {
                divrem_add: 6,
                add: 1,
                addw: 1,
                sub: 1,
                subw: 1,
            }
        );
    }
    /// Two steps, and operand exceptions on them as `(step, slot)` pairs.
    fn encode_with_exceptions(exceptions: &[(u32, MemoryAccessPosition)]) -> Fill {
        let history = ExecutionHistory {
            steps: vec![Step::default(); 2].into(),
            operand_exceptions: exceptions
                .iter()
                .map(|&(step, slot)| OperandException {
                    step,
                    slot: slot as u32,
                    value: 1,
                })
                .collect(),
            ..ExecutionHistory::default()
        };
        Fill::encode(&history, DerivedRows::default(), 1, 0, 1)
    }

    #[test]
    fn exceptions_in_step_then_a_b_c_order_encode() {
        use MemoryAccessPosition::{A, B, C};
        let fill = encode_with_exceptions(&[(0, A), (1, B), (1, C)]);
        assert_eq!(fill.descriptor.exceptions, 3);
    }

    #[test]
    #[should_panic(
        expected = "operand exception 1 (step 0, slot 3) is not after the one before it"
    )]
    fn exceptions_out_of_step_order_are_refused() {
        encode_with_exceptions(&[(1, MemoryAccessPosition::A), (0, MemoryAccessPosition::A)]);
    }

    #[test]
    #[should_panic(
        expected = "operand exception 1 (step 1, slot 2) is not after the one before it"
    )]
    fn exceptions_out_of_slot_order_within_a_step_are_refused() {
        encode_with_exceptions(&[(1, MemoryAccessPosition::C), (1, MemoryAccessPosition::B)]);
    }

    #[test]
    #[should_panic(expected = "operand exception 0 names step 2 slot 3 of a history of 2 steps")]
    fn an_exception_past_the_steps_is_refused() {
        encode_with_exceptions(&[(2, MemoryAccessPosition::A)]);
    }
}
