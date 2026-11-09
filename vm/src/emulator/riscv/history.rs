//! One chunk's execution history: every instruction the chunk ran and every register and memory
//! access it made, in execution order, as a few tables in place of an event stream per chip.
//!
//! A step stores only what the program cannot give back. Its instruction is the program's at `pc`,
//! and which operand slots it accessed, and which of those it wrote, follow from that instruction
//! ([`Slots::of`]). An access's chunk is the history's, and its timestamp is the step's clock plus
//! the slot's [`MemoryAccessPosition`]. That rule holds only for steps traced in full, so the
//! history is written only while events are traced.
//!
//! Reads and writes are stored in tables of their own, so a read does not repeat its value as the
//! one it replaced. Which slots a step writes follows from its instruction, and it writes at most
//! one: the `a` it commits, or a store's memory.
//!
//! A step's operands are the values the instruction saw. [`ExecutionHistory::operands`] gives them
//! back from the step's accesses and its instruction, and the exception table holds every operand
//! that rule gets wrong: `a` of a write to x0, which commits 0, and `b` and `c` of the ECALL
//! closing an unconstrained block, whose step stands in for the ECALL that opened the block and
//! carries that one's clock, pc and reads. The sink fills the table by comparing what it is handed
//! with the rule, so the rule can only be incomplete, never wrong.
//!
//! A load or store whose address is not a multiple of its width is not in the memory chip's list:
//! it is in [`ExecutionHistory::unaligned`], with the access to the next dword when it runs into
//! that one. That access is made at the C position, which a load or store leaves free, and
//! is no slot of the step's.
//!
//! Every row is `#[repr(C)]` plain data with no padding, so a table moves to a device as one
//! buffer; the sizes are asserted below. Clocks, pcs and indices are stored as `u32`, and the sink
//! writing them checks every narrowing in every build.
//!
//! Each table is a [`Rows`]: in a pinned slot of the history arena when the sink took one for the
//! chunk, so the device copies it from where it was written, and on the heap otherwise.

use serde::{Deserialize, Serialize};

use crate::{
    chips::chips::riscv_memory::event::{MemoryAccessPosition, MemoryRecordEnum},
    compiler::riscv::{instruction::Instruction, opcode::Opcode},
    emulator::riscv::{
        event_types::RvChunk, history_arena::Rows, record::AluStream, record_digest::digest_words,
        syscalls::SyscallEvent,
    },
};

/// One chunk's steps and accesses, in execution order.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExecutionHistory {
    /// The chunk of every step and access.
    pub chunk: RvChunk,
    pub steps: Rows<Step>,
    /// Each step's reads, contiguous from its `first_read`, in [`Slots::ORDER`]. That is not the
    /// order they were made in, which their timestamps give: memory, `c`, `b`, then `a`.
    pub reads: Rows<ReadAccess>,
    /// Each step's write, at its `first_write`; a step that writes nothing has none.
    pub writes: Rows<Access>,
    pub chip_steps: ChipSteps,
    /// The operands the rule of [`Self::operands`] gives wrongly, in step order and, within a
    /// step, in `a`, `b`, `c` order.
    pub operand_exceptions: Rows<OperandException>,
    /// One per ECALL whose syscall is sent to the syscall chip.
    pub syscalls: Rows<SyscallEvent>,
    /// The loads and stores whose address is not a multiple of their width, in step order,
    /// which [`ChipSteps::memory`] leaves out. They are read on the host alone, so the table never
    /// takes a region of the arena's slot.
    #[serde(default)]
    pub unaligned: Rows<UnalignedStep>,
}

impl ExecutionHistory {
    /// The read and the write rows of the step at `index`, in [`Slots::ORDER`].
    #[must_use]
    pub fn rows_of(&self, index: usize) -> (&[ReadAccess], &[Access]) {
        let step = &self.steps[index];
        let next = self.steps.get(index + 1);
        let reads_end = next.map_or(self.reads.len(), |next| next.first_read as usize);
        let writes_end = next.map_or(self.writes.len(), |next| next.first_write as usize);
        (
            &self.reads[step.first_read as usize..reads_end],
            &self.writes[step.first_write as usize..writes_end],
        )
    }

    /// The accesses of the step at `index`, `instruction` being the program's at its pc, in
    /// [`Slots::ORDER`]: each with its slot, the write from the writes and every other from the
    /// reads, whose `prev_value` is their own value.
    pub fn accesses_of(
        &self,
        index: usize,
        instruction: &Instruction,
    ) -> impl Iterator<Item = (MemoryAccessPosition, Access)> + '_ {
        self.accesses_in(index, Slots::of(instruction))
    }

    /// [`Self::accesses_of`] for a reader that holds the instruction's slots already.
    pub(crate) fn accesses_in(
        &self,
        index: usize,
        slots: Slots,
    ) -> impl Iterator<Item = (MemoryAccessPosition, Access)> + '_ {
        let (reads, writes) = self.rows_of(index);
        debug_assert_eq!(
            (reads.len(), writes.len()),
            (slots.len() - slots.write_count(), slots.write_count()),
            "step {index}'s rows"
        );
        let (mut reads, mut writes) = (reads.iter(), writes.iter());
        slots.iter().map(move |position| {
            let access = if slots.writes(position) {
                writes.next().copied()
            } else {
                reads.next().map(|&read| read.into())
            };
            let access =
                access.unwrap_or_else(|| panic!("step {index} holds no row for its {position:?}"));
            (position, access)
        })
    }

    /// The operands of the step at `index`, `instruction` being the program's at its pc: a
    /// present slot's is its access's value, a jump's `a` is its pc + 4, an absent `b` or `c` is
    /// the instruction's immediate, and [`Self::operand_exceptions`] overrides any of them.
    #[must_use]
    pub fn operands(&self, index: usize, instruction: &Instruction) -> (u64, u64, u64) {
        let mut values = [None; 4];
        for (position, access) in self.accesses_of(index, instruction) {
            values[position as usize] = Some(access.value);
        }
        self.operands_from(index, instruction, &values)
    }

    /// [`Self::operands`] for a reader that has walked the step's accesses already, `values`
    /// holding each one's value at its [`MemoryAccessPosition`].
    #[must_use]
    pub(crate) fn operands_from(
        &self,
        index: usize,
        instruction: &Instruction,
        values: &[Option<u64>; 4],
    ) -> (u64, u64, u64) {
        let mut operands = ruled_operands(instruction, self.steps[index].pc, |position| {
            values[position as usize]
        });
        let first = self
            .operand_exceptions
            .partition_point(|exception| (exception.step as usize) < index);
        for exception in &self.operand_exceptions[first..] {
            if exception.step as usize != index {
                break;
            }
            operands[exception.operand()] = exception.value;
        }
        let [a, b, c] = operands;
        (a, b, c)
    }

    /// The bytes each table holds in place, by name.
    #[must_use]
    pub fn table_bytes(&self) -> [(&'static str, usize); 7] {
        let Self {
            chunk: _,
            steps,
            reads,
            writes,
            chip_steps,
            operand_exceptions,
            syscalls,
            unaligned,
        } = self;
        [
            ("steps", size_of_val(steps.as_slice())),
            ("reads", size_of_val(reads.as_slice())),
            ("writes", size_of_val(writes.as_slice())),
            (
                "chip_steps",
                chip_steps.all().iter().map(|list| size_of_val(*list)).sum(),
            ),
            (
                "operand_exceptions",
                size_of_val(operand_exceptions.as_slice()),
            ),
            ("syscalls", size_of_val(syscalls.as_slice())),
            ("unaligned", size_of_val(unaligned.as_slice())),
        ]
    }

    /// The bytes the tables hold in place.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.table_bytes().into_iter().map(|(_, bytes)| bytes).sum()
    }

    /// A digest of the chunk and of every row of every table, in order.
    #[must_use]
    pub fn digest(&self) -> u64 {
        Self::digest_all([self])
    }

    /// The digest of `histories` read one after another, so one history's is its [`Self::digest`].
    #[must_use]
    pub fn digest_all<'a>(histories: impl IntoIterator<Item = &'a Self>) -> u64 {
        digest_words(histories.into_iter().flat_map(Self::words))
    }

    /// Appends `later`, the history of the stretch of the same chunk that runs on from this one's
    /// last step, leaving it empty: the history one replay of both stretches would have written.
    /// `later`'s indices point into its own tables, so each moves past the rows already here:
    /// every `first_read` by the reads, every `first_write` by the writes, every chip list entry,
    /// exception and unaligned step by the steps. Rows are moved, never reordered. Syscalls and
    /// access rows hold clocks and memory state, not indices.
    ///
    /// # Panics
    ///
    /// If both histories hold steps and they are of different chunks, or if a moved index does
    /// not fit a `u32`.
    pub fn append(&mut self, later: &mut Self) {
        let Self {
            chunk,
            steps,
            reads,
            writes,
            chip_steps,
            operand_exceptions,
            syscalls,
            unaligned,
        } = later;
        if self.steps.is_empty() {
            self.chunk = *chunk;
        } else if !steps.is_empty() {
            assert_eq!(
                self.chunk, *chunk,
                "a history of chunk {chunk} appended to one of chunk {}",
                self.chunk
            );
        }
        let (step_base, read_base, write_base) =
            (self.steps.len(), self.reads.len(), self.writes.len());
        self.steps.extend(steps.iter().map(|step| Step {
            first_read: moved(step.first_read, read_base, "read index"),
            first_write: moved(step.first_write, write_base, "write index"),
            ..*step
        }));
        steps.clear();
        self.reads.append(reads);
        self.writes.append(writes);
        self.chip_steps.append(chip_steps, step_base);
        self.operand_exceptions
            .extend(operand_exceptions.iter().map(|exception| OperandException {
                step: moved(exception.step, step_base, "step index"),
                ..*exception
            }));
        operand_exceptions.clear();
        self.syscalls.append(syscalls);
        self.unaligned
            .extend(unaligned.iter().map(|unaligned| UnalignedStep {
                step: moved(unaligned.step, step_base, "step index"),
                ..*unaligned
            }));
        unaligned.clear();
    }

    /// Every stored fact as 32-bit words, each table behind its length so a row cannot move from
    /// one table to the next unseen. The unaligned steps come last and only when there are some, so
    /// a history without one keeps the digest it had before the table existed.
    fn words(&self) -> impl Iterator<Item = u32> + '_ {
        let Self {
            chunk,
            steps,
            reads,
            writes,
            chip_steps,
            operand_exceptions,
            syscalls,
            unaligned,
        } = self;
        let wide = |value: u64| [value as u32, (value >> 32) as u32];
        let lists = chip_steps.all();
        let step_words = steps.iter().flat_map(move |step| {
            let Step {
                clk,
                pc,
                next_pc,
                first_read,
                first_write,
            } = *step;
            [clk, pc, next_pc, first_read, first_write]
        });
        let read_words = reads.iter().flat_map(move |read| {
            let ReadAccess {
                value,
                prev_chunk,
                prev_timestamp,
            } = *read;
            let [v0, v1] = wide(value);
            [v0, v1, prev_chunk, prev_timestamp]
        });
        let write_words = writes.iter().flat_map(move |access| {
            let Access {
                value,
                prev_value,
                prev_chunk,
                prev_timestamp,
            } = *access;
            let ([v0, v1], [p0, p1]) = (wide(value), wide(prev_value));
            [v0, v1, p0, p1, prev_chunk, prev_timestamp]
        });
        let exception_words = operand_exceptions.iter().flat_map(move |exception| {
            let OperandException { step, slot, value } = *exception;
            let [v0, v1] = wide(value);
            [step, slot, v0, v1]
        });
        let syscall_words = syscalls.iter().flat_map(move |event| {
            let SyscallEvent {
                chunk,
                clk,
                syscall_id,
                arg1,
                arg2,
            } = *event;
            let ([k0, k1], [x0, x1], [y0, y1]) = (wide(clk), wide(arg1), wide(arg2));
            [chunk, k0, k1, syscall_id, x0, x1, y0, y1]
        });
        let unaligned_words = unaligned.iter().flat_map(move |unaligned| {
            let UnalignedStep {
                step,
                crosses,
                next:
                    Access {
                        value,
                        prev_value,
                        prev_chunk,
                        prev_timestamp,
                    },
            } = *unaligned;
            let ([v0, v1], [p0, p1]) = (wide(value), wide(prev_value));
            [step, crosses, v0, v1, p0, p1, prev_chunk, prev_timestamp]
        });
        let unaligned_len = (!unaligned.is_empty()).then(|| wide(unaligned.len() as u64));
        std::iter::once(*chunk)
            .chain(wide(steps.len() as u64))
            .chain(step_words)
            .chain(wide(reads.len() as u64))
            .chain(read_words)
            .chain(wide(writes.len() as u64))
            .chain(write_words)
            .chain(wide(operand_exceptions.len() as u64))
            .chain(exception_words)
            .chain(lists.into_iter().flat_map(move |list| {
                wide(list.len() as u64)
                    .into_iter()
                    .chain(list.iter().copied())
            }))
            .chain(wide(syscalls.len() as u64))
            .chain(syscall_words)
            .chain(unaligned_len.into_iter().flatten())
            .chain(unaligned_words)
    }
}

/// `index` moved past `base` rows, checked as the sink checks every narrowing.
fn moved(index: u32, base: usize, what: &str) -> u32 {
    let index = index as usize + base;
    u32::try_from(index)
        .unwrap_or_else(|_| panic!("{what} {index:#x} does not fit the history's u32"))
}

/// The operands the rule of [`ExecutionHistory::operands`] gives the step of `instruction` at
/// `pc`, as `[a, b, c]`, `value` being the step's access in a slot when it has one. The sink runs
/// it on what it is handed to write the exceptions and the readers run it on the rows, so the two
/// must see the same slots.
pub(crate) fn ruled_operands(
    instruction: &Instruction,
    pc: u32,
    value: impl Fn(MemoryAccessPosition) -> Option<u64>,
) -> [u64; 3] {
    let a = if instruction.is_jump_instruction() {
        u64::from(pc) + 4
    } else {
        value(MemoryAccessPosition::A).unwrap_or(0)
    };
    let (imm_b, imm_c) = match instruction.opcode {
        Opcode::JAL => (instruction.op_b, 0),
        Opcode::AUIPC => (instruction.op_b, instruction.op_b),
        _ => (instruction.op_b, instruction.op_c),
    };
    [
        a,
        value(MemoryAccessPosition::B).unwrap_or(imm_b),
        value(MemoryAccessPosition::C).unwrap_or(imm_c),
    ]
}

/// One instruction the chunk ran; its operands are [`ExecutionHistory::operands`]'s.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct Step {
    /// The chunk-local clock.
    pub clk: u32,
    pub pc: u32,
    pub next_pc: u32,
    /// The index of the step's first read in [`ExecutionHistory::reads`].
    pub first_read: u32,
    /// The index of the step's write in [`ExecutionHistory::writes`], or of the next step's when
    /// it writes nothing.
    pub first_write: u32,
}

const _: () = assert!(size_of::<Step>() == 20);

impl Step {
    /// The timestamp of the step's access in `position`.
    #[inline]
    #[must_use]
    pub const fn timestamp(&self, position: MemoryAccessPosition) -> u32 {
        self.clk + position as u32
    }

    /// The address of a step's access in `position`, `instruction` being the program's at its pc
    /// and `b` and `c` its operands: the register it names for `a`, `b` and `c`, and for memory
    /// the dword holding `b + c`.
    #[inline]
    #[must_use]
    pub const fn address(
        instruction: &Instruction,
        position: MemoryAccessPosition,
        b: u64,
        c: u64,
    ) -> u64 {
        match position {
            MemoryAccessPosition::A => instruction.op_a as u64,
            MemoryAccessPosition::B => instruction.op_b,
            MemoryAccessPosition::C => instruction.op_c,
            MemoryAccessPosition::Memory => b.wrapping_add(c) & !7,
        }
    }
}

/// One register or memory access: the value it left, and the state it found. A write is stored
/// as one; a read is stored as a [`ReadAccess`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct Access {
    pub value: u64,
    /// The value a write replaced; a read's own value.
    pub prev_value: u64,
    pub prev_chunk: u32,
    pub prev_timestamp: u32,
}

const _: () = assert!(size_of::<Access>() == 24);

/// One register or memory read: the value it found, and when that was written.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct ReadAccess {
    pub value: u64,
    pub prev_chunk: u32,
    pub prev_timestamp: u32,
}

const _: () = assert!(size_of::<ReadAccess>() == 16);

impl From<Access> for ReadAccess {
    #[inline]
    fn from(access: Access) -> Self {
        Self {
            value: access.value,
            prev_chunk: access.prev_chunk,
            prev_timestamp: access.prev_timestamp,
        }
    }
}

impl From<ReadAccess> for Access {
    #[inline]
    fn from(read: ReadAccess) -> Self {
        Self {
            value: read.value,
            prev_value: read.value,
            prev_chunk: read.prev_chunk,
            prev_timestamp: read.prev_timestamp,
        }
    }
}

impl From<MemoryRecordEnum> for Access {
    #[inline]
    fn from(record: MemoryRecordEnum) -> Self {
        match record {
            MemoryRecordEnum::Read(read) => Self {
                value: read.value,
                prev_value: read.value,
                prev_chunk: read.prev_chunk,
                prev_timestamp: read.prev_timestamp,
            },
            MemoryRecordEnum::Write(write) => Self {
                value: write.value,
                prev_value: write.prev_value,
                prev_chunk: write.prev_chunk,
                prev_timestamp: write.prev_timestamp,
            },
        }
    }
}

/// One operand the rule of [`ExecutionHistory::operands`] gives wrongly: what the instruction saw
/// in `slot` of the step at `step`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct OperandException {
    pub step: u32,
    /// The operand's [`MemoryAccessPosition`].
    pub slot: u32,
    pub value: u64,
}

const _: () = assert!(size_of::<OperandException>() == 16);

impl OperandException {
    /// The operand's position in `[a, b, c]`.
    #[inline]
    const fn operand(self) -> usize {
        MemoryAccessPosition::A as usize - self.slot as usize
    }
}

/// A load or store whose address is not a multiple of its width: the step, and the access
/// to the dword after the one its first byte is in, which the step makes at its clock plus `C`
/// when it runs into that dword. A store writes it, a load reads it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct UnalignedStep {
    pub step: u32,
    /// 1 if the access runs into the next dword, and `next` is its access; 0 if `next` is zero.
    pub crosses: u32,
    pub next: Access,
}

const _: () = assert!(size_of::<UnalignedStep>() == 32);

/// For each chip that proves some of the steps, the indices of those steps in execution order; the
/// chip's height follows from the length. The CPU and program chips read every step.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChipSteps {
    /// The ALU lists hold the steps that write an ALU event, so not those whose destination is x0.
    pub add: Rows<u32>,
    pub sub: Rows<u32>,
    pub mul: Rows<u32>,
    pub bitwise: Rows<u32>,
    pub shift_left: Rows<u32>,
    pub shift_right: Rows<u32>,
    pub lt: Rows<u32>,
    pub divrem: Rows<u32>,
    /// The loads and stores whose address is a multiple of their width; the others are in
    /// [`ExecutionHistory::unaligned`].
    pub memory: Rows<u32>,
    pub ecall: Rows<u32>,
    /// Branches, whose comparisons the Lt chip proves beside its own steps.
    pub branch: Rows<u32>,
}

impl ChipSteps {
    /// Every list, in field order.
    pub(crate) fn all(&self) -> [&[u32]; 11] {
        let Self {
            add,
            sub,
            mul,
            bitwise,
            shift_left,
            shift_right,
            lt,
            divrem,
            memory,
            ecall,
            branch,
        } = self;
        [
            add,
            sub,
            mul,
            bitwise,
            shift_left,
            shift_right,
            lt,
            divrem,
            memory,
            ecall,
            branch,
        ]
    }

    /// Every list, in field order, to write.
    fn all_mut(&mut self) -> [&mut Rows<u32>; 11] {
        let Self {
            add,
            sub,
            mul,
            bitwise,
            shift_left,
            shift_right,
            lt,
            divrem,
            memory,
            ecall,
            branch,
        } = self;
        [
            add,
            sub,
            mul,
            bitwise,
            shift_left,
            shift_right,
            lt,
            divrem,
            memory,
            ecall,
            branch,
        ]
    }

    /// Appends each of `later`'s lists to this one's, every entry moved past `steps` steps.
    fn append(&mut self, later: &mut Self, steps: usize) {
        for (list, later) in self.all_mut().into_iter().zip(later.all_mut()) {
            list.extend(later.iter().map(|&index| moved(index, steps, "step index")));
            later.clear();
        }
    }

    /// The list of the ALU chip `stream` names.
    #[must_use]
    pub fn alu(&self, stream: AluStream) -> &[u32] {
        match stream {
            AluStream::Add => &self.add,
            AluStream::Sub => &self.sub,
            AluStream::Mul => &self.mul,
            AluStream::Bitwise => &self.bitwise,
            AluStream::ShiftLeft => &self.shift_left,
            AluStream::ShiftRight => &self.shift_right,
            AluStream::Lt => &self.lt,
            AluStream::DivRem => &self.divrem,
        }
    }

    #[inline]
    pub(crate) fn alu_mut(&mut self, stream: AluStream) -> &mut Rows<u32> {
        match stream {
            AluStream::Add => &mut self.add,
            AluStream::Sub => &mut self.sub,
            AluStream::Mul => &mut self.mul,
            AluStream::Bitwise => &mut self.bitwise,
            AluStream::ShiftLeft => &mut self.shift_left,
            AluStream::ShiftRight => &mut self.shift_right,
            AluStream::Lt => &mut self.lt,
            AluStream::DivRem => &mut self.divrem,
        }
    }
}

/// The operand slots a traced step accesses, and which of those it writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slots {
    /// One bit per slot, at its [`MemoryAccessPosition`].
    present: u8,
    writes: u8,
}

impl Slots {
    /// The order a step's accesses are stored in: the operand slots `a`, `b`, `c`, then memory.
    pub const ORDER: [MemoryAccessPosition; 4] = [
        MemoryAccessPosition::A,
        MemoryAccessPosition::B,
        MemoryAccessPosition::C,
        MemoryAccessPosition::Memory,
    ];

    /// The slots `instruction` accesses when traced, as the emulator's operand fetches make them.
    /// `a` is read by stores and branches and written by everything else, x0 included; `b` and `c`
    /// are register reads.
    #[must_use]
    pub fn of(instruction: &Instruction) -> Self {
        let opcode = instruction.opcode;
        let (b, c) = if instruction.is_alu_instruction() {
            (
                !(instruction.imm_b && instruction.imm_c),
                !instruction.imm_c,
            )
        } else {
            match opcode {
                Opcode::ECALL => (true, true),
                Opcode::JAL | Opcode::AUIPC => (false, false),
                // Loads, stores, branches and JALR: `c` is an immediate.
                _ => (true, false),
            }
        };
        let is_store = matches!(opcode, Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD);
        let a_writes = !is_store && !instruction.is_branch_instruction();
        let bit = |position: MemoryAccessPosition, set: bool| u8::from(set) << position as u8;
        Self {
            present: bit(MemoryAccessPosition::A, true)
                | bit(MemoryAccessPosition::B, b)
                | bit(MemoryAccessPosition::C, c)
                | bit(
                    MemoryAccessPosition::Memory,
                    instruction.is_memory_instruction(),
                ),
            writes: bit(MemoryAccessPosition::A, a_writes)
                | bit(MemoryAccessPosition::Memory, is_store),
        }
    }

    #[must_use]
    pub const fn contains(self, position: MemoryAccessPosition) -> bool {
        self.present & (1 << position as u8) != 0
    }

    #[must_use]
    pub const fn writes(self, position: MemoryAccessPosition) -> bool {
        self.writes & (1 << position as u8) != 0
    }

    #[must_use]
    pub const fn len(self) -> usize {
        self.present.count_ones() as usize
    }

    /// One bit per slot present, at its [`MemoryAccessPosition`]: the mark a sink sets for each
    /// slot a cycle fills.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.present
    }

    /// The number of slots written: one, or none for a branch.
    #[must_use]
    pub const fn write_count(self) -> usize {
        self.writes.count_ones() as usize
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.present == 0
    }

    /// The slots present, in [`Self::ORDER`]: the `i`th is the step's `i`th access.
    pub fn iter(self) -> impl Iterator<Item = MemoryAccessPosition> {
        Self::ORDER
            .into_iter()
            .filter(move |&position| self.contains(position))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each slot `instruction` accesses, as `(slot, writes)`, in [`Slots::ORDER`].
    fn slots(instruction: Instruction) -> Vec<(MemoryAccessPosition, bool)> {
        let slots = Slots::of(&instruction);
        slots
            .iter()
            .map(|position| (position, slots.writes(position)))
            .collect()
    }

    #[test]
    fn slots_follow_the_operand_fetches() {
        use MemoryAccessPosition::{Memory, A, B, C};
        let cases = [
            (
                Opcode::ADD,
                false,
                false,
                vec![(A, true), (B, false), (C, false)],
            ),
            (Opcode::ADD, false, true, vec![(A, true), (B, false)]),
            (Opcode::ADD, true, true, vec![(A, true)]),
            (
                Opcode::LD,
                false,
                true,
                vec![(A, true), (B, false), (Memory, false)],
            ),
            (
                Opcode::SB,
                false,
                true,
                vec![(A, false), (B, false), (Memory, true)],
            ),
            (Opcode::BEQ, false, true, vec![(A, false), (B, false)]),
            (Opcode::JAL, true, true, vec![(A, true)]),
            (Opcode::JALR, false, true, vec![(A, true), (B, false)]),
            (
                Opcode::ECALL,
                false,
                false,
                vec![(A, true), (B, false), (C, false)],
            ),
        ];
        for (opcode, imm_b, imm_c, expected) in cases {
            let instruction = Instruction::new(opcode, 1, 2, 3, imm_b, imm_c);
            assert_eq!(slots(instruction), expected, "{opcode:?} {imm_b} {imm_c}");
        }
    }

    /// One step with two reads and a write, an entry in every chip list, an operand exception and
    /// a syscall.
    fn history() -> ExecutionHistory {
        let mut history = ExecutionHistory {
            chunk: 2,
            steps: Rows::from([Step {
                clk: 8,
                pc: 0x1000,
                next_pc: 0x1004,
                first_read: 0,
                first_write: 0,
            }]),
            reads: Rows::from([
                ReadAccess {
                    value: 1,
                    prev_chunk: 1,
                    prev_timestamp: 6,
                },
                ReadAccess {
                    value: 2,
                    prev_chunk: 1,
                    prev_timestamp: 5,
                },
            ]),
            writes: Rows::from([Access {
                value: 3,
                prev_value: 9,
                prev_chunk: 1,
                prev_timestamp: 7,
            }]),
            operand_exceptions: Rows::from([OperandException {
                step: 0,
                slot: MemoryAccessPosition::A as u32,
                value: 4,
            }]),
            syscalls: Rows::from([SyscallEvent {
                chunk: 2,
                clk: 8,
                syscall_id: 5,
                arg1: 1,
                arg2: 2,
            }]),
            ..ExecutionHistory::default()
        };
        for list in history.chip_steps.all_mut() {
            list.push(0);
        }
        history
    }

    /// Each word the digest reads, changed alone, moves it: every field of every row type, both
    /// words of a 64-bit field, every chip list's entry, and a row's place and table.
    #[test]
    fn the_digest_moves_with_every_stored_fact() {
        const LOW: u64 = 1;
        const HIGH: u64 = 1 << 32;
        let base = history().digest();
        type Change = fn(&mut ExecutionHistory);
        let changes: &[(&str, Change)] = &[
            ("the chunk", |h| h.chunk ^= 1),
            ("a step's clk", |h| h.steps[0].clk ^= 1),
            ("a step's pc", |h| h.steps[0].pc ^= 4),
            ("a step's next_pc", |h| h.steps[0].next_pc ^= 4),
            ("a step's first_read", |h| h.steps[0].first_read ^= 1),
            ("a step's first_write", |h| h.steps[0].first_write ^= 1),
            ("a read's value, low word", |h| h.reads[0].value ^= LOW),
            ("a read's value, high word", |h| h.reads[0].value ^= HIGH),
            ("a read's prev_chunk", |h| h.reads[0].prev_chunk ^= 1),
            ("a read's prev_timestamp", |h| {
                h.reads[0].prev_timestamp ^= 1
            }),
            ("a write's value, low word", |h| h.writes[0].value ^= LOW),
            ("a write's value, high word", |h| h.writes[0].value ^= HIGH),
            ("a write's prev_value, low word", |h| {
                h.writes[0].prev_value ^= LOW
            }),
            ("a write's prev_value, high word", |h| {
                h.writes[0].prev_value ^= HIGH
            }),
            ("a write's prev_chunk", |h| h.writes[0].prev_chunk ^= 1),
            ("a write's prev_timestamp", |h| {
                h.writes[0].prev_timestamp ^= 1
            }),
            ("an exception's step", |h| h.operand_exceptions[0].step ^= 1),
            ("an exception's slot", |h| h.operand_exceptions[0].slot ^= 1),
            ("an exception's value, low word", |h| {
                h.operand_exceptions[0].value ^= LOW
            }),
            ("an exception's value, high word", |h| {
                h.operand_exceptions[0].value ^= HIGH
            }),
            ("a syscall's chunk", |h| h.syscalls[0].chunk ^= 1),
            ("a syscall's clk, low word", |h| h.syscalls[0].clk ^= LOW),
            ("a syscall's clk, high word", |h| h.syscalls[0].clk ^= HIGH),
            ("a syscall's id", |h| h.syscalls[0].syscall_id ^= 1),
            ("a syscall's arg1, low word", |h| h.syscalls[0].arg1 ^= LOW),
            ("a syscall's arg1, high word", |h| {
                h.syscalls[0].arg1 ^= HIGH
            }),
            ("a syscall's arg2, low word", |h| h.syscalls[0].arg2 ^= LOW),
            ("a syscall's arg2, high word", |h| {
                h.syscalls[0].arg2 ^= HIGH
            }),
            ("the read order", |h| h.reads.swap(0, 1)),
            ("a read moved to the writes", |h| {
                let read = h.reads.pop().expect("a read");
                h.writes.push(read.into());
            }),
            ("an entry moved to the next list", |h| {
                let entry = h.chip_steps.add.pop().expect("an add entry");
                h.chip_steps.sub.push(entry);
            }),
        ];
        let mut unmoved: Vec<String> = changes
            .iter()
            .filter(|(_, change)| {
                let mut changed = history();
                change(&mut changed);
                changed.digest() == base
            })
            .map(|(what, _)| (*what).to_string())
            .collect();
        for list in 0..history().chip_steps.all().len() {
            let mut changed = history();
            changed.chip_steps.all_mut()[list][0] ^= 1;
            if changed.digest() == base {
                unmoved.push(format!("chip list {list}'s entry"));
            }
        }
        assert!(unmoved.is_empty(), "the digest misses {unmoved:?}");
        assert_eq!(ExecutionHistory::digest_all([&history()]), base);
        assert_ne!(ExecutionHistory::digest_all([&history(), &history()]), base);
    }

    /// Steps at clocks 8, 12, ... with up to two reads each and a write except at every fourth
    /// step, each list skipping every fourth step from an offset of its own, so every list has
    /// entries on both sides of any cut and no two lists are alike, an operand exception every
    /// fifth step, and a syscall every third.
    fn long_history(steps: u32) -> ExecutionHistory {
        let mut history = ExecutionHistory {
            chunk: 3,
            ..ExecutionHistory::default()
        };
        for index in 0..steps {
            history.steps.push(Step {
                clk: 8 + 4 * index,
                pc: 0x1000 + 4 * index,
                next_pc: 0x1004 + 4 * index,
                first_read: history.reads.len() as u32,
                first_write: history.writes.len() as u32,
            });
            for slot in 0..index % 3 {
                history.reads.push(ReadAccess {
                    value: u64::from(index * 4 + slot),
                    prev_chunk: 2,
                    prev_timestamp: 4 * index + slot,
                });
            }
            if !index.is_multiple_of(4) {
                history.writes.push(Access {
                    value: u64::from(index * 4 + 3),
                    prev_value: u64::from(index),
                    prev_chunk: 2,
                    prev_timestamp: 4 * index + 3,
                });
            }
            for (bit, list) in history.chip_steps.all_mut().into_iter().enumerate() {
                if !(index + bit as u32).is_multiple_of(4) {
                    list.push(index);
                }
            }
            if index.is_multiple_of(5) {
                history.operand_exceptions.push(OperandException {
                    step: index,
                    slot: MemoryAccessPosition::A as u32,
                    value: u64::from(index) + 100,
                });
            }
            if index.is_multiple_of(3) {
                history.syscalls.push(SyscallEvent {
                    chunk: 3,
                    clk: u64::from(8 + 4 * index),
                    syscall_id: index,
                    arg1: 1,
                    arg2: 2,
                });
            }
        }
        history
    }

    /// `history` cut before each step in `cuts`, each piece holding indices into its own tables,
    /// as a replay segment's history does.
    fn cut(history: &ExecutionHistory, cuts: &[u32]) -> Vec<ExecutionHistory> {
        let bounds: Vec<u32> = std::iter::once(0)
            .chain(cuts.iter().copied())
            .chain(std::iter::once(history.steps.len() as u32))
            .collect();
        bounds
            .windows(2)
            .map(|range| {
                let (from, to) = (range[0], range[1]);
                let steps = &history.steps[from as usize..to as usize];
                let row_at = |step: u32| {
                    history.steps.get(step as usize).map_or(
                        (history.reads.len() as u32, history.writes.len() as u32),
                        |step| (step.first_read, step.first_write),
                    )
                };
                let ((first_read, first_write), (read_end, write_end)) = (row_at(from), row_at(to));
                let (lo, hi) = (steps.first().map(|step| step.clk), steps.last());
                let mut piece = ExecutionHistory {
                    chunk: history.chunk,
                    steps: steps
                        .iter()
                        .map(|step| Step {
                            first_read: step.first_read - first_read,
                            first_write: step.first_write - first_write,
                            ..*step
                        })
                        .collect(),
                    reads: Rows::from(&history.reads[first_read as usize..read_end as usize]),
                    writes: Rows::from(&history.writes[first_write as usize..write_end as usize]),
                    operand_exceptions: history
                        .operand_exceptions
                        .iter()
                        .filter(|exception| (from..to).contains(&exception.step))
                        .map(|exception| OperandException {
                            step: exception.step - from,
                            ..*exception
                        })
                        .collect(),
                    syscalls: history
                        .syscalls
                        .iter()
                        .filter(|event| {
                            lo.is_some_and(|lo| event.clk >= u64::from(lo))
                                && hi.is_some_and(|hi| event.clk <= u64::from(hi.clk))
                        })
                        .copied()
                        .collect(),
                    ..ExecutionHistory::default()
                };
                for (list, whole) in piece
                    .chip_steps
                    .all_mut()
                    .into_iter()
                    .zip(history.chip_steps.all())
                {
                    list.extend(
                        whole
                            .iter()
                            .filter(|&&index| (from..to).contains(&index))
                            .map(|index| index - from),
                    );
                }
                piece
            })
            .collect()
    }

    #[test]
    fn histories_cut_and_appended_back_are_the_whole() {
        let whole = long_history(12);
        assert_eq!(whole.operand_exceptions.len(), 3);
        for cuts in [&[5][..], &[1, 6], &[4, 8, 11], &[0, 12]] {
            let mut pieces = cut(&whole, cuts).into_iter();
            let mut folded = pieces.next().expect("at least one piece");
            for mut piece in pieces {
                folded.append(&mut piece);
                assert!(
                    piece.steps.is_empty() && piece.reads.is_empty() && piece.writes.is_empty()
                );
                assert!(piece.operand_exceptions.is_empty());
            }
            assert_eq!(folded.steps, whole.steps, "steps, cut at {cuts:?}");
            assert_eq!(folded.reads, whole.reads, "reads, cut at {cuts:?}");
            assert_eq!(folded.writes, whole.writes, "writes, cut at {cuts:?}");
            assert_eq!(
                folded.chip_steps, whole.chip_steps,
                "lists, cut at {cuts:?}"
            );
            assert_eq!(
                folded.operand_exceptions, whole.operand_exceptions,
                "exceptions, cut at {cuts:?}"
            );
            assert_eq!(folded.syscalls.len(), whole.syscalls.len());
            assert_eq!(folded.digest(), whole.digest(), "cut at {cuts:?}");
        }
    }

    /// An empty first piece has no chunk of its own: it takes the next one's.
    #[test]
    fn a_history_appended_to_an_empty_one_brings_its_chunk() {
        let mut folded = ExecutionHistory::default();
        folded.append(&mut history());
        assert_eq!(folded.digest(), history().digest());
    }

    #[test]
    #[should_panic(expected = "a history of chunk 3 appended to one of chunk 2")]
    fn histories_of_two_chunks_do_not_append() {
        history().append(&mut long_history(2));
    }

    #[test]
    fn bytes_count_every_table_in_place() {
        let history = history();
        assert_eq!(
            history.table_bytes().map(|(table, _)| table),
            [
                "steps",
                "reads",
                "writes",
                "chip_steps",
                "operand_exceptions",
                "syscalls",
                "unaligned"
            ]
        );
        assert_eq!(
            history.bytes(),
            20 + 2 * 16 + 24 + 11 * 4 + 16 + size_of::<SyscallEvent>()
        );
    }

    #[test]
    fn a_memory_access_is_at_the_dword_holding_b_plus_c() {
        let load = Instruction::new(Opcode::LD, 4, 1, 0x10, false, true);
        let address = |position| Step::address(&load, position, 0x2003, 0x10);
        assert_eq!(address(MemoryAccessPosition::Memory), 0x2010);
        assert_eq!(address(MemoryAccessPosition::A), 4);
        assert_eq!(address(MemoryAccessPosition::B), 1);
    }

    /// A history of one step of `instruction` at pc 0x1000, whose accesses hold `values`, one per
    /// slot present, in [`Slots::ORDER`]; a write found its value plus one.
    fn one_step(instruction: &Instruction, values: &[u64]) -> ExecutionHistory {
        let slots = Slots::of(instruction);
        assert_eq!(slots.len(), values.len());
        let mut history = ExecutionHistory {
            steps: Rows::from([Step {
                pc: 0x1000,
                next_pc: 0x1004,
                ..Step::default()
            }]),
            ..ExecutionHistory::default()
        };
        for (position, &value) in slots.iter().zip(values) {
            let read = ReadAccess {
                value,
                ..ReadAccess::default()
            };
            if slots.writes(position) {
                history.writes.push(Access {
                    prev_value: value.wrapping_add(1),
                    ..read.into()
                });
            } else {
                history.reads.push(read);
            }
        }
        history
    }

    /// A load writes `a` and reads memory, a store reads `a` and writes memory, and a branch
    /// writes nothing; each access comes back from its table in slot order.
    #[test]
    fn each_access_comes_back_from_the_table_of_its_kind() {
        use MemoryAccessPosition::{Memory, A, B};
        let access = |value: u64, writes: bool| Access {
            value,
            prev_value: if writes { value + 1 } else { value },
            ..Access::default()
        };
        type Case = (
            Instruction,
            &'static [u64],
            usize,
            Vec<(MemoryAccessPosition, Access)>,
        );
        let cases: [Case; 3] = [
            (
                Instruction::new(Opcode::LD, 4, 1, 0x10, false, true),
                &[0x55, 0x2000, 0x55],
                1,
                vec![
                    (A, access(0x55, true)),
                    (B, access(0x2000, false)),
                    (Memory, access(0x55, false)),
                ],
            ),
            (
                Instruction::new(Opcode::SD, 2, 1, 8, false, true),
                &[9, 0x2000, 9],
                1,
                vec![
                    (A, access(9, false)),
                    (B, access(0x2000, false)),
                    (Memory, access(9, true)),
                ],
            ),
            (
                Instruction::new(Opcode::BEQ, 1, 2, 8, false, true),
                &[1, 1],
                0,
                vec![(A, access(1, false)), (B, access(1, false))],
            ),
        ];
        for (instruction, values, writes, expected) in cases {
            let history = one_step(&instruction, values);
            assert_eq!(history.writes.len(), writes, "{instruction:?}");
            assert_eq!(
                history.accesses_of(0, &instruction).collect::<Vec<_>>(),
                expected,
                "{instruction:?}"
            );
        }
    }

    #[test]
    fn operands_are_the_access_values_or_the_immediates() {
        let add = |rd, b, c, imm_b, imm_c| Instruction::new(Opcode::ADD, rd, b, c, imm_b, imm_c);
        type Case = (Instruction, &'static [u64], (u64, u64, u64));
        let cases: [Case; 11] = [
            (add(1, 2, 3, false, false), &[7, 3, 4], (7, 3, 4)),
            (add(1, 2, 9, false, true), &[12, 3], (12, 3, 9)),
            (add(1, 5, 6, true, true), &[11], (11, 5, 6)),
            (
                Instruction::new(Opcode::LD, 4, 1, 0x10, false, true),
                &[0x55, 0x2000, 0x55],
                (0x55, 0x2000, 0x10),
            ),
            (
                Instruction::new(Opcode::SD, 2, 1, 8, false, true),
                &[9, 0x2000, 9],
                (9, 0x2000, 8),
            ),
            (
                Instruction::new(Opcode::BEQ, 1, 2, 8, false, true),
                &[1, 1],
                (1, 1, 8),
            ),
            (
                Instruction::new(Opcode::JAL, 1, 0x20, 0, true, true),
                &[0x1004],
                (0x1004, 0x20, 0),
            ),
            // A jump's `a` is its pc + 4 even where x0 commits 0.
            (
                Instruction::new(Opcode::JAL, 0, 0x20, 0, true, true),
                &[0],
                (0x1004, 0x20, 0),
            ),
            (
                Instruction::new(Opcode::JALR, 0, 1, 0, false, true),
                &[0, 0x3000],
                (0x1004, 0x3000, 0),
            ),
            (
                Instruction::new(Opcode::AUIPC, 1, 0x5000, 0, true, true),
                &[0x6000],
                (0x6000, 0x5000, 0x5000),
            ),
            (
                Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
                &[4, 1, 2],
                (4, 1, 2),
            ),
        ];
        for (instruction, values, expected) in cases {
            assert_eq!(
                one_step(&instruction, values).operands(0, &instruction),
                expected,
                "{instruction:?}"
            );
        }
    }

    /// Three `ADD x0, x1, x2` steps; the first and the last are excepted, the last in `b` and `c`
    /// too.
    #[test]
    fn an_exception_overrides_the_rule_for_its_operand_of_its_step_alone() {
        use MemoryAccessPosition::{A, B, C};
        let add_x0 = Instruction::new(Opcode::ADD, 0, 1, 2, false, false);
        let mut history = ExecutionHistory::default();
        for index in 0..3u32 {
            let mut step = one_step(&add_x0, &[0, 3, 4]);
            step.steps[0].pc += 4 * index;
            history.append(&mut step);
        }
        let exception = |step, slot: MemoryAccessPosition, value| OperandException {
            step,
            slot: slot as u32,
            value,
        };
        history.operand_exceptions = Rows::from([
            exception(0, A, 7),
            exception(2, A, 8),
            exception(2, B, 30),
            exception(2, C, 40),
        ]);
        assert_eq!(history.operands(0, &add_x0), (7, 3, 4));
        assert_eq!(history.operands(1, &add_x0), (0, 3, 4));
        assert_eq!(history.operands(2, &add_x0), (8, 30, 40));
    }
}
