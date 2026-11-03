//! Accessors for a chunk's execution history and the additions appended during augmentation.

use std::{borrow::Cow, sync::OnceLock};

use hashbrown::HashMap;
use itertools::Itertools;

use crate::{
    chips::chips::{
        alu::event::AluEvent,
        riscv_cpu::{branch::traces::branch_compare, event::CpuEvent},
        riscv_memory::event::{
            MemoryAccessPosition, MemoryReadRecord, MemoryRecordEnum, MemoryWriteRecord,
        },
    },
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
    emulator::riscv::{
        event_types::{RvChunk, RvTimestamp},
        history::{Access, ExecutionHistory, Slots},
        record::{AluStream, EmulationRecord, MemoryAccessRecord},
        syscalls::SyscallEvent,
    },
    iter::{IntoPicoIterator, IntoPicoRefIterator, PicoIterator, PicoSlice},
};

/// A record's execution history and the program its steps' pcs index.
#[derive(Clone, Copy, Debug)]
pub struct HistoryView<'a> {
    pub history: &'a ExecutionHistory,
    pub program: &'a Program,
}

/// The history every reader of `record` takes its steps from: a CPU chunk's own, and an empty one
/// for a deferred record.
///
/// # Panics
///
/// On a CPU chunk without a history, or a deferred record with one.
pub(crate) fn history_of(record: &EmulationRecord) -> &ExecutionHistory {
    if record.is_cpu_chunk {
        record
            .history
            .as_ref()
            .expect("a CPU chunk must have an execution history")
    } else {
        assert!(
            record.history.is_none(),
            "a deferred record must not have an execution history"
        );
        static EMPTY: OnceLock<ExecutionHistory> = OnceLock::new();
        EMPTY.get_or_init(ExecutionHistory::default)
    }
}

/// The syscalls sent to the syscall chip, in execution order.
#[must_use]
pub fn syscalls(record: &EmulationRecord) -> &[SyscallEvent] {
    &history_of(record).syscalls
}

/// How many consecutive steps [`CpuSteps::par_runs`] folds as one run of `len`: about one run per
/// core. Branch comparisons keep these boundaries to preserve the less-than trace's row order.
#[must_use]
pub fn run_length(len: usize) -> usize {
    std::cmp::max(len / num_cpus::get(), 1)
}

/// One run's branch comparisons in the order the less-than chip proves them: the SLT ones, then
/// the SLTU ones, each in execution order. Keeping the run boundaries preserves the less-than
/// trace's row order.
pub(crate) fn in_compare_order<T: Copy>(run: &[T], is_signed: impl Fn(&T) -> bool) -> Vec<T> {
    let (mut ordered, unsigned): (Vec<T>, Vec<T>) =
        run.iter().copied().partition(|compare| is_signed(compare));
    ordered.extend(unsigned);
    ordered
}

/// Keep the branch comparison row order stable across trace generation.
fn ordered_compares(history: &ExecutionHistory, program: &Program, branches: &[u32]) -> Vec<u32> {
    #[cfg(test)]
    tests::ORDERINGS.with(|count| count.set(count.get() + 1));
    let run = run_length(history.steps.len());
    branches
        .chunk_by(|left, right| *left as usize / run == *right as usize / run)
        .flat_map(|group| {
            in_compare_order(group, |&step| {
                compare_opcode(history, program, step) == Opcode::SLT
            })
        })
        .collect()
}

/// The operations one ALU chip proves, in the order its trace lays them out, with random access
/// by row.
#[derive(Clone)]
pub struct AluOps<'a> {
    history: &'a ExecutionHistory,
    program: &'a Program,
    steps: &'a [u32],
    branches: &'a [u32],
    compares: OnceLock<Vec<u32>>,
    appended: &'a [AluEvent],
}

impl<'a> AluOps<'a> {
    /// The operations the ALU chip proves, including branch comparisons.
    #[must_use]
    pub fn of(record: &'a EmulationRecord, stream: AluStream) -> Self {
        let branches = if matches!(stream, AluStream::Lt) {
            history_of(record).chip_steps.branch.as_slice()
        } else {
            &[]
        };
        Self::with_branches(record, stream, branches)
    }

    /// The operations recorded during execution, before branch comparisons are derived.
    #[must_use]
    pub fn recorded(record: &'a EmulationRecord, stream: AluStream) -> Self {
        Self::with_branches(record, stream, &[])
    }

    fn with_branches(record: &'a EmulationRecord, stream: AluStream, branches: &'a [u32]) -> Self {
        let history = history_of(record);
        Self {
            history,
            program: &record.program,
            steps: history.chip_steps.alu(stream),
            branches,
            compares: OnceLock::new(),
            appended: if matches!(stream, AluStream::Add) {
                &record.add_events
            } else {
                &[]
            },
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.steps.len() + self.branches.len() + self.appended.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The operation at position `index`, in row order.
    #[must_use]
    pub fn get(&self, index: usize) -> AluEvent {
        if let Some(&step) = self.steps.get(index) {
            return step_event(self.history, self.program, step);
        }
        let index = index - self.steps.len();
        if index < self.branches.len() {
            let step = ordered(self.history, self.program, self.branches, &self.compares)[index];
            return compare_event(self.history, self.program, step);
        }
        self.appended[index - self.branches.len()]
    }

    /// Every operation's opcode, in order.
    pub fn opcodes(&self) -> impl Iterator<Item = Opcode> + '_ {
        let compares = ordered(self.history, self.program, self.branches, &self.compares);
        self.steps
            .iter()
            .map(|&step| instruction_of(self.history, self.program, step).opcode)
            .chain(
                compares
                    .iter()
                    .map(|&step| compare_opcode(self.history, self.program, step)),
            )
            .chain(self.appended.iter().map(|event| event.opcode))
    }

    #[must_use]
    pub fn positions(&self, opcode: Opcode) -> Vec<usize> {
        self.opcodes().positions(|op| op == opcode).collect()
    }

    #[must_use]
    pub fn count(&self, opcode: Opcode) -> usize {
        let [count] = self.counts([opcode]);
        count
    }

    /// How many operations have each of `opcodes`, from one pass over them: what two chips that
    /// split one list by opcode are sized by.
    #[must_use]
    pub fn counts<const N: usize>(&self, opcodes: [Opcode; N]) -> [usize; N] {
        let mut counts = [0; N];
        for op in self.opcodes() {
            if let Some(slot) = opcodes.iter().position(|&opcode| opcode == op) {
                counts[slot] += 1;
            }
        }
        counts
    }

    #[must_use]
    pub fn contains(&self, opcode: Opcode) -> bool {
        self.opcodes().any(|op| op == opcode)
    }

    /// `f` over every operation, in parallel runs of about one per core.
    pub fn par_flat_map<T: Send>(
        &self,
        f: impl Fn(&AluEvent, &mut Vec<T>) + Send + Sync,
    ) -> Vec<T> {
        let run = std::cmp::max(self.len() / num_cpus::get(), 1);
        let compares = ordered(self.history, self.program, self.branches, &self.compares);
        let mut written = flat_map_runs(self.steps, run, &|&step, out: &mut Vec<T>| {
            f(&step_event(self.history, self.program, step), out);
        });
        written.extend(flat_map_runs(compares, run, &|&step, out: &mut Vec<T>| {
            f(&compare_event(self.history, self.program, step), out);
        }));
        written.extend(flat_map_runs(self.appended, run, &f));
        written
    }
}

fn ordered<'s>(
    history: &ExecutionHistory,
    program: &Program,
    branches: &[u32],
    compares: &'s OnceLock<Vec<u32>>,
) -> &'s [u32] {
    compares.get_or_init(|| ordered_compares(history, program, branches))
}

/// A chunk's CPU steps, or the ones one chip proves, in execution order, with random access by
/// row.
pub struct CpuSteps<'a> {
    history: &'a ExecutionHistory,
    program: &'a Program,
    only: Option<&'a [u32]>,
}

impl<'a> CpuSteps<'a> {
    /// Every CPU step, in execution order.
    ///
    /// # Panics
    ///
    /// If a CPU chunk has no execution history.
    #[must_use]
    pub fn of(record: &'a EmulationRecord) -> Self {
        Self {
            history: history_of(record),
            program: &record.program,
            only: None,
        }
    }

    /// The loads and stores.
    #[must_use]
    pub fn memory(self) -> Self {
        Self {
            only: Some(&self.history.chip_steps.memory),
            ..self
        }
    }

    #[must_use]
    pub fn ecalls(self) -> Self {
        Self {
            only: Some(&self.history.chip_steps.ecall),
            ..self
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.only.map_or(self.history.steps.len(), <[u32]>::len)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The step at position `index`, in execution order.
    #[must_use]
    pub fn get(&self, index: usize) -> Cow<'a, CpuEvent> {
        Cow::Owned(step_cpu_event(
            self.history,
            self.program,
            self.step_index(index),
        ))
    }

    /// The memory records of the step at position `index`, as [`Self::get`]'s event holds them,
    /// without the operands the event rebuilds: for a reader of the accesses alone.
    #[must_use]
    pub fn records(&self, index: usize) -> MemoryAccessRecord {
        let index = self.step_index(index);
        let instruction = self.program.fetch(u64::from(self.history.steps[index].pc));
        step_records(self.history, index, &instruction).0
    }

    /// The history's index of the step at position `index`.
    fn step_index(&self, index: usize) -> usize {
        self.only.map_or(index, |only| only[index] as usize)
    }

    /// The steps in execution order.
    pub fn iter(&self) -> impl Iterator<Item = Cow<'a, CpuEvent>> + '_ {
        (0..self.len()).map(|index| self.get(index))
    }

    /// Whether the chunk runs a load or a store.
    #[must_use]
    pub fn any_memory(&self) -> bool {
        !self.history.chip_steps.memory.is_empty()
    }

    /// How many times each pc ran, over every step.
    #[must_use]
    pub fn pc_counts(&self) -> HashMap<u64, usize> {
        pc_counts(&self.history.steps, |step| u64::from(step.pc))
    }

    /// `f` folded over runs of consecutive steps in parallel, about one run per core: one `T` per
    /// run, in order.
    pub fn par_runs<T: Default + Send>(
        &self,
        f: impl Fn(&CpuEvent, &mut T) + Send + Sync,
    ) -> Vec<T> {
        self.fold_runs(|index, folded| f(&self.get(index), folded))
    }

    /// [`Self::par_runs`] over each step's memory records ([`Self::records`]) in place of its
    /// event, for a reader of the accesses alone.
    pub fn par_record_runs<T: Default + Send>(
        &self,
        f: impl Fn(&MemoryAccessRecord, &mut T) + Send + Sync,
    ) -> Vec<T> {
        self.fold_runs(|index, folded| f(&self.records(index), folded))
    }

    fn fold_runs<T: Default + Send>(&self, f: impl Fn(usize, &mut T) + Send + Sync) -> Vec<T> {
        let len = self.len();
        let run = run_length(len);
        (0..len.div_ceil(run))
            .into_pico_iter()
            .map(|nth| {
                let mut folded = T::default();
                for index in nth * run..std::cmp::min((nth + 1) * run, len) {
                    f(index, &mut folded);
                }
                folded
            })
            .collect()
    }
}

fn pc_counts<T: Sync>(steps: &[T], pc: impl Fn(&T) -> u64 + Send + Sync) -> HashMap<u64, usize> {
    steps
        .pico_iter()
        .pico_fold(HashMap::new, |mut counts, step| {
            *counts.entry(pc(step)).or_insert(0) += 1;
            counts
        })
        .pico_reduce(HashMap::new, |mut counts, other| {
            for (pc, count) in other {
                *counts.entry(pc).or_insert(0) += count;
            }
            counts
        })
}

/// The CPU event the emulator writes for the step at `index`. Its `memory` is the memory access's
/// value, of which only the presence is read, and its `exit_code`, which no chip reads, is 0.
fn step_cpu_event(history: &ExecutionHistory, program: &Program, index: usize) -> CpuEvent {
    let step = &history.steps[index];
    let instruction = program.fetch(u64::from(step.pc));
    let (records, values) = step_records(history, index, &instruction);
    let (a, b, c) = history.operands_from(index, &instruction, &values);
    CpuEvent::new(
        history.chunk,
        u64::from(step.clk),
        u64::from(step.pc),
        u64::from(step.next_pc),
        instruction,
        a,
        b,
        c,
        records.memory.map(|record| record.value()),
        records,
        0,
    )
}

/// The memory records of the step at `index`, `instruction` being the program's at its pc, and
/// each access's value at its [`MemoryAccessPosition`], from one walk of its rows.
fn step_records(
    history: &ExecutionHistory,
    index: usize,
    instruction: &Instruction,
) -> (MemoryAccessRecord, [Option<u64>; 4]) {
    let step = &history.steps[index];
    let slots = Slots::of(instruction);
    let mut records = MemoryAccessRecord::default();
    let mut values = [None; 4];
    for (position, access) in history.accesses_in(index, slots) {
        values[position as usize] = Some(access.value);
        let record = memory_record(
            history.chunk,
            step.timestamp(position),
            slots.writes(position),
            access,
        );
        *match position {
            MemoryAccessPosition::A => &mut records.a,
            MemoryAccessPosition::B => &mut records.b,
            MemoryAccessPosition::C => &mut records.c,
            MemoryAccessPosition::Memory => &mut records.memory,
        } = Some(record);
    }
    (records, values)
}

fn memory_record(
    chunk: RvChunk,
    timestamp: RvTimestamp,
    writes: bool,
    access: Access,
) -> MemoryRecordEnum {
    if writes {
        MemoryRecordEnum::Write(MemoryWriteRecord {
            value: access.value,
            chunk,
            timestamp,
            prev_value: access.prev_value,
            prev_chunk: access.prev_chunk,
            prev_timestamp: access.prev_timestamp,
        })
    } else {
        MemoryRecordEnum::Read(MemoryReadRecord {
            value: access.value,
            chunk,
            timestamp,
            prev_chunk: access.prev_chunk,
            prev_timestamp: access.prev_timestamp,
        })
    }
}

fn flat_map_runs<E: Sync, T: Send>(
    items: &[E],
    run: usize,
    f: &(impl Fn(&E, &mut Vec<T>) + Send + Sync),
) -> Vec<T> {
    items
        .pico_chunks(run)
        .flat_map(|items| {
            let mut written = Vec::new();
            for item in items {
                f(item, &mut written);
            }
            written
        })
        .collect()
}

#[inline]
fn instruction_of(history: &ExecutionHistory, program: &Program, step: u32) -> Instruction {
    program.fetch(u64::from(history.steps[step as usize].pc))
}

/// The less-than row proving the comparison of the branch step at `step`, as the CPU chip would
/// append it.
#[inline]
fn compare_event(history: &ExecutionHistory, program: &Program, step: u32) -> AluEvent {
    let row = &history.steps[step as usize];
    let instruction = program.fetch(u64::from(row.pc));
    let (a, b, _) = history.operands(step as usize, &instruction);
    branch_compare(instruction.opcode, u64::from(row.clk), a, b)
}

/// The opcode of [`compare_event`]'s row, which follows from the branch's opcode alone, so no
/// operand is rebuilt for it.
#[inline]
fn compare_opcode(history: &ExecutionHistory, program: &Program, step: u32) -> Opcode {
    branch_compare(instruction_of(history, program, step).opcode, 0, 0, 0).opcode
}

/// The ALU event the emulator writes for the step at `step`: the step's clock and operands, the
/// instruction's opcode, and its `imm_c` as `is_imm`.
#[inline]
fn step_event(history: &ExecutionHistory, program: &Program, step: u32) -> AluEvent {
    let row = &history.steps[step as usize];
    let instruction = program.fetch(u64::from(row.pc));
    let (a, b, c) = history.operands(step as usize, &instruction);
    AluEvent::new(
        u64::from(row.clk),
        instruction.opcode,
        a,
        b,
        c,
        instruction.imm_c,
    )
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, sync::Arc};

    use super::*;
    use crate::{
        chips::{ffi::FfiOption, tests::fib_records},
        emulator::riscv::history::{ChipSteps, OperandException, ReadAccess, Step},
    };

    thread_local! {
        pub(super) static ORDERINGS: Cell<usize> = const { Cell::new(0) };
    }

    fn orderings() -> usize {
        ORDERINGS.with(Cell::get)
    }

    /// Three branches, the middle one signed, and their history.
    fn branching_record() -> EmulationRecord {
        let program = Program::new(
            vec![
                Instruction::new(Opcode::BEQ, 1, 2, 8, false, true),
                Instruction::new(Opcode::BLT, 1, 2, 8, false, true),
                Instruction::new(Opcode::BNE, 1, 2, 8, false, true),
            ],
            0x1000,
            0x1000,
        );
        let steps = (0..3)
            .map(|index| Step {
                clk: 8 + 4 * index,
                pc: 0x1000 + 4 * index,
                next_pc: 0x1004 + 4 * index,
                first_read: 2 * index,
                first_write: 0,
            })
            .collect();
        let reads = (0..3u64)
            .flat_map(|index| [index, 1])
            .map(|value| ReadAccess {
                value,
                ..ReadAccess::default()
            })
            .collect();
        let mut record = EmulationRecord::new(Arc::new(program));
        record.history = Some(ExecutionHistory {
            steps,
            reads,
            chip_steps: ChipSteps {
                branch: vec![0, 1, 2].into(),
                ..ChipSteps::default()
            },
            ..ExecutionHistory::default()
        });
        record
    }

    #[test]
    fn the_less_than_activity_check_orders_no_branch_comparison() {
        let record = branching_record();
        let branches = record
            .history
            .as_ref()
            .unwrap()
            .chip_steps
            .branch
            .as_slice();
        let before = orderings();
        for _ in 0..2 {
            let ops = AluOps::with_branches(&record, AluStream::Lt, branches);
            assert!(!ops.is_empty());
            assert_eq!(ops.len(), 3);
        }
        assert_eq!(
            orderings(),
            before,
            "a length query ordered the comparisons"
        );

        let ops = AluOps::with_branches(&record, AluStream::Lt, branches);
        let signed = (0..3)
            .filter(|&index| ops.get(index).opcode == Opcode::SLT)
            .count();
        assert_eq!(signed, 1);
        assert_eq!(orderings(), before + 1, "reading the rows orders them once");
    }

    #[test]
    fn a_recorded_count_leaves_out_the_comparisons_built_from_branch_indices() {
        let record = branching_record();
        let ops = AluOps::of(&record, AluStream::Lt);
        assert_eq!(ops.len(), 3);
        assert_eq!(ops.count(Opcode::SLT), 1);
        assert_eq!(ops.count(Opcode::SLTU), 2);
        assert_eq!(
            ops.counts([Opcode::SLTU, Opcode::SLT, Opcode::ADD]),
            [2, 1, 0]
        );
        assert!(AluOps::recorded(&record, AluStream::Lt).is_empty());
    }

    /// Over every chunk of a run, one pass's counts are each opcode's own: the operations of that
    /// opcode and the rows its chip lays out.
    #[test]
    fn one_pass_counts_each_opcode_of_a_split_list() {
        let mut counted = 0;
        for record in fib_records().iter().filter(|record| record.is_cpu_chunk) {
            for (stream, opcodes) in [
                (AluStream::Add, [Opcode::ADD, Opcode::ADDW]),
                (AluStream::Sub, [Opcode::SUB, Opcode::SUBW]),
            ] {
                let ops = record.alu_ops(stream);
                let counts = ops.counts(opcodes);
                let each = opcodes.map(|opcode| ops.opcodes().filter(|&op| op == opcode).count());
                assert_eq!(counts, each, "{stream:?}");
                assert_eq!(
                    counts,
                    opcodes.map(|opcode| ops.positions(opcode).len()),
                    "{stream:?}"
                );
                assert_eq!(counts.iter().sum::<usize>(), ops.len(), "{stream:?}");
                counted += ops.len();
            }
        }
        assert!(counted > 0, "no addition or subtraction in any chunk");
    }

    /// Over every chunk of a run, a step's records are its event's, in each view of the steps.
    #[test]
    fn a_steps_records_are_its_events() {
        let (mut memory, mut ecalls) = (0, 0);
        for record in fib_records().iter().filter(|record| record.is_cpu_chunk) {
            let views = [
                record.cpu_steps(),
                record.cpu_steps().memory(),
                record.cpu_steps().ecalls(),
            ];
            for (view, steps) in ["every step", "memory", "ecalls"].into_iter().zip(views) {
                for index in 0..steps.len() {
                    let (event, records) = (steps.get(index), steps.records(index));
                    assert_eq!(
                        [records.a, records.b, records.c, records.memory]
                            .map(FfiOption::<MemoryRecordEnum>::from),
                        [
                            event.a_record,
                            event.b_record,
                            event.c_record,
                            event.memory_record
                        ],
                        "{view} {index}"
                    );
                }
            }
            memory += record.cpu_steps().memory().len();
            ecalls += record.cpu_steps().ecalls().len();
        }
        assert!(
            memory > 0 && ecalls > 0,
            "{memory} loads and stores, {ecalls} ECALLs"
        );
    }

    #[test]
    #[should_panic(expected = "a CPU chunk must have an execution history")]
    fn a_cpu_chunk_without_history_refuses_step_access() {
        let record = EmulationRecord::new(Arc::new(Program::default()));
        let _ = record.cpu_steps();
    }

    #[test]
    #[should_panic(expected = "a CPU chunk must have an execution history")]
    fn a_cpu_chunk_without_history_refuses_alu_access() {
        let record = EmulationRecord::new(Arc::new(Program::default()));
        let _ = record.alu_ops(AluStream::Add);
    }

    #[test]
    #[should_panic(expected = "a CPU chunk must have an execution history")]
    fn a_cpu_chunk_without_history_refuses_syscall_access() {
        let record = EmulationRecord::new(Arc::new(Program::default()));
        let _ = record.syscalls();
    }

    #[test]
    #[should_panic(expected = "a deferred record must not have an execution history")]
    fn a_deferred_record_with_history_refuses_step_access() {
        let record = EmulationRecord {
            history: Some(ExecutionHistory::default()),
            ..EmulationRecord::default()
        };
        let _ = record.cpu_steps();
    }

    #[test]
    fn deferred_records_have_no_execution_steps() {
        let record = EmulationRecord::default();
        assert!(record.cpu_steps().is_empty());
        assert!(record.cpu_steps().memory().is_empty());
        assert!(record.cpu_steps().ecalls().is_empty());
        assert!(record.alu_ops(AluStream::Lt).is_empty());
        assert!(record.syscalls().is_empty());
    }

    #[test]
    fn additions_appended_during_augmentation_follow_the_history() {
        let program = Program::new(
            vec![Instruction::new(Opcode::ADD, 1, 2, 3, false, false)],
            0x1000,
            0x1000,
        );
        let mut record = EmulationRecord::new(Arc::new(program));
        record.history = Some(ExecutionHistory {
            steps: vec![Step {
                pc: 0x1000,
                ..Step::default()
            }]
            .into(),
            reads: [3, 4]
                .map(|value| ReadAccess {
                    value,
                    ..ReadAccess::default()
                })
                .into(),
            writes: vec![Access {
                value: 7,
                ..Access::default()
            }]
            .into(),
            chip_steps: ChipSteps {
                add: vec![0].into(),
                ..ChipSteps::default()
            },
            ..ExecutionHistory::default()
        });
        record
            .add_events
            .push(AluEvent::new(8, Opcode::ADD, 0, 9, 10, false));
        let ops = record.alu_ops(AluStream::Add);
        assert_eq!(ops.len(), 2);
        assert_eq!(ops.get(0).a, 7);
        assert_eq!(ops.get(1).b, 9);
        assert_eq!(ops.get(1).c, 10);
        assert_eq!(
            ops.opcodes().collect::<Vec<_>>(),
            [Opcode::ADD, Opcode::ADD]
        );
        assert_eq!(ops.counts([Opcode::ADD, Opcode::ADDW]), [2, 0]);
    }

    /// The CPU event of a step, built in one walk of its rows, is the event built from the
    /// accessor and the operand rebuild apart: for a write to x0 with its excepted `a`, a load, a
    /// store and a branch.
    #[test]
    fn a_cpu_event_is_its_steps_accesses_and_rebuilt_operands() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 0, 1, 2, false, false),
            Instruction::new(Opcode::LD, 4, 1, 0x10, false, true),
            Instruction::new(Opcode::SD, 2, 1, 8, false, true),
            Instruction::new(Opcode::BEQ, 1, 2, 8, false, true),
        ];
        let program = Program::new(instructions.clone(), 0x1000, 0x1000);
        // Each step's reads in slot order, and its write as (value, prev_value).
        type Rows = (&'static [u64], Option<(u64, u64)>);
        let rows: [Rows; 4] = [
            (&[1, 2], Some((0, 5))),
            (&[0x2000, 0x55], Some((0x55, 7))),
            (&[9, 0x2000], Some((9, 4))),
            (&[1, 1], None),
        ];
        let mut history = ExecutionHistory {
            chunk: 2,
            operand_exceptions: vec![OperandException {
                step: 0,
                slot: MemoryAccessPosition::A as u32,
                value: 3,
            }]
            .into(),
            ..ExecutionHistory::default()
        };
        for (index, (reads, write)) in (0u32..).zip(rows) {
            history.steps.push(Step {
                clk: 8 + 4 * index,
                pc: 0x1000 + 4 * index,
                next_pc: 0x1004 + 4 * index,
                first_read: history.reads.len() as u32,
                first_write: history.writes.len() as u32,
            });
            history.reads.extend(reads.iter().map(|&value| ReadAccess {
                value,
                prev_chunk: 1,
                prev_timestamp: 3,
            }));
            history
                .writes
                .extend(write.map(|(value, prev_value)| Access {
                    value,
                    prev_value,
                    prev_chunk: 1,
                    prev_timestamp: 3,
                }));
        }
        assert_eq!(history.operands(0, &instructions[0]), (3, 1, 2));

        for (index, instruction) in instructions.iter().enumerate() {
            let step = &history.steps[index];
            let slots = Slots::of(instruction);
            let mut records = MemoryAccessRecord::default();
            for (position, access) in history.accesses_of(index, instruction) {
                let record = Some(memory_record(
                    history.chunk,
                    step.timestamp(position),
                    slots.writes(position),
                    access,
                ));
                match position {
                    MemoryAccessPosition::A => records.a = record,
                    MemoryAccessPosition::B => records.b = record,
                    MemoryAccessPosition::C => records.c = record,
                    MemoryAccessPosition::Memory => records.memory = record,
                }
            }
            let (a, b, c) = history.operands(index, instruction);
            let expected = CpuEvent::new(
                history.chunk,
                u64::from(step.clk),
                u64::from(step.pc),
                u64::from(step.next_pc),
                *instruction,
                a,
                b,
                c,
                records.memory.map(|record| record.value()),
                records,
                0,
            );
            assert_eq!(
                step_cpu_event(&history, &program, index),
                expected,
                "{instruction:?}"
            );
        }
    }
}
