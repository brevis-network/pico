//! The execution history against the program it ran: every CPU chunk's record carries a history
//! and no augmentation row.
//!
//! Per chunk: each step has as many accesses as its instruction has slots, and each read leaves
//! its value as it found it; each access comes after the state it found, at the timestamp derived
//! from its step; each chip's list names exactly the steps of that chip's instructions, in order;
//! a load or store is in the memory list when its address is a multiple of its width and in the
//! unaligned table otherwise, with the next dword's access exactly when it runs into that dword;
//! and each syscall is an ECALL step's.

use std::{collections::HashSet, sync::Arc};

use pico_vm::{
    chips::chips::riscv_memory::event::MemoryAccessPosition,
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
    emulator::riscv::{
        emulator::guard::access_width,
        history::{Access, ExecutionHistory, Slots, UnalignedStep},
        record::{AluStream, EmulationRecord},
        syscalls::SyscallCode,
    },
};

use crate::{record_parity::WHOLE, trace_source::history_emulation};

/// A chunk's problems past this many are counted, not listed: one broken field repeats on every
/// step.
const LISTED_PER_CHUNK: usize = 8;

const ALU_STREAMS: [(&str, AluStream); 8] = [
    ("add", AluStream::Add),
    ("sub", AluStream::Sub),
    ("mul", AluStream::Mul),
    ("bitwise", AluStream::Bitwise),
    ("shift_left", AluStream::ShiftLeft),
    ("shift_right", AluStream::ShiftRight),
    ("lt", AluStream::Lt),
    ("divrem", AluStream::DivRem),
];

const TOTALS: [&str; 12] = [
    "steps",
    "reads",
    "writes",
    "memory",
    "unaligned",
    "branch",
    "ecall",
    "add",
    "lt",
    "syscalls",
    "operand exceptions",
    "bytes",
];

/// The address and width of a load or store.
type MemoryAccess = Option<(u64, u64)>;

/// Each chip list the history keeps, by name, beside the steps whose instruction belongs in it.
/// `memory` holds each step's address and width if it is a load or store whose rows are right.
fn lists<'a>(
    history: &'a ExecutionHistory,
    instructions: &[Instruction],
    memory: &[MemoryAccess],
) -> Vec<(&'static str, &'a [u32], Vec<u32>)> {
    let steps_where = |belongs: &dyn Fn(usize, &Instruction) -> bool| -> Vec<u32> {
        (0..instructions.len())
            .filter(|&index| belongs(index, &instructions[index]))
            .map(|index| u32::try_from(index).expect("a chunk's steps fit u32"))
            .collect()
    };
    let chip_steps = &history.chip_steps;
    let mut lists = vec![
        (
            "memory",
            chip_steps.memory.as_slice(),
            steps_where(&|index, _| {
                memory[index].is_some_and(|(addr, width)| addr.is_multiple_of(width))
            }),
        ),
        (
            "branch",
            chip_steps.branch.as_slice(),
            steps_where(&|_, instruction| instruction.is_branch_instruction()),
        ),
        (
            "ecall",
            chip_steps.ecall.as_slice(),
            steps_where(&|_, instruction| instruction.is_ecall_instruction()),
        ),
    ];
    for (name, stream) in ALU_STREAMS {
        // The emulator writes no ALU event for a destination of x0.
        let belongs = |_, instruction: &Instruction| {
            instruction.is_alu_instruction()
                && AluStream::of(instruction.opcode) == stream
                && instruction.op_a != 0
        };
        lists.push((name, chip_steps.alu(stream), steps_where(&belongs)));
    }
    lists
}

/// The index of the first entry at which `written` and `expected` differ, if any.
fn first_difference(written: &[u32], expected: &[u32]) -> Option<usize> {
    (0..written.len().max(expected.len())).find(|&i| written.get(i) != expected.get(i))
}

/// The unaligned table against the steps' addresses: exactly the loads and stores whose address
/// is no multiple of their width, in step order, each carrying the next dword's access exactly
/// when it runs into that dword, an access made after the state it found.
fn check_unaligned(history: &ExecutionHistory, memory: &[MemoryAccess], found: &mut Vec<String>) {
    let expected: Vec<u32> = (0..memory.len())
        .filter(|&index| memory[index].is_some_and(|(addr, width)| !addr.is_multiple_of(width)))
        .map(|index| u32::try_from(index).expect("a chunk's steps fit u32"))
        .collect();
    let written: Vec<u32> = history.unaligned.iter().map(|entry| entry.step).collect();
    if let Some(at) = first_difference(&written, &expected) {
        found.push(format!(
            "unaligned table: entry {at} is {:?} in the history, {:?} by the program",
            written.get(at),
            expected.get(at)
        ));
        return;
    }
    for &UnalignedStep {
        step,
        crosses,
        next,
    } in history.unaligned.iter()
    {
        let Some((addr, width)) = memory[step as usize] else {
            continue;
        };
        let runs_over = addr % 8 + width > 8;
        if crosses != u32::from(runs_over) || (!runs_over && next != Access::default()) {
            found.push(format!(
                "unaligned step {step}, {width} byte(s) at 0x{addr:x}: crosses {crosses}, next \
                 dword's access {next:?}"
            ));
            continue;
        }
        let at = (
            history.chunk,
            history.steps[step as usize].timestamp(MemoryAccessPosition::C),
        );
        if runs_over && (next.prev_chunk, next.prev_timestamp) >= at {
            found.push(format!(
                "unaligned step {step}: the next dword's access at {at:?} found the state of {:?}",
                (next.prev_chunk, next.prev_timestamp)
            ));
        }
    }
}

/// The problems of one CPU chunk's history against the program, listed into `found`.
fn check_history(
    history: &ExecutionHistory,
    instructions: &[Instruction],
    found: &mut Vec<String>,
) {
    let steps = &history.steps;
    if let Some(index) = (1..steps.len()).find(|&i| {
        steps[i].first_read < steps[i - 1].first_read
            || steps[i].first_write < steps[i - 1].first_write
    }) {
        found.push(format!(
            "step {index}'s rows start before its predecessor's"
        ));
        return;
    }
    if steps.last().is_some_and(|last| {
        last.first_read as usize > history.reads.len()
            || last.first_write as usize > history.writes.len()
    }) {
        found.push("the last step's rows start past their tables".to_string());
        return;
    }

    let mut memory = vec![None; steps.len()];
    for (index, (step, instruction)) in steps.iter().zip(instructions).enumerate() {
        let slots = Slots::of(instruction);
        let (reads, writes) = history.rows_of(index);
        let expected = (slots.len() - slots.write_count(), slots.write_count());
        if (reads.len(), writes.len()) != expected {
            found.push(format!(
                "step {index} ({instruction:?}): {} read(s) and {} write(s), {expected:?} by its \
                 slots",
                reads.len(),
                writes.len()
            ));
            continue;
        }
        // A read keeps no value it replaced; in debug builds the sink checks it replaced none.
        for (position, access) in history.accesses_of(index, instruction) {
            let at = (history.chunk, step.timestamp(position));
            if (access.prev_chunk, access.prev_timestamp) >= at {
                found.push(format!(
                    "step {index} ({instruction:?}): the {position:?} access at {at:?} found \
                     the state of {:?}",
                    (access.prev_chunk, access.prev_timestamp)
                ));
            }
        }
        if instruction.is_memory_instruction() {
            let (_, b, c) = history.operands(index, instruction);
            memory[index] = Some((b.wrapping_add(c), access_width(instruction.opcode)));
        }
    }

    // The rule gets exactly two operands wrong: `a` of a write to x0, which commits 0, and `b`
    // and `c` of the ECALL closing an unconstrained block, read after the reads its step carries.
    let mut previous = None;
    for exception in &history.operand_exceptions {
        let (step, slot) = (exception.step, exception.slot);
        let order = (step, std::cmp::Reverse(slot));
        if previous.is_some_and(|previous| previous >= order) {
            found.push(format!(
                "operand exception of step {step} slot {slot}: out of order"
            ));
        }
        previous = Some(order);
        const A: u32 = MemoryAccessPosition::A as u32;
        const B: u32 = MemoryAccessPosition::B as u32;
        const C: u32 = MemoryAccessPosition::C as u32;
        let expected = match (instructions.get(step as usize), slot) {
            (Some(instruction), A) => instruction.op_a == 0,
            (Some(instruction), B | C) => instruction.is_ecall_instruction(),
            _ => false,
        };
        if !expected {
            found.push(format!(
                "operand exception of step {step} slot {slot}: {:?} is no x0 write or closing \
                 ECALL",
                instructions.get(step as usize)
            ));
        }
    }

    for (name, written, expected) in lists(history, instructions, &memory) {
        if let Some(at) = first_difference(written, &expected) {
            found.push(format!(
                "{name} list: entry {at} is {:?} in the history, {:?} by the program",
                written.get(at),
                expected.get(at)
            ));
        }
    }
    check_unaligned(history, &memory, found);

    let ecall_clocks: HashSet<u32> = history
        .chip_steps
        .ecall
        .iter()
        .map(|&index| steps[index as usize].clk)
        .collect();
    for syscall in &history.syscalls {
        let clk = u32::try_from(syscall.clk).ok();
        if syscall.chunk != history.chunk || !clk.is_some_and(|clk| ecall_clocks.contains(&clk)) {
            found.push(format!(
                "a syscall at chunk {} clock {} is no ECALL step's",
                syscall.chunk, syscall.clk
            ));
        }
    }
}

/// The problems of one CPU chunk's record.
fn check_chunk(record: &EmulationRecord) -> Vec<String> {
    let mut found = Vec::new();
    if !record.add_events.is_empty() {
        found.push("augmentation rows before the augment pass".to_string());
    }
    match &record.history {
        None => found.push("no history".to_string()),
        Some(history) => {
            let instructions: Vec<Instruction> = history
                .steps
                .iter()
                .map(|step| record.program.fetch(u64::from(step.pc)))
                .collect();
            check_history(history, &instructions, &mut found);
        }
    }
    found
}

/// One guest's history check over all its runs.
#[derive(Default)]
pub struct Check {
    problems: Vec<String>,
    totals: [usize; TOTALS.len()],
    /// CPU chunks over every run, and in the run in progress.
    chunks: usize,
    run_chunks: usize,
    precompile_events: usize,
}

impl Check {
    pub fn record(&mut self, run: &str, record: &EmulationRecord) {
        if !record.is_cpu_chunk {
            self.precompile_events += record
                .precompile_events
                .sorted_groups()
                .iter()
                .map(|(_, events)| events.len())
                .sum::<usize>();
            return;
        }
        let label = format!("{run} chunk {}", self.run_chunks);
        self.run_chunks += 1;
        let found = check_chunk(record);
        if let Some(history) = &record.history {
            let chip_steps = &history.chip_steps;
            for (total, n) in self.totals.iter_mut().zip([
                history.steps.len(),
                history.reads.len(),
                history.writes.len(),
                chip_steps.memory.len(),
                history.unaligned.len(),
                chip_steps.branch.len(),
                chip_steps.ecall.len(),
                chip_steps.add.len(),
                chip_steps.lt.len(),
                history.syscalls.len(),
                history.operand_exceptions.len(),
                history.bytes(),
            ]) {
                *total += n;
            }
        }
        let unlisted = found.len().saturating_sub(LISTED_PER_CHUNK);
        for problem in found.into_iter().take(LISTED_PER_CHUNK) {
            self.problems.push(format!("[{label}] {problem}"));
        }
        if unlisted > 0 {
            self.problems
                .push(format!("[{label}] and {unlisted} more problem(s)"));
        }
    }

    pub fn end_run(&mut self, run: &str) {
        if self.run_chunks == 0 {
            self.problems.push(format!("[{run}] no CPU chunk"));
        }
        self.chunks += std::mem::take(&mut self.run_chunks);
    }

    pub fn finish(mut self, guest: &str) -> Vec<String> {
        println!(
            "{guest}: {} CPU chunk(s), {} precompile event(s)",
            self.chunks, self.precompile_events
        );
        for (count, total) in TOTALS.iter().zip(self.totals) {
            println!("  {count:<18} {total:>10}");
        }
        let total = |count: &str| {
            let at = TOTALS.iter().position(|&name| name == count);
            self.totals[at.unwrap_or_else(|| panic!("no total {count}"))]
        };
        // What every guest runs; a zero would make the checks above say nothing. `add` is the one
        // ALU list here: every guest moves its stack pointer with an ADDI, so none lacks one.
        let mut problems = Vec::new();
        for count in [
            "steps", "reads", "writes", "memory", "branch", "ecall", "add",
        ] {
            if total(count) == 0 {
                problems.push(format!("no {count} in any chunk"));
            }
        }
        // Every precompile call is an ECALL whose syscall is sent.
        if self.precompile_events > 0 && total("syscalls") == 0 {
            problems.push(format!(
                "{} precompile event(s) and no syscall in the history",
                self.precompile_events
            ));
        }
        self.problems.extend(problems);
        self.problems
    }
}

const DATA: u64 = 0x2_0000;
const LOADS: [Opcode; 7] = [
    Opcode::LB,
    Opcode::LBU,
    Opcode::LH,
    Opcode::LHU,
    Opcode::LW,
    Opcode::LWU,
    Opcode::LD,
];
const STORES: [Opcode; 4] = [Opcode::SB, Opcode::SH, Opcode::SW, Opcode::SD];
/// One per opcode and offset in a dword.
const ACCESSES: u64 = 8 * (LOADS.len() + STORES.len()) as u64;

/// Every load and store at every offset in a dword, each in a dword pair of its own, then HALT:
/// the misaligned accesses the parity guests may never make.
fn misaligned_program() -> Arc<Program> {
    let li = |rd: u8, imm: u64| Instruction::new(Opcode::ADD, rd, 0, imm, true, true);
    let image = (0..2 * ACCESSES)
        .map(|i| {
            (
                DATA + 8 * i,
                0x8091_a2b3_c4d5_e6f7_u64.rotate_left(8 * i as u32) ^ i,
            )
        })
        .collect();
    let mut instructions = vec![li(7, 0xfedc_ba98_7654_3210)];
    let mut pair = 0;
    for opcode in LOADS.into_iter().chain(STORES) {
        for offset in 0..8 {
            instructions.push(li(6, DATA + 16 * pair));
            let op_a = if STORES.contains(&opcode) { 7 } else { 5 };
            instructions.push(Instruction::new(opcode, op_a, 6, offset, false, true));
            pair += 1;
        }
    }
    instructions.extend([
        li(5, SyscallCode::HALT as u64),
        li(10, 0),
        Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
    ]);
    Arc::new(Program {
        instructions: instructions.into(),
        pc_start: 0,
        pc_base: 0,
        memory_image: Arc::new(image),
        preprocessed_shape: None,
        profiled_functions: Default::default(),
    })
}

/// The history check, and with `test-utils` the counting sink, on a run of misaligned loads and
/// stores: 44 of its 88 accesses are misaligned, 26 of those run into the next dword, and both
/// checks count every one of the 88.
#[test]
fn misaligned_loads_and_stores_are_checked_and_counted() {
    crate::before_any_emulation();
    let program = misaligned_program();
    let (mut problems, mut aligned, mut unaligned, mut crossing) = (Vec::new(), 0, 0, 0);
    #[cfg(feature = "test-utils")]
    let mut counted = Vec::new();
    history_emulation(program.clone(), &[], WHOLE, |record| {
        if !record.is_cpu_chunk {
            return;
        }
        problems.extend(check_chunk(&record));
        if let Some(history) = &record.history {
            aligned += history.chip_steps.memory.len();
            unaligned += history.unaligned.len();
            crossing += history
                .unaligned
                .iter()
                .filter(|entry| entry.crosses == 1)
                .count();
        }
        #[cfg(feature = "test-utils")]
        counted.push(crate::counting::history_side(&record, &mut problems));
    });
    assert_eq!(
        (aligned, unaligned, crossing),
        (44, 44, 26),
        "the memory list's steps, the unaligned table's, and those that run into the next dword"
    );
    #[cfg(feature = "test-utils")]
    problems.extend(
        crate::counting::compare_run("misaligned", program, &[], WHOLE, &counted, false).problems,
    );
    assert!(
        problems.is_empty(),
        "{} problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}
