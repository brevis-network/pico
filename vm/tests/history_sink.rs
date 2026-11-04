//! The history sink on the record-parity guests: every CPU chunk's record carries an execution
//! history and no per-chip event stream, and the history agrees with the program it ran.
//!
//! Per chunk: each step has as many accesses as its instruction has slots, and each read leaves
//! its value as it found it; each access comes after the state it found, at the timestamp derived
//! from its step; each chip's list names exactly the steps of that chip's instructions, in order;
//! and each syscall is an ECALL step's.

use std::{collections::HashSet, sync::Arc};

use pico_vm::{
    chips::chips::riscv_memory::event::MemoryAccessPosition,
    compiler::riscv::{instruction::Instruction, program::Program},
    emulator::{
        riscv::{
            history::{ExecutionHistory, Slots},
            public_values::RecordFinalPvsState,
            record::{AluStream, EmulationRecord},
            record_slots::hold_records_unbounded,
            riscv_emulator::RiscvEmulator,
            sink::{HistorySink, Sink},
        },
        stdin::EmulatorStdin,
    },
    mle::machine::riscv::Kb,
};

// Only the guests and their runs: the comparison in there is between two emulation paths.
#[allow(dead_code)]
#[path = "common/record_parity.rs"]
mod record_parity;
use record_parity::{opts, program, stdin, GUESTS};

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

/// Runs `emulator` to the end, handing every record it emits to `on_record`.
fn emulate(
    emulator: &mut RiscvEmulator,
    stdin: &EmulatorStdin<Program, Vec<u8>>,
    mut on_record: impl FnMut(EmulationRecord),
) {
    emulator.write_stdin(stdin);
    loop {
        let report = emulator
            .emulate_batch(&mut |record: EmulationRecord| on_record(record))
            .expect("emulate_batch");
        if report.done {
            break;
        }
    }
}

/// Each chip list the history keeps, by name, beside the steps whose instruction belongs in it.
fn lists<'a>(
    history: &'a ExecutionHistory,
    instructions: &[Instruction],
) -> Vec<(&'static str, &'a [u32], Vec<u32>)> {
    let steps_where = |belongs: &dyn Fn(&Instruction) -> bool| -> Vec<u32> {
        (0..instructions.len())
            .filter(|&index| belongs(&instructions[index]))
            .map(|index| u32::try_from(index).expect("a chunk's steps fit u32"))
            .collect()
    };
    let chip_steps = &history.chip_steps;
    let mut lists = vec![
        (
            "memory",
            chip_steps.memory.as_slice(),
            steps_where(&Instruction::is_memory_instruction),
        ),
        (
            "branch",
            chip_steps.branch.as_slice(),
            steps_where(&Instruction::is_branch_instruction),
        ),
        (
            "ecall",
            chip_steps.ecall.as_slice(),
            steps_where(&Instruction::is_ecall_instruction),
        ),
    ];
    for (name, stream) in ALU_STREAMS {
        // The emulator writes no ALU event for a destination of x0.
        let belongs = |instruction: &Instruction| {
            instruction.is_alu_instruction()
                && AluStream::of(instruction.opcode) == stream
                && instruction.op_a != 0
        };
        lists.push((name, chip_steps.alu(stream), steps_where(&belongs)));
    }
    lists
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

    for (name, written, expected) in lists(history, instructions) {
        if let Some(at) =
            (0..written.len().max(expected.len())).find(|&i| written.get(i) != expected.get(i))
        {
            found.push(format!(
                "{name} list: entry {at} is {:?} in the history, {:?} by the program",
                written.get(at),
                expected.get(at)
            ));
        }
    }

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

/// Every run of the guest called `name` in [`GUESTS`], through the history sink.
fn check(name: &str) {
    let guest = GUESTS
        .iter()
        .find(|guest| guest.name == name)
        .unwrap_or_else(|| panic!("no guest {name}"));
    let mut problems = Vec::new();
    let mut totals = [0usize; 11];
    const TOTALS: [&str; 11] = [
        "steps",
        "reads",
        "writes",
        "memory",
        "branch",
        "ecall",
        "add",
        "lt",
        "syscalls",
        "operand exceptions",
        "bytes",
    ];
    let mut chunks = 0;
    let mut precompile_events = 0;

    for run in guest.runs() {
        let label = format!("{name} @ {}", run.chunk_size);
        let program = program(guest.elf);
        hold_records_unbounded();
        let mut emulator = RiscvEmulator::new_single::<Kb>(
            program.clone(),
            Arc::new(RecordFinalPvsState::default()),
            opts(run.chunk_size),
        )
        .with_sink(Sink::History(HistorySink::new(EmulationRecord::new(
            program.clone(),
        ))));
        let mut chunk = 0;
        emulate(&mut emulator, &stdin(&run.stdin), |record| {
            if !record.is_cpu_chunk {
                precompile_events += record
                    .precompile_events
                    .sorted_groups()
                    .iter()
                    .map(|(_, events)| events.len())
                    .sum::<usize>();
                return;
            }
            let label = format!("{label} chunk {chunk}");
            chunk += 1;
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
                        .map(|step| program.fetch(u64::from(step.pc)))
                        .collect();
                    check_history(history, &instructions, &mut found);
                    let chip_steps = &history.chip_steps;
                    for (total, n) in totals.iter_mut().zip([
                        history.steps.len(),
                        history.reads.len(),
                        history.writes.len(),
                        chip_steps.memory.len(),
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
            }
            let unlisted = found.len().saturating_sub(LISTED_PER_CHUNK);
            for problem in found.into_iter().take(LISTED_PER_CHUNK) {
                problems.push(format!("[{label}] {problem}"));
            }
            if unlisted > 0 {
                problems.push(format!("[{label}] and {unlisted} more problem(s)"));
            }
        });
        if chunk == 0 {
            problems.push(format!("[{label}] no CPU chunk"));
        }
        chunks += chunk;
    }

    println!("{name}: {chunks} CPU chunk(s), {precompile_events} precompile event(s)");
    for (count, total) in TOTALS.iter().zip(totals) {
        println!("  {count:<18} {total:>10}");
    }
    let total = |count: &str| {
        let at = TOTALS.iter().position(|&name| name == count);
        totals[at.unwrap_or_else(|| panic!("no total {count}"))]
    };
    // What every guest runs; a zero would make the checks above say nothing. `add` is the one ALU
    // list here: every guest moves its stack pointer with an ADDI, so none lacks one.
    for count in [
        "steps", "reads", "writes", "memory", "branch", "ecall", "add",
    ] {
        if total(count) == 0 {
            problems.push(format!("no {count} in any chunk"));
        }
    }
    // Every precompile call is an ECALL whose syscall is sent.
    if precompile_events > 0 && total("syscalls") == 0 {
        problems.push(format!(
            "{precompile_events} precompile event(s) and no syscall in the history"
        ));
    }

    for problem in &problems {
        println!("FAIL: {problem}");
    }
    assert!(
        problems.is_empty(),
        "{} problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}

#[test]
fn fib() {
    check("fib");
}

#[test]
fn ed25519() {
    check("ed25519");
}

#[test]
fn poseidon2() {
    check("poseidon2");
}

#[test]
fn aggregator() {
    check("aggregator");
}

#[test]
fn bls12381_fp() {
    check("bls12381-fp");
}

#[test]
fn sha2() {
    check("sha2");
}

#[test]
fn sha3() {
    check("sha3");
}

#[test]
fn tiny_keccak() {
    check("tiny-keccak");
}

#[test]
fn k256() {
    check("k256");
}

#[test]
fn bn254_fp() {
    check("bn254-fp");
}

#[test]
fn bls12381_ws() {
    check("bls12381-ws");
}

#[test]
fn bn254_ws() {
    check("bn254-ws");
}
