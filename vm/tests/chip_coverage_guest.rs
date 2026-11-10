//! The chip-coverage guest (`vm/examples/patch-testing/guests/chip-coverage`), the fixture device
//! traces are held to the host's on: its shipped ELF is the pinned one (`common/chip_coverage.rs`),
//! the golden height file pins its program, and a run of it reaches what the guest's header
//! promises.

use std::collections::BTreeMap;

use pico_vm::{
    compiler::riscv::opcode::Opcode,
    emulator::riscv::record::{AluStream, EmulationRecord},
    instances::chiptype::riscv_chiptype::RiscvChipType,
    mle::machine::{
        riscv::{augmented_record, Kb},
        shape::mle_natural_heights,
    },
};
use sha2::{Digest, Sha256};

#[path = "common/chip_coverage.rs"]
mod chip_coverage;
// Only the program, stdin and options builders.
#[allow(dead_code)]
#[path = "common/record_parity.rs"]
mod record_parity;
// Only the run on an ELF and an input: this guest is none of the parity guests.
#[allow(dead_code)]
#[path = "common/trace_source.rs"]
mod trace_source;
use record_parity::{program, WHOLE};
use trace_source::history_run;

/// Every record a run of the guest emits in chunks of `chunk_size` cycles, held together.
fn records(chunk_size: u32) -> Vec<EmulationRecord> {
    let mut records = Vec::new();
    history_run(chip_coverage::elf(), &[], chunk_size, |record| {
        records.push(record)
    });
    records
}

#[test]
fn the_chip_coverage_elf_is_the_pinned_one() {
    chip_coverage::elf();
}

/// Some line of the golden height file is keyed by this guest's program, digested as the height
/// witness digests it: its instructions, entry, base and memory image.
#[test]
fn the_golden_heights_pin_the_chip_coverage_guest() {
    let program = program(chip_coverage::elf());
    let digest = hex::encode(Sha256::digest(
        bincode::serialize(&(
            &*program.instructions,
            program.pc_start,
            program.pc_base,
            &*program.memory_image,
        ))
        .expect("serialize the program"),
    ));
    let golden = include_str!("natural_heights.txt");
    assert!(
        golden
            .lines()
            .filter(|line| !line.starts_with('#'))
            .any(|line| line.split('\t').next() == Some(digest.as_str())),
        "vm/tests/natural_heights.txt pins no record of the chip-coverage guest (program {digest})"
    );
}

/// One chunk and its deferred records give every chip the guest names a real row, and the host's
/// extra-record pass adds the derived rows the device has to reproduce.
#[test]
fn the_chip_coverage_guest_reaches_every_chip_family() {
    let chips = RiscvChipType::<Kb>::all_chips();
    let records = records(WHOLE);
    let mut heights = BTreeMap::<String, usize>::new();
    let mut cpu_chunks = 0;
    for record in &records {
        let augmented = augmented_record(&chips, record);
        for (name, rows) in mle_natural_heights(&augmented) {
            let max = heights.entry(name).or_default();
            *max = (*max).max(rows);
        }
        if !record.is_cpu_chunk {
            continue;
        }
        cpu_chunks += 1;
        let steps = record.cpu_steps();
        let x0_writes = steps
            .iter()
            .filter(|step| step.instruction.op_a == 0)
            .filter(|step| {
                matches!(
                    step.instruction.opcode,
                    Opcode::ADD | Opcode::LD | Opcode::LW | Opcode::MUL | Opcode::SLT
                )
            })
            .count();
        assert!(x0_writes >= 5, "{x0_writes} writes to x0");
        let add = |r: &EmulationRecord| r.alu_ops(AluStream::Add).len();
        assert!(
            add(&augmented) > add(record),
            "division raised no derived add row"
        );
        let branches = steps
            .iter()
            .filter(|step| step.instruction.is_branch_instruction())
            .count();
        let compares = augmented.alu_ops(AluStream::Lt).len();
        assert!(
            branches > 0 && compares >= branches,
            "{branches} branches, {compares} compare rows"
        );
        assert!(steps.ecalls().len() >= 256 + 4, "too few ecalls");
    }
    assert_eq!(cpu_chunks, 1, "the guest fits one chunk of {WHOLE}");
    for chip in [
        "Cpu",
        "Ecall",
        "Add",
        "Sub",
        "Addw",
        "Subw",
        "Mul",
        "Bitwise",
        "LessThan",
        "ShiftLeft",
        "ShiftRight",
        "DivRem",
        "MemoryReadWrite",
        "MemoryLocal",
        "SyscallRiscv",
        "RiscvKoalaBearPoseidon2",
        "MemoryInitialize",
        "MemoryFinalize",
        "KeccakPermute",
        "KeccakControl",
        "Poseidon2Permute",
        "SyscallPrecompile",
    ] {
        assert!(
            heights.get(chip).is_some_and(|&rows| rows > 0),
            "{chip} has no row: {heights:?}"
        );
    }
    // Global's natural height counts its one padding row.
    assert!(heights["Global"] > 1, "Global has no real row");
}

/// The 256 back-to-back ECALLs hold a whole chunk at a size below that.
#[test]
fn a_chip_coverage_chunk_opens_and_closes_on_an_ecall() {
    let records = records(64);
    let found = records.iter().filter(|r| r.is_cpu_chunk).any(|record| {
        let steps = record.cpu_steps();
        steps.len() > 1
            && steps.get(0).instruction.is_ecall_instruction()
            && steps
                .get(steps.len() - 1)
                .instruction
                .is_ecall_instruction()
    });
    assert!(found, "no chunk of 64 cycles opens and closes on an ECALL");
}
