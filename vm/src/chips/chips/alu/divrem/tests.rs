use crate::{
    chips::chips::alu::{
        divrem::{utils::get_quotient_and_remainder, DivRemChip},
        event::AluEvent,
    },
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
    emulator::riscv::{
        history::{Access, ExecutionHistory, ReadAccess, Step},
        record::EmulationRecord,
    },
    machine::chip::ChipBehavior,
};
use p3_koala_bear::KoalaBear;
use rand::{rng, seq::IndexedRandom, RngExt};

/// CPU-only test with large random u64 values.
/// Exposes LtUnsignedGadget::populate bug: byte_flags has WORD_SIZE=4 entries
/// but populate iterates over 8 bytes and accesses byte_flags[i] with i up to 7.
#[test]
fn test_divrem_cpu_large_random_values() {
    type F = KoalaBear;
    let rng = &mut rng();
    let all_ops = [
        Opcode::DIV,
        Opcode::DIVU,
        Opcode::REM,
        Opcode::REMU,
        Opcode::DIVW,
        Opcode::DIVUW,
        Opcode::REMW,
        Opcode::REMUW,
    ];
    let events: Vec<AluEvent> = (0..1024u64)
        .map(|i| {
            let op = *all_ops.choose(rng).unwrap();
            let b: u64 = rng.random();
            let c: u64 = rng.random_range(1..u64::MAX);
            let (quotient, remainder) = get_quotient_and_remainder(b, c, op);
            let a = match op {
                Opcode::DIV | Opcode::DIVU | Opcode::DIVW | Opcode::DIVUW => quotient,
                Opcode::REM | Opcode::REMU | Opcode::REMW | Opcode::REMUW => remainder,
                _ => unreachable!(),
            };
            AluEvent::new(i, op, a, b, c, false)
        })
        .collect();

    let instructions = events
        .iter()
        .map(|event| Instruction::new(event.opcode, 1, 2, 3, false, false))
        .collect();
    let mut record = EmulationRecord::new(std::sync::Arc::new(Program::new(
        instructions,
        0x1000,
        0x1000,
    )));
    let mut history = ExecutionHistory::default();
    for (index, event) in events.iter().enumerate() {
        history.steps.push(Step {
            clk: event.clk as u32,
            pc: 0x1000 + index as u32 * 4,
            first_read: history.reads.len() as u32,
            first_write: history.writes.len() as u32,
            ..Step::default()
        });
        history.writes.push(Access {
            value: event.a,
            ..Access::default()
        });
        history
            .reads
            .extend([event.b, event.c].map(|value| ReadAccess {
                value,
                ..ReadAccess::default()
            }));
        history.chip_steps.divrem.push(index as u32);
    }
    record.history = Some(history);

    let chip = DivRemChip::<F>::default();
    // This will panic with "index out of bounds: the len is 4 but the index is ..."
    // if LtUnsignedGadget::populate has the byte indexing bug.
    let _trace = chip.generate_main(&record, &mut EmulationRecord::default());
    println!("CPU trace generation with large random u64 values succeeded");
}
