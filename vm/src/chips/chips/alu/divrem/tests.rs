use crate::{
    chips::chips::alu::{
        divrem::{utils::get_quotient_and_remainder, DivRemChip},
        event::AluEvent,
    },
    compiler::riscv::opcode::Opcode,
    emulator::riscv::record::EmulationRecord,
    machine::chip::ChipBehavior,
};
use p3_koala_bear::KoalaBear;
use rand::{prelude::IndexedRandom, rng, RngExt};

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
    let divrem_events: Vec<AluEvent> = (0..1024u64)
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

    let record = EmulationRecord {
        divrem_events,
        ..Default::default()
    };

    let chip = DivRemChip::<F>::default();
    // This will panic with "index out of bounds: the len is 4 but the index is ..."
    // if LtUnsignedGadget::populate has the byte indexing bug.
    let _trace = chip.generate_main(&record, &mut EmulationRecord::default());
    println!("CPU trace generation with large random u64 values succeeded");
}
