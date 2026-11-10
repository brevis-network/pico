//! A guest's records, emulated by the serial interpreter through the history sink, for the suites
//! that read them.

use std::sync::Arc;

use pico_vm::{
    compiler::riscv::program::Program,
    emulator::riscv::{
        public_values::RecordFinalPvsState,
        record::EmulationRecord,
        record_slots::hold_records_unbounded,
        riscv_emulator::RiscvEmulator,
        sink::{HistorySink, Sink},
    },
    mle::machine::riscv::Kb,
};

use crate::record_parity::{opts, program, stdin, Run};

/// Every record one run of the guest in `elf` emits, handed to `on_record` in emission order.
pub fn history_records(elf: &[u8], run: &Run, on_record: impl FnMut(EmulationRecord)) {
    history_run(elf, &run.stdin, run.chunk_size, on_record);
}

/// Every record the guest in `elf` emits on `input` in chunks of `chunk_size` cycles, handed to
/// `on_record` in emission order. The bound on records held at once is lifted: a test holding them
/// would stop at it.
pub fn history_run(
    elf: &[u8],
    input: &[Vec<u8>],
    chunk_size: u32,
    on_record: impl FnMut(EmulationRecord),
) {
    history_emulation(program(elf), input, chunk_size, on_record);
}

/// [`history_run`] on a compiled program, returning the emulator as the run left it, for a check
/// that reads its end state.
pub fn history_emulation(
    program: Arc<Program>,
    input: &[Vec<u8>],
    chunk_size: u32,
    mut on_record: impl FnMut(EmulationRecord),
) -> RiscvEmulator {
    hold_records_unbounded();
    let mut emulator = RiscvEmulator::new_single::<Kb>(
        program.clone(),
        Arc::new(RecordFinalPvsState::default()),
        opts(chunk_size),
    )
    .with_sink(Sink::History(HistorySink::new(EmulationRecord::new(
        program,
    ))));
    emulator.write_stdin(&stdin(input));
    loop {
        let report = emulator
            .emulate_batch(&mut |record: EmulationRecord| on_record(record))
            .expect("emulate_batch");
        if report.done {
            break;
        }
    }
    emulator
}
