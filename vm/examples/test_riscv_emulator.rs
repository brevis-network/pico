use itertools::enumerate;
use pico_vm::{
    compiler::riscv::compiler::{Compiler, SourceType},
    emulator::{
        opts::EmulatorOpts,
        record::RecordBehavior,
        riscv::riscv_emulator::{EmulatorMode, RiscvEmulator},
    },
    machine::logger::setup_logger,
};
use std::time::Instant;
use tracing::{debug, info, trace};

#[path = "common/parse_args.rs"]
mod parse_args;

fn main() {
    setup_logger();

    let (elf, stdin, _, _) = parse_args::parse_args();

    let start = Instant::now();

    info!("\n Creating Program..");
    let compiler = Compiler::new(SourceType::RiscV, elf);
    let program = compiler.compile();
    let pc_start = program.pc_start;

    info!("\n Creating emulator (at {:?})..", start.elapsed());
    let mut emulator = RiscvEmulator::new(program, EmulatorOpts::test_opts());
    info!(
        "Running with chunk size: {}, batch size: {}",
        emulator.chunk_size, emulator.chunk_batch_size
    );

    emulator.emulator_mode = EmulatorMode::Trace;
    for input in &*stdin.buffer {
        emulator.state.input_stream.push(input.clone());
    }

    let mut done = false;
    let mut record_count = 0;
    let mut execution_record_count = 0;
    let mut prev_next_pc = pc_start;

    let mut flag_first_nonexecution = true;
    loop {
        if emulator.emulate_to_batch().unwrap() {
            done = true;
        }

        for (i, record) in enumerate(emulator.batch_records.iter()) {
            if !record.cpu_events.is_empty() {
                execution_record_count += 1;
            } else if flag_first_nonexecution {
                execution_record_count += 1;
                flag_first_nonexecution = false;
            }
            record_count += 1;

            debug!(
                "\n\n**** record {}, execution record {} ****\n",
                record_count, execution_record_count
            );

            let stats = record.stats();
            for (key, value) in &stats {
                debug!("{:<25}: {}", key, value);
            }

            trace!("public values: {:?}", record.public_values);

            // For the first chunk, cpu events should not be empty
            if i == 0 {
                assert!(!record.cpu_events.is_empty());
                assert_eq!(record.public_values.start_pc, prev_next_pc);
            }
            if !record.cpu_events.is_empty() {
                assert_ne!(record.public_values.start_pc, 0);
            } else {
                assert_eq!(record.public_values.start_pc, record.public_values.next_pc);
            }

            assert_eq!(record.public_values.chunk, record_count as u32);
            assert_eq!(
                record.public_values.execution_chunk,
                execution_record_count as u32
            );
            assert_eq!(record.public_values.exit_code, 0);

            prev_next_pc = record.public_values.next_pc;
        }

        if done {
            assert_eq!(
                emulator.batch_records.last().unwrap().public_values.next_pc,
                0
            );
            break;
        }
    }
}
