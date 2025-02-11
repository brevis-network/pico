use itertools::enumerate;
use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    emulator::{
        opts::EmulatorOpts,
        record::RecordBehavior,
        riscv::riscv_emulator::{EmulatorMode, RiscvEmulator},
        stdin::EmulatorStdin,
    },
    machine::logger::setup_logger,
};
use std::time::Instant;
use tracing::{debug, info, trace};

#[path = "common/parse_args.rs"]
mod parse_args;

fn run<F: PrimeField32>(elf: &'static [u8], stdin: EmulatorStdin<Program, Vec<u8>>) {
    let start = Instant::now();

    info!("Creating Program..");
    let compiler = Compiler::new(SourceType::RISCV, elf);
    let program = compiler.compile();
    let pc_start = program.pc_start;

    info!("Creating emulator (at {:?})..", start.elapsed());
    let mut emulator = RiscvEmulator::new::<F>(program, EmulatorOpts::test_opts());
    info!(
        "Running with chunk size: {}, batch size: {}",
        emulator.opts.chunk_size, emulator.opts.chunk_batch_size
    );

    emulator.emulator_mode = EmulatorMode::Trace;
    for input in &*stdin.inputs {
        emulator.state.input_stream.push(input.clone());
    }

    let mut record_count = 0;
    let mut execution_record_count = 0;
    let mut prev_next_pc = pc_start;

    loop {
        let (batch_records, done) = emulator.emulate_batch().unwrap();

        for (i, record) in enumerate(batch_records.iter()) {
            if !record.cpu_events.is_empty() {
                execution_record_count += 1;
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
            assert_eq!(batch_records.last().unwrap().public_values.next_pc, 0);
            break;
        }
    }
}

fn main() {
    setup_logger();

    let (elf, stdin, args) = parse_args::parse_args();
    match args.field.as_str() {
        "bb" => run::<BabyBear>(elf, stdin),
        "kb" => run::<KoalaBear>(elf, stdin),
        _ => panic!("Unsupported field for RISCV emulator: {}", args.field),
    }
}
