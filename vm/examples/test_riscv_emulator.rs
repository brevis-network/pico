use itertools::enumerate;
use log::{debug, info};
use p3_air::{Air, BaseAir};
use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    emulator::{
        opts::EmulatorOpts,
        record::RecordBehavior,
        riscv::{
            record::EmulationRecord,
            riscv_emulator::{EmulationError, EmulatorMode, RiscvEmulator},
            stdin::EmulatorStdin,
        },
    },
    instances::{
        configs::riscv_config::StarkConfig as RiscvSC, machine::simple_machine::SimpleMachine,
    },
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip},
        logger::setup_logger,
        machine::MachineBehavior,
    },
    primitives::consts::{RECURSION_NUM_PVS, RISCV_NUM_PVS},
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use std::{env, time::Instant};

#[path = "common/parse_args.rs"]
mod parse_args;

fn main() {
    setup_logger();

    let (elf, stdin, _, _) = parse_args::parse_args(env::args().collect());

    let start = Instant::now();

    info!("\n Creating Program..");
    let compiler = Compiler::new(SourceType::RiscV, elf);
    let program = compiler.compile();
    let pc_start = program.pc_start.clone();

    info!("\n Creating emulator (at {:?})..", start.elapsed());
    let mut emulator = RiscvEmulator::new(program, EmulatorOpts::test_opts());
    info!(
        "Running with chunk size: {}, batch size: {}",
        emulator.chunk_size, emulator.chunk_batch_size
    );

    emulator.emulator_mode = EmulatorMode::Trace;
    for input in &stdin.buffer {
        emulator.state.input_stream.push(input.clone());
    }

    let mut done = false;
    let mut record_count = 0;
    let mut execution_record_count = 0;
    let mut prev_next_pc = pc_start;

    loop {
        if emulator.emulate_to_batch().unwrap() {
            done = true;
        }

        for (i, record) in enumerate(emulator.batch_records.iter()) {
            if record.cpu_events.len() > 0 {
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

            debug!("public values: {:?}", record.public_values);

            // For the first chunk, cpu events should not be empty
            if i == 0 {
                assert!(record.cpu_events.len() > 0);
                assert_eq!(record.public_values.start_pc, prev_next_pc);
            }
            if record.cpu_events.len() > 0 {
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
