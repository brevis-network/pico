use itertools::enumerate;
use log::{debug, info};
use p3_air::{Air, BaseAir};
use p3_baby_bear::BabyBear;
use p3_field::{AbstractField, Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use pico_vm::{
    chips::chips::{
        alu::{add_sub::AddSubChip, bitwise::BitwiseChip, divrem::DivRemChip, mul::MulChip},
        byte::ByteChip,
        cpu::CpuChip,
        lt::LtChip,
        memory::initialize_finalize::{MemoryChipType, MemoryInitializeFinalizeChip},
        memory_program::MemoryProgramChip,
        program::ProgramChip,
        sll::SLLChip,
        sr::traces::ShiftRightChip,
    },
    compiler::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::bb_poseidon2::BabyBearPoseidon2,
    emulator::{
        opts::EmulatorOpts,
        record::RecordBehavior,
        riscv::{
            public_values::RISCV_NUM_PVS,
            record::EmulationRecord,
            riscv_emulator::{EmulationError, EmulatorMode, RiscvEmulator},
        },
        stdin::EmulatorStdin,
    },
    instances::simple_machine::SimpleMachine,
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip},
        machine::MachineBehavior,
    },
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use std::{env, time::Instant};

fn pars_args(args: Vec<String>) -> (&'static [u8], EmulatorStdin) {
    const ELF_FIB: &[u8] = include_bytes!("../src/compiler/test_data/riscv32im-sp1-fibonacci-elf");
    const ELF_KECCAK: &[u8] = include_bytes!("../src/compiler/test_data/riscv32im-pico-keccak-elf");

    if args.len() > 3 {
        eprintln!("Invalid number of arguments");
        std::process::exit(1);
    }
    let mut test_case = String::from("fib"); // default test_case is fibonacci
    let mut n = 0;
    let mut stdin = EmulatorStdin::new();

    if args.len() > 1 {
        test_case = args[1].clone();
        if args.len() > 2 {
            n = args[2].parse::<u32>().unwrap();
        }
    }

    let mut elf: &[u8];
    if test_case == "fibonacci" || test_case == "fib" || test_case == "f" {
        elf = ELF_FIB;
        if n == 0 {
            n = 40000; // default fibonacci seq num
        }
        stdin.write(&n);
        info!("Test Fibonacci, sequence n={}", n);
    } else if test_case == "keccak" || test_case == "k" {
        elf = ELF_KECCAK;
        if n == 0 {
            n = 100; // default keccak input str len
        }
        let input_str = (0..n).map(|_| "x").collect::<String>();
        stdin.write(&input_str);
        info!("Test Keccak, string len n={}", input_str.len());
    } else {
        eprintln!("Invalid test case. Accept: [ fibonacci | fib | f ], [ keccak | k ]\n");
        std::process::exit(1);
    }

    (elf, stdin)
}

fn main() {
    env_logger::init();

    // run with default fibo, in which n = 40000
    let (elf, stdin) = pars_args(env::args().collect());

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
