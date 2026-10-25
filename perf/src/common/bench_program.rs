use anyhow::Error;
use pico_vm::{configs::config::StarkGenericConfig, emulator::stdin::EmulatorStdin};
use std::{env, fs};

#[derive(Clone, Copy, Debug)]
pub struct BenchProgram {
    pub name: &'static str,
    pub elf: &'static str,
    pub input: Option<&'static str>,
}

pub const PROGRAMS: &[BenchProgram] = &[
    BenchProgram {
        name: "subblock",
        elf: "./perf/bench_data/subblock-elf",
        input: None,
    },
    BenchProgram {
        name: "aggregator",
        elf: "./perf/bench_data/aggregator-elf",
        input: None,
    },
    BenchProgram {
        name: "fibonacci-300kn",
        elf: "./perf/bench_data/fibonacci-elf",
        input: Some("fibonacci-300kn"),
    },
    BenchProgram {
        name: "pure-fibonacci",
        elf: "./perf/bench_data/pure-fibonacci-elf",
        input: Some("pure-fibonacci"),
    },
    BenchProgram {
        name: "bn",
        elf: "./perf/bench_data/bn-elf",
        input: None,
    },
    BenchProgram {
        name: "bls12381",
        elf: "./perf/bench_data/bls12381-elf",
        input: None,
    },
    BenchProgram {
        name: "tendermint",
        elf: "./perf/bench_data/tendermint-elf",
        input: None,
    },
    // common reth app, could custom input by ENV `BENCH_RETH_BLOCK`
    BenchProgram {
        name: "reth",
        elf: "./perf/bench_data/reth-elf",
        // specify input file by ENV `BENCH_RETH_BLOCK`
        // e.g. if `BENCH_RETH_BLOCK=22712700`, the input is `./perf/bench_data/reth-22712700.bin`
        input: Some("reth"),
    },
    BenchProgram {
        name: "reth-17106222",
        elf: "./perf/bench_data/reth-elf",
        input: Some("./perf/bench_data/reth-17106222.bin"),
    },
    BenchProgram {
        name: "reth-18884864",
        elf: "./perf/bench_data/reth-elf",
        input: Some("./perf/bench_data/reth-18884864.bin"),
    },
    BenchProgram {
        name: "primus",
        elf: "./perf/bench_data/primus-elf",
        input: Some("./perf/bench_data/primus.bin"),
    },
    BenchProgram {
        name: "reth-24600825",
        elf: "./perf/bench_data/reth-elf",
        input: Some("./perf/bench_data/reth-24600825.bin"),
    },
    BenchProgram {
        name: "simple-fib",
        elf: "./examples/fibonacci/app/elf/riscv32im-pico-zkvm-elf",
        input: None,
    },
    BenchProgram {
        name: "rv64-fibonacci",
        elf: "./perf/bench_data/rv64/no-commit-fib-elf",
        input: Some("rv64-fibonacci"),
    },
    BenchProgram {
        name: "rv64-reth",
        elf: "./perf/bench_data/rv64/reth-elf",
        // specify input file by ENV `BENCH_RETH_BLOCK`
        // e.g. if `BENCH_RETH_BLOCK=22712700`, the input is `./perf/bench_data/reth-22712700.bin`
        input: Some("rv64-reth"),
    },
];

pub fn load_input(input: &str) -> Result<Vec<u8>, Error> {
    if input == "fibonacci-300kn" {
        Ok(bincode::serialize(&300_000u32)?)
    } else if input == "pure-fibonacci" {
        Ok(bincode::serialize(&20u32)?)
    } else if input == "rv64-fibonacci" {
        let n: u32 = env::var("FIB_N")
            .unwrap_or("10".to_string())
            .parse()
            .expect("FIB_N must be a valid u32");
        Ok(bincode::serialize(&n)?)
    } else if input == "reth" {
        // use block `18884864` as default
        let block = env::var("BENCH_RETH_BLOCK").unwrap_or("18884864".to_string());
        let input = format!("./perf/bench_data/reth-{block}.bin");
        Ok(fs::read(input)?)
    } else if input == "rv64-reth" {
        // use block `18884864` as default
        let block = env::var("BENCH_RETH_BLOCK").unwrap_or("18884864".to_string());
        let input = format!("./perf/bench_data/rv64/reth-{block}.bin");
        Ok(fs::read(input)?)
    } else {
        Ok(fs::read(input)?)
    }
}

#[allow(clippy::type_complexity)]
pub fn load<P, SC: StarkGenericConfig>(
    bench: &BenchProgram,
) -> Result<(Vec<u8>, EmulatorStdin<P, Vec<u8>>), Error> {
    let elf = fs::read(bench.elf)?;
    let mut stdin_builder = EmulatorStdin::<P, Vec<u8>>::new_builder::<SC>();

    if let Some(input) = bench.input {
        let input_bytes = load_input(input)?;
        stdin_builder.write_slice(&input_bytes);
    }

    let stdin = stdin_builder.finalize();
    Ok((elf, stdin))
}
