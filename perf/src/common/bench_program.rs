use anyhow::Error;
use pico_vm::{configs::config::StarkGenericConfig, emulator::stdin::EmulatorStdin};
use std::fs;

#[derive(Clone, Copy, Debug)]
pub struct BenchProgram {
    pub name: &'static str,
    pub elf: &'static str,
    pub input: Option<&'static str>,
}

pub const PROGRAMS: &[BenchProgram] = &[
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
        name: "tendermint",
        elf: "./perf/bench_data/tendermint-elf",
        input: None,
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
        name: "reth-22059900",
        elf: "./perf/bench_data/reth-elf",
        input: Some("./perf/bench_data/reth-22059900.bin"),
    },
    BenchProgram {
        name: "reth-20528709",
        elf: "./perf/bench_data/reth-elf",
        input: Some("./perf/bench_data/reth-20528709.bin"),
    },
    BenchProgram {
        name: "reth-22528700",
        elf: "./perf/bench_data/reth-elf",
        input: Some("./perf/bench_data/reth-22528700.bin"),
    },
    BenchProgram {
        name: "reth-22515566",
        elf: "./perf/bench_data/reth-elf",
        input: Some("./perf/bench_data/reth-22515566.bin"),
    },
    BenchProgram {
        name: "reth-22745330",
        elf: "./perf/bench_data/reth-elf",
        input: Some("./perf/bench_data/reth-22745330.bin"),
    },
];

fn load_input(input: &str) -> Result<Vec<u8>, Error> {
    if input == "fibonacci-300kn" {
        Ok(bincode::serialize(&300_000u32)?)
    } else if input == "pure-fibonacci" {
        Ok(bincode::serialize(&20u32)?)
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

    let (stdin, _deferred_proof) = stdin_builder.finalize();
    Ok((elf, stdin))
}
