use crate::common::{
    parse::env_usize,
    program::{ProgramInput, VK_DIGEST_PATH},
};
use anyhow::{Context, Error};
use pico_vm::{
    compiler::riscv::program::Program,
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{EmulatorStdin, EmulatorStdinBuilder},
};
use std::{
    env, fs,
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
};

// Helper: load stdin_builder (by deserializing a builder)
pub fn load_stdin_builder_from_file<P: AsRef<Path>>(
    path: P,
) -> anyhow::Result<EmulatorStdinBuilder<Vec<u8>, KoalaBearPoseidon2>> {
    let path_ref = path.as_ref();
    let f = BufReader::new(
        File::open(path_ref).with_context(|| format!("failed to open {}", path_ref.display()))?,
    );
    let builder: EmulatorStdinBuilder<Vec<u8>, KoalaBearPoseidon2> =
        bincode::deserialize_from(f).context("failed to deserialize stdin_builder")?;
    // let (stdin, _) = builder.finalize::<Program>();
    Ok(builder)
}

// Helper: build file paths (adjust names to match your existing files)
pub fn agg_builder_path(block: u64, gas_threshold: u64) -> String {
    // perf/bench_data/block23043570/gas7000000/final_aggregator_stdin_builder.bin
    format!(
        "./perf/bench_data/block{b}/gas{gas_threshold}/final_aggregator_stdin_builder.bin",
        b = block
    )
}

pub fn agg_file_path(block: u64, gas_threshold: u64, base: &str) -> String {
    format!(
        "./perf/bench_data/block{b}/gas{gas_threshold}/{base}.bin",
        b = block
    )
}
pub fn subblock_builder_path(block: u64, gas_threshold: u64, idx: usize) -> String {
    format!(
        "./perf/bench_data/block{}/gas{}/subblock_stdin_builder_{}.bin",
        block, gas_threshold, idx
    )
}

pub fn build_stdin(input: &ProgramInput) -> anyhow::Result<(u64, EmulatorStdin<Program, Vec<u8>>)> {
    // we'll set this in the match
    let block: u64;

    let stdin: EmulatorStdin<Program, Vec<u8>> = match input {
        ProgramInput::Simple { block: b, input } => {
            block = *b;
            let mut builder =
                EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
            if let Some(bytes) = input {
                builder.write_slice(bytes);
            }
            builder.finalize()
        }

        ProgramInput::Common { task_id, inputs } => {
            block = *task_id;
            let mut builder =
                EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
            for x in inputs {
                let bytes = bincode::serialize(x).context("serialize Common.inputs")?;
                builder.write_slice(&bytes);
            }
            builder.finalize()
        }

        // Aggregator: always load from the corresponding file
        ProgramInput::Aggregator { block: b, .. } => {
            block = *b;
            let gas_threshold = env_usize("GAS_THRESHOLD").unwrap();
            let path = agg_builder_path(block, gas_threshold as u64);
            let mut stdin_builder = load_stdin_builder_from_file(&path)
                .with_context(|| format!("load aggregator stdin from {}", path))?;

            // TRICKY: replace vk digest in aggregator stdin builder
            let vk_digest_buf = std::fs::read(VK_DIGEST_PATH).unwrap();
            stdin_builder.buffer[1] = vk_digest_buf;

            stdin_builder.finalize()
        }

        // Subblock: always load from the corresponding file
        // If your enum variant already carries `deferred_index`, use it.
        // If not, fallback to env var as before.
        ProgramInput::Subblock { block: b, .. } => {
            block = *b;
            let gas_threshold = env_usize("GAS_THRESHOLD").unwrap();
            let idx = env_usize("DEFERRED_INDEX").expect("DEFERRED_INDEX missing");

            let path = subblock_builder_path(block, gas_threshold as u64, idx);
            let stdin_builder = load_stdin_builder_from_file(&path)
                .with_context(|| format!("load subblock stdin from {}", path))?;
            stdin_builder.finalize()
        }
        ProgramInput::AggregatorRaw {
            block: b,
            num_subblocks: _n,
            builder_bytes,
        } => {
            block = *b;

            let mut stdin_builder: EmulatorStdinBuilder<Vec<u8>, KoalaBearPoseidon2> =
                bincode::deserialize(builder_bytes)
                    .context("deserialize AggregatorRaw.builder_bytes")?;
            // TRICKY: replace vk digest in aggregator stdin builder
            let vk_digest_buf = std::fs::read(VK_DIGEST_PATH).unwrap();
            stdin_builder.buffer[1] = vk_digest_buf;

            stdin_builder.finalize()
        }

        ProgramInput::SubblockRaw {
            block: b,
            num_subblocks: _n,
            subblock_index: _i,
            builder_bytes,
        } => {
            block = *b;
            let stdin_builder: EmulatorStdinBuilder<Vec<u8>, KoalaBearPoseidon2> =
                bincode::deserialize(builder_bytes)
                    .context("deserialize SubblockRaw.builder_bytes")?;

            stdin_builder.finalize()
        }
    };

    Ok((block, stdin))
}

pub fn load_reth_input_for_block(block: u64) -> anyhow::Result<Vec<u8>, Error> {
    let dir = env::var("RETH_INPUT_DIR").unwrap_or_else(|_| "perf/bench_data/bins".to_string());
    let path = PathBuf::from(dir).join(format!("{block}.bin"));
    fs::read(&path).with_context(|| {
        format!(
            "Failed to read reth input for block {block} at {}",
            path.display()
        )
    })
}
