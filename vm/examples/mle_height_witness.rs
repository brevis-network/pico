//! Records and checks the golden height file, `vm/tests/natural_heights.txt` (`mle::heights`).
//!
//! - `run --guest <name>` emulates a record-parity guest on the input its first run reads, and
//!   `run --elf <path> --input <path>` a guest reading one file, as the single-node prover feeds
//!   reth. Either emulates as that prover does, through the snapshot pipeline under
//!   `EmulatorOpts::bench_riscv_ops()` with `NUM_THREADS` workers and its deferred split
//!   (`--after-every-chunk` takes the one `emulate_with_pipeline` makes), and hands each record to
//!   `prepare_chunk_shaped`, whose hook checks the record's heights and writes them to
//!   `MLE_HEIGHTS`. It needs `--features height-witness`, and proves nothing. The `mle-single-node`
//!   binary of `distributed-vm`, built through `single_node_mle.sh` with `pico-vm/height-witness`
//!   added to `FEATURES`, writes the same lines for the records it proves.
//! - `record [--replace] <file>...` adds run files to the golden file, refusing a record it pins at
//!   other heights under the same key and a line whose heights were not compared with the
//!   history's; `--replace` first drops the golden records under the runs' keys, as an intended
//!   change to the heights needs.
//! - `check <file>...` fails on a run's key the golden file lacks, a record only one of them
//!   holds, and a height that differs.
//!
//! ```text
//! MLE_HEIGHTS=fib.tsv CHUNK_SIZE=8388608 cargo run --release -p pico-vm \
//!   --features height-witness --example mle_height_witness -- run --guest fib
//! cargo run --release -p pico-vm --example mle_height_witness -- check fib.tsv
//! ```

use std::{
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::atomic::{AtomicUsize, Ordering},
};

use clap::{Parser, Subcommand};
use pico_vm::{
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{opts::EmulatorOpts, riscv::record_slots::hold_records_unbounded},
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::{logger::setup_logger, witness::ProvingWitness},
    mle::{
        env_u32,
        heights::{self, Index},
        machine::riscv::{prepare_chunk_shaped, Kb},
    },
    proverchain::riscv::{emulate_snapshot_pipeline_with, DeferredSplit},
};

// Only the guests, their inputs and the program and stdin builders.
#[allow(dead_code)]
#[path = "../tests/common/record_parity.rs"]
mod record_parity;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Emulate a guest and write each record's heights to `MLE_HEIGHTS`.
    Run {
        #[arg(long, conflicts_with_all = ["elf", "input"])]
        guest: Option<String>,
        #[arg(long, requires = "input")]
        elf: Option<PathBuf>,
        #[arg(long, requires = "elf")]
        input: Option<PathBuf>,
        #[arg(long)]
        after_every_chunk: bool,
    },
    /// Add run files to the golden file.
    Record {
        #[arg(long)]
        replace: bool,
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
    /// Check run files against the golden file.
    Check {
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
}

fn main() -> ExitCode {
    setup_logger();
    let result = match Args::parse().command {
        Command::Run {
            guest,
            elf,
            input,
            after_every_chunk,
        } => run(guest, elf.zip(input), after_every_chunk),
        Command::Record { replace, files } => record(replace, &files),
        Command::Check { files } => check(&files),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn run(
    guest: Option<String>,
    file_guest: Option<(PathBuf, PathBuf)>,
    after_every_chunk: bool,
) -> Result<(), String> {
    if !cfg!(feature = "height-witness") {
        return Err("built without the height-witness feature: no height would be written".into());
    }
    if std::env::var_os("MLE_HEIGHTS").is_none() {
        return Err("MLE_HEIGHTS names no file to write the heights to".into());
    }
    hold_records_unbounded();
    let (name, elf, stdin) = match (guest, file_guest) {
        (Some(name), None) => {
            let guest = record_parity::GUESTS
                .iter()
                .find(|guest| guest.name == name)
                .ok_or_else(|| {
                    format!(
                        "{name} is none of the guests {:?}",
                        record_parity::GUESTS.map(|guest| guest.name)
                    )
                })?;
            let stdin = record_parity::stdin(&guest.runs()[0].stdin);
            (name, guest.elf.to_vec(), stdin)
        }
        (None, Some((elf, input))) => (
            elf.display().to_string(),
            read_bytes(&elf)?,
            record_parity::stdin(&[read_bytes(&input)?]),
        ),
        _ => return Err("name a --guest, or an --elf and its --input".into()),
    };
    let witness =
        ProvingWitness::<KoalaBearPoseidon2, RiscvChipType<Kb>, Vec<u8>>::setup_for_mle_riscv(
            record_parity::program(&elf),
            stdin,
            EmulatorOpts::bench_riscv_ops(),
        );
    let workers = env_u32("NUM_THREADS")
        .and_then(|n| NonZeroUsize::new(n as usize))
        .unwrap_or(NonZeroUsize::MIN);
    let deferred_split = if after_every_chunk {
        DeferredSplit::AfterEveryChunk
    } else {
        DeferredSplit::FromChunk16
    };
    let chips = RiscvChipType::<Kb>::all_chips();
    let records = AtomicUsize::new(0);
    emulate_snapshot_pipeline_with(&witness, workers, deferred_split, |record, _done| {
        drop(prepare_chunk_shaped(&chips, record, false));
        records.fetch_add(1, Ordering::Relaxed);
    })
    .map_err(|err| format!("{name}: {err}"))?;
    println!("{name}: {} record(s) packaged", records.into_inner());
    Ok(())
}

fn record(replace: bool, files: &[PathBuf]) -> Result<(), String> {
    let run = run_index(files)?;
    let path = golden_path();
    let merged = heights::merge(read_index(&path)?, run, replace)?;
    std::fs::write(&path, heights::render(&merged))
        .map_err(|err| format!("{}: {err}", path.display()))?;
    println!(
        "{}: {} key(s), {} record(s)",
        path.display(),
        merged.len(),
        record_count(&merged)
    );
    Ok(())
}

fn check(files: &[PathBuf]) -> Result<(), String> {
    let run = run_index(files)?;
    let found = heights::mismatches(&read_index(&golden_path())?, &run);
    if !found.is_empty() {
        return Err(found.join("\n"));
    }
    println!(
        "{} key(s), {} record(s): each pinned, at its heights",
        run.len(),
        record_count(&run)
    );
    Ok(())
}

fn run_index(files: &[PathBuf]) -> Result<Index, String> {
    let mut entries = Vec::new();
    for file in files {
        let text =
            std::fs::read_to_string(file).map_err(|err| format!("{}: {err}", file.display()))?;
        entries.extend(heights::read(&text).map_err(|err| format!("{}: {err}", file.display()))?);
    }
    if entries.is_empty() {
        return Err("the run files hold no record".into());
    }
    heights::index(entries)
}

fn read_index(path: &Path) -> Result<Index, String> {
    let text = std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    heights::read(&text)
        .and_then(heights::index)
        .map_err(|err| format!("{}: {err}", path.display()))
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|err| format!("{}: {err}", path.display()))
}

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("natural_heights.txt")
}

fn record_count(index: &Index) -> usize {
    index.values().map(|records| records.len()).sum()
}
