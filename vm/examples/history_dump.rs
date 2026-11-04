//! Writes history dumps (`emulator::riscv::history_dump`): for each chunk asked for, its fill, its
//! program table and the event streams the host's accessors rebuild from the same history. The
//! kernel repository's loader tests and its device self-test read them.
//!
//! It emulates as the single-node prover does, through the snapshot pipeline under
//! `EmulatorOpts::bench_riscv_ops()` with `NUM_THREADS` workers, a record-parity guest on the input
//! its first run reads (`--guest`) or a guest reading one file (`--elf`, `--input`), as the prover
//! feeds reth. Deferred records carry no history and are never dumped.
//!
//! ```text
//! cargo run --release -p pico-vm --example history_dump -- --guest fib --out dumps
//! NUM_THREADS=8 cargo run --release -p pico-vm --example history_dump -- \
//!   --elf reth.elf --input 23993050.bin --chunks 5,6,37 --out dumps
//! ```

use std::{
    collections::BTreeSet,
    fs::File,
    io::BufWriter,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Mutex,
};

use clap::Parser;
use pico_vm::{
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        opts::EmulatorOpts,
        riscv::{
            history_dump::{self, HostStreams},
            record::EmulationRecord,
            record_slots::hold_records_unbounded,
        },
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::{logger::setup_logger, witness::ProvingWitness},
    mle::{env_u32, machine::riscv::Kb},
    proverchain::riscv::{emulate_snapshot_pipeline_with, DeferredSplit},
};

// Only the guests, their inputs and the program and stdin builders.
#[allow(dead_code)]
#[path = "../tests/common/record_parity.rs"]
mod record_parity;

#[derive(Parser)]
struct Args {
    #[arg(long, conflicts_with_all = ["elf", "input"])]
    guest: Option<String>,
    #[arg(long, requires = "input")]
    elf: Option<PathBuf>,
    #[arg(long, requires = "elf")]
    input: Option<PathBuf>,
    /// The chunks to dump, by index; every chunk with a history when none is named.
    #[arg(long, value_delimiter = ',')]
    chunks: Vec<u32>,
    /// The directory the dumps go to, one `chunk-<index>.hdump` each.
    #[arg(long)]
    out: PathBuf,
}

fn main() -> ExitCode {
    setup_logger();
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<(), String> {
    hold_records_unbounded();
    let (name, elf, stdin) = match (args.guest, args.elf.zip(args.input)) {
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
    std::fs::create_dir_all(&args.out).map_err(|err| format!("{}: {err}", args.out.display()))?;
    let wanted: BTreeSet<u32> = args.chunks.into_iter().collect();
    let witness =
        ProvingWitness::<KoalaBearPoseidon2, RiscvChipType<Kb>, Vec<u8>>::setup_for_mle_riscv(
            record_parity::program(&elf),
            stdin,
            EmulatorOpts::bench_riscv_ops(),
        );
    let workers = env_u32("NUM_THREADS")
        .and_then(|n| NonZeroUsize::new(n as usize))
        .unwrap_or(NonZeroUsize::MIN);
    let written = Mutex::new(Vec::new());
    let failed = Mutex::new(Vec::new());
    emulate_snapshot_pipeline_with(
        &witness,
        workers,
        DeferredSplit::FromChunk16,
        |record, _| {
            let Some(chunk) = record
                .history_view()
                .filter(|view| !view.history.steps.is_empty())
                .map(|view| view.history.chunk)
            else {
                return;
            };
            if !wanted.is_empty() && !wanted.contains(&chunk) {
                return;
            }
            let path = args.out.join(format!("chunk-{chunk}.hdump"));
            match dump(&path, &record) {
                Ok(()) => written.lock().unwrap().push(chunk),
                Err(err) => failed
                    .lock()
                    .unwrap()
                    .push(format!("{}: {err}", path.display())),
            }
        },
    )
    .map_err(|err| format!("{name}: {err}"))?;
    let failed = failed.into_inner().unwrap();
    if !failed.is_empty() {
        return Err(failed.join("\n"));
    }
    let mut written = written.into_inner().unwrap();
    written.sort_unstable();
    let missing: Vec<u32> = wanted
        .iter()
        .filter(|chunk| written.binary_search(chunk).is_err())
        .copied()
        .collect();
    if !missing.is_empty() {
        return Err(format!("{name}: no chunk with a history at {missing:?}"));
    }
    println!(
        "{name}: dumped chunk(s) {written:?} to {}",
        args.out.display()
    );
    Ok(())
}

fn dump(path: &Path, record: &EmulationRecord) -> Result<(), String> {
    let view = record
        .history_view()
        .expect("a dumped record has a history");
    let mut out = BufWriter::new(File::create(path).map_err(|err| err.to_string())?);
    history_dump::write(
        &mut out,
        view.history,
        view.program,
        &HostStreams::of(record).events(),
    )
    .and_then(|()| std::io::Write::flush(&mut out))
    .map_err(|err| err.to_string())
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|err| format!("{}: {err}", path.display()))
}
