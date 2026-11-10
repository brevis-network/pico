//! Holds a guest's device traces to the host's, record by record, under the fixed oracle
//! (`mle::machine::trace_oracle`). Exits 0 only on the verdict the mode asks for.
//!
//! The guest emulates as the single-node prover emulates it (the snapshot pipeline under
//! `EmulatorOpts::bench_riscv_ops()`, `NUM_THREADS` workers, its deferred split), so a chunk index
//! here is the one the bench lines and the chunk census print, counted from 0. Each selected record
//! is packaged for the device, its device context generated on card 0 (pin the card with
//! `CUDA_VISIBLE_DEVICES`), and held to the host context built from the same record.
//!
//! - Default: every record, or `--chunks`' CPU chunks (and every deferred record with
//!   `--deferred`), must pass, every chip that reads the history with a real unit in a chunk having
//!   launched its history kernel for it, and at least one such chip in the run. Records are held
//!   under the prover's bound (`MLE_HISTORY_SLOTS` slots), so each CPU chunk's history is written
//!   into a pinned arena slot and uploaded from there, as the prover's are; a CPU chunk whose
//!   history holds no slot fails.
//!   `--airs` names chips each one must compare with a real unit.
//! - `--guest chip-coverage` runs the chip-coverage guest's pinned ELF, reading nothing; any other
//!   `--guest` is a record-parity guest on its first run's input.
//! - `--poison-history`: every history fill's device region is poisoned before its copies, so a
//!   kernel reading a byte no copy wrote reads poison, the alternation's fills included. Must pass.
//! - `--corrupt-history <table>[:row]` (the positive control): that row of every selected CPU
//!   chunk's history, row 0 unless named, is changed on the card after its upload lands and before
//!   any reader runs (`trace_oracle::corrupt`). The same change made on the host names the airs it
//!   moves; the chunk must fail in exactly those. A change the chunk cannot take, one that moves no
//!   host trace, and a chunk that passes all fail the control.
//! - `--alternate <n>`, `n` at least 2: the first two selected records, which must differ, in every
//!   `--airs` air too, generated `n` times in turn. Held until emulation returns, they hold heap
//!   copies of their histories meanwhile, so neither keeps a slot a later chunk's emulation waits
//!   for; the alternation uploads them from two pinned slots of an arena of their own.
//! - `--digest-out <path>`, beside the default mode or `--poison-history`: once emulation returns,
//!   pass or fail, `path` gets one line per air the device generated for a checked record,
//!   `<record> <air> <rows> <cols> <sha256>`, in record order and then air id. `<record>` is
//!   `chunk-<n>` for CPU chunk `n` and `deferred-<n>` for the record the verdict lines call
//!   `deferred record of chunk <n>`. The hash covers every cell of the device trace in the
//!   device's own row order, each as its canonical `u32` little-endian, taken before any rule
//!   pairs a unit. A tree that must keep every device trace bit-identical writes the same file:
//!   `diff` the two.
//!
//! ```text
//! CUDA_VISIBLE_DEVICES=0 MLE_SPLIT_REPLAY=1 cargo run --release -p pico-vm --features cuda \
//!   --example mle_trace_oracle -- --guest fib --poison-history
//! ... -- --elf perf/bench_data/rv64/reth-elf --input perf/bench_data/rv64/reth-23993050.bin \
//!   --chunks 5,6,37 --alternate 10
//! ... -- --guest chip-coverage --corrupt-history add
//! ... -- --elf perf/bench_data/rv64/reth-elf --input perf/bench_data/rv64/reth-23993050.bin \
//!   --chunks 5,6,37 --digest-out reth-23993050.digests
//! ```

use std::{
    collections::{BTreeMap, BTreeSet},
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
        record::RecordBehavior,
        riscv::history_arena::{HistoryArena, HistoryCapacity, SpillPolicy, Table},
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::{chip::MetaChip, logger::setup_logger, witness::ProvingWitness},
    mle::{
        env_u32,
        machine::{
            riscv::{
                air_id_for, air_name, init_mle_gpu_pool, prepare_chunk_shaped, Kb, PreparedChunk,
                MLE_GPU_DEVICE,
            },
            trace_oracle::{
                self,
                corrupt::{self, Corruption},
                poison, ChunkFailure, HistoryReads, HostSide, Trace,
            },
        },
    },
    proverchain::riscv::{emulate_snapshot_pipeline_with, DeferredSplit},
};
use sha2::{Digest, Sha256};

#[path = "../tests/common/chip_coverage.rs"]
mod chip_coverage;
// Only the guests, their inputs and the program and stdin builders.
#[allow(dead_code)]
#[path = "../tests/common/record_parity.rs"]
mod record_parity;

#[derive(Parser)]
struct Args {
    /// `chip-coverage`, or a record-parity guest on the input its first run reads.
    #[arg(long, conflicts_with = "elf")]
    guest: Option<String>,
    /// A guest ELF; with `--input`, the one file it reads, as the single-node prover feeds reth.
    #[arg(long)]
    elf: Option<PathBuf>,
    #[arg(long, requires = "elf")]
    input: Option<PathBuf>,
    /// CPU chunks to check, counted from 0. Unset: every record.
    #[arg(long, value_delimiter = ',')]
    chunks: Vec<usize>,
    /// With `--chunks`, every deferred record too.
    #[arg(long)]
    deferred: bool,
    /// Chips each checked record must compare with at least one real unit.
    #[arg(long, value_delimiter = ',')]
    airs: Vec<String>,
    /// Whitelist mode: each record pads to the shape the prover picks for it.
    #[arg(long)]
    bucket: bool,
    /// Split deferred records after every chunk rather than from chunk 16.
    #[arg(long)]
    after_every_chunk: bool,
    #[arg(
        long,
        value_parser = Corruption::parse,
        conflicts_with_all = ["poison_history", "alternate"]
    )]
    corrupt_history: Option<Corruption>,
    #[arg(long)]
    poison_history: bool,
    #[arg(long)]
    alternate: Option<usize>,
    /// Each checked record's device traces, one digest line per air, written here.
    #[arg(long, conflicts_with_all = ["corrupt_history", "alternate"])]
    digest_out: Option<PathBuf>,
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

fn air_ids(names: &[String]) -> Result<Vec<usize>, String> {
    names
        .iter()
        .map(|name| air_id_for(name).ok_or_else(|| format!("{name} is no chip of the machine")))
        .collect()
}

fn run(args: Args) -> Result<(), String> {
    let chips = RiscvChipType::<Kb>::all_chips();
    let orchestrator = RiscvChipType::<Kb>::gpu_generate_extra_record_and_main_chips();
    if args.alternate.is_some_and(|rounds| rounds < 2) {
        return Err(
            "--alternate needs at least 2 rounds: one generates no chunk after the other".into(),
        );
    }
    init_mle_gpu_pool(MLE_GPU_DEVICE);

    let (name, elf, stdin) = match (&args.guest, &args.elf) {
        (Some(name), None) if name == "chip-coverage" => (
            name.clone(),
            chip_coverage::elf().to_vec(),
            record_parity::stdin(&[]),
        ),
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
            (name.clone(), guest.elf.to_vec(), stdin)
        }
        (None, Some(elf)) => {
            let input = match &args.input {
                Some(path) => vec![read_bytes(path)?],
                None => Vec::new(),
            };
            (
                elf.display().to_string(),
                read_bytes(elf)?,
                record_parity::stdin(&input),
            )
        }
        _ => return Err("name a --guest, or an --elf".into()),
    };

    let required = air_ids(&args.airs)?;
    let control = args.corrupt_history.is_some();
    if let Some(corruption) = args.corrupt_history {
        println!("changing {corruption} of every selected chunk's history on the card");
        corrupt::arm(corruption);
    } else if args.poison_history {
        println!("poisoning every history fill's device region before its copies");
        poison::arm();
    }

    let witness = ProvingWitness::<KoalaBearPoseidon2, RiscvChipType<Kb>>::setup_for_mle_riscv(
        record_parity::program(&elf),
        stdin,
        EmulatorOpts::bench_riscv_ops(),
    );
    let workers = env_u32("NUM_THREADS")
        .and_then(|n| NonZeroUsize::new(n as usize))
        .unwrap_or(NonZeroUsize::MIN);
    let deferred_split = if args.after_every_chunk {
        DeferredSplit::AfterEveryChunk
    } else {
        DeferredSplit::FromChunk16
    };
    struct State {
        seen: BTreeSet<usize>,
        checked: usize,
        history_reads: usize,
        failed: Vec<String>,
        held: Vec<PreparedChunk>,
        /// Each record's digest lines in air-id order, by its index and then deferred after CPU:
        /// the workers hand records over out of order.
        digests: BTreeMap<(usize, bool), Vec<String>>,
    }
    let state = Mutex::new(State {
        seen: BTreeSet::new(),
        checked: 0,
        history_reads: 0,
        failed: Vec::new(),
        held: Vec::new(),
        digests: BTreeMap::new(),
    });
    let selected = |cpu: bool, chunk: usize| {
        if cpu {
            args.chunks.is_empty() || args.chunks.contains(&chunk)
        } else {
            !control && (args.chunks.is_empty() || args.deferred)
        }
    };

    emulate_snapshot_pipeline_with(&witness, workers, deferred_split, |record, _done| {
        let (cpu, chunk) = (record.is_cpu_chunk, record.chunk_index().saturating_sub(1));
        if !selected(cpu, chunk) {
            return;
        }
        let what = format!(
            "{} {chunk}",
            if cpu {
                "chunk"
            } else {
                "deferred record of chunk"
            }
        );
        let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
        if cpu {
            state.seen.insert(chunk);
            match &record.history {
                Some(history) if history.holds_slot() => {
                    let spilled: Vec<&str> = history.spilled().map(|t| t.name()).collect();
                    if !spilled.is_empty() {
                        println!("{what}: tables {spilled:?} outgrew their arena regions");
                    }
                }
                _ => state.failed.push(format!(
                    "{what}: its history holds no arena slot, so its upload read no pinned memory"
                )),
            }
        }
        let mut prepared = prepare_chunk_shaped(&chips, record, args.bucket);
        if args.alternate.is_some() {
            if state.held.len() < 2 {
                // Held until emulation returns, a record in its slot keeps that slot from every
                // chunk emulated after it, and at two slots the next chunk waits for good. A clone
                // is a heap copy and holds none; this drops the original, and its slot goes back.
                prepared.record.history = prepared.record.history.clone();
                state.held.push(prepared);
            }
            return;
        }
        let host = HostSide::build(&chips, &prepared.record);
        state.checked += 1;
        let moved = match args.corrupt_history {
            None => None,
            Some(corruption) => match moved_airs(&chips, &host, &prepared, corruption) {
                Ok(airs) => Some(airs),
                Err(err) => {
                    state.failed.push(format!("{what}: {corruption}: {err}"));
                    return;
                }
            },
        };
        let digesting = args.digest_out.is_some();
        let label = format!("{}-{chunk}", if cpu { "chunk" } else { "deferred" });
        let mut digests = BTreeMap::<usize, String>::new();
        let verdict = trace_oracle::generate_and_check_with(
            &host,
            &orchestrator,
            &prepared,
            &required,
            |air, trace| {
                if digesting {
                    digests.insert(air, digest_line(&label, air, trace));
                }
            },
        );
        if digesting
            && state
                .digests
                .insert((chunk, !cpu), digests.into_values().collect())
                .is_some()
        {
            state.failed.push(format!(
                "{what}: a second record labelled {label}: the digest file cannot tell them apart"
            ));
        }
        match (verdict, moved) {
            (Ok((verdict, reads)), None) => {
                trace_oracle::log_verdict(chunk, &verdict);
                let airs = verdict.compared.len();
                match reads {
                    HistoryReads::NoHistory => println!(
                        "{what}: {airs} airs equal, none from a history: the record carries none"
                    ),
                    HistoryReads::Read(readers) => println!(
                        "{what}: {airs} airs equal, {readers} of them read from the history"
                    ),
                }
                state.history_reads += reads.count();
            }
            (Err(failures), None) => state
                .failed
                .push(format!("{what}:\n{}", trace_oracle::describe(&failures))),
            (Ok(_), Some(moved)) => state.failed.push(format!(
                "{what}: passed with its history changed on the card, which moves {} on the \
                 host: the change reached no reader",
                names(&moved)
            )),
            (Err(failures), Some(moved)) => {
                let failed: BTreeSet<usize> = failures
                    .iter()
                    .filter_map(|f| match f {
                        ChunkFailure::Air { air, .. } => Some(*air),
                        _ => None,
                    })
                    .collect();
                let only_airs = failures
                    .iter()
                    .all(|f| matches!(f, ChunkFailure::Air { .. }));
                if only_airs && failed == moved {
                    println!(
                        "{what}: failed as the control must, in exactly {}",
                        names(&moved)
                    );
                } else {
                    state.failed.push(format!(
                        "{what}: the change moves {} on the host, and the device failed so:\n{}",
                        names(&moved),
                        trace_oracle::describe(&failures)
                    ));
                }
            }
        }
    })
    .map_err(|err| format!("{name}: {err}"))?;
    corrupt::disarm();

    let mut state = state.into_inner().unwrap_or_else(|e| e.into_inner());
    let missing: Vec<&usize> = args
        .chunks
        .iter()
        .filter(|c| !state.seen.contains(c))
        .collect();
    if !missing.is_empty() {
        state
            .failed
            .push(format!("{name}: no CPU chunk {missing:?} was emulated"));
    }
    if let Some(rounds) = args.alternate {
        match <[PreparedChunk; 2]>::try_from(std::mem::take(&mut state.held)) {
            Err(held) => state.failed.push(format!(
                "{name}: alternation needs two records, {} selected",
                held.len()
            )),
            Ok(mut held) => match pin_held(&mut held) {
                Err(err) => state.failed.push(format!("{name}: alternation: {err}")),
                Ok(()) => match trace_oracle::alternate(
                    &chips,
                    &orchestrator,
                    held.each_ref(),
                    rounds,
                    &required,
                ) {
                    Ok(alternated) => {
                        state.checked += alternated.verdicts.len();
                        state.history_reads += alternated.history_reads;
                        println!("{rounds} alternating rounds equal");
                    }
                    Err(err) => state.failed.push(format!("{name}: alternation: {err}")),
                },
            },
        }
    }
    poison::disarm();
    if let Some(path) = &args.digest_out {
        let airs: usize = state.digests.values().map(Vec::len).sum();
        let text: String = state
            .digests
            .values()
            .flatten()
            .map(|line| format!("{line}\n"))
            .collect();
        match std::fs::write(path, text) {
            Ok(()) => println!(
                "{name}: {airs} device trace digest(s) of {} record(s) written to {}",
                state.digests.len(),
                path.display()
            ),
            Err(err) => state.failed.push(format!("{}: {err}", path.display())),
        }
    }
    if state.checked == 0 {
        state.failed.push(format!("{name}: no record checked"));
    }
    if !control && !state.seen.is_empty() && state.history_reads == 0 {
        state
            .failed
            .push(format!("{name}: no compared air read the history"));
    }
    if state.failed.is_empty() {
        println!(
            "{name}: {} device context(s) held to the host",
            state.checked
        );
        Ok(())
    } else {
        Err(state.failed.join("\n"))
    }
}

/// Puts `held`'s histories, heap copies while emulation ran, back in pinned memory, so the
/// alternation uploads each from a slot as the prover does: an arena of their own, apart from the
/// prover's, with a slot per history and each table's region the larger history's, spilling
/// refused. A slot goes back when its record drops, the arena gone or not.
fn pin_held(held: &mut [PreparedChunk; 2]) -> Result<(), String> {
    let rows: Vec<_> = held
        .iter()
        .filter_map(|chunk| chunk.record.history.as_ref().map(|history| history.rows()))
        .collect();
    let Some(slots) = NonZeroUsize::new(rows.len()) else {
        return Ok(());
    };
    let capacity = Table::ALL
        .into_iter()
        .fold(HistoryCapacity::CENSUS, |capacity, table| {
            let most = rows.iter().map(|rows| rows[table.index()]).max();
            capacity.with_rows(table, most.unwrap_or(0))
        });
    let arena = HistoryArena::pin(slots, capacity.chunk_size(), capacity, SpillPolicy::Refuse)
        .map_err(|err| format!("pinning the held records' histories: {err}"))?;
    for chunk in held {
        if let Some(history) = &mut chunk.record.history {
            *history = arena.fill(history).map_err(|err| err.to_string())?;
        }
    }
    Ok(())
}

/// The airs `corruption` moves in `prepared`'s host traces, `host` being its unchanged ones:
/// those its device context must fail in. `Err` when the record cannot take the change, and when
/// the change moves nothing, which would make the control vacuous.
fn moved_airs(
    chips: &[MetaChip<Kb, RiscvChipType<Kb>>],
    host: &HostSide,
    prepared: &PreparedChunk,
    corruption: Corruption,
) -> Result<BTreeSet<usize>, String> {
    let changed = corrupt::changed_record(&prepared.record, corruption)?;
    let moved = host.differing_airs(&HostSide::build(chips, &changed));
    if moved.is_empty() {
        return Err("the change moves no host trace, so the control would prove nothing".into());
    }
    Ok(moved)
}

/// `label`'s line for `air`: the air's name, its rows and columns, and the SHA-256 of its cells in
/// row order, each as its canonical `u32` little-endian.
fn digest_line(label: &str, air: usize, trace: Trace<'_>) -> String {
    let mut hasher = Sha256::new();
    let mut bytes = Vec::with_capacity(4 << 16);
    for cells in trace.cells.chunks(1 << 16) {
        bytes.clear();
        bytes.extend(cells.iter().flat_map(|cell| cell.to_le_bytes()));
        hasher.update(&bytes);
    }
    let name = air_name(air).map_or_else(|| format!("air-{air}"), str::to_owned);
    format!(
        "{label} {name} {} {} {}",
        trace.height(),
        trace.width,
        hex::encode(hasher.finalize())
    )
}

fn names(airs: &BTreeSet<usize>) -> String {
    let names: Vec<&str> = airs
        .iter()
        .map(|&air| air_name(air).unwrap_or("an unnamed air"))
        .collect();
    names.join(", ")
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|err| format!("{}: {err}", path.display()))
}
