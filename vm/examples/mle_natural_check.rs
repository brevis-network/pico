//! Does `mle_natural_heights` predict what tracegen actually produces?
//!
//! The shape a record proves under is chosen from the predicted heights, before any trace
//! exists, so a prediction that under-reports by one row hands the prover a shape its trace
//! overflows. This emulates a workload, reads every chunk's real per-air trace height, and
//! compares. No proving.
//!
//! Usage:
//!   cargo run --release -p pico-vm --example mle_natural_check -- --elf keccak --n 10 --field kb
//!   MLE_NATURAL_DUMP=1 ... to print the predicted and generated heights side by side

use p3_matrix::Matrix;
use pico_vm::{
    compiler::riscv::compiler::{Compiler, SourceType},
    configs::stark_config::KoalaBearPoseidon2,
    emulator::opts::EmulatorOpts,
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::logger::setup_logger,
    mle::machine::{
        riscv,
        shape::{mle_natural_heights, MLE_MIN_LOG_HEIGHT},
    },
};
use tracing::info;

#[path = "common/parse_args.rs"]
mod parse_args;

fn main() {
    setup_logger();
    let (elf, stdin, args) = parse_args::parse_args::<KoalaBearPoseidon2>();
    assert_eq!(args.field, "kb", "kb-only");

    let compiler = Compiler::new(SourceType::RISCV, elf).expect("failed to parse ELF");
    let records = riscv::emulate_with_opts(compiler.compile(), &stdin, EmulatorOpts::default())
        .expect("emulation failed")
        .records;
    let chips = RiscvChipType::<riscv::Kb>::all_chips();
    info!("{} chunk(s)", records.len());

    let mut checked = 0usize;
    let mut wrong = 0usize;
    // `MLE_NATURAL_DUMP=1`: print both sides per chunk. The shared argument parser is
    // clap-based and rejects unknown flags, so this is an env var like the other probes.
    let dump = std::env::var("MLE_NATURAL_DUMP").is_ok_and(|v| v == "1");
    for (i, record) in records.iter().enumerate() {
        // Size from the record tracegen reads, not the emulator's: `extra_record` output is
        // appended before any trace is built.
        let augmented = riscv::augmented_record(&chips, record);
        let predicted = mle_natural_heights(&augmented);
        // `bucket = false` leaves the record unshaped, so each trace lands on its natural height.
        let ctx = riscv::build_ctx(&chips, record, false);
        if dump {
            info!("chunk {i}: is_cpu_chunk={}", augmented.is_cpu_chunk);
            for (air_id, actx) in ctx.per_trace.iter() {
                let name = riscv::air_name(*air_id).unwrap_or("?");
                let rows = predicted
                    .get(name)
                    .map_or("-".to_string(), |r| r.to_string());
                info!(
                    "  {name:<26} predicted {rows:>9}  generated {}",
                    actx.common_main.height()
                );
            }
        }
        for (air_id, actx) in ctx.per_trace.iter() {
            let name = riscv::air_name(*air_id).unwrap_or("?");
            // Byte and Program are pinned machine-wide and never take part in a match.
            if name == "Byte" || name == "Program" {
                continue;
            }
            let actual = actx.common_main.height();
            let Some(&rows) = predicted.get(name) else {
                wrong += 1;
                info!("chunk {i}: {name} has no prediction, tracegen gave {actual} rows");
                continue;
            };
            checked += 1;
            // Tracegen pads to a power of two and never below the 2^l_skip floor, so what has to
            // hold is that the raw prediction rounds to the same height.
            let got = rows.max(1).next_power_of_two().max(1 << MLE_MIN_LOG_HEIGHT);
            if got != actual {
                wrong += 1;
                info!(
                    "chunk {i}: {name} predicted {rows} rows -> 2^{} but tracegen gave 2^{} \
                     (trace {} x {})",
                    got.ilog2(),
                    actual.ilog2(),
                    actual,
                    actx.common_main.width()
                );
            }
        }
        // An air with no events is absent from the unbucketed trace set but present under
        // canonical presence, at the floor, so a zero prediction is not a disagreement.
        for (name, rows) in predicted.iter() {
            let generated = ctx
                .per_trace
                .iter()
                .any(|(id, _)| riscv::air_name(*id) == Some(name.as_str()));
            if !generated && *rows > 0 {
                wrong += 1;
                info!("chunk {i}: predicted {name} at {rows} rows, which tracegen did not produce");
            }
        }
    }
    info!("{checked} air heights checked, {wrong} disagreements");
    assert_eq!(
        wrong, 0,
        "the natural-height prediction does not match tracegen"
    );
}
