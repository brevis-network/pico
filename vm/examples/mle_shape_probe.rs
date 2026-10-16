//! A0N shape-bucket probe: emulate an ELF and print, per chunk, each core AIR's
//! event-driven height (pre-padding) plus which optional AIRs are present. Feeds the
//! coarse-bucket (`RiscvPadShape`) configuration for the MLE path.
//!
//! Usage:
//!   cargo run --release -p pico-vm --example mle_shape_probe -- --elf fib --n 3000000 --field kb

use p3_matrix::Matrix;
use pico_mle_core::{config::riscv_params_with_100_bits_security, StarkEngine};
use pico_vm::{
    compiler::riscv::compiler::{Compiler, SourceType},
    configs::stark_config::KoalaBearPoseidon2,
    emulator::opts::EmulatorOpts,
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::logger::setup_logger,
    mle::machine::riscv,
};
use tracing::info;

#[path = "common/parse_args.rs"]
mod parse_args;

fn main() {
    setup_logger();
    let (elf, stdin, args) = parse_args::parse_args::<KoalaBearPoseidon2>();
    assert_eq!(args.field, "kb", "kb-only");

    let compiler = Compiler::new(SourceType::RISCV, elf).expect("failed to parse ELF");
    let program = compiler.compile();
    info!(
        "program: {} instructions (log2 ceil {}), pc_start {:#x}",
        program.instructions.len(),
        usize::BITS
            - program
                .instructions
                .len()
                .next_power_of_two()
                .leading_zeros()
            - 1,
        program.pc_start,
    );

    let emulated = riscv::emulate_with_opts(program, &stdin, EmulatorOpts::default())
        .expect("emulation failed");
    info!(
        "emulated {} chunk(s) into {} record(s)",
        emulated.chunks,
        emulated.records.len()
    );
    let records = emulated.records;
    // Heights via `build_ctx` — the exact traces proving uses (covers every AIR incl.
    // precompiles / memory / byte / program, unlike `riscv_heights`' core-only view).
    let chips = RiscvChipType::<riscv::Kb>::all_chips();
    // `SHAPE_PROBE_NATURAL=1` reads the event-driven heights instead of the bucketed ones: the
    // input a height ladder is fitted to. Bucketed (the default) reads back what the whitelist
    // path actually proves.
    let bucket = !std::env::var("SHAPE_PROBE_NATURAL")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    info!("heights = {}", if bucket { "bucketed" } else { "natural" });
    let mut distinct: std::collections::HashSet<Vec<(usize, usize)>> = Default::default();
    for (i, record) in records.iter().enumerate() {
        let ctx = riscv::build_ctx(&chips, record, bucket);
        let mut named: Vec<(&str, usize, u32)> = ctx
            .per_trace
            .iter()
            .map(|(air_id, actx)| {
                let h = actx.common_main.height();
                let log = usize::BITS - h.next_power_of_two().leading_zeros() - 1;
                (riscv::air_name(*air_id).unwrap_or("?"), h, log)
            })
            .collect();
        named.sort_by_key(|&(_, height, _)| std::cmp::Reverse(height));
        info!("chunk {i}:");
        for (name, h, log) in &named {
            info!("  {name:<24} height {h:>9}  (2^{log})");
        }
        // Shape identity = (air_id, height) set — what the proof layout is keyed on.
        let mut key: Vec<(usize, usize)> = ctx
            .per_trace
            .iter()
            .map(|(air_id, actx)| (*air_id, actx.common_main.height()))
            .collect();
        key.sort_unstable();
        // One machine-readable line per chunk, for the ladder fitter: air_id:log2_height pairs.
        let cells: Vec<String> = key
            .iter()
            .map(|(air_id, h)| {
                let log = usize::BITS - h.next_power_of_two().leading_zeros() - 1;
                format!("{air_id}:{log}")
            })
            .collect();
        info!("[shape] chunk={i} {}", cells.join(" "));
        distinct.insert(key);
    }
    info!("distinct proof shapes: {}", distinct.len());

    // The cross-app acceptance value: with the program table bucketed, the RISC-V vk's lean
    // pre-hash must be IDENTICAL across guest programs.
    let engine: riscv::Engine = StarkEngine::new(riscv_params_with_100_bits_security(
        riscv::log_stacked_height_from_env(),
    ));
    let airs = riscv::mle_riscv_air_refs(compiler.compile(), true);
    let (_, vk) = engine.keygen_with_app_prep(&airs, riscv::RISCV_APP_PREP_AIR_IDS);
    info!("riscv vk lean pre_hash = {:?}", vk.pre_hash);
}
