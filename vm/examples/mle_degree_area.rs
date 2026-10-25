//! Area-weighted per-AIR constraint degrees, using REAL per-chunk trace heights.
//!
//! NOTE: the per-AIR evaluation this bound was built to price was implemented and then reverted —
//! it traded computation for kernel launches and lost on more than one card. The bound is kept
//! because it is also the ceiling that lowering the degree-pinning AIRs would unlock.
//!
//! Weighting the degree histogram by bucket heights assumes every AIR is present at its bucket
//! height, and a real reth chunk is nothing like that: the precompile AIRs hold most of the columns
//! but see zero events, while `Cpu` — the AIR that pins the global degree — is always present and
//! the tallest. So this emulates the block, takes the UNPADDED heights, joins them with each AIR's
//! `vk.max_constraint_degree`, and reports
//!   sum_i area_i * (d - d_i) / d      where area_i = height_i * common_main_cols_i
//!
//! That single law is a rough upper bound, not a prediction. It over-credits column interpolation,
//! whose threads are `num_y * num_columns` regardless of the point count and which reads 2 values
//! per thread and writes `d`, so its saving follows `(2+d)/(2+D)`. The zerocheck kernels do scale
//! with the point count but weight by `num_monomials` / `rules_len` rather than columns. Pricing a
//! real change needs a per-bucket model and a measured ceiling-to-time conversion factor.
//!
//! Usage:
//!   cargo run --release -p pico-vm --example mle_degree_area \
//!     --features "bigint-rug tcmalloc mmap-memory cuda-mle" -- --elf reth --n 188 --field kb

use std::{collections::BTreeMap, sync::Arc};

use p3_matrix::Matrix;
use pico_mle_core::{config::riscv_params_with_100_bits_security, StarkEngine};
use pico_vm::{
    compiler::riscv::compiler::{Compiler, SourceType},
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        opts::EmulatorOpts,
        riscv::{emulator::RiscvEmulator, public_values::RecordFinalPvsState},
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::logger::setup_logger,
    mle::machine::{recursion::Engine, riscv},
};
use tracing::info;

#[path = "common/parse_args.rs"]
mod parse_args;

fn main() {
    setup_logger();
    let (elf, stdin, args) = parse_args::parse_args::<KoalaBearPoseidon2>();
    assert_eq!(args.field, "kb", "kb-only");

    let program = Compiler::new(SourceType::RISCV, elf)
        .expect("failed to parse ELF")
        .compile();

    // Degrees come from the VK (per-AIR `max_constraint_degree`); they are chip properties, so any
    // ELF gives the same numbers.
    let engine: Engine = StarkEngine::new(riscv_params_with_100_bits_security(23));
    let airs = riscv::mle_riscv_air_refs(program.clone(), true);
    let (_, vk) = engine.keygen_with_app_prep(&airs, riscv::RISCV_APP_PREP_AIR_IDS);
    let global = vk.inner.max_constraint_degree();
    let deg: Vec<u8> = vk
        .inner
        .per_air
        .iter()
        .map(|a| a.max_constraint_degree)
        .collect();
    let cols: Vec<usize> = vk
        .inner
        .per_air
        .iter()
        .map(|a| a.params.width.common_main)
        .collect();

    let chips = RiscvChipType::<riscv::Kb>::all_chips();
    info!("global max_constraint_degree = {global}");

    // Who pins the global degree: the global (= proof shape) stays put unless every AIR on this
    // list comes down together, so lowering one of them on its own buys nothing here.
    info!("=== AIRs at the global degree {global} (these pin the proof shape) ===");
    for (i, d) in deg.iter().enumerate() {
        if *d as usize >= global {
            info!(
                "  air {i:<3} {:<28} cols={}",
                riscv::air_name(i).unwrap_or("?"),
                cols[i]
            );
        }
    }

    // (degree) -> (airs seen, area) accumulated over every chunk; UNPADDED heights.
    let mut by_deg: BTreeMap<u8, (usize, u128)> = BTreeMap::new();
    let mut per_air_area: BTreeMap<usize, u128> = BTreeMap::new();
    let mut chunk_i = 0usize;

    // Stream the records instead of collecting them (what `riscv::emulate` does): each record
    // holds buffers from a bounded pinned pool, so holding every chunk at once deadlocks the
    // emulator once the block needs more chunks than the pool has buffers. Blocks 239/240/246 do.
    // Measuring inside the callback drops each record immediately and returns its buffers.
    let final_pvs_state = Arc::new(RecordFinalPvsState::default());
    let mut emulator = RiscvEmulator::new_single::<riscv::Kb>(
        program,
        final_pvs_state,
        EmulatorOpts::default(),
        None,
    );
    emulator.write_stdin(&stdin);
    loop {
        let report = emulator
            .emulate_batch(&mut |record| {
                // `false` = no shape padding: the real event-driven heights (the padded path
                // asserts, because Cpu's real rows exceed its shape bucket at CHUNK_SIZE=2^23).
                let ctx = riscv::build_ctx(&chips, &record, false);
                let mut chunk_area: u128 = 0;
                for (air_id, actx) in ctx.per_trace.iter() {
                    let h = actx.common_main.height() as u128;
                    let area = h * cols[*air_id] as u128;
                    chunk_area += area;
                    *per_air_area.entry(*air_id).or_default() += area;
                    let e = by_deg.entry(deg[*air_id]).or_insert((0, 0));
                    e.0 += 1;
                    e.1 += area;
                }
                // Whether the grouped launch collapses to one group is decided by the degrees
                // actually PRESENT in a chunk, not by the whole AIR list.
                let mut present: Vec<u8> =
                    ctx.per_trace.iter().map(|(id, _)| deg[*id]).collect();
                present.sort_unstable();
                let at_global = present.iter().filter(|d| **d as usize >= global).count();
                info!(
                    "chunk {chunk_i}: {} present AIRs, area = {:.1}M cells, present degrees {:?}, {at_global} at global",
                    ctx.per_trace.len(),
                    chunk_area as f64 / 1e6,
                    present,
                );
                chunk_i += 1;
            })
            .expect("emulate_batch failed");
        if report.done {
            break;
        }
    }
    info!("emulated {chunk_i} chunk(s)");

    let tot: u128 = by_deg.values().map(|v| v.1).sum();
    info!("=== REAL-height area by constraint degree (all chunks) ===");
    for (d, (n, area)) in by_deg.iter() {
        info!(
            "  degree {d:<2}: {n:>4} (air,chunk) pairs   area {:>9.1}M ({:>5.1}%)   saves {:>5.1}% here",
            *area as f64 / 1e6,
            100.0 * *area as f64 / tot as f64,
            100.0 * (global as f64 - *d as f64).max(0.0) / global as f64
        );
    }
    let saved: f64 = by_deg
        .iter()
        .map(|(d, v)| v.1 as f64 * (global as f64 - *d as f64).max(0.0) / global as f64)
        .sum();
    info!(
        "=> REAL-height ceiling = {:.1}% of the mle_rounds round-poly evaluation work",
        100.0 * saved / tot as f64
    );

    // What-if for lowering `Cpu` to 3: the global stays wherever the other AIRs leave it, so this
    // reprices the ceiling with only Cpu's own degree changed.
    let cpu_area: u128 = per_air_area
        .iter()
        .filter(|(id, _)| riscv::air_name(**id) == Some("Cpu"))
        .map(|(_, a)| *a)
        .sum();
    if cpu_area > 0 {
        let extra = cpu_area as f64 * (global as f64 - 3.0).max(0.0) / global as f64;
        info!(
            "=> if Cpu were degree 3: ceiling = {:.1}% (Cpu is {:.1}% of area)",
            100.0 * (saved + extra) / tot as f64,
            100.0 * cpu_area as f64 / tot as f64,
        );
    }

    info!("=== biggest AIRs by real area (name, degree, cols, area) ===");
    let mut rows: Vec<(usize, u128)> = per_air_area.into_iter().collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.1));
    for (air_id, area) in rows.iter() {
        info!(
            "  air {air_id:<3} {:<28} deg={} cols={:<6} area {:>9.1}M ({:>5.1}%)",
            riscv::air_name(*air_id).unwrap_or("?"),
            deg[*air_id],
            cols[*air_id],
            *area as f64 / 1e6,
            100.0 * *area as f64 / tot as f64
        );
    }
}
