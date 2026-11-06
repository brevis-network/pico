//! Tier probe: does every shape the whitelist admits fit the recursion tiers?
//!
//! The convert ladder has to hold every RISC-V shape the whitelist admits, and
//! `mle_riscv_shapes` makes that set enumerable. This walks all of it, builds the convert program
//! each shape would be verified by, reports which row it takes and the per-chip natural height
//! against that row.
//! No proving, and no keygen for the convert side — the heights come from the program, so
//! building it is the whole cost.
//!
//! The combine tier follows: the per-chip peaks over the 36 node shapes fall on different nodes
//! (Poseidon2Packed on [C2,C2], most chips on [C0,C0]), and the nodes with a B child verify a
//! child padded to the combine row itself, so the row is confirmed by a second probe pass over
//! the row as written (`docs/tier-tables.md`). The deferred node, padded to the combine tier
//! under the whitelist, is checked against it as well. Bootstrapping the combine-tier child
//! layout needs one convert keygen and one combine keygen; the other 35 node shapes are built,
//! not keygen'd. The compress and embed nodes close the walk, each against its own row: compress
//! is the one program over that same combine-tier child, and embed the one program over the
//! compress proof's layout, which a third keygen, of the compress program, yields
//! (`compress_proof_layout`).
//!
//! An overflowing shape fails loudly here rather than part-way through a proving run
//! (`check_recursion_tier` asserts); `MLE_SHAPE_MARGIN=1` adds the per-chip slack lines.
//!
//! Four sections, and four kinds of machine-readable line at `RUST_LOG=info`, which is what the
//! tables are re-measured from (`docs/tier-tables.md`):
//!   - `probe_columns: label <chip ×21>`: the chip order of every `probe_natural:` line, once;
//!   - `probe_natural: convert <label> <log2 ×21>`, one per riscv shape; `probe_natural: combine
//!     <node> <log2 ×21>`, one per node shape (`<node>` is the node label with its space replaced
//!     by `_`, e.g. `[C0,C1]_complete`); `probe_natural: deferred|embed|compress <log2 ×21>`;
//!   - `probe_widths: <chip> prep=<p> main=<m>`: this binary's per-chip trace widths, read off
//!     the convert VK the combine section keygens (the fitting tools' cost table);
//!   - `probe_summary: ...`: the line counts, last.
//!
//! Environment:
//!   `MLE_TIER_PROBE_STRIDE=n`: walk every n-th riscv shape (a quick pass);
//!   `MLE_TIER_PROBE_REPORT_ONLY=1`: report, do not assert. A shape no convert row holds is
//!     counted as "no row" and the walk goes on; nothing panics on tables the circuits have
//!     outgrown, which is the state the tables are re-measured from. The three keygens (the
//!     convert and combine bootstrap keygens, and the compress keygen the embed section needs)
//!     then take the table raised wherever the program is taller than it (logged as `keygen
//!     shape: ... raised`); the child layouts keep the tables' heights, so the measurements are
//!     still against the tables as written.
//!
//! Usage:
//!   MLE_SHAPE_MARGIN=1 RUST_LOG=info,mle_shape_margin=info \
//!     cargo run --release -p pico-vm --example mle_tier_probe
//!   MLE_TIER_PROBE_REPORT_ONLY=1 MLE_TIER_PROBE_STRIDE=50 MLE_SHAPE_MARGIN=1 \
//!     RUST_LOG=info,mle_shape_margin=info cargo run --release -p pico-vm --example mle_tier_probe

use std::{collections::BTreeMap, sync::Arc};

use pico_mle_core::{
    config::{
        compress_params_with_128_bits_security, recursion_params_with_128_bits_security,
        riscv_params_with_128_bits_security,
    },
    StarkEngine,
};
use pico_vm::{
    compiler::riscv::compiler::{Compiler, SourceType},
    instances::chiptype::recursion_chiptype::RecursionChipType,
    machine::{chip::ChipBehavior, logger::setup_logger},
    mle::{
        compiler::recursion::{ConvertProgramInput, ConvertVerifierCircuit, RecursionVkLayout},
        machine::{
            recursion::{
                check_recursion_tier, compress_proof_layout,
                extract_recursion_vk_layout_from_heights, recursion_air_refs_with_preprocessed,
                recursion_natural_rows, recursion_tier_fit, select_convert_row,
                try_select_convert_row, Engine,
            },
            riscv,
            shape::{
                RecursionTier, MLE_RECURSION_COMBINE_LOG_HEIGHTS, MLE_RECURSION_CONVERT_LADDER,
            },
            vk_map::synthesize_riscv_child_heights,
        },
    },
};
use tracing::info;

/// `MLE_TIER_PROBE_REPORT_ONLY=1`: measure and report every shape, assert nothing.
fn report_only() -> bool {
    std::env::var("MLE_TIER_PROBE_REPORT_ONLY")
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// The log2 of the power-of-two height a natural row count pads to.
fn log2_of(rows: usize) -> usize {
    rows.next_power_of_two().trailing_zeros() as usize
}

/// `probe_natural: <role> [<label>] <log2 ×21>`, in `mle_recursion_chips` order, which is the
/// order `recursion_natural_rows` reports in and `probe_columns:` names.
fn natural_line(role: &str, label: Option<&str>, natural: &[(String, usize)]) -> String {
    let heights: Vec<String> = natural
        .iter()
        .map(|(_, rows)| log2_of(*rows).to_string())
        .collect();
    match label {
        Some(label) => format!("probe_natural: {role} {label} {}", heights.join(" ")),
        None => format!("probe_natural: {role} {}", heights.join(" ")),
    }
}

fn main() {
    setup_logger();
    let report_only = report_only();
    if report_only {
        info!("MLE_TIER_PROBE_REPORT_ONLY=1: every shape is measured and reported, none asserted");
    }
    let elf = std::fs::read("./perf/bench_data/rv64/fib-elf").expect("fib elf");
    let program = Compiler::new(SourceType::RISCV, &elf)
        .expect("parse ELF")
        .compile();

    // One RISC-V vk serves every shape: under the catch-all its layout-relevant content is
    // app-independent, and only the per-air heights below vary.
    let engine: Engine = StarkEngine::new(riscv_params_with_128_bits_security(
        riscv::log_stacked_height_from_env(),
    ));
    let airs = riscv::mle_riscv_air_refs(program, true);
    let (_, vk) = engine.keygen_with_app_prep(&airs, riscv::RISCV_APP_PREP_AIR_IDS);
    let vk = Arc::new(vk);

    let chip_names: Vec<String> = RecursionChipType::<riscv::Kb>::mle_recursion_chips()
        .iter()
        .map(ChipBehavior::<riscv::Kb>::name)
        .collect();
    info!("probe_columns: label {}", chip_names.join(" "));

    // Every shape the whitelist admits, not just the per-family catch-alls: a ladder class is
    // smaller than the catch-all but `trace_ordering` sorts by height, so a different relative
    // order can repack the stacking. `MLE_TIER_PROBE_STRIDE=n` walks every n-th shape for a
    // quick pass.
    let stride: usize = std::env::var("MLE_TIER_PROBE_STRIDE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let all = pico_vm::mle::machine::shape::mle_riscv_shapes();
    let shapes: Vec<_> = all.iter().step_by(stride.max(1)).cloned().collect();
    info!(
        "whitelist riscv shapes: {} of {} (stride {stride})",
        shapes.len(),
        all.len()
    );

    // Per chip, the tallest natural height any shape asks for. That maximum is what the tier has
    // to be; anything above it is slack no shape can use.
    let mut peak: BTreeMap<(usize, String), (usize, String)> = BTreeMap::new();
    let mut tier_of: BTreeMap<(usize, String), usize> = BTreeMap::new();
    let mut rows_taken = vec![0usize; MLE_RECURSION_CONVERT_LADDER.len()];
    let last = MLE_RECURSION_CONVERT_LADDER.len() - 1;
    let mut no_row = 0usize;

    for (label, shape) in &shapes {
        let heights = synthesize_riscv_child_heights(&vk, shape);
        let layout = extract_recursion_vk_layout_from_heights(&vk, Some(&heights));
        let program = ConvertVerifierCircuit::build_verify_program(&ConvertProgramInput {
            vk: layout,
            vk_verification: true,
        });
        let natural = recursion_natural_rows(&program);
        info!(
            "{}",
            natural_line("convert", Some(label.as_str()), &natural)
        );
        let selected = if report_only {
            try_select_convert_row(&natural)
        } else {
            Some(select_convert_row(&natural))
        };
        // A shape no row holds is accounted against the last row, the row that would have to
        // grow to admit it; only the report-only mode gets here.
        let (row, held) = match selected {
            Some(row) => (row, true),
            None => (last, false),
        };
        let tier = RecursionTier::Convert(row);
        if held {
            if !report_only {
                check_recursion_tier(label, &natural, tier);
            }
            rows_taken[row] += 1;
        } else {
            no_row += 1;
        }
        for (chip, natural, row_log) in recursion_tier_fit(&natural, tier) {
            let log = log2_of(natural);
            tier_of.insert((row, chip.clone()), row_log);
            let entry = peak.entry((row, chip)).or_insert((0, String::new()));
            if log > entry.0 {
                *entry = (log, label.clone());
            }
        }
        if held {
            info!("{label}: convert row {row}");
        } else {
            info!("{label}: no convert row holds it");
        }
    }

    info!(
        "── per convert row and chip: the tallest any shape on that row needs, against the row ──"
    );
    for (row, taken) in rows_taken.iter().enumerate() {
        let mut reclaimable = 0isize;
        if row == last && no_row > 0 {
            info!("row {row}: {taken} shapes, plus {no_row} no row holds (accounted here)");
        } else {
            info!("row {row}: {taken} shapes");
        }
        for ((r, chip), (log, who)) in &peak {
            if *r != row {
                continue;
            }
            let tier = tier_of[&(row, chip.clone())];
            let slack = tier as isize - *log as isize;
            reclaimable += slack;
            info!("  {chip:<18} peak 2^{log} ({who})  row 2^{tier}  slack {slack}");
        }
        info!("total reclaimable notches on convert row {row}: {reclaimable}");
    }
    if no_row > 0 {
        info!(
            "shapes no convert row holds: {no_row} of {} (the last row would have to grow)",
            shapes.len()
        );
    }

    let nodes = combine_tier_report(&vk, report_only);
    info!(
        "probe_summary: convert {} (no row {no_row}) combine {nodes} deferred 1 embed 1 compress 1",
        shapes.len()
    );
}

/// The combine tier, over every node shape `preregister_standard_shapes` builds; then the
/// deferred node over a B child against the combine tier, the compress node over the same B child
/// against the compress row, and the embed node over the compress proof's layout against the
/// embed row. Returns the number of combine node shapes.
///
/// Children come in one shape per convert ladder row (C0, C1, C2) plus the combine tier (B), so
/// the node shapes are the ordered pairs over {C0, C1, C2, B} at both completeness flags, plus
/// the single-child roots. The per-chip peaks fall on different nodes (for the shipped tables:
/// Poseidon2Packed on [C2,C2], ExtDotProduct and MemoryVar on [C0,C2], UnpackBlock and
/// GkrSumcheckRound on [C0,C1], the rest on [C0,C0]); the nodes with a B child depend on the
/// combine row itself, so the row is confirmed by a second pass over the row as written.
fn combine_tier_report(
    riscv_vk: &Arc<pico_mle_core::keygen::types::MultiStarkVerifyingKey<riscv::Sc>>,
    report_only: bool,
) -> usize {
    let engine: Engine = StarkEngine::new(recursion_params_with_128_bits_security());
    let chips = RecursionChipType::<riscv::Kb>::mle_recursion_chips();
    let tier_heights = |table: &[(&str, usize)]| -> Vec<Option<usize>> {
        chips
            .iter()
            .map(|chip| {
                let name = ChipBehavior::<riscv::Kb>::name(chip);
                Some(
                    table
                        .iter()
                        .find(|(n, _)| *n == name)
                        .map(|(_, log)| *log)
                        .unwrap_or_else(|| panic!("chip `{name}` missing from the tier table")),
                )
            })
            .collect()
    };

    // A convert vk, to hang the convert-tier child layout on: the core catch-all, the largest
    // riscv shape a convert proof can be built over.
    let core: Vec<(String, usize)> = pico_vm::mle::machine::shape::MLE_CORE_CANONICAL_PRESENCE
        .iter()
        .map(|n| {
            (
                n.to_string(),
                pico_vm::mle::machine::shape::bucket_log_height(n, true),
            )
        })
        .collect();
    let heights = synthesize_riscv_child_heights(riscv_vk, &core);
    let layout = extract_recursion_vk_layout_from_heights(riscv_vk, Some(&heights));
    let mut cp = ConvertVerifierCircuit::build_verify_program(&ConvertProgramInput {
        vk: layout,
        vk_verification: true,
    });
    let last = MLE_RECURSION_CONVERT_LADDER.len() - 1;
    let natural_cp = recursion_natural_rows(&cp);
    cp.shape = Some(keygen_shape(
        RecursionTier::Convert(last),
        &natural_cp,
        report_only,
    ));
    let (_, convert_vk) =
        engine.keygen_merged_preprocessed(&recursion_air_refs_with_preprocessed(&Arc::new(cp)));

    // This binary's per-chip trace widths, off that VK. `recursion_air_refs_with_preprocessed`
    // lists the AIRs in `mle_recursion_chips` order, so the per-air keys zip with the chips.
    assert_eq!(
        convert_vk.inner.per_air.len(),
        chips.len(),
        "the convert VK has one per-air key per recursion chip"
    );
    for (chip, air) in chips.iter().zip(&convert_vk.inner.per_air) {
        let name = ChipBehavior::<riscv::Kb>::name(chip);
        let width = &air.params.width;
        info!(
            "probe_widths: {name} prep={} main={}",
            width.preprocessed.unwrap_or(0),
            width.main_width()
        );
    }

    // One child layout per convert row, plus the combine-tier one bootstrapped from the
    // [C_last, C_last] node, exactly as `preregister_standard_shapes` builds them.
    let cs: Vec<_> = MLE_RECURSION_CONVERT_LADDER
        .iter()
        .map(|row| extract_recursion_vk_layout_from_heights(&convert_vk, Some(&tier_heights(row))))
        .collect();
    let (cc, _) = build_combine(
        &[cs[last].clone(), cs[last].clone()],
        false,
        true,
        report_only,
    );
    let (_, combine_vk) =
        engine.keygen_merged_preprocessed(&recursion_air_refs_with_preprocessed(&cc));
    let b = extract_recursion_vk_layout_from_heights(
        &combine_vk,
        Some(&tier_heights(MLE_RECURSION_COMBINE_LOG_HEIGHTS)),
    );
    let mut kinds: Vec<(String, _)> = cs
        .iter()
        .enumerate()
        .map(|(r, c)| (format!("C{r}"), c.clone()))
        .collect();
    kinds.push(("B".to_string(), b.clone()));
    let mut nodes = Vec::new();
    for complete in [false, true] {
        for (ln, l) in &kinds {
            for (rn, r) in &kinds {
                nodes.push((
                    vec![l.clone(), r.clone()],
                    complete,
                    format!("[{ln},{rn}]{}", if complete { " complete" } else { "" }),
                ));
            }
        }
    }
    for (n, k) in &kinds {
        nodes.push((vec![k.clone()], true, format!("[{n}] complete")));
    }
    let n_nodes = nodes.len();

    let mut peak: BTreeMap<String, (usize, String)> = BTreeMap::new();
    let mut tier_of: BTreeMap<String, usize> = BTreeMap::new();
    let mut fit = |label: &str, natural: &[(String, usize)]| {
        let node = label.replace(' ', "_");
        info!("{}", natural_line("combine", Some(node.as_str()), natural));
        if !report_only {
            check_recursion_tier(label, natural, RecursionTier::Combine);
        }
        for (chip, natural, tier) in recursion_tier_fit(natural, RecursionTier::Combine) {
            let log = log2_of(natural);
            tier_of.insert(chip.clone(), tier);
            let e = peak.entry(chip).or_insert((0, String::new()));
            if log > e.0 {
                *e = (log, label.to_string());
            }
        }
        if report_only {
            info!("{label}: measured against the combine tier");
        } else {
            info!("{label}: fits the combine tier");
        }
    };
    for (pair, complete, label) in nodes {
        fit(
            &label,
            &build_combine(&pair, complete, false, report_only).1,
        );
    }
    info!("── combine tier: the tallest any node shape needs ──");
    let mut reclaimable = 0isize;
    for (chip, (log, who)) in &peak {
        let tier = tier_of[chip];
        let slack = tier as isize - *log as isize;
        reclaimable += slack;
        info!("  {chip:<18} peak 2^{log} ({who})  tier 2^{tier}  slack {slack}");
    }
    info!("total reclaimable notches across the combine tier: {reclaimable}");

    // The deferred node takes the combine tier too: its child is a B-shaped complete root. It is
    // reported on its own rather than folded into the peak above, so the combine tier reads as
    // the maximum over the node shapes alone.
    let deferred = ConvertVerifierCircuit::build_deferred_program::<riscv::Kb>(&b, true);
    single_report(
        "deferred",
        &recursion_natural_rows(&deferred),
        RecursionTier::Combine,
        report_only,
    );
    // The compress node: in whitelist mode the one program over the B child, built as
    // `CompressMachine::keygen_for` builds it, which is also the `[B] complete` node shape above.
    let (mut compress_program, over_b) = node_over(&b);
    single_report("compress", &over_b, RecursionTier::Compress, report_only);
    // The embed node verifies the compress proof: keygen the compress program at the
    // compress preset and row (raised where outgrown, in report-only mode), synthesize the compress
    // proof's layout from that key as the soundness manifest does (`compress_proof_layout`, the
    // row's heights), and measure embed's program over it.
    compress_program.shape = Some(keygen_shape(RecursionTier::Compress, &over_b, report_only));
    let compress_engine: Engine = StarkEngine::new(compress_params_with_128_bits_security());
    let (_, compress_vk) = compress_engine.keygen_merged_preprocessed(
        &recursion_air_refs_with_preprocessed(&Arc::new(compress_program)),
    );
    let (_, over_compress) = node_over(&compress_proof_layout(&compress_vk));
    single_report("embed", &over_compress, RecursionTier::Embed, report_only);
    n_nodes
}

/// One program against its tier: the `probe_natural:` line, the per-chip slack and the tightest
/// chip; the tier assertion unless `report_only`.
fn single_report(role: &str, natural: &[(String, usize)], tier: RecursionTier, report_only: bool) {
    info!("{}", natural_line(role, None, natural));
    if !report_only {
        check_recursion_tier(&format!("[B] {role}"), natural, tier);
    }
    let mut worst: Option<(String, isize)> = None;
    for (chip, rows, tier_log) in recursion_tier_fit(natural, tier) {
        let log = log2_of(rows);
        let slack = tier_log as isize - log as isize;
        info!("  {chip:<18} natural 2^{log}  {tier:?} 2^{tier_log}  slack {slack}");
        if worst.as_ref().is_none_or(|(_, s)| slack < *s) {
            worst = Some((chip, slack));
        }
    }
    if let Some((chip, slack)) = worst {
        info!("{role} node against the {tier:?} tier: tightest chip {chip}, slack {slack}");
    }
}

/// The program a complete single-child node runs over `child` in whitelist mode, with its natural
/// row counts: `build_verify_n_program_multi(&[child], false, true, true)`, the call
/// `CompressMachine::keygen_for` (child: the B layout) and `EmbedMachine::keygen_for` (child: the
/// compress proof's layout) make before padding.
fn node_over(
    child: &RecursionVkLayout,
) -> (
    pico_vm::compiler::recursion::program::RecursionProgram<riscv::Kb>,
    Vec<(String, usize)>,
) {
    let program = ConvertVerifierCircuit::build_verify_n_program_multi::<riscv::Kb>(
        &[child],
        false,
        true,
        true,
    );
    let natural = recursion_natural_rows(&program);
    (program, natural)
}

/// The shape a probe keygen takes: the tier's table, or, in report-only mode, that table raised
/// wherever the program is taller than it (`padded_row_count` refuses a declared height below
/// the real one, and the report-only mode has to bootstrap the child layouts from tables the
/// circuits have outgrown). The layouts extracted from the resulting VKs take the tables' heights
/// explicitly, so the raise does not reach them. Each raise is logged.
fn keygen_shape(
    tier: RecursionTier,
    natural: &[(String, usize)],
    report_only: bool,
) -> pico_vm::instances::compiler::shapes::recursion_shape::RecursionPadShape {
    if !report_only {
        return pico_vm::mle::machine::shape::mle_recursion_pad_shape_for(tier);
    }
    for (chip, rows, tier_log) in recursion_tier_fit(natural, tier) {
        let log = log2_of(rows);
        if log > tier_log {
            info!("keygen shape: {chip} raised 2^{tier_log} -> 2^{log}, the {tier:?} table is outgrown");
        }
    }
    pico_vm::mle::machine::shape::mle_recursion_pad_shape_holding(tier, natural)
}

/// The combine node program for `layouts`, at the combine tier, with the natural row counts it
/// had before it took the shape. Only the one program that is keygen'd (`for_keygen`, the
/// bootstrap node) takes the raised shape of [`keygen_shape`] in report-only mode; the 36 the
/// walk builds and does not keygen (the bootstrap node's shape among them, built again) take the
/// table as written, since nothing reads their shape.
#[allow(clippy::type_complexity)]
fn build_combine(
    layouts: &[RecursionVkLayout],
    is_complete: bool,
    for_keygen: bool,
    report_only: bool,
) -> (
    Arc<pico_vm::compiler::recursion::program::RecursionProgram<riscv::Kb>>,
    Vec<(String, usize)>,
) {
    let refs: Vec<_> = layouts.iter().collect();
    let mut p = ConvertVerifierCircuit::build_verify_n_program_multi::<riscv::Kb>(
        &refs,
        false,
        is_complete,
        true,
    );
    let natural = recursion_natural_rows(&p);
    p.shape = Some(if for_keygen {
        keygen_shape(RecursionTier::Combine, &natural, report_only)
    } else {
        pico_vm::mle::machine::shape::mle_recursion_pad_shape_for(RecursionTier::Combine)
    });
    (Arc::new(p), natural)
}
