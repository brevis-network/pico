//! Tier probe: does every shape the whitelist admits fit the recursion tiers?
//!
//! The convert ladder has to hold every RISC-V shape the whitelist admits, and
//! `mle_riscv_shapes` makes that set enumerable. This walks all of it, builds the convert program
//! each shape would be verified by, reports which row it takes and the per-chip natural height
//! against that row.
//! No proving, and no keygen for the convert side — the heights come from the program, so
//! building it is the whole cost.
//!
//! The combine tier follows: its maximum is attained at a node verifying two last-row convert
//! children, so once the convert ladder is fixed the combine tier is too. The deferred node,
//! padded to the combine tier under the whitelist, is checked against it as well. Bootstrapping the
//! combine-tier child layout needs one convert keygen and one combine keygen; the other 35
//! node shapes are built, not keygen'd.
//!
//! An overflowing shape fails loudly here rather than part-way through a proving run
//! (`check_recursion_tier` asserts); `MLE_SHAPE_MARGIN=1` adds the per-chip slack lines.
//!
//! Usage:
//!   MLE_SHAPE_MARGIN=1 RUST_LOG=info,mle_shape_margin=info \
//!     cargo run --release -p pico-vm --example mle_tier_probe

use std::{collections::BTreeMap, sync::Arc};

use pico_mle_core::{
    config::{recursion_params_with_100_bits_security, riscv_params_with_100_bits_security},
    StarkEngine,
};
use pico_vm::{
    compiler::riscv::compiler::{Compiler, SourceType},
    machine::logger::setup_logger,
    mle::{
        compiler::recursion::{ConvertProgramInput, ConvertVerifierCircuit},
        machine::{
            recursion::{
                check_recursion_tier, extract_recursion_vk_layout_from_heights,
                recursion_air_refs_with_preprocessed, recursion_natural_rows, recursion_tier_fit,
                select_convert_row, Engine,
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

fn main() {
    setup_logger();
    let elf = std::fs::read("./perf/bench_data/rv64/fib-elf").expect("fib elf");
    let program = Compiler::new(SourceType::RISCV, &elf)
        .expect("parse ELF")
        .compile();

    // One RISC-V vk serves every shape: under the catch-all its layout-relevant content is
    // app-independent, and only the per-air heights below vary.
    let engine: Engine = StarkEngine::new(riscv_params_with_100_bits_security(
        riscv::log_stacked_height_from_env(),
    ));
    let airs = riscv::mle_riscv_air_refs(program, true);
    let (_, vk) = engine.keygen_with_app_prep(&airs, riscv::RISCV_APP_PREP_AIR_IDS);
    let vk = Arc::new(vk);

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

    for (label, shape) in &shapes {
        let heights = synthesize_riscv_child_heights(&vk, shape);
        let layout = extract_recursion_vk_layout_from_heights(&vk, Some(&heights));
        let program = ConvertVerifierCircuit::build_verify_program(&ConvertProgramInput {
            vk: layout,
            vk_verification: true,
        });
        let natural = recursion_natural_rows(&program);
        let row = select_convert_row(&natural);
        let tier = RecursionTier::Convert(row);
        check_recursion_tier(label, &natural, tier);
        rows_taken[row] += 1;
        for (chip, natural, row_log) in recursion_tier_fit(&natural, tier) {
            let log = natural.next_power_of_two().trailing_zeros() as usize;
            tier_of.insert((row, chip.clone()), row_log);
            let entry = peak.entry((row, chip)).or_insert((0, String::new()));
            if log > entry.0 {
                *entry = (log, label.clone());
            }
        }
        info!("{label}: convert row {row}");
    }

    info!(
        "── per convert row and chip: the tallest any shape on that row needs, against the row ──"
    );
    for (row, taken) in rows_taken.iter().enumerate() {
        let mut reclaimable = 0usize;
        info!("row {row}: {taken} shapes");
        for ((r, chip), (log, who)) in &peak {
            if *r != row {
                continue;
            }
            let tier = tier_of[&(row, chip.clone())];
            let slack = tier - log;
            reclaimable += slack;
            info!("  {chip:<18} peak 2^{log} ({who})  row 2^{tier}  slack {slack}");
        }
        info!("total reclaimable notches on convert row {row}: {reclaimable}");
    }

    combine_tier_report(&vk);
}

/// The combine tier, over every node shape `preregister_standard_shapes` builds plus the deferred
/// node over a B child.
///
/// Children come in one shape per convert ladder row (C0, C1, C2) plus the combine tier (B), so
/// the node shapes are the ordered pairs over {C0, C1, C2, B} at both completeness flags, plus
/// the single-child roots. The maximum is at [C2, C2]: it does the most verifying work, and it
/// depends on the convert ladder rather than on the combine tier, which is why tightening
/// terminates.
fn combine_tier_report(
    riscv_vk: &Arc<pico_mle_core::keygen::types::MultiStarkVerifyingKey<riscv::Sc>>,
) {
    let engine: Engine = StarkEngine::new(recursion_params_with_100_bits_security());
    let chips = pico_vm::instances::chiptype::recursion_chiptype::RecursionChipType::<riscv::Kb>::mle_recursion_chips();
    let tier_heights = |table: &[(&str, usize)]| -> Vec<Option<usize>> {
        chips
            .iter()
            .map(|chip| {
                let name = pico_vm::machine::chip::ChipBehavior::<riscv::Kb>::name(chip);
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
    cp.shape = Some(pico_vm::mle::machine::shape::mle_recursion_pad_shape_for(
        RecursionTier::Convert(last),
    ));
    let (_, convert_vk) =
        engine.keygen_merged_preprocessed(&recursion_air_refs_with_preprocessed(&Arc::new(cp)));

    // One child layout per convert row, plus the combine-tier one bootstrapped from the
    // [C_last, C_last] node, exactly as `preregister_standard_shapes` builds them.
    let cs: Vec<_> = MLE_RECURSION_CONVERT_LADDER
        .iter()
        .map(|row| extract_recursion_vk_layout_from_heights(&convert_vk, Some(&tier_heights(row))))
        .collect();
    let (cc, _) = build_combine(&[cs[last].clone(), cs[last].clone()], false);
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

    let mut peak: BTreeMap<String, (usize, String)> = BTreeMap::new();
    let mut tier_of: BTreeMap<String, usize> = BTreeMap::new();
    let mut fit = |label: &str, natural: &[(String, usize)]| {
        check_recursion_tier(label, natural, RecursionTier::Combine);
        for (chip, natural, tier) in recursion_tier_fit(natural, RecursionTier::Combine) {
            let log = natural.next_power_of_two().trailing_zeros() as usize;
            tier_of.insert(chip.clone(), tier);
            let e = peak.entry(chip).or_insert((0, String::new()));
            if log > e.0 {
                *e = (log, label.to_string());
            }
        }
        info!("{label}: fits the combine tier");
    };
    for (pair, complete, label) in nodes {
        fit(&label, &build_combine(&pair, complete).1);
    }
    // The deferred node takes the combine tier too: its child is a B-shaped complete root.
    let deferred = ConvertVerifierCircuit::build_deferred_program::<riscv::Kb>(&b, true);
    fit("[B] deferred", &recursion_natural_rows(&deferred));
    info!("── combine tier: the tallest any node shape needs ──");
    let mut reclaimable = 0usize;
    for (chip, (log, who)) in &peak {
        let tier = tier_of[chip];
        reclaimable += tier - log;
        info!(
            "  {chip:<18} peak 2^{log} ({who})  tier 2^{tier}  slack {}",
            tier - log
        );
    }
    info!("total reclaimable notches across the combine tier: {reclaimable}");
}

/// The combine node program for `layouts`, at the combine tier, with the natural row counts it
/// had before it took the tier's shape.
#[allow(clippy::type_complexity)]
fn build_combine(
    layouts: &[pico_vm::mle::compiler::recursion::RecursionVkLayout],
    is_complete: bool,
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
    p.shape = Some(pico_vm::mle::machine::shape::mle_recursion_pad_shape_for(
        RecursionTier::Combine,
    ));
    (Arc::new(p), natural)
}
