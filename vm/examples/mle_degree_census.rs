//! Enumerates every constraint that sits at the global `max_constraint_degree`.
//!
//! Which AIRs pin the global degree decides whether lowering it is worth pricing — but reading the
//! chip sources only finds the constraints one thinks to look at, and
//! `SymbolicConstraints::max_constraint_degree` also folds in interaction `count`/`message`
//! degrees, so an AIR can be pinned at the cap with no top-degree `assert_*` anywhere. This walks
//! the VK's constraint DAG instead and reports, per AIR, what is at the top.
//!
//! Keygen only: no emulation, no block input, no GPU.
//!
//! Usage:
//!   cargo run --release -p pico-vm --example mle_degree_census \
//!     --features "bigint-rug tcmalloc mmap-memory cuda-mle" -- --elf reth --n 188 --field kb

use pico_mle_core::{
    air::symbolic::{SymbolicExpressionDag, SymbolicExpressionNode},
    config::riscv_params_with_100_bits_security,
    StarkEngine,
};
use pico_vm::{
    compiler::riscv::compiler::{Compiler, SourceType},
    configs::stark_config::KoalaBearPoseidon2,
    machine::logger::setup_logger,
    mle::machine::{recursion::Engine, riscv},
};
use tracing::info;

#[path = "common/parse_args.rs"]
mod parse_args;

/// Degree of every DAG node. Compound nodes cache it; leaves do not.
fn node_degrees<F: p3_field::Field>(dag: &SymbolicExpressionDag<F>) -> Vec<usize> {
    dag.nodes
        .iter()
        .map(|n| match n {
            SymbolicExpressionNode::Variable(v) => v.degree_multiple(),
            SymbolicExpressionNode::IsFirstRow
            | SymbolicExpressionNode::IsLastRow
            | SymbolicExpressionNode::IsTransition => 1,
            SymbolicExpressionNode::Constant(_) => 0,
            SymbolicExpressionNode::Add {
                degree_multiple, ..
            }
            | SymbolicExpressionNode::Sub {
                degree_multiple, ..
            }
            | SymbolicExpressionNode::Neg {
                degree_multiple, ..
            }
            | SymbolicExpressionNode::Mul {
                degree_multiple, ..
            } => *degree_multiple,
        })
        .collect()
}

fn main() {
    setup_logger();
    let (elf, _stdin, args) = parse_args::parse_args::<KoalaBearPoseidon2>();
    assert_eq!(args.field, "kb", "kb-only");

    let program = Compiler::new(SourceType::RISCV, elf)
        .expect("failed to parse ELF")
        .compile();

    let engine: Engine = StarkEngine::new(riscv_params_with_100_bits_security(23));
    let airs = riscv::mle_riscv_air_refs(program, true);
    let (_, vk) = engine.keygen_with_app_prep(&airs, riscv::RISCV_APP_PREP_AIR_IDS);
    let global = vk.inner.max_constraint_degree();
    info!("global max_constraint_degree = {global}");

    let mut pinning = 0usize;
    for (air_id, avk) in vk.inner.per_air.iter().enumerate() {
        let d = avk.max_constraint_degree as usize;
        if d < global {
            continue;
        }
        pinning += 1;
        let dag = &avk.symbolic_constraints;
        let degs = node_degrees(&dag.constraints);

        let top_constraints: Vec<usize> = dag
            .constraints
            .constraint_idx
            .iter()
            .enumerate()
            .filter(|(_, idx)| degs[**idx] >= global)
            .map(|(i, _)| i)
            .collect();

        let mut top_counts = 0usize;
        let mut top_fields = 0usize;
        for it in &dag.interactions {
            if degs[it.count] >= global {
                top_counts += 1;
            }
            top_fields += it.message.iter().filter(|f| degs[**f] >= global).count();
        }

        info!(
            "air {air_id:<3} {:<30} deg={d}  cols={:<5} | at-degree-{global}: {} plain constraint(s) of {}, {top_counts} interaction count(s), {top_fields} interaction field(s)",
            riscv::air_name(air_id).unwrap_or("?"),
            avk.params.width.common_main,
            top_constraints.len(),
            dag.constraints.constraint_idx.len(),
        );
        // Ordinals alone do not say WHICH source constraint is at the top, and reading the chip
        // for triple-`when` chains misses the ones whose multiplier is itself degree 2. Print the
        // trace columns each top-degree constraint touches: that identifies the site against the
        // chip's column struct without guessing.
        for i in &top_constraints {
            let root = dag.constraints.constraint_idx[*i];
            let mut seen = vec![false; dag.constraints.nodes.len()];
            let mut stack = vec![root];
            let mut cols_used: Vec<(usize, usize)> = Vec::new();
            while let Some(nid) = stack.pop() {
                if seen[nid] {
                    continue;
                }
                seen[nid] = true;
                match &dag.constraints.nodes[nid] {
                    SymbolicExpressionNode::Variable(v) => {
                        if let Some(off) = v.entry.offset() {
                            cols_used.push((off, v.index));
                        }
                    }
                    SymbolicExpressionNode::Add {
                        left_idx,
                        right_idx,
                        ..
                    }
                    | SymbolicExpressionNode::Sub {
                        left_idx,
                        right_idx,
                        ..
                    }
                    | SymbolicExpressionNode::Mul {
                        left_idx,
                        right_idx,
                        ..
                    } => {
                        stack.push(*left_idx);
                        stack.push(*right_idx);
                    }
                    SymbolicExpressionNode::Neg { idx, .. } => stack.push(*idx),
                    _ => {}
                }
            }
            cols_used.sort_unstable();
            cols_used.dedup();
            let pretty: Vec<String> = cols_used
                .iter()
                .map(|(off, idx)| {
                    if *off == 0 {
                        format!("c{idx}")
                    } else {
                        format!("next.c{idx}")
                    }
                })
                .collect();
            info!("      constraint #{i}: cols {}", pretty.join(" "));
        }
    }
    info!("{pinning} AIR(s) pin the global degree at {global}");
}
