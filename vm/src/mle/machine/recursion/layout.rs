//! Stacking layout, constraint-DAG extraction, and VK-layout extraction.
//!
//! [`extract_recursion_vk_layout`] projects a RISCV verifying key (and optional proof) into the
//! [`RecursionVkLayout`] the verifier circuit is built from: per-air constraint DAGs
//! ([`to_eval_dag`]), the height-descending trace ordering, and the per-commit stacking placement
//! ([`stacking_layout_for_commit`]). [`recursion_vk_layouts_equal`] is the keygen dedup key.

use p3_field::PrimeField32;

use crate::mle::compiler::recursion::{
    AirStructure, EvalDag, EvalEntry, EvalInteraction, EvalNode, RecursionVkLayout,
};
use pico_mle_core::{
    air::symbolic::{symbolic_variable::Entry, SymbolicConstraintsDag, SymbolicExpressionNode},
    keygen::types::MultiStarkVerifyingKey,
    protocol::{
        proof::Proof,
        stacking::{lifted_log_height, present_gkr_shape, stacking_sort_key, StackedLayout},
    },
};

use super::{witness::digest_to_u32s, Sc};
use crate::mle::machine::riscv::RISCV_APP_PREP_AIR_IDS;

// ─── Stacking layout ─────────────────────────────────────────────────────────

/// Compute `(n = log_height - l_skip, row_idx, stacked_col_idx, need_rot)` for each
/// column of a stacked commit. `matrices` = `(width, log_height)` already sorted by
/// descending `log_height`; `need_rot_per_matrix` is parallel to `matrices`.
/// Returns `(stacked_width, per-sub-column layout)`.
pub fn stacking_layout_for_commit(
    matrices: &[(usize, usize)],
    need_rot_per_matrix: &[bool],
    l_skip: usize,
    n_stack: usize,
) -> (usize, Vec<(isize, usize, usize, bool)>) {
    debug_assert_eq!(matrices.len(), need_rot_per_matrix.len());
    // Project core's greedy placement instead of re-deriving it. `matrices` arrives
    // height-descending with power-of-two slice lengths, so the fill is exact and neither
    // `StackedLayout::new` guard can fire — hence `.expect` rather than `?`.
    let layout = StackedLayout::new(l_skip, l_skip + n_stack, matrices.to_vec()).expect(
        "recursion stacking layout must fit: present-trace heights <= 2^(l_skip + n_stack), \
         and power-of-two slices fill each stacked column exactly",
    );
    let result = layout
        .sorted_cols
        .iter()
        .map(|col| {
            let n = col.slice.log_height() as isize - layout.l_skip() as isize;
            (
                n,
                col.slice.row_idx,
                col.slice.col_idx,
                need_rot_per_matrix[col.mat_idx],
            )
        })
        .collect();
    (layout.width(), result)
}

// ─── Constraint DAG → field-independent EvalDag ──────────────────────────────

/// Convert a [`SymbolicConstraintsDag`] into a field-independent [`EvalDag`] for the
/// recursion verifier circuit. Returns `(uses_public_values, eval_dag)`.
fn to_eval_dag<F: PrimeField32>(dag: &SymbolicConstraintsDag<F>) -> (bool, EvalDag) {
    let mut uses_public_values = false;
    let nodes: Vec<EvalNode> = dag
        .constraints
        .nodes
        .iter()
        .map(|node| match node {
            SymbolicExpressionNode::Variable(var) => {
                let entry = match var.entry {
                    Entry::Preprocessed { offset } => EvalEntry::Preprocessed { offset },
                    Entry::Main { part_index, offset } => EvalEntry::Main { part_index, offset },
                    Entry::Public => {
                        uses_public_values = true;
                        EvalEntry::Public
                    }
                };
                EvalNode::Variable {
                    entry,
                    index: var.index,
                }
            }
            SymbolicExpressionNode::IsFirstRow => EvalNode::IsFirstRow,
            SymbolicExpressionNode::IsLastRow => EvalNode::IsLastRow,
            SymbolicExpressionNode::IsTransition => EvalNode::IsTransition,
            SymbolicExpressionNode::Constant(f) => EvalNode::Constant(f.as_canonical_u32()),
            SymbolicExpressionNode::Add {
                left_idx,
                right_idx,
                ..
            } => EvalNode::Add(*left_idx, *right_idx),
            SymbolicExpressionNode::Sub {
                left_idx,
                right_idx,
                ..
            } => EvalNode::Sub(*left_idx, *right_idx),
            SymbolicExpressionNode::Neg { idx, .. } => EvalNode::Neg(*idx),
            SymbolicExpressionNode::Mul {
                left_idx,
                right_idx,
                ..
            } => EvalNode::Mul(*left_idx, *right_idx),
        })
        .collect();

    let interactions: Vec<EvalInteraction> = dag
        .interactions
        .iter()
        .map(|int| EvalInteraction {
            bus_index: int.kind as u16,
            message: int.message.clone(),
            count: int.count,
            count_weight: int.count_weight,
        })
        .collect();

    let eval_dag = EvalDag {
        nodes,
        constraint_idx: dag.constraints.constraint_idx.clone(),
        interactions,
    };
    (uses_public_values, eval_dag)
}

// ─── VK-layout equality (Convert keygen dedup) ───────────────────────────────

/// Two RISCV proofs share a convert proving key if and only if their [`RecursionVkLayout`]s agree.
/// `n_per_trace` and `stacking_col_layout` are included: two chunks can share
/// `stacking_widths` yet differ in per-trace heights, which changes the verify program.
pub fn recursion_vk_layouts_equal(a: &RecursionVkLayout, b: &RecursionVkLayout) -> bool {
    // The merged commitment VALUE is the child's identity, and identity is witnessed (not
    // baked) into the parent circuit — two same-shape children with different identities
    // share one parent program, so equality compares the MODE only. The lean vk_pre_hash
    // below covers everything shape-relevant.
    a.merged_preprocessed_commit.is_some() == b.merged_preprocessed_commit.is_some()
        && a.trace_ordering == b.trace_ordering
        && a.n_max == b.n_max
        && a.n_logup == b.n_logup
        && a.n_stack == b.n_stack
        && a.l_skip == b.l_skip
        && a.stacking_widths == b.stacking_widths
        && a.vk_pre_hash == b.vk_pre_hash
        && a.per_air.len() == b.per_air.len()
        && a.per_air
            .iter()
            .zip(b.per_air.iter())
            .all(|(pa, pb)| pa.is_present == pb.is_present && pa.log_height == pb.log_height)
        && a.n_per_trace == b.n_per_trace
        && a.stacking_col_layout == b.stacking_col_layout
}

// ─── VK layout extraction ─────────────────────────────────────────────────────

pub fn extract_recursion_vk_layout(
    vk: &MultiStarkVerifyingKey<Sc>,
    proof: Option<&Proof<Sc>>,
) -> RecursionVkLayout {
    // Project the proof onto its per-air (presence, log_height) vector — the only thing a
    // layout takes from a proof. `None` entries are absent AIRs.
    let heights: Option<Vec<Option<usize>>> = proof.map(|p| {
        (0..vk.inner.per_air.len())
            .map(|i| {
                p.trace_vdata
                    .get(i)
                    .and_then(|v| v.as_ref())
                    .map(|vd| vd.log_height)
            })
            .collect()
    });
    extract_recursion_vk_layout_from_heights(vk, heights.as_deref())
}

/// Layout from an explicit per-air (presence, log_height) vector: `Some(log)` = present at that
/// height, `None` = absent; `None` for the whole vector = the worst-case all-present layout.
///
/// This is what lets the vk-map builder SYNTHESIZE layouts without proving: under the shape
/// buckets, heights are a deterministic function of the presence pattern, so
/// `(vk, presence pattern)` fully determines the layout a real proof of that pattern would
/// yield (validated against real proofs by the builder).
pub fn extract_recursion_vk_layout_from_heights(
    vk: &MultiStarkVerifyingKey<Sc>,
    heights: Option<&[Option<usize>]>,
) -> RecursionVkLayout {
    // Merged-preprocessed vks (recursion machines): the single multi-matrix prep commitment
    // becomes a layout-level constant (observed once, stacking commit 1); per-air
    // `preprocessed_commit` stays `None` so every prep AIR observes its log_height like a
    // non-prep AIR (mirroring the host verifier's merged branch).
    let merged_preprocessed_commit: Option<[u32; 8]> = vk
        .inner
        .merged_preprocessed_commit
        .as_ref()
        .map(|c| c.map(|f| PrimeField32::as_canonical_u32(&f)));
    let merged_prep = merged_preprocessed_commit.is_some();
    let params = &vk.inner.params;
    let per_air_vk = &vk.inner.per_air;

    let l_skip = params.l_skip;
    let n_stack = params.n_stack;
    let num_airs = per_air_vk.len();

    // Compute presence and trace_ordering from the proof (or defaults when no proof).
    let (per_air, trace_ordering, n_logup, n_max) = if let Some(heights) = heights {
        // Presence: from trace_vdata (required AIRs are always present).
        let per_air: Vec<AirStructure> = per_air_vk
            .iter()
            .enumerate()
            .map(|(i, avk)| {
                // Merged mode: pdata.commit is the SHARED merged commitment (kept at the
                // layout level, not per air).
                let preprocessed_commit = if merged_prep {
                    None
                } else {
                    avk.preprocessed_data
                        .as_ref()
                        .map(|pdata| pdata.commit.map(|f| PrimeField32::as_canonical_u32(&f)))
                };
                let is_present = heights[i].is_some();
                let (uses_public_values, eval_dag) = to_eval_dag(&avk.symbolic_constraints);
                tracing::trace!(
                    "EvalDag air_id={}: {} nodes, {} constraints, {} interactions",
                    i,
                    eval_dag.nodes.len(),
                    eval_dag.constraint_idx.len(),
                    eval_dag.interactions.len(),
                );
                // App-identity preprocessed table (RISC-V program): witnessed, not baked. Per-air
                // mode ⟺ the RISCV machine (convert/combine keygen use merged mode), so the
                // per-air app-prep set is exactly `RISCV_APP_PREP_AIR_IDS`.
                let app_preprocessed = !merged_prep && RISCV_APP_PREP_AIR_IDS.contains(&i);
                AirStructure {
                    is_required: avk.is_required,
                    is_present,
                    log_height: heights[i],
                    has_preprocessed: avk.preprocessed_data.is_some(),
                    preprocessed_commit,
                    app_preprocessed,
                    num_cached_mains: avk.params.width.cached_mains.len(),
                    num_common_main_cols: avk.params.width.common_main,
                    num_preprocessed_cols: avk.params.width.preprocessed.unwrap_or(0),
                    cached_main_widths: avk.params.width.cached_mains.clone(),
                    num_public_values: avk.params.num_public_values,
                    num_interactions: avk.symbolic_constraints.interactions.len(),
                    need_rot: avk.params.need_rot,
                    uses_public_values,
                    eval_dag,
                }
            })
            .collect();

        // trace_ordering: ALL AIRs (fixed count=num_airs), sorted by descending log_height
        // then air_id — matching the RISCV verifier's (is_none, Reverse(log_height), air_id)
        // sort. Absent AIRs (log_height=0) sort last. This is required by the logup GKR layer:
        // height-descending guarantees each interaction's stacked sub-cube stays aligned to
        // 2^(l_skip+n_lift) (small slices are factors of larger ones placed first).
        let mut trace_ordering: Vec<usize> = (0..num_airs).collect();
        trace_ordering.sort_by_key(|&air_id| {
            let log_height = heights[air_id].unwrap_or(0);
            stacking_sort_key(log_height, air_id)
        });

        // n_logup / n_max: PRESENT AIRs only, via the shared `present_gkr_shape` helper so
        // this cannot drift from the verifier's transcript extractor (`ExtractionShape`).
        // Including absent AIRs' `ni << l_skip` terms can tip `total_interactions` across a
        // power-of-2 boundary and yield an n_logup off-by-one (harmless on large programs like
        // reth, but wrong on small ones like fib), which then mismatches the proof's GKR
        // sumcheck round count.
        let (n_logup, _num_gkr_rounds, n_max) = present_gkr_shape(
            l_skip,
            trace_ordering.iter().filter_map(|&air_id| {
                let log_height = heights[air_id]?;
                Some((
                    per_air_vk[air_id].symbolic_constraints.interactions.len(),
                    log_height,
                ))
            }),
        );

        (per_air, trace_ordering, n_logup, n_max)
    } else {
        // No proof: all AIRs present, identity ordering, worst-case n_logup and n_max.
        let per_air: Vec<AirStructure> = per_air_vk
            .iter()
            .enumerate()
            .map(|(air_id, avk)| {
                let preprocessed_commit = if merged_prep {
                    None
                } else {
                    avk.preprocessed_data
                        .as_ref()
                        .map(|pdata| pdata.commit.map(|f| PrimeField32::as_canonical_u32(&f)))
                };
                let (uses_public_values, eval_dag) = to_eval_dag(&avk.symbolic_constraints);
                tracing::trace!(
                    "EvalDag air_id={}: {} nodes, {} constraints, {} interactions",
                    air_id,
                    eval_dag.nodes.len(),
                    eval_dag.constraint_idx.len(),
                    eval_dag.interactions.len(),
                );
                let app_preprocessed = !merged_prep && RISCV_APP_PREP_AIR_IDS.contains(&air_id);
                AirStructure {
                    is_required: avk.is_required,
                    is_present: true,
                    log_height: Some(l_skip + n_stack),
                    has_preprocessed: avk.preprocessed_data.is_some(),
                    preprocessed_commit,
                    app_preprocessed,
                    num_cached_mains: avk.params.width.cached_mains.len(),
                    num_common_main_cols: avk.params.width.common_main,
                    num_preprocessed_cols: avk.params.width.preprocessed.unwrap_or(0),
                    cached_main_widths: avk.params.width.cached_mains.clone(),
                    num_public_values: avk.params.num_public_values,
                    num_interactions: avk.symbolic_constraints.interactions.len(),
                    need_rot: avk.params.need_rot,
                    uses_public_values,
                    eval_dag,
                }
            })
            .collect();

        let trace_ordering: Vec<usize> = (0..num_airs).collect();

        // Worst-case: all AIRs present at the max stacked height (l_skip + n_stack), via the
        // same `present_gkr_shape` helper so the no-proof and proof branches (and the verifier)
        // agree. n_max collapses to n_stack here.
        let (n_logup, _num_gkr_rounds, n_max) = present_gkr_shape(
            l_skip,
            per_air_vk.iter().map(|avk| {
                (
                    avk.symbolic_constraints.interactions.len(),
                    l_skip + n_stack,
                )
            }),
        );

        (per_air, trace_ordering, n_logup, n_max)
    };

    // Stacking widths (actual number of stacked columns per commit) and layout.
    // stacking_layout_for_commit now returns (stacked_width, per-sub-col layout).
    let mut stacking_widths: Vec<usize> = Vec::new();
    let mut stacking_col_layout: Vec<Vec<(isize, usize, usize, bool)>> = Vec::new();

    // Commit 0: common main. Each air_id in trace_ordering contributes common_main_width columns
    // at that air's log_height. The matrices are already in descending log_height order.
    {
        let commit0_matrices: Vec<(usize, usize)> = trace_ordering
            .iter()
            .map(|&air_id| {
                let (width, log_height) = if let Some(heights) = heights {
                    if let Some(log_height) = heights[air_id] {
                        (per_air_vk[air_id].params.width.common_main, log_height)
                    } else {
                        // absent AIR → width=0 so stacking_layout_for_commit skips it entirely,
                        // matching the actual RISCV proof's stacking which also excluded this AIR
                        (0, 0)
                    }
                } else {
                    (
                        per_air_vk[air_id].params.width.common_main,
                        l_skip + n_stack, // worst-case when no heights
                    )
                };
                (width, log_height)
            })
            .collect();
        let commit0_need_rot: Vec<bool> = trace_ordering
            .iter()
            .map(|&air_id| per_air_vk[air_id].params.need_rot)
            .collect();
        let (sw, layout) =
            stacking_layout_for_commit(&commit0_matrices, &commit0_need_rot, l_skip, n_stack);
        stacking_widths.push(sw);
        stacking_col_layout.push(layout);
    }

    // Merged-preprocessed mode: commit 1 is the machine's single multi-matrix prep commitment.
    // Matrix order = trace_ordering restricted to preprocessed AIRs (the keygen commits prep
    // traces sorted by (Reverse(height), air_idx), which is exactly this restriction).
    if merged_prep {
        let mut matrices: Vec<(usize, usize)> = Vec::new();
        let mut need_rots: Vec<bool> = Vec::new();
        for &air_id in &trace_ordering {
            let avk = &per_air_vk[air_id];
            if avk.preprocessed_data.is_none() {
                continue;
            }
            let is_present = heights.map(|h| h[air_id].is_some()).unwrap_or(true);
            if !is_present {
                continue;
            }
            let log_height = match heights {
                Some(h) => h[air_id].unwrap_or(0),
                None => l_skip + n_stack,
            };
            matrices.push((avk.params.width.preprocessed.unwrap_or(0), log_height));
            need_rots.push(avk.params.need_rot);
        }
        let (sw, layout) = stacking_layout_for_commit(&matrices, &need_rots, l_skip, n_stack);
        stacking_widths.push(sw);
        stacking_col_layout.push(layout);
    }

    // Remaining commits: per-trace preprocessed (per-air mode only) and cached mains
    // (single matrix each). Iterate trace_ordering (height-descending) to match the
    // prover's sort-for-stacking. Only PRESENT AIRs appear in the actual proof's stacked
    // commits.
    for &air_id in &trace_ordering {
        let avk = &per_air_vk[air_id];
        let need_rot = avk.params.need_rot;
        let is_present = heights.map(|h| h[air_id].is_some()).unwrap_or(true);
        if !is_present {
            continue;
        }
        let log_height = match heights {
            Some(h) => h[air_id].unwrap_or(0),
            None => l_skip + n_stack,
        };
        if !merged_prep && avk.preprocessed_data.is_some() {
            let w = avk.params.width.preprocessed.unwrap_or(0);
            let (sw, layout) =
                stacking_layout_for_commit(&[(w, log_height)], &[need_rot], l_skip, n_stack);
            stacking_widths.push(sw);
            stacking_col_layout.push(layout);
        }
        for &w_full in &avk.params.width.cached_mains {
            let (sw, layout) =
                stacking_layout_for_commit(&[(w_full, log_height)], &[need_rot], l_skip, n_stack);
            stacking_widths.push(sw);
            stacking_col_layout.push(layout);
        }
    }

    let whir = &params.whir;
    let num_queries_per_whir_round = whir.rounds.iter().map(|r| r.num_queries).collect();

    // ENFORCEMENT POINT for the trace-height / LogUp mod-p overflow bound: re-derive the host
    // verifier's per-bus bound (mle-core `verifier/mod.rs`,
    // `VerifierError::TraceHeightsTooLarge`) over the heights baked into this layout and
    // reject any layout that could let a child's LogUp fractional sum wrap mod p. The
    // in-circuit recursion verifier does NOT reproduce this inequality; it does not need to,
    // by a three-step argument:
    //   1. a child's per-air heights are BAKED into the parent program (a proof of different
    //      heights does not verify against it) — heights are not a prover degree of freedom;
    //   2. in whitelist mode every acceptable vk is enumerated through this very function
    //      (build_vk_map synthesis + preregister), so the whole vk universe passes here;
    //   3. this assert runs unconditionally (release included) at every layout creation —
    //      the cost is a handful of u64 multiply-adds, paid once per keygen.
    // INVARIANT the argument rests on: heights must REMAIN baked. If any future change makes
    // child heights witnessed (e.g. closest-fit dynamic shapes), this bound must move
    // in-circuit.
    //
    // A present air contributes its proof height; with no proof, the worst case is `l_skip +
    // n_stack`. The shift is done in u64 (the helper returns only the exponent) so an oversized
    // height can't wrap it and slip past the bound.
    assert!(
        vk.inner.trace_height_constraints.iter().all(|constraint| {
            let sum: u64 = (0..num_airs)
                .filter_map(|air_id| {
                    let log_height = match heights {
                        Some(h) => h[air_id]?,
                        None => l_skip + n_stack,
                    };
                    Some(
                        (1u64 << lifted_log_height(log_height, l_skip))
                            * constraint.coefficients[air_id] as u64,
                    )
                })
                .sum();
            sum < constraint.threshold as u64
        }),
        "recursion vk layout violates the host LogUp overflow bound (a bus has \
         Σ 2^lifted·count_weight >= its field-order threshold); these baked trace heights would \
         trip the verifier's TraceHeightsTooLarge check"
    );

    //
    // n_per_trace: log_height - l_skip for each trace in trace_ordering.
    // Absent AIRs (no trace_vdata) use log_height=0 → n_per_trace = -l_skip (negative).
    // In verify_one, negative n takes the safe branch that does NOT index bc_r_challenges.
    let n_per_trace: Vec<isize> = trace_ordering
        .iter()
        .map(|&air_id| {
            let log_height = match heights {
                // absent AIR → log_height=0 → negative n_per_trace
                Some(h) => h[air_id].unwrap_or(0),
                None => l_skip + n_stack, // no heights → worst-case
            };
            log_height as isize - l_skip as isize
        })
        .collect();

    RecursionVkLayout {
        vk_pre_hash: digest_to_u32s(&vk.pre_hash),
        merged_preprocessed_commit,
        l_skip,
        n_stack,
        n_max,
        max_constraint_degree: params.max_constraint_degree,
        n_logup,
        logup_pow_bits: params.logup.pow_bits,
        mu_pow_bits: whir.mu_pow_bits,
        folding_pow_bits: whir.folding_pow_bits,
        query_phase_pow_bits: whir.query_phase_pow_bits,
        k_whir: params.k_whir(),
        num_whir_rounds: params.num_whir_rounds(),
        log_final_poly_len: params.log_final_poly_len(),
        num_queries_per_whir_round,
        per_air,
        trace_ordering,
        n_per_trace,
        stacking_widths,
        stacking_col_layout,
        log_rs_domain_size: params.log_stacked_height() + params.log_blowup,
    }
}

#[cfg(test)]
mod tests {
    use super::stacking_layout_for_commit;

    /// Pins the `StackedLayout::new` projection against a hand-computed packing, covering the cases
    /// the e2e gates never feed it: a zero-width (absent) matrix, one shorter than `2^l_skip`
    /// (negative `n`), and one that overflows into further stacked columns.
    #[test]
    fn stacking_layout_matches_hand_computed_packing() {
        // l_skip = 2, n_stack = 2 → stacked height 2^4 = 16.
        let (l_skip, n_stack) = (2, 2);

        // (width, log_height), height-descending as the function requires. The zero-width entry
        // sorts last exactly as an absent AIR does in `trace_ordering`.
        let matrices = [(3, 4), (2, 3), (1, 1), (0, 0)];
        let need_rot = [true, false, true, false];

        // m0: slice_len 16 → one full stacked column each, cols 0,1,2.  n = 4-2 =  2
        // m1: slice_len  8 → both halves of col 3.                      n = 3-2 =  1
        // m2: log_ht 1 < l_skip → lifted to slice_len 4, col 4.         n = 1-2 = -1
        // m3: width 0 → contributes nothing.
        let expected = vec![
            (2, 0, 0, true),
            (2, 0, 1, true),
            (2, 0, 2, true),
            (1, 0, 3, false),
            (1, 8, 3, false),
            (-1, 0, 4, true),
        ];

        let (stacked_width, layout) =
            stacking_layout_for_commit(&matrices, &need_rot, l_skip, n_stack);

        assert_eq!(layout, expected);
        // 4 filled columns plus the partially-filled col 4.
        assert_eq!(stacked_width, 5);
    }

    /// A single matrix exactly as tall as the stacked matrix occupies one column per trace column,
    /// which is the shape the preprocessed / cached-main call sites pass.
    #[test]
    fn stacking_layout_single_full_height_matrix() {
        let (l_skip, n_stack) = (3, 1);
        let (stacked_width, layout) =
            stacking_layout_for_commit(&[(2, 4)], &[false], l_skip, n_stack);

        assert_eq!(layout, vec![(1, 0, 0, false), (1, 0, 1, false)]);
        assert_eq!(stacked_width, 2);
    }
}
