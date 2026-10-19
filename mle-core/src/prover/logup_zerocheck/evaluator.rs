//! Shared constraint-DAG evaluators for the CPU LogUp-ZeroCheck backends.
//!
//! Both CPU backends — the reference column-major one ([`super::ColMajorEvalHelper`]) and the
//! optimized row-major/SIMD one (`cpu::logup_zerocheck::RowMajorEvalHelper`) — evaluate the same
//! symbolic constraint DAG over a `(local, next)` row pair. This module is the single home for
//! that logic: the [`ViewPair`] row-pair accessor and the [`SymbolicEvaluator`] implementations
//! they share ([`ConstraintEvaluator`] over an extension field, and [`PackedConstraintEvaluator`]
//! over `F::Packing` for SIMD), plus the buffer-reusing [`eval_nodes_into`].

use std::{
    iter::zip,
    ops::{Add, Mul, Neg, Sub},
};

use p3_field::{ExtensionField, Field, PackedValue};

use crate::{
    air::symbolic::{
        symbolic_expression::SymbolicEvaluator,
        symbolic_variable::{Entry, SymbolicVariable},
        SymbolicConstraintsDag, SymbolicExpressionDag, SymbolicExpressionNode,
    },
    interaction::Interaction,
};

/// A compacted evaluation plan for one AIR's LogUp interactions: the sub-DAG of constraint-DAG
/// nodes reachable from the interaction message/count roots, in topological order with child
/// indices remapped into [`Self::nodes`], together with the interactions whose `message`/`count`
/// indices now point into that compact node list.
///
/// Built once per AIR when a proving key is transported to a device by
/// [`InteractionEvalPlan::from_dag`] — replacing the old per-present-AIR, per-prover
/// `SymbolicConstraints::from(&dag)` rebuild of the whole DAG into `Arc<SymbolicExpression>` trees.
/// Evaluated per row via [`SymbolicEvaluator::eval_nodes`], so shared subexpressions are computed
/// once and each message/count is a flat-array read rather than a recursive pointer-chasing tree
/// walk. Evaluating this plan yields bit-identical message/count values to walking the original
/// interaction expressions: the sub-DAG keeps every node's operation, dropping only nodes reachable
/// solely from plain constraints.
#[derive(Clone, Debug)]
pub struct InteractionEvalPlan<F> {
    /// Interaction-reachable nodes in topological order; every child `*_idx` field indexes into
    /// this vec.
    pub nodes: Vec<SymbolicExpressionNode<F>>,
    /// Interactions with `message`/`count` node indices remapped into [`Self::nodes`].
    pub interactions: Vec<Interaction<usize>>,
}

/// Evaluate one interaction from an already-evaluated node arena.
///
/// Keeping the `h_β(message, kind)` expression here ensures the materialized GKR input path and
/// the fused weighted-accumulation path cannot drift apart.
#[inline]
fn eval_interaction<F, FF, EF>(
    interaction: &Interaction<usize>,
    nodes: &[FF],
    beta_pows: &[EF],
) -> (FF, EF)
where
    F: Field,
    FF: ExtensionField<F>,
    EF: ExtensionField<FF> + ExtensionField<F>,
{
    let b = F::from_u32(interaction.kind as u32 + 1);
    let msg_len = interaction.message.len();
    debug_assert!(msg_len < beta_pows.len());
    let denom = zip(&interaction.message, beta_pows)
        .fold(beta_pows[msg_len] * b, |h_beta, (&msg_idx, &beta_j)| {
            h_beta + beta_j * nodes[msg_idx]
        });
    (nodes[interaction.count], denom)
}

impl<F: Field> InteractionEvalPlan<F> {
    /// Extract the interaction sub-DAG from a full constraint DAG.
    pub fn from_dag(dag: &SymbolicConstraintsDag<F>) -> Self {
        let all_nodes = &dag.constraints.nodes;
        let n = all_nodes.len();

        // 1. Mark every node reachable from an interaction root (a message field or the count). The
        //    DAG is topologically ordered (a node's children have smaller indices), so a single
        //    high→low sweep propagates "reachable" from each kept node down to its children.
        let mut keep = vec![false; n];
        for interaction in &dag.interactions {
            for &msg_idx in &interaction.message {
                keep[msg_idx] = true;
            }
            keep[interaction.count] = true;
        }
        for idx in (0..n).rev() {
            if !keep[idx] {
                continue;
            }
            match &all_nodes[idx] {
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
                    keep[*left_idx] = true;
                    keep[*right_idx] = true;
                }
                SymbolicExpressionNode::Neg { idx: child, .. } => keep[*child] = true,
                _ => {}
            }
        }

        // 2. Compact the kept nodes, preserving topological order, remapping child indices into the
        //    compact list. `remap[old] = new` is valid for every child because children (smaller
        //    old index) are visited before their parents.
        let mut remap = vec![usize::MAX; n];
        let mut nodes = Vec::new();
        for (idx, node) in all_nodes.iter().enumerate() {
            if !keep[idx] {
                continue;
            }
            remap[idx] = nodes.len();
            let remapped = match node {
                SymbolicExpressionNode::Add {
                    left_idx,
                    right_idx,
                    degree_multiple,
                } => SymbolicExpressionNode::Add {
                    left_idx: remap[*left_idx],
                    right_idx: remap[*right_idx],
                    degree_multiple: *degree_multiple,
                },
                SymbolicExpressionNode::Sub {
                    left_idx,
                    right_idx,
                    degree_multiple,
                } => SymbolicExpressionNode::Sub {
                    left_idx: remap[*left_idx],
                    right_idx: remap[*right_idx],
                    degree_multiple: *degree_multiple,
                },
                SymbolicExpressionNode::Mul {
                    left_idx,
                    right_idx,
                    degree_multiple,
                } => SymbolicExpressionNode::Mul {
                    left_idx: remap[*left_idx],
                    right_idx: remap[*right_idx],
                    degree_multiple: *degree_multiple,
                },
                SymbolicExpressionNode::Neg {
                    idx: child,
                    degree_multiple,
                } => SymbolicExpressionNode::Neg {
                    idx: remap[*child],
                    degree_multiple: *degree_multiple,
                },
                // Leaf nodes carry no child indices.
                SymbolicExpressionNode::Variable(var) => SymbolicExpressionNode::Variable(*var),
                SymbolicExpressionNode::Constant(c) => SymbolicExpressionNode::Constant(*c),
                SymbolicExpressionNode::IsFirstRow => SymbolicExpressionNode::IsFirstRow,
                SymbolicExpressionNode::IsLastRow => SymbolicExpressionNode::IsLastRow,
                SymbolicExpressionNode::IsTransition => SymbolicExpressionNode::IsTransition,
            };
            nodes.push(remapped);
        }

        // 3. Remap the interaction roots into the compact node list.
        let interactions = dag
            .interactions
            .iter()
            .map(|interaction| Interaction {
                message: interaction.message.iter().map(|&i| remap[i]).collect(),
                count: remap[interaction.count],
                kind: interaction.kind,
                count_weight: interaction.count_weight,
            })
            .collect();

        Self {
            nodes,
            interactions,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.interactions.is_empty()
    }

    pub fn len(&self) -> usize {
        self.interactions.len()
    }
}

/// A borrowed view of one trace partition's `local` row together with its optional rotated `next`
/// row. Row access is by `(row_offset, column_idx)` where `row_offset` is 0 (local) or 1 (next).
///
/// The `'a` lifetime binds the view to its source rows, so it cannot outlive them, and `Send`/`Sync`
/// follow from `T`: the view only reads, so sharing one across threads requires `T: Sync`.
pub struct ViewPair<'a, T> {
    local: &'a [T],
    next: Option<&'a [T]>,
}

impl<'a, T> ViewPair<'a, T> {
    fn new(local: &'a [T], next: Option<&'a [T]>) -> Self {
        Self { local, next }
    }

    /// Reads the entry at `column_idx` of the local (`row_offset == 0`) or next
    /// (`row_offset == 1`) row.
    ///
    /// # Safety
    ///
    /// No matrix bounds checks are done. The caller must ensure `column_idx` is in range and that
    /// `next` is present when `row_offset == 1`. Slice borrows enforce the lifetime requirement.
    #[inline]
    pub unsafe fn get(&self, row_offset: usize, column_idx: usize) -> &T {
        match row_offset {
            0 => self.local.get_unchecked(column_idx),
            1 => self.next.unwrap_unchecked().get_unchecked(column_idx),
            _ => panic!("row offset {row_offset} not supported"),
        }
    }
}

/// Evaluates the constraint DAG over an extension field `EF`, one row at a time. Constraints are
/// evaluated on the partitioned `(local, next)` views held here.
pub struct ConstraintEvaluator<'a, F, EF> {
    pub preprocessed: Option<ViewPair<'a, EF>>,
    pub partitioned_main: Vec<ViewPair<'a, EF>>,
    pub is_first_row: EF,
    pub is_last_row: EF,
    pub is_transition: EF,
    pub public_values: &'a [F],
}

impl<F: Field, EF: ExtensionField<F>> SymbolicEvaluator<F, EF> for ConstraintEvaluator<'_, F, EF> {
    fn eval_const(&self, c: F) -> EF {
        c.into()
    }
    fn eval_is_first_row(&self) -> EF {
        self.is_first_row
    }
    fn eval_is_last_row(&self) -> EF {
        self.is_last_row
    }
    fn eval_is_transition(&self) -> EF {
        self.is_transition
    }

    /// SAFETY: we only use this trait implementation after a previous scan has ensured all matrix
    /// bounds are satisfied, so no bounds checks are done here.
    fn eval_var(&self, symbolic_var: SymbolicVariable<F>) -> EF {
        let index = symbolic_var.index;
        match symbolic_var.entry {
            Entry::Preprocessed { offset } => unsafe {
                *self
                    .preprocessed
                    .as_ref()
                    .unwrap_unchecked()
                    .get(offset, index)
            },
            Entry::Main { part_index, offset } => unsafe {
                *self.partitioned_main[part_index].get(offset, index)
            },
            Entry::Public => unsafe { EF::from(*self.public_values.get_unchecked(index)) },
        }
    }
}

/// Split `row_parts` — selectors at index 0, then one entry per trace partition (each optionally
/// followed by its rotated `next` row when `needs_next`) — into the preprocessed view pair and the
/// main-partition view pairs. Shared by the scalar and packed evaluator builders.
pub fn build_view_pairs<'a, T>(
    row_parts: &'a [Vec<T>],
    has_preprocessed: bool,
    needs_next: bool,
) -> (Option<ViewPair<'a, T>>, Vec<ViewPair<'a, T>>) {
    let mut view_pairs: Vec<ViewPair<'a, T>> = if needs_next {
        let (pairs, remainder) = row_parts[1..].as_chunks::<2>();
        debug_assert!(remainder.is_empty());
        pairs
            .iter()
            .map(|pair| ViewPair::new(&pair[0], Some(&pair[1][..])))
            .collect()
    } else {
        row_parts[1..]
            .iter()
            .map(|part| ViewPair::new(part, None))
            .collect()
    };
    let preprocessed = if has_preprocessed {
        Some(view_pairs.remove(0))
    } else {
        None
    };
    (preprocessed, view_pairs)
}

/// Build a scalar [`ConstraintEvaluator`] for one row from its `row_parts` (see
/// [`build_view_pairs`] for the expected layout).
pub fn build_evaluator<'a, F: Field, FF: ExtensionField<F>>(
    row_parts: &'a [Vec<FF>],
    has_preprocessed: bool,
    needs_next: bool,
    public_values: &'a [F],
) -> ConstraintEvaluator<'a, F, FF> {
    let sels = &row_parts[0];
    let (preprocessed, partitioned_main) =
        build_view_pairs(row_parts, has_preprocessed, needs_next);
    ConstraintEvaluator {
        preprocessed,
        partitioned_main,
        is_first_row: sels[0],
        is_transition: sels[1],
        is_last_row: sels[2],
        public_values,
    }
}

impl<F: Field, FF: ExtensionField<F>> ConstraintEvaluator<'_, F, FF> {
    /// Batch this row's constraints with the given λ powers: `Σ_i lambda_pows[i] · c_i(row)`.
    pub fn acc_constraints<EF: ExtensionField<FF>>(
        &self,
        constraints_dag: &SymbolicExpressionDag<F>,
        lambda_pows: &[EF],
    ) -> EF {
        let nodes = self.eval_nodes(&constraints_dag.nodes);
        zip(lambda_pows, &constraints_dag.constraint_idx)
            .fold(EF::ZERO, |acc, (&lambda_pow, &idx)| {
                acc + lambda_pow * nodes[idx]
            })
    }

    /// Evaluate each interaction's `(numerator, denominator)` at this row from the compact
    /// interaction sub-DAG in `plan`. The denominator omits the global `alpha` term.
    ///
    /// The sub-DAG is evaluated once (deduping shared subexpressions), then each interaction's
    /// message fields and count are read by node index — bit-identical to, but cheaper than,
    /// walking a rebuilt `SymbolicExpression` tree per field.
    pub fn eval_interactions<EF>(
        &self,
        plan: &InteractionEvalPlan<F>,
        beta_pows: &[EF],
    ) -> Vec<(FF, EF)>
    where
        EF: ExtensionField<FF> + ExtensionField<F>,
    {
        let nodes = self.eval_nodes(&plan.nodes);
        plan.interactions
            .iter()
            .map(|interaction| eval_interaction::<F, FF, EF>(interaction, &nodes, beta_pows))
            .collect()
    }

    /// Sum the interactions' `(numer, denom)` weighted by `eq_3bs`, returning `[Σ numer, Σ denom]`.
    pub fn acc_interactions<EF>(
        &self,
        plan: &InteractionEvalPlan<F>,
        beta_pows: &[EF],
        eq_3bs: &[EF],
    ) -> [EF; 2]
    where
        EF: ExtensionField<FF> + ExtensionField<F>,
    {
        debug_assert_eq!(eq_3bs.len(), plan.interactions.len());
        let nodes = self.eval_nodes(&plan.nodes);
        let mut numer = EF::ZERO;
        let mut denom = EF::ZERO;
        for (&eq_3b, interaction) in zip(eq_3bs, &plan.interactions) {
            let (n, d) = eval_interaction::<F, FF, EF>(interaction, &nodes, beta_pows);
            numer += eq_3b * n;
            denom += eq_3b * d;
        }
        [numer, denom]
    }
}

/// Evaluates the constraint DAG using packed base field (`F::Packing`), processing `WIDTH`
/// independent rows simultaneously via SIMD.
///
/// On aarch64/NEON: WIDTH=4, on x86/AVX2: WIDTH=8, scalar fallback: WIDTH=1. This reduces the
/// number of DAG walks from N to ceil(N/WIDTH), cutting cache misses on the ~30K-node DAG by
/// WIDTH×.
pub struct PackedConstraintEvaluator<'a, F: Field> {
    pub preprocessed: Option<ViewPair<'a, F::Packing>>,
    pub partitioned_main: Vec<ViewPair<'a, F::Packing>>,
    pub is_first_row: F::Packing,
    pub is_last_row: F::Packing,
    pub is_transition: F::Packing,
    pub public_values: &'a [F],
}

impl<F: Field> SymbolicEvaluator<F, F::Packing> for PackedConstraintEvaluator<'_, F> {
    fn eval_const(&self, c: F) -> F::Packing {
        F::Packing::from_fn(|_| c)
    }
    fn eval_is_first_row(&self) -> F::Packing {
        self.is_first_row
    }
    fn eval_is_last_row(&self) -> F::Packing {
        self.is_last_row
    }
    fn eval_is_transition(&self) -> F::Packing {
        self.is_transition
    }

    fn eval_var(&self, symbolic_var: SymbolicVariable<F>) -> F::Packing {
        let index = symbolic_var.index;
        match symbolic_var.entry {
            Entry::Preprocessed { offset } => unsafe {
                *self
                    .preprocessed
                    .as_ref()
                    .unwrap_unchecked()
                    .get(offset, index)
            },
            Entry::Main { part_index, offset } => unsafe {
                *self.partitioned_main[part_index].get(offset, index)
            },
            Entry::Public => unsafe {
                F::Packing::from_fn(|_| *self.public_values.get_unchecked(index))
            },
        }
    }
}

/// Evaluate DAG nodes into a pre-allocated buffer, avoiding per-call allocation. The buffer is
/// cleared and reused across calls, saving ~120KB allocation per invocation for typical KeccakAir
/// DAGs (~30K nodes).
#[inline]
pub fn eval_nodes_into<F, E>(
    evaluator: &impl SymbolicEvaluator<F, E>,
    nodes: &[SymbolicExpressionNode<F>],
    buf: &mut Vec<E>,
) where
    F: Field,
    E: Add<E, Output = E> + Sub<E, Output = E> + Mul<E, Output = E> + Neg<Output = E> + Clone,
{
    buf.clear();
    for node in nodes {
        let val = match *node {
            SymbolicExpressionNode::Variable(var) => evaluator.eval_var(var),
            SymbolicExpressionNode::Constant(c) => evaluator.eval_const(c),
            SymbolicExpressionNode::Add {
                left_idx,
                right_idx,
                ..
            } => buf[left_idx].clone() + buf[right_idx].clone(),
            SymbolicExpressionNode::Sub {
                left_idx,
                right_idx,
                ..
            } => buf[left_idx].clone() - buf[right_idx].clone(),
            SymbolicExpressionNode::Neg { idx, .. } => -buf[idx].clone(),
            SymbolicExpressionNode::Mul {
                left_idx,
                right_idx,
                ..
            } => buf[left_idx].clone() * buf[right_idx].clone(),
            SymbolicExpressionNode::IsFirstRow => evaluator.eval_is_first_row(),
            SymbolicExpressionNode::IsLastRow => evaluator.eval_is_last_row(),
            SymbolicExpressionNode::IsTransition => evaluator.eval_is_transition(),
        };
        buf.push(val);
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    use super::{ConstraintEvaluator, InteractionEvalPlan, ViewPair};
    use crate::{
        air::symbolic::{
            build_symbolic_constraints_dag,
            symbolic_expression::{SymbolicEvaluator, SymbolicExpression},
            symbolic_variable::{Entry, SymbolicVariable},
            SymbolicConstraints,
        },
        interaction::Interaction,
        lookup::LookupType,
    };

    type F = KoalaBear;

    /// Trivial evaluator resolving a local main-partition-0 column to `row[index]`.
    struct RowEval {
        row: Vec<F>,
    }
    impl SymbolicEvaluator<F, F> for RowEval {
        fn eval_const(&self, c: F) -> F {
            c
        }
        fn eval_var(&self, var: SymbolicVariable<F>) -> F {
            match var.entry {
                Entry::Main {
                    part_index: 0,
                    offset: 0,
                } => self.row[var.index],
                _ => unreachable!("this test uses only local main-partition-0 columns"),
            }
        }
        fn eval_is_first_row(&self) -> F {
            unreachable!()
        }
        fn eval_is_last_row(&self) -> F {
            unreachable!()
        }
        fn eval_is_transition(&self) -> F {
            unreachable!()
        }
    }

    fn col(index: usize) -> SymbolicExpression<F> {
        SymbolicExpression::Variable(SymbolicVariable::new(
            Entry::Main {
                part_index: 0,
                offset: 0,
            },
            index,
        ))
    }

    /// The compact interaction sub-DAG ([`InteractionEvalPlan`]) evaluates each interaction's
    /// message/count to exactly the same field value as walking the rebuilt tree form
    /// (`SymbolicConstraints::from(&dag)` + `eval_expr`) — the byte-for-byte guarantee the LogUp
    /// prover relies on after replacing the per-AIR tree rebuild with node-index reads. Also checks
    /// the plan pruned the constraint-only nodes and preserved interaction metadata/order.
    #[test]
    fn interaction_eval_plan_matches_tree_eval() {
        // Interactions share a subexpression (`col0 + col1`) so dedup is exercised; a constraint
        // referencing only col3/col4 contributes nodes reachable *solely* from constraints, which
        // the plan must prune.
        let shared = col(0) + col(1);
        let interactions = vec![
            Interaction {
                message: vec![shared.clone(), col(2) * col(0)],
                count: col(1) - F::ONE,
                kind: LookupType::Byte,
                count_weight: 0,
            },
            Interaction {
                message: vec![shared.clone() * col(2)],
                count: col(0) + col(2),
                kind: LookupType::Memory,
                count_weight: 3,
            },
        ];
        let constraints = vec![col(3) * col(4) - col(3)];
        let dag = build_symbolic_constraints_dag(&constraints, &interactions);

        let plan = InteractionEvalPlan::from_dag(&dag);
        // The plan holds strictly fewer nodes than the full DAG: the constraint-only nodes are gone.
        assert!(plan.nodes.len() < dag.constraints.nodes.len());
        assert_eq!(plan.len(), dag.interactions.len());
        assert!(!plan.is_empty());

        let eval = RowEval {
            row: (0..5).map(|i| F::from_u32(3 * i as u32 + 2)).collect(),
        };
        let plan_nodes = eval.eval_nodes(&plan.nodes);
        let tree = SymbolicConstraints::from(&dag);

        assert_eq!(plan.interactions.len(), tree.interactions.len());
        for (plan_int, tree_int) in plan.interactions.iter().zip(&tree.interactions) {
            assert_eq!(plan_nodes[plan_int.count], eval.eval_expr(&tree_int.count));
            assert_eq!(plan_int.message.len(), tree_int.message.len());
            for (&msg_idx, msg_expr) in plan_int.message.iter().zip(&tree_int.message) {
                assert_eq!(plan_nodes[msg_idx], eval.eval_expr(msg_expr));
            }
            // Metadata carried through the compaction unchanged.
            assert_eq!(plan_int.kind, tree_int.kind);
            assert_eq!(plan_int.count_weight, tree_int.count_weight);
        }
    }

    /// The fused accumulation path must match materializing every interaction.
    #[test]
    fn fused_interaction_accumulation_matches_materialized_results() {
        let shared = col(0) + col(1);
        let interactions = vec![
            Interaction {
                message: vec![shared.clone(), col(2) * col(0)],
                count: col(1) - F::ONE,
                kind: LookupType::Byte,
                count_weight: 0,
            },
            Interaction {
                message: vec![shared * col(2)],
                count: col(0) + col(2),
                kind: LookupType::Memory,
                count_weight: 1,
            },
        ];
        let dag = build_symbolic_constraints_dag(&[], &interactions);
        let plan = InteractionEvalPlan::from_dag(&dag);
        let row = [F::from_u32(2), F::from_u32(5), F::from_u32(11)];
        let evaluator = ConstraintEvaluator {
            preprocessed: None,
            partitioned_main: vec![ViewPair::new(&row, None)],
            is_first_row: F::ZERO,
            is_last_row: F::ZERO,
            is_transition: F::ONE,
            public_values: &[],
        };
        let beta = F::from_u32(17);
        let beta_pows = [F::ONE, beta, beta.square()];
        let eq_3bs = [F::from_u32(19), F::from_u32(23)];
        let materialized = evaluator.eval_interactions(&plan, &beta_pows);
        let expected = materialized
            .iter()
            .zip(eq_3bs)
            .fold([F::ZERO; 2], |[numer, denom], (&(n, d), eq)| {
                [numer + eq * n, denom + eq * d]
            });
        assert_eq!(
            evaluator.acc_interactions(&plan, &beta_pows, &eq_3bs),
            expected
        );
    }

    /// An AIR with no interactions yields an empty plan (the prover early-outs on `is_empty`).
    #[test]
    fn interaction_eval_plan_empty_when_no_interactions() {
        let dag = build_symbolic_constraints_dag(&[col(1) - col(0) - F::ONE], &[]);
        let plan = InteractionEvalPlan::from_dag(&dag);
        assert!(plan.is_empty());
        assert_eq!(plan.len(), 0);
        assert!(plan.nodes.is_empty());
    }

    #[test]
    fn view_pair_borrows_and_reads_local_and_next_rows() {
        let local = [F::from_u32(3), F::from_u32(5)];
        let next = [F::from_u32(7), F::from_u32(11)];
        let pair = ViewPair::new(&local, Some(&next));

        // SAFETY: both rows have length two and the next row is present.
        unsafe {
            assert_eq!(*pair.get(0, 1), local[1]);
            assert_eq!(*pair.get(1, 0), next[0]);
        }
    }
}
