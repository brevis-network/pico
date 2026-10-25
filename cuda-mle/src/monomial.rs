//! Host-side monomial expansion feeding the GPU zerocheck.
//!
//! Symbolic constraint DAGs are flattened into sums of monomials, which the monomial kernel
//! then evaluates on the device.
//!
//! The `#[repr(C)]` types below ([`PackedVar`], [`MonomialHeader`], [`LambdaTerm`],
//! [`InteractionMonomialTerm`]) are a FROZEN binary ABI shared with `cuda/include/monomial.cuh`
//! (see the [`entry_type`] doc for the code table and the intentional hole at `2`). The consumer
//! chain is `pkey.rs` (host-side expansion via [`ExpandedMonomials::from_dag`] /
//! [`ExpandedInteractionMonomials::from_symbolic_constraints`], then H2D upload) feeding
//! `logup_zerocheck/batch_mle_monomial.cu` (the GPU-side evaluation kernels).

use std::sync::Arc;

use mle_core::air::symbolic::{
    symbolic_expression::SymbolicExpression,
    symbolic_variable::{Entry, SymbolicVariable},
    SymbolicConstraints, SymbolicExpressionDag, SymbolicExpressionNode,
};
use p3_field::Field;
use rustc_hash::FxHashMap;

/// Entry-type codes packed into the low 4 bits of a [`PackedVar`].
///
/// **FROZEN ABI.** These numeric values are a binary contract shared with the CUDA side —
/// `cuda/include/monomial.cuh`'s `PackedVar::entry_type()` accessor and the monomial kernels
/// dispatch on exactly these codes. They must never change without updating both sides in
/// lockstep (and regenerating any cached keys derived from a monomial layout).
///
/// The value `2` is intentionally unused: it leaves a permanent hole in the code space where a
/// retired `Entry` variant used to live. Do not reuse it.
pub mod entry_type {
    /// `Entry::Preprocessed` — a preprocessed (fixed) trace column.
    pub const PREPROCESSED: u8 = 0;
    /// `Entry::Main` — a main (witness) trace column, possibly partitioned.
    pub const MAIN: u8 = 1;
    // 2 is intentionally unused (a retired `Entry` variant); the code space keeps a hole.
    /// `Entry::Public` — a public value.
    pub const PUBLIC: u8 = 3;
    /// `IsFirstRow` boundary selector.
    pub const IS_FIRST: u8 = 8;
    /// `IsLastRow` boundary selector.
    pub const IS_LAST: u8 = 9;
    /// `IsTransition` transition selector.
    pub const IS_TRANSITION: u8 = 10;
}

/// One factor of a monomial, bit-packed exactly as `cuda/include/monomial.cuh` expects:
/// bits 0..4 entry type, 4..12 part index, 12..16 row offset, 16..32 column index.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct PackedVar(pub u32);

impl PackedVar {
    pub fn new(kind: u8, part: u8, row_off: u8, col: u16) -> Self {
        assert!(row_off < 16, "PackedVar row offset needs to fit in 4 bits");
        Self((kind as u32) | ((part as u32) << 4) | ((row_off as u32) << 12) | ((col as u32) << 16))
    }

    pub fn from_symbolic_var<F: Field>(sv: &SymbolicVariable<F>) -> Self {
        assert!(
            sv.index <= u16::MAX as usize,
            "column index of the symbolic variable does not fit in a PackedVar"
        );
        let (kind, part, row_off) = match sv.entry {
            Entry::Main { part_index, offset } => {
                (entry_type::MAIN, part_index as u8, offset as u8)
            }
            Entry::Preprocessed { offset } => (entry_type::PREPROCESSED, 0, offset as u8),
            Entry::Public => (entry_type::PUBLIC, 0, 0),
        };
        Self::new(kind, part, row_off, sv.index as u16)
    }

    pub fn is_first() -> Self {
        Self::new(entry_type::IS_FIRST, 0, 0, 0)
    }

    pub fn is_last() -> Self {
        Self::new(entry_type::IS_LAST, 0, 0, 0)
    }

    pub fn is_transition() -> Self {
        Self::new(entry_type::IS_TRANSITION, 0, 0, 0)
    }
}

/// Locates one monomial inside the flat buffers: its factors are
/// `variables[var_offset..var_offset + num_vars]` and its terms are
/// `terms[term_offset..term_offset + num_terms]`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MonomialHeader {
    pub var_offset: u32,
    pub term_offset: u32,
    pub num_vars: u16,
    pub num_terms: u16,
}

/// Contribution of a monomial to one constraint: the constraint's index (its power of lambda)
/// and the coefficient it carries there.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LambdaTerm<F> {
    pub constraint_idx: u32,
    pub coefficient: F,
}

/// Contribution of a monomial to one interaction.
/// Numerator:   sum of coefficient * eq_3bs[interaction_idx].
/// Denominator: sum of coefficient * beta_pows[field_idx] * eq_3bs[interaction_idx].
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InteractionMonomialTerm<F> {
    pub coefficient: F,
    pub interaction_idx: u16,
    pub field_idx: u16, // denominator: position in the message (beta power); numerator: 0
}

/// A product of packed variables times a scalar, used while expanding.
#[derive(Clone)]
struct Monomial<F> {
    pub factors: Vec<PackedVar>,
    pub scale: F,
}

/// Constraint monomials laid out in the flat form the GPU kernels read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpandedMonomials<F> {
    pub headers: Vec<MonomialHeader>,
    pub variables: Vec<PackedVar>,
    pub lambda_terms: Vec<LambdaTerm<F>>,
}

impl<F: Field> ExpandedMonomials<F> {
    pub fn from_dag(graph: &SymbolicExpressionDag<F>) -> Self {
        let mut memo: FxHashMap<usize, Arc<[Monomial<F>]>> = FxHashMap::default();

        let mut by_factors: FxHashMap<Vec<PackedVar>, Vec<(u32, F)>> = FxHashMap::default();

        for (ci, &root) in graph.constraint_idx.iter().enumerate() {
            let poly = expand_dag_node(graph, root, &mut memo);
            for m in poly.iter() {
                if m.scale == F::ZERO {
                    continue;
                }
                by_factors
                    .entry(m.factors.clone())
                    .or_default()
                    .push((ci as u32, m.scale));
            }
        }

        let mut grouped: Vec<_> = by_factors.into_iter().collect();
        grouped.sort_by(|(p, _), (q, _)| p.len().cmp(&q.len()).then_with(|| p.cmp(q)));

        let (hdrs, flat_vars, flat_terms) = flatten_monomials(
            grouped,
            |ts| ts.sort_by_key(|(ci, _)| *ci),
            |(ci, c)| LambdaTerm {
                constraint_idx: ci,
                coefficient: c,
            },
        );

        Self {
            headers: hdrs,
            variables: flat_vars,
            lambda_terms: flat_terms,
        }
    }
}

fn expand_dag_node<F: Field>(
    graph: &SymbolicExpressionDag<F>,
    at: usize,
    memo: &mut FxHashMap<usize, Arc<[Monomial<F>]>>,
) -> Arc<[Monomial<F>]> {
    if let Some(hit) = memo.get(&at) {
        return Arc::clone(hit);
    }

    let built = match &graph.nodes[at] {
        SymbolicExpressionNode::Constant(k) => single_term(vec![], *k),
        SymbolicExpressionNode::Variable(v) => {
            single_term(vec![PackedVar::from_symbolic_var(v)], F::ONE)
        }
        SymbolicExpressionNode::IsFirstRow => single_term(vec![PackedVar::is_first()], F::ONE),
        SymbolicExpressionNode::IsLastRow => single_term(vec![PackedVar::is_last()], F::ONE),
        SymbolicExpressionNode::IsTransition => {
            single_term(vec![PackedVar::is_transition()], F::ONE)
        }
        SymbolicExpressionNode::Add {
            left_idx: a,
            right_idx: b,
            ..
        } => {
            let lhs = expand_dag_node(graph, *a, memo);
            let rhs = expand_dag_node(graph, *b, memo);
            let mut acc = Vec::with_capacity(lhs.len() + rhs.len());
            acc.extend(lhs.iter().cloned());
            acc.extend(rhs.iter().cloned());
            merge_duplicates(acc)
        }
        SymbolicExpressionNode::Sub {
            left_idx: a,
            right_idx: b,
            ..
        } => {
            let lhs = expand_dag_node(graph, *a, memo);
            let rhs = expand_dag_node(graph, *b, memo);
            let mut acc = Vec::with_capacity(lhs.len() + rhs.len());
            acc.extend(lhs.iter().cloned());
            for mut m in rhs.iter().cloned() {
                m.scale = -m.scale;
                acc.push(m);
            }
            merge_duplicates(acc)
        }
        SymbolicExpressionNode::Mul {
            left_idx: a,
            right_idx: b,
            ..
        } => {
            let lhs = expand_dag_node(graph, *a, memo);
            let rhs = expand_dag_node(graph, *b, memo);
            let mut acc = Vec::with_capacity(lhs.len() * rhs.len());
            for u in lhs.iter() {
                for w in rhs.iter() {
                    let mut prod = u.factors.clone();
                    prod.extend(&w.factors);
                    prod.sort();
                    acc.push(Monomial {
                        factors: prod,
                        scale: u.scale * w.scale,
                    });
                }
            }
            merge_duplicates(acc)
        }
        SymbolicExpressionNode::Neg { idx: a, .. } => expand_dag_node(graph, *a, memo)
            .iter()
            .cloned()
            .map(|mut m| {
                m.scale = -m.scale;
                m
            })
            .collect(),
    };

    let shared = Arc::from(built);
    memo.insert(at, Arc::clone(&shared));
    shared
}

fn single_term<F: Field>(factors: Vec<PackedVar>, scale: F) -> Vec<Monomial<F>> {
    vec![Monomial { factors, scale }]
}

/// Writes grouped monomials into a header list plus flat variable and term buffers, in the
/// order the groups are given.
fn flatten_monomials<In, Out, SortFn, MapFn>(
    groups: impl IntoIterator<Item = (Vec<PackedVar>, Vec<In>)>,
    mut order_terms: SortFn,
    mut convert: MapFn,
) -> (Vec<MonomialHeader>, Vec<PackedVar>, Vec<Out>)
where
    SortFn: FnMut(&mut Vec<In>),
    MapFn: FnMut(In) -> Out,
{
    let it = groups.into_iter();
    let (lower, _) = it.size_hint();
    let mut hdrs = Vec::with_capacity(lower);
    let mut flat_vars = Vec::new();
    let mut flat_terms = Vec::new();

    for (factors, mut ts) in it {
        order_terms(&mut ts);
        assert!(
            factors.len() <= u16::MAX as usize,
            "a monomial header cannot describe this many variables"
        );
        assert!(
            ts.len() <= u16::MAX as usize,
            "a monomial header cannot describe this many terms"
        );
        hdrs.push(MonomialHeader {
            var_offset: flat_vars.len() as u32,
            num_vars: factors.len() as u16,
            term_offset: flat_terms.len() as u32,
            num_terms: ts.len() as u16,
        });
        flat_vars.extend(factors);
        flat_terms.extend(ts.into_iter().map(&mut convert));
    }

    (hdrs, flat_vars, flat_terms)
}

/// Adds up the scales of monomials with identical factor lists and drops the ones that cancel.
fn merge_duplicates<F: Field>(input: Vec<Monomial<F>>) -> Vec<Monomial<F>> {
    let mut sums: FxHashMap<Vec<PackedVar>, F> = FxHashMap::default();
    for m in input {
        *sums.entry(m.factors).or_insert(F::ZERO) += m.scale;
    }
    sums.into_iter()
        .filter(|(_, s)| *s != F::ZERO)
        .map(|(factors, scale)| Monomial { factors, scale })
        .collect()
}

// ----------------------------------------------------------------------------
// LogUp interactions: numerator / denominator monomials
// ----------------------------------------------------------------------------

/// Interaction (LogUp) monomials laid out in the flat form the GPU kernels read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpandedInteractionMonomials<F> {
    /// Headers of the numerator (multiplicity) monomials.
    pub numer_headers: Vec<MonomialHeader>,
    /// Flat factor buffer for the numerator monomials.
    pub numer_variables: Vec<PackedVar>,
    /// Numerator terms; `field_idx` is always 0 here.
    pub numer_terms: Vec<InteractionMonomialTerm<F>>,
    /// Headers of the denominator (message) monomials.
    pub denom_headers: Vec<MonomialHeader>,
    /// Flat factor buffer for the denominator monomials.
    pub denom_variables: Vec<PackedVar>,
    /// Denominator terms, tagged with interaction and message position.
    pub denom_terms: Vec<InteractionMonomialTerm<F>>,
    /// How many interactions the AIR has.
    pub num_interactions: u32,
    /// Longest message among the interactions.
    pub max_fields_len: usize,
}

impl<F: Field> ExpandedInteractionMonomials<F> {
    /// Expands every interaction's multiplicity and message fields into monomials.
    pub fn from_symbolic_constraints(sym_constraints: &SymbolicConstraints<F>) -> Self {
        let ints = &sym_constraints.interactions;
        if ints.is_empty() {
            // No interactions: every buffer stays empty.
            return Self {
                numer_headers: Vec::new(),
                numer_variables: Vec::new(),
                numer_terms: Vec::new(),
                // denominator side
                denom_headers: Vec::new(),
                denom_variables: Vec::new(),
                denom_terms: Vec::new(),
                num_interactions: 0,
                max_fields_len: 0,
            };
        }

        let widest = ints.iter().map(|it| it.message.len()).max().unwrap_or(0);

        // Numerator: expand each multiplicity (`count`) and group the resulting monomials by
        // their factor list, remembering (interaction, coefficient) per occurrence.
        let mut numer_groups: FxHashMap<Vec<PackedVar>, Vec<(u16, F)>> = FxHashMap::default();
        for (interaction_pos, it) in ints.iter().enumerate() {
            let poly = expand_expr_tree(&it.count);
            for m in poly {
                if m.scale == F::ZERO {
                    continue;
                }
                numer_groups
                    .entry(m.factors)
                    .or_default()
                    .push((interaction_pos as u16, m.scale));
            }
        }

        // Denominator: expand each message field separately. A field at position `field_pos_idx`
        // contributes coefficient * beta_pows[fi] * eq_3bs[interaction], so the group entries
        // are (interaction, field position, coefficient).
        let mut denom_groups: FxHashMap<Vec<PackedVar>, Vec<(u16, u16, F)>> = FxHashMap::default();
        for (interaction_pos, it) in ints.iter().enumerate() {
            for (field_pos_idx, field_expr) in it.message.iter().enumerate() {
                let poly = expand_expr_tree(field_expr);
                for m in poly {
                    if m.scale == F::ZERO {
                        continue;
                    }
                    denom_groups.entry(m.factors).or_default().push((
                        interaction_pos as u16,
                        field_pos_idx as u16,
                        m.scale,
                    ));
                }
            }
        }

        // Sort both maps by `from_dag`'s comparator ((len, vars)) before serializing, so the two
        // expansion paths (`from_dag` / `from_symbolic_constraints`) lay out the GPU buffer in the
        // same deterministic order instead of arbitrary hashmap iteration order. Field sums are
        // unaffected by this reordering; only the buffer layout changes.
        let mut numer_sorted: Vec<_> = numer_groups.into_iter().collect();
        numer_sorted.sort_by(|(p, _), (q, _)| p.len().cmp(&q.len()).then_with(|| p.cmp(q)));

        let (n_hdrs, n_vars, n_terms) = flatten_monomials(
            numer_sorted,
            |_| {},
            |(interaction_pos, c)| InteractionMonomialTerm {
                interaction_idx: interaction_pos,
                field_idx: 0, // not used on the numerator side
                coefficient: c,
            },
        );

        let mut denom_sorted: Vec<_> = denom_groups.into_iter().collect();
        denom_sorted.sort_by(|(p, _), (q, _)| p.len().cmp(&q.len()).then_with(|| p.cmp(q)));

        let (d_hdrs, d_vars, d_terms) = flatten_monomials(
            denom_sorted,
            |_| {},
            |(interaction_pos, field_pos_idx, c)| InteractionMonomialTerm {
                interaction_idx: interaction_pos,
                field_idx: field_pos_idx,
                coefficient: c,
            },
        );

        Self {
            numer_headers: n_hdrs,
            numer_variables: n_vars,
            numer_terms: n_terms,
            denom_headers: d_hdrs,
            denom_variables: d_vars,
            denom_terms: d_terms,
            num_interactions: ints.len() as u32,
            max_fields_len: widest,
        }
    }
}

/// Expands a tree-shaped `SymbolicExpression` (no DAG sharing) into merged monomials.
fn expand_expr_tree<F: Field>(e: &SymbolicExpression<F>) -> Vec<Monomial<F>> {
    match e {
        SymbolicExpression::Constant(k) => single_term(vec![], *k),
        SymbolicExpression::Variable(v) => {
            single_term(vec![PackedVar::from_symbolic_var(v)], F::ONE)
        }
        SymbolicExpression::IsFirstRow => single_term(vec![PackedVar::is_first()], F::ONE),
        SymbolicExpression::IsLastRow => single_term(vec![PackedVar::is_last()], F::ONE),
        SymbolicExpression::IsTransition => single_term(vec![PackedVar::is_transition()], F::ONE),
        SymbolicExpression::Add { x: a, y: b, .. } => {
            let mut acc = expand_expr_tree(a);
            acc.extend(expand_expr_tree(b));
            merge_duplicates(acc)
        }
        SymbolicExpression::Sub { x: a, y: b, .. } => {
            let mut acc = expand_expr_tree(a);
            for mut m in expand_expr_tree(b) {
                m.scale = -m.scale;
                acc.push(m);
            }
            merge_duplicates(acc)
        }
        SymbolicExpression::Mul { x: a, y: b, .. } => {
            let lhs = expand_expr_tree(a);
            let rhs = expand_expr_tree(b);
            let mut acc = Vec::with_capacity(lhs.len() * rhs.len());
            for u in &lhs {
                for w in &rhs {
                    let mut prod = u.factors.clone();
                    prod.extend(&w.factors);
                    prod.sort();
                    acc.push(Monomial {
                        factors: prod,
                        scale: u.scale * w.scale,
                    });
                }
            }
            merge_duplicates(acc)
        }
        SymbolicExpression::Neg { x: a, .. } => expand_expr_tree(a)
            .into_iter()
            .map(|mut m| {
                m.scale = -m.scale;
                m
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use mle_core::{
        air::symbolic::SymbolicDagBuilder, interaction::Interaction, lookup::LookupType,
    };
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::prelude::F;

    // ─────────────────────────── ABI / layout contract ───────────────────────────

    /// The `#[repr(C)]` monomial structs are a binary ABI contract with
    /// `cuda/include/monomial.cuh` — sizes and the `PackedVar` bit packing must match its
    /// accessors and its `static_assert`s exactly.
    #[test]
    fn packed_types_abi_contract() {
        assert_eq!(core::mem::size_of::<PackedVar>(), 4);
        assert_eq!(core::mem::size_of::<MonomialHeader>(), 12);
        assert_eq!(core::mem::size_of::<LambdaTerm<F>>(), 8);
        assert_eq!(core::mem::size_of::<InteractionMonomialTerm<F>>(), 8);

        // monomial.cuh: entry_type = bits 0-3, part_index = 4-11, offset = 12-15, col = 16-31.
        let v = PackedVar::new(entry_type::MAIN, 0xAB, 0xC, 0xBEEF);
        assert_eq!(v.0 & 0xF, u32::from(entry_type::MAIN));
        assert_eq!((v.0 >> 4) & 0xFF, 0xAB);
        assert_eq!((v.0 >> 12) & 0xF, 0xC);
        assert_eq!(v.0 >> 16, 0xBEEF);

        // The frozen entry-type codes (hole at 2) match cuda/include/monomial.cuh.
        assert_eq!(entry_type::PREPROCESSED, 0);
        assert_eq!(entry_type::MAIN, 1);
        assert_eq!(entry_type::PUBLIC, 3);
        assert_eq!(entry_type::IS_FIRST, 8);
        assert_eq!(entry_type::IS_LAST, 9);
        assert_eq!(entry_type::IS_TRANSITION, 10);
    }

    // ─────────────────────────── independent oracle ───────────────────────────

    /// Deterministic pseudo-random field value for every leaf a [`PackedVar`] can name.
    /// A bijective multiply keeps distinct leaves distinct; the additive offset keeps the
    /// all-zero packing (`Preprocessed{offset:0}, index 0`) off of `F::ZERO`. The `>> 4`
    /// bounds the result below `2^28 < p`, so `from_u32` never panics.
    fn assignment(v: PackedVar) -> F {
        F::from_u32(v.0.wrapping_mul(0x9E37_79B9).wrapping_add(0x1234_5678) >> 4)
    }

    /// Direct evaluation of the DAG (the independent oracle): a serial walk over the
    /// topologically-ordered nodes, mirroring `mle_core`'s `SymbolicEvaluator::eval_nodes`.
    fn eval_dag_nodes(dag: &SymbolicExpressionDag<F>) -> Vec<F> {
        let mut vals: Vec<F> = Vec::with_capacity(dag.nodes.len());
        for node in &dag.nodes {
            let v = match node {
                SymbolicExpressionNode::Constant(c) => *c,
                SymbolicExpressionNode::Variable(var) => {
                    assignment(PackedVar::from_symbolic_var(var))
                }
                SymbolicExpressionNode::IsFirstRow => assignment(PackedVar::is_first()),
                SymbolicExpressionNode::IsLastRow => assignment(PackedVar::is_last()),
                SymbolicExpressionNode::IsTransition => assignment(PackedVar::is_transition()),
                SymbolicExpressionNode::Add {
                    left_idx,
                    right_idx,
                    ..
                } => vals[*left_idx] + vals[*right_idx],
                SymbolicExpressionNode::Sub {
                    left_idx,
                    right_idx,
                    ..
                } => vals[*left_idx] - vals[*right_idx],
                SymbolicExpressionNode::Mul {
                    left_idx,
                    right_idx,
                    ..
                } => vals[*left_idx] * vals[*right_idx],
                SymbolicExpressionNode::Neg { idx, .. } => -vals[*idx],
            };
            vals.push(v);
        }
        vals
    }

    /// Direct evaluation of a `SymbolicExpression` tree (the interaction oracle): the twin of
    /// [`eval_dag_nodes`] over the pre-DAG tree shape (Arc `x`/`y` children).
    fn eval_expr(e: &SymbolicExpression<F>) -> F {
        match e {
            SymbolicExpression::Constant(c) => *c,
            SymbolicExpression::Variable(v) => assignment(PackedVar::from_symbolic_var(v)),
            SymbolicExpression::IsFirstRow => assignment(PackedVar::is_first()),
            SymbolicExpression::IsLastRow => assignment(PackedVar::is_last()),
            SymbolicExpression::IsTransition => assignment(PackedVar::is_transition()),
            SymbolicExpression::Add { x, y, .. } => eval_expr(x) + eval_expr(y),
            SymbolicExpression::Sub { x, y, .. } => eval_expr(x) - eval_expr(y),
            SymbolicExpression::Mul { x, y, .. } => eval_expr(x) * eval_expr(y),
            SymbolicExpression::Neg { x, .. } => -eval_expr(x),
        }
    }

    /// Host-side fold of the expanded zerocheck monomials (the subject), matching what the GPU
    /// monomial kernel computes: `Σ_monomials (Π vars) · Σ_terms λ^{constraint_idx}·coeff`.
    fn eval_expanded(exp: &ExpandedMonomials<F>, lambda_pows: &[F]) -> F {
        let mut total = F::ZERO;
        for h in &exp.headers {
            let vars =
                &exp.variables[h.var_offset as usize..h.var_offset as usize + h.num_vars as usize];
            let terms = &exp.lambda_terms
                [h.term_offset as usize..h.term_offset as usize + h.num_terms as usize];
            let mono: F = vars.iter().map(|&v| assignment(v)).product();
            let lam: F = terms
                .iter()
                .map(|t| lambda_pows[t.constraint_idx as usize] * t.coefficient)
                .sum();
            total += mono * lam;
        }
        total
    }

    /// Host-side fold of one expanded interaction side (numerator or denominator), matching the
    /// GPU kernel: `Σ_monomials (Π vars) · Σ_terms term_weight(term)`.
    fn eval_interaction_side(
        headers: &[MonomialHeader],
        variables: &[PackedVar],
        terms: &[InteractionMonomialTerm<F>],
        mut term_weight: impl FnMut(&InteractionMonomialTerm<F>) -> F,
    ) -> F {
        let mut total = F::ZERO;
        for h in headers {
            let vars =
                &variables[h.var_offset as usize..h.var_offset as usize + h.num_vars as usize];
            let ts = &terms[h.term_offset as usize..h.term_offset as usize + h.num_terms as usize];
            let mono: F = vars.iter().map(|&v| assignment(v)).product();
            let w: F = ts.iter().map(&mut term_weight).sum();
            total += mono * w;
        }
        total
    }

    /// A DAG exercising every `SymbolicExpressionNode` kind, all three `Entry` variants, the three
    /// selectors, a subexpression reused across constraints (drives `expand_dag_node`'s memo),
    /// and a cancellation (`a*b - a*b`, pruned to zero coefficient). Built exactly as production
    /// does (`pkey.rs`): `SymbolicDagBuilder::add_expr` produces an authentic memoized arena where
    /// structurally-identical subexpressions share a node index.
    fn test_dag() -> SymbolicExpressionDag<F> {
        // Leaves exercising all three `Entry` variants.
        let vm: SymbolicExpression<F> = SymbolicVariable::<F>::new(
            Entry::Main {
                part_index: 0,
                offset: 1,
            },
            3,
        )
        .into();
        let vp: SymbolicExpression<F> =
            SymbolicVariable::<F>::new(Entry::Preprocessed { offset: 0 }, 2).into();
        let vpub: SymbolicExpression<F> = SymbolicVariable::<F>::new(Entry::Public, 5).into();
        let c3 = SymbolicExpression::Constant(F::from_u32(3));

        // A subexpression reused across constraints, so `expand_dag_node` hits its memo.
        let shared = vm.clone() * vp.clone();

        let constraints = [
            // Add + Sub + Constant + shared Mul + Public var.
            shared.clone() + vpub.clone() - c3,
            // Reuse `shared` (cache hit) inside another Mul.
            shared.clone() * vpub.clone(),
            // Cancellation: a*b - a*b -> merge_duplicates prunes it to an empty expansion.
            shared.clone() - shared.clone(),
            // Three selectors + a surviving Neg node (kept because it sits under a Mul, where the
            // builder does not fold it into an adjacent Add/Sub).
            vm.clone() * (-(vp.clone() * vpub.clone()))
                + SymbolicExpression::IsFirstRow * SymbolicExpression::IsLastRow
                + SymbolicExpression::IsTransition,
        ];

        let mut builder = SymbolicDagBuilder::<F>::default();
        let constraint_idx: Vec<usize> = constraints.iter().map(|e| builder.add_expr(e)).collect();
        SymbolicExpressionDag {
            nodes: builder.nodes,
            constraint_idx,
        }
    }

    /// `from_dag` preserves the DAG semantics: the λ-combined expanded monomials evaluate to the
    /// λ-combined direct DAG evaluation on an arbitrary assignment. This is an *independent*
    /// oracle (direct node walk) — unlike `test_monomial_vs_dag_equivalence`, which is GPU-vs-GPU.
    #[test]
    fn expanded_monomials_match_direct_dag_eval() {
        let dag = test_dag();
        let node_vals = eval_dag_nodes(&dag);

        let lambda = F::from_u32(7919);
        let lambda_pows: Vec<F> = (0..dag.constraint_idx.len())
            .scan(F::ONE, |acc, _| {
                let cur = *acc;
                *acc *= lambda;
                Some(cur)
            })
            .collect();

        // Oracle: Σ_i λ^i · constraint_i(assignment), indexed by constraint *position*, matching
        // how `from_dag` tags each `LambdaTerm.constraint_idx`.
        let expected: F = dag
            .constraint_idx
            .iter()
            .zip(&lambda_pows)
            .map(|(&idx, &lp)| lp * node_vals[idx])
            .sum();

        let exp = ExpandedMonomials::from_dag(&dag);
        assert_eq!(eval_expanded(&exp, &lambda_pows), expected);
    }

    /// `from_symbolic_constraints` preserves the LogUp numerator/denominator semantics: expanding
    /// the count / message expressions into monomials and folding them the GPU way equals a direct
    /// tree walk of the original `SymbolicExpression`s. Interactions have mixed message lengths and
    /// share monomials (in both counts and messages) so cross-interaction grouping is exercised.
    #[test]
    fn interaction_monomials_match_direct_tree_eval() {
        let a: SymbolicExpression<F> = SymbolicVariable::<F>::new(
            Entry::Main {
                part_index: 0,
                offset: 0,
            },
            0,
        )
        .into();
        let b: SymbolicExpression<F> = SymbolicVariable::<F>::new(
            Entry::Main {
                part_index: 0,
                offset: 0,
            },
            1,
        )
        .into();
        let p: SymbolicExpression<F> =
            SymbolicVariable::<F>::new(Entry::Preprocessed { offset: 0 }, 0).into();
        let pubv: SymbolicExpression<F> = SymbolicVariable::<F>::new(Entry::Public, 0).into();

        let interactions = vec![
            // message len 2; count monomial `a*b` is shared with interaction 3.
            Interaction {
                message: vec![a.clone() + b.clone(), p.clone()],
                count: a.clone() * b.clone(),
                kind: LookupType::Memory,
                count_weight: 1,
            },
            // message len 1 (a square); count shares the variable `a` and the `pubv` monomial.
            Interaction {
                message: vec![b.clone() * b.clone()],
                count: a.clone() + pubv.clone(),
                kind: LookupType::Byte,
                count_weight: 0,
            },
            // message len 3; count reuses the `a*b` monomial plus a Public term.
            Interaction {
                message: vec![a.clone(), b.clone(), p.clone()],
                count: a.clone() * b.clone() - pubv.clone(),
                kind: LookupType::Range,
                count_weight: 1,
            },
        ];
        let symbolic = SymbolicConstraints {
            constraints: Vec::new(),
            interactions,
        };
        let exp = ExpandedInteractionMonomials::from_symbolic_constraints(&symbolic);

        assert_eq!(exp.num_interactions, 3);
        assert_eq!(exp.max_fields_len, 3);

        // Arbitrary nonzero folding vectors.
        let eq_3bs: Vec<F> = (0..exp.num_interactions as usize)
            .map(|i| F::from_u32(11 + 7 * i as u32))
            .collect();
        let beta_pows: Vec<F> = (0..exp.max_fields_len)
            .map(|i| F::from_u32(3 + 5 * i as u32))
            .collect();

        // Oracle: direct tree walk of each interaction's count / message fields.
        let mut numer_oracle = F::ZERO;
        let mut denom_oracle = F::ZERO;
        for (j, interaction) in symbolic.interactions.iter().enumerate() {
            numer_oracle += eq_3bs[j] * eval_expr(&interaction.count);
            let mut field_sum = F::ZERO;
            for (f, field) in interaction.message.iter().enumerate() {
                field_sum += beta_pows[f] * eval_expr(field);
            }
            denom_oracle += eq_3bs[j] * field_sum;
        }

        // Subject: fold the expanded monomials the way the GPU kernels do.
        let numer_subject = eval_interaction_side(
            &exp.numer_headers,
            &exp.numer_variables,
            &exp.numer_terms,
            |t| t.coefficient * eq_3bs[t.interaction_idx as usize],
        );
        let denom_subject = eval_interaction_side(
            &exp.denom_headers,
            &exp.denom_variables,
            &exp.denom_terms,
            |t| {
                t.coefficient * beta_pows[t.field_idx as usize] * eq_3bs[t.interaction_idx as usize]
            },
        );

        assert_eq!(numer_subject, numer_oracle);
        assert_eq!(denom_subject, denom_oracle);
    }

    /// The empty-interactions early return yields all-empty vectors and zeroed scalar fields.
    #[test]
    fn empty_interactions_yield_empty_expansion() {
        let symbolic: SymbolicConstraints<F> = SymbolicConstraints {
            constraints: Vec::new(),
            interactions: Vec::new(),
        };
        let exp = ExpandedInteractionMonomials::from_symbolic_constraints(&symbolic);
        assert!(exp.numer_headers.is_empty());
        assert!(exp.numer_variables.is_empty());
        assert!(exp.numer_terms.is_empty());
        assert!(exp.denom_headers.is_empty());
        assert!(exp.denom_variables.is_empty());
        assert!(exp.denom_terms.is_empty());
        assert_eq!(exp.num_interactions, 0);
        assert_eq!(exp.max_fields_len, 0);
    }
}
