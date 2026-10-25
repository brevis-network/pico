extern crate alloc;

use alloc::vec::Vec;
use std::{cmp::Ordering, collections::BinaryHeap};

use getset::Getters;
use itertools::Itertools;
use mle_core::air::symbolic::{
    symbolic_variable::SymbolicVariable, SymbolicExpressionDag, SymbolicExpressionNode,
};
use p3_field::{Field, PrimeField32};
use rustc_hash::FxHashMap;

pub mod codec;

/// Where a rule reads an operand from (or, for the last slot of a rule, where it writes its
/// result): a scratch-buffer slot, a trace variable, a selector, a constant or a challenge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Source<F> {
    Intermediate(usize),
    TerminalIntermediate,
    Var(SymbolicVariable<F>),
    /// LogUp fractional-sumcheck challenge leaf: `index` into the runtime `d_challenges[]`
    /// (β-powers) buffer. This is cuda-mle's own rule-IR node, decoupled from
    /// `mle_core::Entry`. The MLE backend deliberately dropped `Entry::Challenge`
    /// because challenges are applied numerically (GKR), not as symbolic AIR
    /// leaves. Encodes to the exact legacy `Entry::Challenge` wire byte so the CUDA
    /// interpreter (`gkr_input.cu` / `batch_mle.cu`, `ENTRY_CHALLENGE`) is unchanged.
    Challenge(usize),
    IsFirst,
    IsLast,
    IsTransition,
    Constant(F),
}

/// One instruction of the straight-line program that the GPU interpreter executes per row.
#[derive(Clone, Debug, PartialEq)]
pub enum Rule<F> {
    // Binary ops take (lhs, rhs, dst) and compute dst <- lhs op rhs.
    Add(Source<F>, Source<F>, Source<F>),
    Sub(Source<F>, Source<F>, Source<F>),
    Mul(Source<F>, Source<F>, Source<F>),
    // Negation takes (src, dst) and computes dst <- -src.
    Neg(Source<F>, Source<F>),
    Variable(Source<F>),
    // Copy of a variable into a scratch slot: (src, dst) with dst <- src.
    BufferVar(Source<F>, Source<F>),
}

#[derive(derive_new::new, Clone, Debug, PartialEq)]
pub struct RuleWithFlag<F> {
    /// The instruction itself.
    pub inner: Rule<F>,
    /// Set when this instruction produces a constraint value that must be folded into the
    /// running accumulator.
    pub need_accumulate: bool,
}

/// Per-node facts that depend only on the DAG shape, computed once in `new`.
#[derive(Debug, Copy, Clone)]
struct NodeTraits {
    // lowest DAG position reachable by walking down from this node (itself included)
    pub min_reach: usize,
    pub is_constraint: bool,
    pub computed: bool,
    pub cache_var: bool,
}

/// Per-node bookkeeping for the currently scheduled range.
#[derive(Debug, Copy, Clone)]
struct NodeLiveness {
    pub uses: usize,
    /// Highest DAG position (inclusive) that still reads this node.
    pub final_reader: usize,
    /// Scratch-buffer slot holding the node, or usize::MAX when it never gets one.
    pub slot: usize,
}

impl NodeLiveness {
    pub fn record_use(&mut self, reader: usize) {
        self.final_reader = self.final_reader.max(reader);
        self.uses += 1;
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct SlotLease {
    slot: usize,
    expires: usize,
}

impl PartialOrd for SlotLease {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
        Some(self.cmp(rhs))
    }
}

impl Ord for SlotLease {
    fn cmp(&self, rhs: &Self) -> Ordering {
        rhs.expires
            .cmp(&self.expires)
            .then_with(|| rhs.slot.cmp(&self.slot))
    }
}

#[derive(Debug, Clone)]
pub struct SymbolicRulesGpu<F> {
    /// Instructions a single GPU thread runs in order to evaluate every constraint.
    pub rules: Vec<RuleWithFlag<F>>,
    /// How many `F` scratch slots the instructions need.
    pub buffer_size: usize,
    /// For each constraint (accumulated) node, the index of the first instruction that
    /// produces it. Each node appears once.
    pub dag_idx_to_rule_idx: FxHashMap<usize, usize>,
}

/// Turns a slice of a topologically ordered DAG into rules, handing out scratch slots and
/// recycling them through a min-heap keyed on when each slot becomes free.
///
/// `set_range` picks the slice; `to_rules` then emits the instructions for it.
#[derive(Getters)]
pub struct SymbolicRulesBuilder<'a, F> {
    /// Node list of the whole DAG; all positions below index into it.
    nodes: &'a [SymbolicExpressionNode<F>],

    // One entry per DAG node, indexed by position.
    traits: Vec<NodeTraits>,

    // Liveness of the nodes the current range touches (keyed by DAG position). Rebuilt on every
    // `set_range` call.
    liveness: FxHashMap<usize, NodeLiveness>,
    slot_heap: BinaryHeap<SlotLease>,

    // Half-open range [span_lo, span_hi) actually scheduled by the last `set_range`.
    span_lo: usize,
    span_hi: usize,
}

impl<'a, F: Field> SymbolicRulesBuilder<'a, F> {
    /// Requires `graph.constraint_idx` in ascending (topological) order.
    pub fn new(graph: &'a SymbolicExpressionDag<F>, cache_vars: bool) -> Self {
        debug_assert!(graph.constraint_idx.iter().is_sorted());
        let mut tbl = vec![
            NodeTraits {
                min_reach: usize::MAX,
                is_constraint: false,
                computed: false,
                cache_var: false,
            };
            graph.nodes.len()
        ];
        for &c in &graph.constraint_idx {
            tbl[c].is_constraint = true;
        }

        for (at, nd) in graph.nodes.iter().enumerate() {
            tbl[at].min_reach = tbl[at].min_reach.min(at);
            match nd {
                SymbolicExpressionNode::Add {
                    left_idx: lhs,
                    right_idx: rhs,
                    ..
                }
                | SymbolicExpressionNode::Sub {
                    left_idx: lhs,
                    right_idx: rhs,
                    ..
                }
                | SymbolicExpressionNode::Mul {
                    left_idx: lhs,
                    right_idx: rhs,
                    ..
                } => {
                    tbl[at].computed = true;
                    tbl[at].min_reach = tbl[at]
                        .min_reach
                        .min(tbl[*lhs].min_reach)
                        .min(tbl[*rhs].min_reach);
                }
                SymbolicExpressionNode::Neg { idx: src, .. } => {
                    tbl[at].computed = true;
                    tbl[at].min_reach = tbl[at].min_reach.min(tbl[*src].min_reach);
                }
                SymbolicExpressionNode::Variable(_) => {
                    if cache_vars {
                        tbl[at].cache_var = true;
                    }
                }
                _ => {}
            }
        }
        Self {
            nodes: &graph.nodes,
            traits: tbl,
            liveness: FxHashMap::default(),
            slot_heap: BinaryHeap::new(),
            span_lo: 0,
            span_hi: 0,
        }
    }

    /// Plans scratch slots for the nodes at positions `lo..hi` (end excluded), discarding
    /// whatever the previous call planned. Earlier nodes that this range depends on are
    /// pulled in and planned too.
    pub fn set_range(&mut self, mut lo: usize, hi: usize) {
        debug_assert!(lo < hi);
        debug_assert!(hi <= self.nodes.len());
        self.liveness.clear();
        let asked_lo = lo;
        for k in asked_lo..hi {
            lo = lo.min(self.traits[k].min_reach);
        }
        // Remember the widened range; `to_rules` walks it.
        self.span_lo = lo;
        self.span_hi = hi;

        // A node gets a liveness entry once something reads it (buffered or not). Walking
        // backwards means every reader is visited before the node it reads.
        for (pos, (nd, tr)) in self
            .nodes
            .iter()
            .zip(self.traits.iter())
            .enumerate()
            .take(hi)
            .skip(lo)
            .rev()
        {
            if !self.liveness.contains_key(&pos) && !tr.is_constraint {
                // Nothing reads it and it is not a constraint: not needed.
                continue;
            }
            let fresh = NodeLiveness {
                uses: 1,
                final_reader: pos,
                slot: usize::MAX,
            };
            self.liveness
                .entry(pos)
                .and_modify(|lv| {
                    lv.uses += 1;
                })
                .or_insert(fresh);

            match nd {
                SymbolicExpressionNode::Add {
                    left_idx: lhs,
                    right_idx: rhs,
                    ..
                }
                | SymbolicExpressionNode::Sub {
                    left_idx: lhs,
                    right_idx: rhs,
                    ..
                }
                | SymbolicExpressionNode::Mul {
                    left_idx: lhs,
                    right_idx: rhs,
                    ..
                } => {
                    self.liveness
                        .entry(*lhs)
                        .and_modify(|lv| lv.record_use(pos))
                        .or_insert(fresh);
                    self.liveness
                        .entry(*rhs)
                        .and_modify(|lv| lv.record_use(pos))
                        .or_insert(fresh);
                }
                SymbolicExpressionNode::Neg { idx: src, .. } => {
                    self.liveness
                        .entry(*src)
                        .and_modify(|lv| lv.record_use(pos))
                        .or_insert(fresh);
                }
                _ => {}
            }
        }

        // Gather, in ascending position order (topological), every node that needs a slot,
        // then hand out slots greedily: reuse the slot that frees up first when it is already
        // free, otherwise open a new one.
        let slotted = (lo..hi)
            .filter(|&pos| {
                if let Some(lv) = self.liveness.get(&pos) {
                    debug_assert!(lv.uses > 0);
                    let tr = &self.traits[pos];
                    tr.computed || (tr.cache_var && lv.uses > 1)
                } else {
                    false
                }
            })
            .collect_vec();

        let heap = &mut self.slot_heap;
        heap.clear();

        for pos in slotted {
            if heap.is_empty() || heap.peek().unwrap().expires > pos {
                let slot = heap.len();
                let lv = self.liveness.get_mut(&pos).unwrap();
                let expires = lv.final_reader;
                lv.slot = slot;
                heap.push(SlotLease { slot, expires });
            } else {
                let freed = heap.pop().unwrap();
                let slot = freed.slot;
                let lv = self.liveness.get_mut(&pos).unwrap();
                let expires = lv.final_reader;
                lv.slot = slot;
                heap.push(SlotLease { slot, expires });
            }
        }
    }

    pub fn to_rules(&self) -> SymbolicRulesGpu<F> {
        let operand_of = |at: usize, reader: usize| {
            match &self.nodes[at] {
                // Leaves map straight to a source; no slot lookup.
                SymbolicExpressionNode::IsFirstRow => Source::IsFirst,
                SymbolicExpressionNode::IsLastRow => Source::IsLast,
                SymbolicExpressionNode::IsTransition => Source::IsTransition,
                SymbolicExpressionNode::Constant(k) => Source::Constant(*k),
                SymbolicExpressionNode::Variable(v) => {
                    if self.traits[at].cache_var {
                        // A slot exists only when the variable is read more than once.
                        let slot = self.liveness[&at].slot;
                        if slot != usize::MAX && at != reader {
                            Source::Intermediate(slot)
                        } else {
                            Source::Var(*v)
                        }
                    } else {
                        Source::Var(*v)
                    }
                }
                SymbolicExpressionNode::Add { .. }
                | SymbolicExpressionNode::Sub { .. }
                | SymbolicExpressionNode::Mul { .. }
                | SymbolicExpressionNode::Neg { .. } => {
                    // Computed node: look up its slot, if it was given one.
                    let slot = self
                        .liveness
                        .get(&at)
                        .map(|lv| lv.slot)
                        .unwrap_or(usize::MAX);
                    if slot == usize::MAX {
                        Source::TerminalIntermediate
                    } else {
                        Source::Intermediate(slot)
                    }
                }
            }
        };

        // Constraint node -> first instruction emitting it. Positions are walked in order
        // because FxHashMap iteration order is arbitrary.
        let mut first_rule_of = FxHashMap::default();
        let emitted = (self.span_lo..self.span_hi)
            .filter(|pos| self.liveness.contains_key(pos))
            .enumerate()
            .map(|(rule_pos, pos)| {
                let nd = &self.nodes[pos];
                let op = match nd {
                    SymbolicExpressionNode::Add {
                        left_idx: lhs,
                        right_idx: rhs,
                        ..
                    } => Rule::Add(
                        operand_of(*lhs, pos),
                        operand_of(*rhs, pos),
                        operand_of(pos, pos),
                    ),
                    SymbolicExpressionNode::Sub {
                        left_idx: lhs,
                        right_idx: rhs,
                        ..
                    } => Rule::Sub(
                        operand_of(*lhs, pos),
                        operand_of(*rhs, pos),
                        operand_of(pos, pos),
                    ),
                    SymbolicExpressionNode::Mul {
                        left_idx: lhs,
                        right_idx: rhs,
                        ..
                    } => Rule::Mul(
                        operand_of(*lhs, pos),
                        operand_of(*rhs, pos),
                        operand_of(pos, pos),
                    ),
                    SymbolicExpressionNode::Neg { idx: src, .. } => {
                        Rule::Neg(operand_of(*src, pos), operand_of(pos, pos))
                    }
                    SymbolicExpressionNode::Variable(_) => {
                        let leaf = operand_of(pos, pos);
                        let slot = self.liveness[&pos].slot;
                        // Copy into a slot only when caching is on for this variable and it
                        // was actually given one (i.e. it has more than one reader).
                        if self.traits[pos].cache_var && slot != usize::MAX {
                            Rule::BufferVar(leaf, Source::Intermediate(slot))
                        } else {
                            Rule::Variable(leaf)
                        }
                    }
                    _ => Rule::Variable(operand_of(pos, pos)),
                };
                let acc = self.traits[pos].is_constraint;
                if acc {
                    // or_insert: the earliest instruction wins
                    first_rule_of.entry(pos).or_insert(rule_pos);
                }
                RuleWithFlag::new(op, acc)
            })
            .collect::<Vec<_>>();

        SymbolicRulesGpu {
            rules: emitted,
            buffer_size: self.slot_heap.len(),
            dag_idx_to_rule_idx: first_rule_of,
        }
    }
}

impl<F: Field + PrimeField32> SymbolicRulesGpu<F> {
    pub fn new(graph: &SymbolicExpressionDag<F>, cache_vars: bool) -> Self {
        let mut planner = SymbolicRulesBuilder::new(graph, cache_vars);
        planner.set_range(0, graph.nodes.len());
        planner.to_rules()
    }
}
