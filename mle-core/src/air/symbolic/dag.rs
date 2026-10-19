use std::sync::Arc;

use p3_field::Field;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

use super::SymbolicConstraints;
use crate::{
    air::symbolic::{symbolic_expression::SymbolicExpression, symbolic_variable::SymbolicVariable},
    interaction::{Interaction, SymbolicInteraction},
};

/// A node in symbolic expression DAG.
/// Basically replace `Arc`s in `SymbolicExpression` with node IDs.
/// Intended to be serializable and deserializable.
#[derive(Clone, Debug, Hash, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound(
    serialize = "F: p3_field::PrimeField64",
    deserialize = "F: p3_field::PrimeField64"
))]
#[repr(C)]
pub enum SymbolicExpressionNode<F> {
    Variable(SymbolicVariable<F>),
    IsFirstRow,
    IsLastRow,
    IsTransition,
    /// Serialized as the canonical value (see `canonical_serde`): this node is part of the hashed
    /// vk / constraint-digest preimages, which must not depend on the field type's own serde.
    Constant(#[serde(with = "crate::canonical_serde::canonical_field")] F),
    Add {
        left_idx: usize,
        right_idx: usize,
        degree_multiple: usize,
    },
    Sub {
        left_idx: usize,
        right_idx: usize,
        degree_multiple: usize,
    },
    Neg {
        idx: usize,
        degree_multiple: usize,
    },
    Mul {
        left_idx: usize,
        right_idx: usize,
        degree_multiple: usize,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound(
    serialize = "F: p3_field::PrimeField64",
    deserialize = "F: p3_field::PrimeField64"
))]
#[repr(C)]
pub struct SymbolicExpressionDag<F> {
    /// Nodes in **topological** order.
    pub nodes: Vec<SymbolicExpressionNode<F>>,
    /// Node indices of expressions to assert equal zero.
    pub constraint_idx: Vec<usize>,
}

impl<F> SymbolicExpressionDag<F> {
    pub fn max_rotation(&self) -> usize {
        let mut rotation = 0;
        for node in &self.nodes {
            if let SymbolicExpressionNode::Variable(var) = node {
                rotation = rotation.max(var.entry.offset().unwrap_or(0));
            }
        }
        rotation
    }

    pub fn num_constraints(&self) -> usize {
        self.constraint_idx.len()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "F: p3_field::PrimeField64",
    deserialize = "F: p3_field::PrimeField64"
))]
#[repr(C)]
pub struct SymbolicConstraintsDag<F> {
    /// DAG with all symbolic expressions as nodes.
    /// These nodes include expressions for plain AIR constraints as well as symbolic expressions
    /// used for `interactions`.
    pub constraints: SymbolicExpressionDag<F>,
    /// List of all interactions, where expressions in the interactions
    /// are referenced by node idx as `usize`.
    ///
    /// These expressions are converted into a LogUp fractional sum
    /// which must be proven using GKR.
    pub interactions: Vec<Interaction<usize>>,
}

pub(crate) fn build_symbolic_constraints_dag<F: Field>(
    constraints: &[SymbolicExpression<F>],
    interactions: &[SymbolicInteraction<F>],
) -> SymbolicConstraintsDag<F> {
    let mut builder = SymbolicDagBuilder::new();
    let mut constraint_idx: Vec<usize> = constraints
        .iter()
        .map(|expr| builder.add_expr(expr))
        .collect();
    constraint_idx.sort();
    constraint_idx.dedup();
    let interactions: Vec<Interaction<usize>> = interactions
        .iter()
        .map(|interaction| {
            let fields: Vec<usize> = interaction
                .message
                .iter()
                .map(|field_expr| builder.add_expr(field_expr))
                .collect();
            let count = builder.add_expr(&interaction.count);
            Interaction {
                message: fields,
                count,
                kind: interaction.kind,
                count_weight: interaction.count_weight,
            }
        })
        .collect();
    let constraints = SymbolicExpressionDag {
        nodes: builder.nodes,
        constraint_idx,
    };
    SymbolicConstraintsDag {
        constraints,
        interactions,
    }
}

/// Builder for constructing a symbolic expression DAG with structural deduplication
/// and algebraic simplifications.
///
/// Two caches are used:
/// - `expr_to_idx`: Fast path for expressions with the same Arc pointer
/// - `node_to_idx`: Structural deduplication - catches identical nodes with different Arc pointers
///
/// Algebraic simplifications performed:
/// - Constant folding: `a + b` → `c`, `a - b` → `c`, `a * b` → `c`, `-a` → `c` (for constants a,b)
/// - `x + 0` → `x`, `0 + x` → `x`
/// - `x - 0` → `x`
/// - `x * 1` → `x`, `1 * x` → `x`
/// - `x * 0` → `0`, `0 * x` → `0`
/// - `x + (-y)` → `x - y`
/// - `x - (-y)` → `x + y`
pub struct SymbolicDagBuilder<F: Field> {
    /// Cache: Arc pointer -> node index (fast path for same Arc)
    pub expr_to_idx: FxHashMap<*const SymbolicExpression<F>, usize>,
    /// Cache: node structure -> node index (structural deduplication)
    pub node_to_idx: FxHashMap<SymbolicExpressionNode<F>, usize>,
    /// Nodes in topological order
    pub nodes: Vec<SymbolicExpressionNode<F>>,
}

impl<F: Field> Default for SymbolicDagBuilder<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field> SymbolicDagBuilder<F> {
    pub fn new() -> Self {
        Self {
            expr_to_idx: FxHashMap::default(),
            node_to_idx: FxHashMap::default(),
            nodes: Vec::new(),
        }
    }

    /// Add a symbolic expression to the DAG, returning its node index.
    /// Performs structural deduplication and algebraic simplifications.
    pub fn add_expr(&mut self, expr: &SymbolicExpression<F>) -> usize {
        // Fast path: check if we've seen this exact Arc pointer before
        let ptr = expr as *const SymbolicExpression<F>;
        if let Some(&idx) = self.expr_to_idx.get(&ptr) {
            return idx;
        }

        let idx = match expr {
            SymbolicExpression::Variable(var) => {
                self.intern_node(SymbolicExpressionNode::Variable(*var))
            }
            SymbolicExpression::IsFirstRow => self.intern_node(SymbolicExpressionNode::IsFirstRow),
            SymbolicExpression::IsLastRow => self.intern_node(SymbolicExpressionNode::IsLastRow),
            SymbolicExpression::IsTransition => {
                self.intern_node(SymbolicExpressionNode::IsTransition)
            }
            SymbolicExpression::Constant(cons) => {
                self.intern_node(SymbolicExpressionNode::Constant(*cons))
            }
            SymbolicExpression::Add {
                x,
                y,
                degree_multiple,
            } => {
                let left_idx = self.add_expr(x.as_ref());
                let right_idx = self.add_expr(y.as_ref());

                // Constant folding: const + const = const
                if let (Some(a), Some(b)) = (self.get_const(left_idx), self.get_const(right_idx)) {
                    self.intern_node(SymbolicExpressionNode::Constant(a + b))
                }
                // Simplify: 0 + x = x, x + 0 = x
                else if self.is_const(left_idx, F::ZERO) {
                    right_idx
                } else if self.is_const(right_idx, F::ZERO) {
                    left_idx
                }
                // Normalize: x + (-y) = x - y
                else if let Some(neg_child_idx) = self.get_neg_child(right_idx) {
                    self.intern_node(SymbolicExpressionNode::Sub {
                        left_idx,
                        right_idx: neg_child_idx,
                        degree_multiple: *degree_multiple,
                    })
                } else {
                    self.intern_node(SymbolicExpressionNode::Add {
                        left_idx,
                        right_idx,
                        degree_multiple: *degree_multiple,
                    })
                }
            }
            SymbolicExpression::Sub {
                x,
                y,
                degree_multiple,
            } => {
                let left_idx = self.add_expr(x.as_ref());
                let right_idx = self.add_expr(y.as_ref());

                // Constant folding: const - const = const
                if let (Some(a), Some(b)) = (self.get_const(left_idx), self.get_const(right_idx)) {
                    self.intern_node(SymbolicExpressionNode::Constant(a - b))
                }
                // Simplify: x - 0 = x
                else if self.is_const(right_idx, F::ZERO) {
                    left_idx
                }
                // Simplify: x - (-y) = x + y (double negation)
                else if let Some(neg_child_idx) = self.get_neg_child(right_idx) {
                    self.intern_node(SymbolicExpressionNode::Add {
                        left_idx,
                        right_idx: neg_child_idx,
                        degree_multiple: *degree_multiple,
                    })
                } else {
                    self.intern_node(SymbolicExpressionNode::Sub {
                        left_idx,
                        right_idx,
                        degree_multiple: *degree_multiple,
                    })
                }
            }
            SymbolicExpression::Neg { x, degree_multiple } => {
                let child_idx = self.add_expr(x.as_ref());

                // Constant folding: -const = const
                if let Some(c) = self.get_const(child_idx) {
                    self.intern_node(SymbolicExpressionNode::Constant(-c))
                } else {
                    self.intern_node(SymbolicExpressionNode::Neg {
                        idx: child_idx,
                        degree_multiple: *degree_multiple,
                    })
                }
            }
            SymbolicExpression::Mul {
                x,
                y,
                degree_multiple,
            } => {
                // An important case to remember: square will have Arc::as_ptr(&x) ==
                // Arc::as_ptr(&y) The `expr_to_idx` will ensure only one recursive
                // call is done to prevent exponential behavior.
                let left_idx = self.add_expr(x.as_ref());
                let right_idx = self.add_expr(y.as_ref());

                // Constant folding: const * const = const
                if let (Some(a), Some(b)) = (self.get_const(left_idx), self.get_const(right_idx)) {
                    self.intern_node(SymbolicExpressionNode::Constant(a * b))
                }
                // Simplify: 0 * x = 0, x * 1 = x (return left_idx)
                // Simplify: x * 0 = 0, 1 * x = x (return right_idx)
                else if self.is_const(left_idx, F::ZERO) || self.is_const(right_idx, F::ONE) {
                    left_idx
                } else if self.is_const(right_idx, F::ZERO) || self.is_const(left_idx, F::ONE) {
                    right_idx
                } else {
                    self.intern_node(SymbolicExpressionNode::Mul {
                        left_idx,
                        right_idx,
                        degree_multiple: *degree_multiple,
                    })
                }
            }
        };

        self.expr_to_idx.insert(ptr, idx);
        idx
    }

    /// Intern a node: return existing index if the node already exists, otherwise add it.
    fn intern_node(&mut self, node: SymbolicExpressionNode<F>) -> usize {
        *self.node_to_idx.entry(node.clone()).or_insert_with(|| {
            let idx = self.nodes.len();
            self.nodes.push(node);
            idx
        })
    }

    /// Check if a node at given index is a constant with specific value.
    fn is_const(&self, idx: usize, val: F) -> bool {
        matches!(&self.nodes[idx], SymbolicExpressionNode::Constant(c) if *c == val)
    }

    /// Get constant value from a node, if it is a constant.
    fn get_const(&self, idx: usize) -> Option<F> {
        match &self.nodes[idx] {
            SymbolicExpressionNode::Constant(c) => Some(*c),
            _ => None,
        }
    }

    /// If a node is a Neg, return its child index.
    fn get_neg_child(&self, idx: usize) -> Option<usize> {
        match &self.nodes[idx] {
            SymbolicExpressionNode::Neg { idx, .. } => Some(*idx),
            _ => None,
        }
    }
}

impl<F: Field> SymbolicExpressionDag<F> {
    /// Convert each node to a [`SymbolicExpression<F>`] reference and return
    /// the full list.
    fn to_symbolic_expressions(&self) -> Vec<Arc<SymbolicExpression<F>>> {
        let mut exprs: Vec<Arc<SymbolicExpression<_>>> = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            let expr = match *node {
                SymbolicExpressionNode::Variable(var) => SymbolicExpression::Variable(var),
                SymbolicExpressionNode::IsFirstRow => SymbolicExpression::IsFirstRow,
                SymbolicExpressionNode::IsLastRow => SymbolicExpression::IsLastRow,
                SymbolicExpressionNode::IsTransition => SymbolicExpression::IsTransition,
                SymbolicExpressionNode::Constant(f) => SymbolicExpression::Constant(f),
                SymbolicExpressionNode::Add {
                    left_idx,
                    right_idx,
                    degree_multiple,
                } => SymbolicExpression::Add {
                    x: exprs[left_idx].clone(),
                    y: exprs[right_idx].clone(),
                    degree_multiple,
                },
                SymbolicExpressionNode::Sub {
                    left_idx,
                    right_idx,
                    degree_multiple,
                } => SymbolicExpression::Sub {
                    x: exprs[left_idx].clone(),
                    y: exprs[right_idx].clone(),
                    degree_multiple,
                },
                SymbolicExpressionNode::Neg {
                    idx,
                    degree_multiple,
                } => SymbolicExpression::Neg {
                    x: exprs[idx].clone(),
                    degree_multiple,
                },
                SymbolicExpressionNode::Mul {
                    left_idx,
                    right_idx,
                    degree_multiple,
                } => SymbolicExpression::Mul {
                    x: exprs[left_idx].clone(),
                    y: exprs[right_idx].clone(),
                    degree_multiple,
                },
            };
            exprs.push(Arc::new(expr));
        }
        exprs
    }
}

// TEMPORARY conversions until we switch main interfaces to use SymbolicConstraintsDag
impl<'a, F: Field> From<&'a SymbolicConstraintsDag<F>> for SymbolicConstraints<F> {
    fn from(dag: &'a SymbolicConstraintsDag<F>) -> Self {
        let exprs = dag.constraints.to_symbolic_expressions();
        let constraints = dag
            .constraints
            .constraint_idx
            .iter()
            .map(|&idx| exprs[idx].as_ref().clone())
            .collect::<Vec<_>>();
        let interactions = dag
            .interactions
            .iter()
            .map(|interaction| {
                let fields = interaction
                    .message
                    .iter()
                    .map(|&idx| exprs[idx].as_ref().clone())
                    .collect();
                let count = exprs[interaction.count].as_ref().clone();
                Interaction {
                    message: fields,
                    count,
                    kind: interaction.kind,
                    count_weight: interaction.count_weight,
                }
            })
            .collect::<Vec<_>>();
        SymbolicConstraints {
            constraints,
            interactions,
        }
    }
}

impl<F: Field> From<SymbolicConstraintsDag<F>> for SymbolicConstraints<F> {
    fn from(dag: SymbolicConstraintsDag<F>) -> Self {
        (&dag).into()
    }
}

impl<F: Field> From<SymbolicConstraints<F>> for SymbolicConstraintsDag<F> {
    fn from(sc: SymbolicConstraints<F>) -> Self {
        build_symbolic_constraints_dag(&sc.constraints, &sc.interactions)
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    use crate::{
        air::symbolic::{
            dag::{build_symbolic_constraints_dag, SymbolicExpressionDag, SymbolicExpressionNode},
            symbolic_expression::SymbolicExpression,
            symbolic_variable::{Entry, SymbolicVariable},
        },
        interaction::Interaction,
        lookup::LookupType,
    };

    type F = KoalaBear;

    #[test]
    fn test_duplicate_constraints_are_deduplicated() {
        // Create a simple expression
        let expr: SymbolicExpression<F> = SymbolicExpression::Variable(SymbolicVariable::new(
            Entry::Main {
                part_index: 0,
                offset: 0,
            },
            0,
        ));

        // Simulate calling assert_zero twice on the same expression
        let constraints = vec![expr.clone(), expr.clone()];
        let interactions = vec![];

        let dag = build_symbolic_constraints_dag(&constraints, &interactions);

        // Nodes are deduplicated - there's only 1 node in the DAG
        assert_eq!(
            dag.constraints.nodes.len(),
            1,
            "Nodes should be deduplicated"
        );

        // constraint_idx should also be deduplicated
        assert_eq!(
            dag.constraints.constraint_idx,
            vec![0],
            "constraint_idx should be deduplicated"
        );

        // Only 1 constraint
        assert_eq!(
            dag.constraints.num_constraints(),
            1,
            "Duplicate constraints should be deduplicated"
        );
    }

    #[test]
    fn test_structural_deduplication() {
        // Create two structurally identical expressions with different Arc pointers
        // This simulates: builder.assert_zero(x - ONE); builder.assert_zero(x - ONE);
        let var = SymbolicVariable::<F>::new(
            Entry::Main {
                part_index: 0,
                offset: 0,
            },
            0,
        );
        let expr1 = SymbolicExpression::from(var) - SymbolicExpression::Constant(F::ONE);
        let expr2 = SymbolicExpression::from(var) - SymbolicExpression::Constant(F::ONE);

        // These are different Arc allocations
        assert!(!std::ptr::eq(&expr1, &expr2));

        let constraints = vec![expr1, expr2];
        let dag = build_symbolic_constraints_dag(&constraints, &[]);

        // With structural deduplication, both expressions should map to the same node
        // Nodes: Variable(0), Constant(1), Sub(0,1)
        assert_eq!(dag.constraints.nodes.len(), 3);
        assert_eq!(dag.constraints.constraint_idx, vec![2]);
    }

    #[test]
    fn test_algebraic_simplifications() {
        let var = SymbolicVariable::<F>::new(
            Entry::Main {
                part_index: 0,
                offset: 0,
            },
            0,
        );
        let x = SymbolicExpression::from(var);
        let zero = SymbolicExpression::Constant(F::ZERO);
        let one = SymbolicExpression::Constant(F::ONE);

        // Test x + 0 = x
        let expr_add_zero = x.clone() + zero.clone();
        let dag = build_symbolic_constraints_dag(&[expr_add_zero], &[]);
        // Should only have Variable node, no Add node
        assert_eq!(dag.constraints.nodes.len(), 2); // Variable + Constant(0) interned but Add simplified away
        assert!(matches!(
            dag.constraints.nodes[dag.constraints.constraint_idx[0]],
            SymbolicExpressionNode::Variable(_)
        ));

        // Test 0 + x = x
        let expr_zero_add = zero.clone() + x.clone();
        let dag = build_symbolic_constraints_dag(&[expr_zero_add], &[]);
        assert!(matches!(
            dag.constraints.nodes[dag.constraints.constraint_idx[0]],
            SymbolicExpressionNode::Variable(_)
        ));

        // Test x * 1 = x
        let expr_mul_one = x.clone() * one.clone();
        let dag = build_symbolic_constraints_dag(&[expr_mul_one], &[]);
        assert!(matches!(
            dag.constraints.nodes[dag.constraints.constraint_idx[0]],
            SymbolicExpressionNode::Variable(_)
        ));

        // Test 1 * x = x
        let expr_one_mul = one.clone() * x.clone();
        let dag = build_symbolic_constraints_dag(&[expr_one_mul], &[]);
        assert!(matches!(
            dag.constraints.nodes[dag.constraints.constraint_idx[0]],
            SymbolicExpressionNode::Variable(_)
        ));

        // Test x * 0 = 0
        let expr_mul_zero = x.clone() * zero.clone();
        let dag = build_symbolic_constraints_dag(&[expr_mul_zero], &[]);
        assert!(matches!(
            dag.constraints.nodes[dag.constraints.constraint_idx[0]],
            SymbolicExpressionNode::Constant(c) if c == F::ZERO
        ));

        // Test x - 0 = x
        let expr_sub_zero = x.clone() - zero.clone();
        let dag = build_symbolic_constraints_dag(&[expr_sub_zero], &[]);
        assert!(matches!(
            dag.constraints.nodes[dag.constraints.constraint_idx[0]],
            SymbolicExpressionNode::Variable(_)
        ));

        // Test x + (-y) normalizes to x - y (same as Sub)
        let y = SymbolicExpression::from(SymbolicVariable::<F>::new(
            Entry::Main {
                part_index: 0,
                offset: 0,
            },
            1,
        ));
        let expr_add_neg = x.clone() + (-y.clone());
        let expr_sub = x.clone() - y.clone();
        let dag1 = build_symbolic_constraints_dag(&[expr_add_neg], &[]);
        let dag2 = build_symbolic_constraints_dag(&[expr_sub], &[]);
        // Both should produce the same constraint node (Sub)
        assert!(matches!(
            dag1.constraints.nodes[dag1.constraints.constraint_idx[0]],
            SymbolicExpressionNode::Sub { .. }
        ));
        assert_eq!(
            dag1.constraints.nodes[dag1.constraints.constraint_idx[0]],
            dag2.constraints.nodes[dag2.constraints.constraint_idx[0]]
        );

        // Test x - (-y) = x + y
        let expr_sub_neg = x.clone() - (-y.clone());
        let dag = build_symbolic_constraints_dag(&[expr_sub_neg], &[]);
        assert!(matches!(
            dag.constraints.nodes[dag.constraints.constraint_idx[0]],
            SymbolicExpressionNode::Add { .. }
        ));
    }

    #[test]
    fn test_constant_folding() {
        let two = SymbolicExpression::<F>::Constant(F::TWO);
        let three = SymbolicExpression::<F>::Constant(F::from_u32(3));
        let five = F::from_u32(5);
        let six = F::from_u32(6);
        let neg_three = -F::from_u32(3);

        // Test 2 + 3 = 5
        let expr_add = two.clone() + three.clone();
        let dag = build_symbolic_constraints_dag(&[expr_add], &[]);
        assert!(matches!(
            dag.constraints.nodes[dag.constraints.constraint_idx[0]],
            SymbolicExpressionNode::Constant(c) if c == five
        ));

        // Test 3 - 2 = 1
        let expr_sub = three.clone() - two.clone();
        let dag = build_symbolic_constraints_dag(&[expr_sub], &[]);
        assert!(matches!(
            dag.constraints.nodes[dag.constraints.constraint_idx[0]],
            SymbolicExpressionNode::Constant(c) if c == F::ONE
        ));

        // Test 2 * 3 = 6
        let expr_mul = two.clone() * three.clone();
        let dag = build_symbolic_constraints_dag(&[expr_mul], &[]);
        assert!(matches!(
            dag.constraints.nodes[dag.constraints.constraint_idx[0]],
            SymbolicExpressionNode::Constant(c) if c == six
        ));

        // Test -3 = neg_three
        let expr_neg = -three.clone();
        let dag = build_symbolic_constraints_dag(&[expr_neg], &[]);
        assert!(matches!(
            dag.constraints.nodes[dag.constraints.constraint_idx[0]],
            SymbolicExpressionNode::Constant(c) if c == neg_three
        ));

        // Test chained: (2 + 3) * 2 = 10
        let expr_chain = (two.clone() + three.clone()) * two.clone();
        let dag = build_symbolic_constraints_dag(&[expr_chain], &[]);
        assert!(matches!(
            dag.constraints.nodes[dag.constraints.constraint_idx[0]],
            SymbolicExpressionNode::Constant(c) if c == F::from_u32(10)
        ));
    }

    #[test]
    fn test_symbolic_constraints_dag() {
        // expr = Constant(1) * Variable, which simplifies to just Variable
        let expr = SymbolicExpression::Constant(F::ONE)
            * SymbolicVariable::new(
                Entry::Main {
                    part_index: 1,
                    offset: 2,
                },
                3,
            );
        let constraints = vec![
            SymbolicExpression::IsFirstRow * SymbolicExpression::IsLastRow
                + SymbolicExpression::Constant(F::ONE)
                + SymbolicExpression::IsFirstRow * SymbolicExpression::IsLastRow
                + expr.clone(),
            expr.clone() * expr.clone(),
        ];
        let interactions = vec![Interaction {
            kind: LookupType::Byte,
            message: vec![expr.clone(), SymbolicExpression::Constant(F::TWO)],
            count: SymbolicExpression::Constant(F::ONE),
            count_weight: 1,
        }];
        let dag = build_symbolic_constraints_dag(&constraints, &interactions);
        assert_eq!(
            dag.constraints,
            SymbolicExpressionDag::<F> {
                nodes: vec![
                    SymbolicExpressionNode::IsFirstRow,
                    SymbolicExpressionNode::IsLastRow,
                    SymbolicExpressionNode::Mul {
                        left_idx: 0,
                        right_idx: 1,
                        degree_multiple: 2
                    },
                    SymbolicExpressionNode::Constant(F::ONE),
                    SymbolicExpressionNode::Add {
                        left_idx: 2,
                        right_idx: 3,
                        degree_multiple: 2
                    },
                    // With structural deduplication, IsFirstRow * IsLastRow is now reused
                    // instead of duplicated. The second occurrence reuses node index 2.
                    SymbolicExpressionNode::Add {
                        left_idx: 4,
                        right_idx: 2,
                        degree_multiple: 2
                    },
                    // expr = Constant(1) * Variable simplifies to just Variable (1 * x = x)
                    SymbolicExpressionNode::Variable(SymbolicVariable::new(
                        Entry::Main {
                            part_index: 1,
                            offset: 2
                        },
                        3
                    )),
                    // First constraint: ... + expr (which is Variable at index 6)
                    SymbolicExpressionNode::Add {
                        left_idx: 5,
                        right_idx: 6,
                        degree_multiple: 2
                    },
                    // Second constraint: expr * expr = Variable * Variable
                    SymbolicExpressionNode::Mul {
                        left_idx: 6,
                        right_idx: 6,
                        degree_multiple: 2
                    },
                    SymbolicExpressionNode::Constant(F::TWO),
                ],
                constraint_idx: vec![7, 8],
            }
        );
        assert_eq!(
            dag.interactions,
            vec![Interaction {
                kind: LookupType::Byte,
                // expr simplified to Variable at index 6, Constant(2) at index 9
                message: vec![6, 9],
                count: 3,
                count_weight: 1,
            }]
        );
    }
}
