use core::{
    fmt::Debug,
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use std::{
    hash::{Hash, Hasher},
    ptr,
    sync::Arc,
};

use p3_field::{Algebra, Dup, Field, PrimeCharacteristicRing};
use serde::{Deserialize, Serialize};

use super::{dag::SymbolicExpressionNode, symbolic_variable::SymbolicVariable};

/// An expression over `SymbolicVariable`s.
// Note: avoid deriving Hash because it will hash the entire sub-tree
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "F: Field")]
pub enum SymbolicExpression<F> {
    Variable(SymbolicVariable<F>),
    IsFirstRow,
    IsLastRow,
    IsTransition,
    Constant(F),
    Add {
        x: Arc<Self>,
        y: Arc<Self>,
        degree_multiple: usize,
    },
    Sub {
        x: Arc<Self>,
        y: Arc<Self>,
        degree_multiple: usize,
    },
    Neg {
        x: Arc<Self>,
        degree_multiple: usize,
    },
    Mul {
        x: Arc<Self>,
        y: Arc<Self>,
        degree_multiple: usize,
    },
}

impl<F: Field> Hash for SymbolicExpression<F> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // First hash the discriminant of the enum
        std::mem::discriminant(self).hash(state);
        // Degree multiple is not necessary
        match self {
            Self::Variable(v) => v.hash(state),
            Self::IsFirstRow => {}   // discriminant is enough
            Self::IsLastRow => {}    // discriminant is enough
            Self::IsTransition => {} // discriminant is enough
            Self::Constant(f) => f.hash(state),
            Self::Add { x, y, .. } => {
                ptr::hash(&**x, state);
                ptr::hash(&**y, state);
            }
            Self::Sub { x, y, .. } => {
                ptr::hash(&**x, state);
                ptr::hash(&**y, state);
            }
            Self::Neg { x, .. } => {
                ptr::hash(&**x, state);
            }
            Self::Mul { x, y, .. } => {
                ptr::hash(&**x, state);
                ptr::hash(&**y, state);
            }
        }
    }
}

// We intentionally do not compare degree_multiple in PartialEq and Eq because degree_multiple is
// metadata used for optimization/debugging purposes but it does not change the underlying
// expression.
impl<F: Field> PartialEq for SymbolicExpression<F> {
    fn eq(&self, other: &Self) -> bool {
        // First check if the variants match
        if std::mem::discriminant(self) != std::mem::discriminant(other) {
            return false;
        }

        // Then check equality based on variant-specific data
        match (self, other) {
            (Self::Variable(v1), Self::Variable(v2)) => v1 == v2,
            // IsFirstRow, IsLastRow, and IsTransition are all unit variants,
            // so if the discriminants match, they're equal
            (Self::IsFirstRow, Self::IsFirstRow) => true,
            (Self::IsLastRow, Self::IsLastRow) => true,
            (Self::IsTransition, Self::IsTransition) => true,
            (Self::Constant(c1), Self::Constant(c2)) => c1 == c2,
            // For compound expressions, compare pointers to match how Hash is implemented
            (Self::Add { x: x1, y: y1, .. }, Self::Add { x: x2, y: y2, .. }) => {
                Arc::ptr_eq(x1, x2) && Arc::ptr_eq(y1, y2)
            }
            (Self::Sub { x: x1, y: y1, .. }, Self::Sub { x: x2, y: y2, .. }) => {
                Arc::ptr_eq(x1, x2) && Arc::ptr_eq(y1, y2)
            }
            (Self::Neg { x: x1, .. }, Self::Neg { x: x2, .. }) => Arc::ptr_eq(x1, x2),
            (Self::Mul { x: x1, y: y1, .. }, Self::Mul { x: x2, y: y2, .. }) => {
                Arc::ptr_eq(x1, x2) && Arc::ptr_eq(y1, y2)
            }
            // This should never be reached because we've already checked the discriminants
            _ => false,
        }
    }
}

impl<F: Field> Eq for SymbolicExpression<F> {}

impl<F: Field> SymbolicExpression<F> {
    /// Returns the multiple of `n` (the trace length) in this expression's degree.
    pub const fn degree_multiple(&self) -> usize {
        match self {
            SymbolicExpression::Variable(v) => v.degree_multiple(),
            SymbolicExpression::IsFirstRow => 1,
            SymbolicExpression::IsLastRow => 1,
            SymbolicExpression::IsTransition => 1,
            SymbolicExpression::Constant(_) => 0,
            SymbolicExpression::Add {
                degree_multiple, ..
            } => *degree_multiple,
            SymbolicExpression::Sub {
                degree_multiple, ..
            } => *degree_multiple,
            SymbolicExpression::Neg {
                degree_multiple, ..
            } => *degree_multiple,
            SymbolicExpression::Mul {
                degree_multiple, ..
            } => *degree_multiple,
        }
    }
}

impl<F: Field> Default for SymbolicExpression<F> {
    fn default() -> Self {
        Self::Constant(F::ZERO)
    }
}

impl<F: Field> From<F> for SymbolicExpression<F> {
    fn from(value: F) -> Self {
        Self::Constant(value)
    }
}

impl<F: Field> Dup for SymbolicExpression<F> {
    #[inline]
    fn dup(&self) -> Self {
        self.clone()
    }
}

impl<F: Field> PrimeCharacteristicRing for SymbolicExpression<F> {
    type PrimeSubfield = F::PrimeSubfield;

    const ZERO: Self = Self::Constant(F::ZERO);
    const ONE: Self = Self::Constant(F::ONE);
    const TWO: Self = Self::Constant(F::TWO);
    const NEG_ONE: Self = Self::Constant(F::NEG_ONE);

    #[inline]
    fn from_prime_subfield(f: Self::PrimeSubfield) -> Self {
        Self::Constant(F::from_prime_subfield(f))
    }

    fn from_bool(b: bool) -> Self {
        Self::Constant(F::from_bool(b))
    }
}

impl<F: Field> Algebra<F> for SymbolicExpression<F> {}

impl<F: Field> Algebra<SymbolicVariable<F>> for SymbolicExpression<F> {}

impl<F: Field> Add for SymbolicExpression<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let degree_multiple = self.degree_multiple().max(rhs.degree_multiple());
        Self::Add {
            x: Arc::new(self),
            y: Arc::new(rhs),
            degree_multiple,
        }
    }
}

impl<F: Field> Add<F> for SymbolicExpression<F> {
    type Output = Self;

    fn add(self, rhs: F) -> Self {
        self + Self::from(rhs)
    }
}

impl<F: Field> AddAssign for SymbolicExpression<F> {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs;
    }
}

impl<F: Field> AddAssign<SymbolicVariable<F>> for SymbolicExpression<F> {
    fn add_assign(&mut self, rhs: SymbolicVariable<F>) {
        *self += SymbolicExpression::from(rhs);
    }
}

impl<F: Field> AddAssign<F> for SymbolicExpression<F> {
    fn add_assign(&mut self, rhs: F) {
        *self += Self::from(rhs);
    }
}

impl<F: Field> Sum for SymbolicExpression<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|x, y| x + y).unwrap_or(Self::ZERO)
    }
}

impl<F: Field> Sum<F> for SymbolicExpression<F> {
    fn sum<I: Iterator<Item = F>>(iter: I) -> Self {
        iter.map(|x| Self::from(x)).sum()
    }
}

impl<F: Field> Sub for SymbolicExpression<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        let degree_multiple = self.degree_multiple().max(rhs.degree_multiple());
        Self::Sub {
            x: Arc::new(self),
            y: Arc::new(rhs),
            degree_multiple,
        }
    }
}

impl<F: Field> Sub<F> for SymbolicExpression<F> {
    type Output = Self;

    fn sub(self, rhs: F) -> Self {
        self - Self::from(rhs)
    }
}

impl<F: Field> SubAssign for SymbolicExpression<F> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.clone() - rhs;
    }
}

impl<F: Field> SubAssign<F> for SymbolicExpression<F> {
    fn sub_assign(&mut self, rhs: F) {
        *self -= Self::from(rhs);
    }
}

impl<F: Field> SubAssign<SymbolicVariable<F>> for SymbolicExpression<F> {
    fn sub_assign(&mut self, rhs: SymbolicVariable<F>) {
        *self -= SymbolicExpression::from(rhs);
    }
}

impl<F: Field> Neg for SymbolicExpression<F> {
    type Output = Self;

    fn neg(self) -> Self {
        let degree_multiple = self.degree_multiple();
        Self::Neg {
            x: Arc::new(self),
            degree_multiple,
        }
    }
}

impl<F: Field> Mul for SymbolicExpression<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        #[allow(clippy::suspicious_arithmetic_impl)]
        let degree_multiple = self.degree_multiple() + rhs.degree_multiple();
        Self::Mul {
            x: Arc::new(self),
            y: Arc::new(rhs),
            degree_multiple,
        }
    }
}

impl<F: Field> Mul<F> for SymbolicExpression<F> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self {
        self * Self::from(rhs)
    }
}

impl<F: Field> MulAssign for SymbolicExpression<F> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.clone() * rhs;
    }
}

impl<F: Field> MulAssign<F> for SymbolicExpression<F> {
    fn mul_assign(&mut self, rhs: F) {
        *self *= Self::from(rhs);
    }
}

impl<F: Field> MulAssign<SymbolicVariable<F>> for SymbolicExpression<F> {
    fn mul_assign(&mut self, rhs: SymbolicVariable<F>) {
        *self *= SymbolicExpression::from(rhs);
    }
}

impl<F: Field> Product for SymbolicExpression<F> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|x, y| x * y).unwrap_or(Self::ONE)
    }
}

impl<F: Field> Product<F> for SymbolicExpression<F> {
    fn product<I: Iterator<Item = F>>(iter: I) -> Self {
        iter.map(|x| Self::from(x)).product()
    }
}

pub trait SymbolicEvaluator<F, E>
where
    F: Field,
    E: Add<E, Output = E> + Sub<E, Output = E> + Mul<E, Output = E> + Neg<Output = E>,
{
    fn eval_const(&self, c: F) -> E;
    fn eval_var(&self, symbolic_var: SymbolicVariable<F>) -> E;
    fn eval_is_first_row(&self) -> E;
    fn eval_is_last_row(&self) -> E;
    fn eval_is_transition(&self) -> E;

    fn eval_expr(&self, symbolic_expr: &SymbolicExpression<F>) -> E {
        match symbolic_expr {
            SymbolicExpression::Variable(var) => self.eval_var(*var),
            SymbolicExpression::Constant(c) => self.eval_const(*c),
            SymbolicExpression::Add { x, y, .. } => self.eval_expr(x) + self.eval_expr(y),
            SymbolicExpression::Sub { x, y, .. } => self.eval_expr(x) - self.eval_expr(y),
            SymbolicExpression::Neg { x, .. } => -self.eval_expr(x),
            SymbolicExpression::Mul { x, y, .. } => self.eval_expr(x) * self.eval_expr(y),
            SymbolicExpression::IsFirstRow => self.eval_is_first_row(),
            SymbolicExpression::IsLastRow => self.eval_is_last_row(),
            SymbolicExpression::IsTransition => self.eval_is_transition(),
        }
    }

    /// Assumes that `nodes` are in topological order (if B references A, then B comes after A).
    /// Simple serial evaluation in order.
    fn eval_nodes(&self, nodes: &[SymbolicExpressionNode<F>]) -> Vec<E>
    where
        E: Clone,
    {
        let mut exprs: Vec<E> = Vec::with_capacity(nodes.len());
        for node in nodes {
            let expr = match *node {
                SymbolicExpressionNode::Variable(var) => self.eval_var(var),
                SymbolicExpressionNode::Constant(c) => self.eval_const(c),
                SymbolicExpressionNode::Add {
                    left_idx,
                    right_idx,
                    ..
                } => exprs[left_idx].clone() + exprs[right_idx].clone(),
                SymbolicExpressionNode::Sub {
                    left_idx,
                    right_idx,
                    ..
                } => exprs[left_idx].clone() - exprs[right_idx].clone(),
                SymbolicExpressionNode::Neg { idx, .. } => -exprs[idx].clone(),
                SymbolicExpressionNode::Mul {
                    left_idx,
                    right_idx,
                    ..
                } => exprs[left_idx].clone() * exprs[right_idx].clone(),
                SymbolicExpressionNode::IsFirstRow => self.eval_is_first_row(),
                SymbolicExpressionNode::IsLastRow => self.eval_is_last_row(),
                SymbolicExpressionNode::IsTransition => self.eval_is_transition(),
            };
            exprs.push(expr);
        }
        exprs
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    use super::{SymbolicEvaluator, SymbolicExpression};
    use crate::{
        air::symbolic::{
            dag::build_symbolic_constraints_dag,
            symbolic_variable::{Entry, SymbolicVariable},
            SymbolicConstraints,
        },
        interaction::Interaction,
        lookup::LookupType,
    };

    type F = KoalaBear;

    /// Trivial evaluator: resolves a local (offset 0) main-partition-0 column to `row[index]`.
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

    /// Build a small AIR constraint (`col1 - col0 - 1`) into the flat `SymbolicConstraintsDag`,
    /// then *evaluate* the DAG via `eval_nodes`: a satisfying row (`col1 = col0 + 1`) yields 0,
    /// a violating row yields the nonzero residual. Exercises DAG construction + evaluation.
    #[test]
    fn small_air_dag_builds_and_evaluates() {
        let constraint = col(1) - col(0) - F::ONE;
        let dag = build_symbolic_constraints_dag(&[constraint], &[]);
        assert_eq!(dag.constraints.constraint_idx.len(), 1);
        let root = dag.constraints.constraint_idx[0];

        // Satisfying row: col0 = 5, col1 = 6  ->  6 - 5 - 1 = 0
        let ok = RowEval {
            row: vec![F::from_u32(5), F::from_u32(6)],
        }
        .eval_nodes(&dag.constraints.nodes);
        assert_eq!(ok[root], F::ZERO);

        // Violating row: col0 = 5, col1 = 7  ->  7 - 5 - 1 = 1
        let bad = RowEval {
            row: vec![F::from_u32(5), F::from_u32(7)],
        }
        .eval_nodes(&dag.constraints.nodes);
        assert_eq!(bad[root], F::ONE);
    }

    /// Reading an interaction's `count`/`message` from the evaluated arena (`nodes[idx]`) must match
    /// the old tree eval (`SymbolicConstraints::from(&dag)` + `eval_expr`) — the equality
    /// `batch_constraints` relies on to skip rebuilding the tree per trace.
    #[test]
    fn dag_interaction_nodes_match_tree_eval() {
        // A plain constraint plus two interactions, so the arena holds interaction-only nodes too.
        let interactions = vec![
            Interaction {
                message: vec![col(0) + col(1), col(2) * col(0)],
                count: col(1) - F::ONE,
                kind: LookupType::Byte,
                count_weight: 0,
            },
            Interaction {
                message: vec![col(2) - col(0)],
                count: col(0) + col(2),
                kind: LookupType::Byte,
                count_weight: 0,
            },
        ];
        let dag = build_symbolic_constraints_dag(&[col(1) - col(0) - F::ONE], &interactions);

        let eval = RowEval {
            row: vec![F::from_u32(5), F::from_u32(6), F::from_u32(7)],
        };
        let nodes = eval.eval_nodes(&dag.constraints.nodes);
        let tree = SymbolicConstraints::from(&dag);

        // Order preserved, and every interaction's count/message evaluates identically both ways.
        assert_eq!(dag.interactions.len(), tree.interactions.len());
        for (dag_int, tree_int) in dag.interactions.iter().zip(&tree.interactions) {
            assert_eq!(nodes[dag_int.count], eval.eval_expr(&tree_int.count));
            assert_eq!(dag_int.message.len(), tree_int.message.len());
            for (&msg_idx, msg_expr) in dag_int.message.iter().zip(&tree_int.message) {
                assert_eq!(nodes[msg_idx], eval.eval_expr(msg_expr));
            }
        }
    }
}
