//! Test-only builder that evaluates a chip's constraints on one concrete row pair and records
//! every violated constraint. Survivor of the removed FRI folders (tag `legacy-fri-last`), ported
//! to the windowed `AirBuilder` of Plonky3 0.5.

use crate::machine::{
    builder::{ChipBuilder, EmptyLookupBuilder, ScopedBuilder},
    septic::SepticDigest,
};
use p3_air::{AirBuilder, ExtensionBuilder, RowWindow};
use p3_field::{ExtensionField, Field};

#[derive(Debug)]
pub enum DebugConstraintFailure<F, EF> {
    FieldInequality(F, F),
    ExtensionNonzero(EF),
    NonBoolean(F),
}

/// A folder for debugging constraints.
#[allow(dead_code)]
pub struct DebugConstraintFolder<'a, F, EF> {
    pub(crate) preprocessed: RowWindow<'a, F>,
    pub(crate) main: RowWindow<'a, F>,
    pub(crate) global_cumulative_sum: SepticDigest<F>,
    pub(crate) is_first_row: F,
    pub(crate) is_last_row: F,
    pub(crate) is_transition: F,
    pub(crate) public_values: &'a [F],
    pub(crate) failures: Vec<(Vec<String>, DebugConstraintFailure<F, EF>)>,
    pub(crate) scopes: Vec<String>,
    pub(crate) constraint_count: usize,
}

impl<F, EF> DebugConstraintFolder<'_, F, EF>
where
    F: Field,
{
    #[inline]
    fn debug_eq_constraint(&mut self, x: F, y: F) {
        self.constraint_count += 1;
        if x != y {
            self.new_failure(DebugConstraintFailure::FieldInequality(x, y));
        }
    }

    #[inline]
    fn new_failure(&mut self, failure: DebugConstraintFailure<F, EF>) {
        let mut scopes = self.scopes.clone();
        scopes.push(format!("constraint#{}", self.constraint_count));
        self.failures.push((scopes, failure));
    }
}

impl<F, EF> ScopedBuilder for DebugConstraintFolder<'_, F, EF> {
    fn enter_scope(&mut self, scope: impl AsRef<str>) {
        self.scopes.push(scope.as_ref().to_string());
    }
    fn exit_scope(&mut self) {
        self.scopes.pop();
    }
}

impl<'a, F, EF> AirBuilder for DebugConstraintFolder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type F = F;
    type Expr = F;
    type Var = F;
    type PreprocessedWindow = RowWindow<'a, F>;
    type MainWindow = RowWindow<'a, F>;
    type PublicVar = F;

    fn is_first_row(&self) -> Self::Expr {
        self.is_first_row
    }

    fn is_last_row(&self) -> Self::Expr {
        self.is_last_row
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size == 2 {
            self.is_transition
        } else {
            panic!("only supports a window size of 2")
        }
    }

    fn main(&self) -> Self::MainWindow {
        self.main
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.debug_eq_constraint(x.into(), F::ZERO);
    }

    fn assert_one<I: Into<Self::Expr>>(&mut self, x: I) {
        self.debug_eq_constraint(x.into(), F::ONE);
    }

    fn assert_eq<I1: Into<Self::Expr>, I2: Into<Self::Expr>>(&mut self, x: I1, y: I2) {
        self.debug_eq_constraint(x.into(), y.into());
    }

    /// Assert that `x` is a boolean, i.e. either 0 or 1.
    fn assert_bool<I: Into<Self::Expr>>(&mut self, x: I) {
        self.constraint_count += 1;
        let x = x.into();
        if x != F::ZERO && x != F::ONE {
            self.new_failure(DebugConstraintFailure::NonBoolean(x));
        }
    }
}

impl<F, EF> ExtensionBuilder for DebugConstraintFolder<'_, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type EF = EF;
    type VarEF = EF;
    type ExprEF = EF;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        let x = x.into();
        if x != EF::ZERO {
            self.new_failure(DebugConstraintFailure::ExtensionNonzero(x));
        }
    }
}

impl<F, EF> ChipBuilder<F> for DebugConstraintFolder<'_, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
}

impl<F: Field, EF: ExtensionField<F>> EmptyLookupBuilder for DebugConstraintFolder<'_, F, EF> {}
