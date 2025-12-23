use crate::{
    compiler::recursion::ir::{
        Ext as RecursionExt, Felt as RecursionFelt, SymbolicExt as RecursionSymbolicExt,
    },
    configs::config::{FieldGenericConfig, PackedChallenge, PackedVal, StarkGenericConfig},
    machine::{
        builder::{
            ChipBuilder, EmptyLookupBuilder, LookupBuilder, PermutationBuilder,
            PublicValuesBuilder, ScopedBuilder,
        },
        lookup::{symbolic_to_virtual_pair, SymbolicLookup, VirtualPairLookup},
        septic::SepticDigest,
    },
    primitives::consts::MAX_NUM_PVS,
};
use alloc::sync::Arc;
use p3_air::{AirBuilder, ExtensionBuilder, PairBuilder};
use p3_field::{ExtensionField, Field, FieldAlgebra};
use p3_matrix::{
    dense::{RowMajorMatrix, RowMajorMatrixView},
    stack::VerticalPair,
};
use p3_uni_stark::{Entry, SymbolicExpression, SymbolicVariable};
use std::{
    marker::PhantomData,
    ops::{Add, Mul, MulAssign, Sub},
};

// SymbolicConstraintFolder for lookup-related variables and constraints
// It also impls functions for SymbolicAirBuilder, thus replacing it
pub struct SymbolicConstraintFolder<F: Field> {
    pub(crate) preprocessed: RowMajorMatrix<SymbolicVariable<F>>,
    pub(crate) main: RowMajorMatrix<SymbolicVariable<F>>,
    pub(crate) looking: Vec<VirtualPairLookup<F>>,
    pub(crate) looked: Vec<VirtualPairLookup<F>>,
    pub(crate) constraints: Vec<SymbolicExpression<F>>,
    pub(crate) public_values: Vec<SymbolicVariable<F>>,
}

impl<F: Field> SymbolicConstraintFolder<F> {
    /// Creates a new [`InteractionBuilder`] with the given width.
    #[must_use]
    pub fn new(preprocessed_width: usize, main_width: usize) -> Self {
        let preprocessed_width = preprocessed_width.max(1);
        let preprocessed_values = [0, 1]
            .into_iter()
            .flat_map(|offset| {
                (0..preprocessed_width).map(move |column| {
                    SymbolicVariable::new(Entry::Preprocessed { offset }, column)
                })
            })
            .collect();

        let main_values = [0, 1]
            .into_iter()
            .flat_map(|offset| {
                (0..main_width)
                    .map(move |column| SymbolicVariable::new(Entry::Main { offset }, column))
            })
            .collect();

        let public_values = (0..MAX_NUM_PVS)
            .map(move |index| SymbolicVariable::new(Entry::Public, index))
            .collect();

        Self {
            preprocessed: RowMajorMatrix::new(preprocessed_values, preprocessed_width),
            main: RowMajorMatrix::new(main_values, main_width),
            looking: vec![],
            looked: vec![],
            constraints: vec![],
            public_values,
        }
    }

    /// Returns lookup
    #[must_use]
    pub fn lookups(self) -> (Vec<VirtualPairLookup<F>>, Vec<VirtualPairLookup<F>>) {
        (self.looking, self.looked)
    }

    pub fn constraints(self) -> Vec<SymbolicExpression<F>> {
        self.constraints
    }
}

impl<F: Field> ScopedBuilder for SymbolicConstraintFolder<F> {}

impl<F: Field> AirBuilder for SymbolicConstraintFolder<F> {
    type F = F;
    type Expr = SymbolicExpression<F>;
    type Var = SymbolicVariable<F>;
    type M = RowMajorMatrix<Self::Var>;

    fn main(&self) -> Self::M {
        self.main.clone()
    }

    fn is_first_row(&self) -> Self::Expr {
        SymbolicExpression::IsFirstRow
    }

    fn is_last_row(&self) -> Self::Expr {
        SymbolicExpression::IsLastRow
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size == 2 {
            SymbolicExpression::IsTransition
        } else {
            panic!("uni-machine only supports a window size of 2")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.constraints.push(x.into());
    }
}

impl<F: Field> PublicValuesBuilder for SymbolicConstraintFolder<F> {
    type PublicVar = SymbolicVariable<F>;
    fn public_values(&self) -> &[Self::PublicVar] {
        &self.public_values
    }
}

impl<F: Field> LookupBuilder<SymbolicLookup<SymbolicExpression<F>>>
    for SymbolicConstraintFolder<F>
{
    fn looking(&mut self, message: SymbolicLookup<SymbolicExpression<F>>) {
        let values = message
            .values
            .into_iter()
            .map(|v| symbolic_to_virtual_pair(&v))
            .collect::<Vec<_>>();

        let multiplicity = symbolic_to_virtual_pair(&message.multiplicity);

        self.looking.push(VirtualPairLookup::new(
            values,
            multiplicity,
            message.kind,
            message.scope,
        ));
    }

    fn looked(&mut self, message: SymbolicLookup<SymbolicExpression<F>>) {
        let values = message
            .values
            .into_iter()
            .map(|v| symbolic_to_virtual_pair(&v))
            .collect::<Vec<_>>();

        let multiplicity = symbolic_to_virtual_pair(&message.multiplicity);

        self.looked.push(VirtualPairLookup::new(
            values,
            multiplicity,
            message.kind,
            message.scope,
        ));
    }
}

impl<F: Field> ChipBuilder<F> for SymbolicConstraintFolder<F> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed.clone()
    }
}

impl<F: Field> PairBuilder for SymbolicConstraintFolder<F> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed.clone()
    }
}

/// Prover Constraint Folder
#[derive(Debug)]
pub struct ProverConstraintFolder<SC: StarkGenericConfig> {
    pub preprocessed: RowMajorMatrix<PackedVal<SC>>,
    pub main: RowMajorMatrix<PackedVal<SC>>,
    pub perm: RowMajorMatrix<PackedChallenge<SC>>,
    pub public_values: Arc<[SC::Val]>,
    pub perm_challenges: Arc<[PackedChallenge<SC>]>,
    pub regional_cumulative_sum: PackedChallenge<SC>,
    pub global_cumulative_sum: SepticDigest<SC::Val>,
    pub is_first_row: PackedVal<SC>,
    pub is_last_row: PackedVal<SC>,
    pub is_transition: PackedVal<SC>,
    pub alpha: SC::Challenge,
    pub accumulator: PackedChallenge<SC>,
}

impl<SC: StarkGenericConfig> ScopedBuilder for ProverConstraintFolder<SC> {}

impl<SC: StarkGenericConfig> AirBuilder for ProverConstraintFolder<SC> {
    type F = SC::Val;
    type Expr = PackedVal<SC>;
    type Var = PackedVal<SC>;
    type M = RowMajorMatrix<PackedVal<SC>>;

    fn main(&self) -> Self::M {
        self.main.clone()
    }

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
            panic!("uni-machine only supports a window size of 2")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let x: PackedVal<SC> = x.into();
        self.accumulator *= PackedChallenge::<SC>::from_f(self.alpha);
        self.accumulator += x;
    }
}

impl<SC: StarkGenericConfig> PublicValuesBuilder for ProverConstraintFolder<SC> {
    type PublicVar = Self::F;

    fn public_values(&self) -> &[Self::F] {
        &self.public_values
    }
}

impl<SC: StarkGenericConfig> PermutationBuilder for ProverConstraintFolder<SC> {
    type MP = RowMajorMatrix<PackedChallenge<SC>>;
    type RandomVar = PackedChallenge<SC>;

    fn permutation(&self) -> Self::MP {
        self.perm.clone()
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        &self.perm_challenges
    }

    type RegionalSum = PackedChallenge<SC>;
    type GlobalSum = SC::Val;

    fn regional_cumulative_sum(&self) -> &Self::RegionalSum {
        &self.regional_cumulative_sum
    }

    fn global_cumulative_sum(&self) -> &SepticDigest<Self::GlobalSum> {
        &self.global_cumulative_sum
    }
}

impl<SC: StarkGenericConfig> ExtensionBuilder for ProverConstraintFolder<SC> {
    type EF = SC::Challenge;
    type ExprEF = PackedChallenge<SC>;
    type VarEF = PackedChallenge<SC>;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        let x: PackedChallenge<SC> = x.into();
        self.accumulator *= PackedChallenge::<SC>::from_f(self.alpha);
        self.accumulator += x;
    }
}

impl<SC: StarkGenericConfig> ChipBuilder<SC::Val> for ProverConstraintFolder<SC> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed.clone()
    }
}

impl<SC: StarkGenericConfig> PairBuilder for ProverConstraintFolder<SC> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed.clone()
    }
}

type ViewPair<'a, T> = VerticalPair<RowMajorMatrixView<'a, T>, RowMajorMatrixView<'a, T>>;

/// Verifier Constraint Folder
#[derive(Debug)]
pub struct VerifierConstraintFolder<'a, SC: StarkGenericConfig> {
    pub preprocessed: ViewPair<'a, SC::Challenge>,
    pub main: ViewPair<'a, SC::Challenge>,
    pub perm: ViewPair<'a, SC::Challenge>,
    pub perm_challenges: &'a [SC::Challenge],
    pub regional_cumulative_sum: &'a SC::Challenge,
    pub global_cumulative_sum: &'a SepticDigest<SC::Val>,
    pub public_values: &'a [SC::Val],
    pub is_first_row: SC::Challenge,
    pub is_last_row: SC::Challenge,
    pub is_transition: SC::Challenge,
    pub alpha: SC::Challenge,
    pub accumulator: SC::Challenge,
}

impl<SC: StarkGenericConfig> ScopedBuilder for VerifierConstraintFolder<'_, SC> {}

impl<'a, SC: StarkGenericConfig> AirBuilder for VerifierConstraintFolder<'a, SC> {
    type F = SC::Val;
    type Expr = SC::Challenge;
    type Var = SC::Challenge;
    type M = ViewPair<'a, SC::Challenge>;

    fn main(&self) -> Self::M {
        self.main
    }

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
            panic!("uni-machine only supports a window size of 2")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let x: SC::Challenge = x.into();
        self.accumulator *= self.alpha;
        self.accumulator += x;
    }
}

impl<SC: StarkGenericConfig> ExtensionBuilder for VerifierConstraintFolder<'_, SC> {
    type EF = SC::Challenge;
    type ExprEF = SC::Challenge;
    type VarEF = SC::Challenge;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        let x: SC::Challenge = x.into();
        self.accumulator *= self.alpha;
        self.accumulator += x;
    }
}

impl<'a, SC: StarkGenericConfig> PermutationBuilder for VerifierConstraintFolder<'a, SC> {
    type MP = ViewPair<'a, SC::Challenge>;
    type RandomVar = SC::Challenge;

    fn permutation(&self) -> Self::MP {
        self.perm
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        self.perm_challenges
    }

    type RegionalSum = SC::Challenge;
    type GlobalSum = SC::Val;

    fn regional_cumulative_sum(&self) -> &'a Self::RegionalSum {
        self.regional_cumulative_sum
    }

    fn global_cumulative_sum(&self) -> &'a SepticDigest<Self::GlobalSum> {
        self.global_cumulative_sum
    }
}

impl<SC: StarkGenericConfig> PublicValuesBuilder for VerifierConstraintFolder<'_, SC> {
    type PublicVar = Self::F;

    fn public_values(&self) -> &[Self::F] {
        self.public_values
    }
}

impl<SC: StarkGenericConfig> ChipBuilder<SC::Val> for VerifierConstraintFolder<'_, SC> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

impl<SC: StarkGenericConfig> PairBuilder for VerifierConstraintFolder<'_, SC> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

pub type RecursiveVerifierConstraintFolder<'a, FC> = GenericVerifierConstraintFolder<
    'a,
    <FC as FieldGenericConfig>::F,
    <FC as FieldGenericConfig>::EF,
    RecursionFelt<<FC as FieldGenericConfig>::F>,
    RecursionExt<<FC as FieldGenericConfig>::F, <FC as FieldGenericConfig>::EF>,
    RecursionSymbolicExt<<FC as FieldGenericConfig>::F, <FC as FieldGenericConfig>::EF>,
>;

/// A folder for verifier constraints.
pub struct GenericVerifierConstraintFolder<'a, F, EF, PubVar, Var, Expr> {
    /// The preprocessed trace.
    pub preprocessed: VerticalPair<RowMajorMatrixView<'a, Var>, RowMajorMatrixView<'a, Var>>,
    /// The main trace.
    pub main: VerticalPair<RowMajorMatrixView<'a, Var>, RowMajorMatrixView<'a, Var>>,
    /// The permutation trace.
    pub perm: VerticalPair<RowMajorMatrixView<'a, Var>, RowMajorMatrixView<'a, Var>>,
    /// The challenges for the permutation.
    pub perm_challenges: &'a [Var],
    /// The local cumulative sum of the permutation.
    pub regional_cumulative_sum: &'a Var,
    /// The global cumulative sum of the permutation.
    pub global_cumulative_sum: &'a SepticDigest<PubVar>,
    /// The selector for the first row.
    pub is_first_row: Var,
    /// The selector for the last row.
    pub is_last_row: Var,
    /// The selector for the transition.
    pub is_transition: Var,
    /// The constraint folding challenge.
    pub alpha: Var,
    /// The accumulator for the constraint folding.
    pub accumulator: Expr,
    /// The public values.
    pub public_values: &'a [PubVar],
    /// The marker type.
    pub _marker: PhantomData<(F, EF)>,
}

impl<F, EF, PV, V, E> ScopedBuilder for GenericVerifierConstraintFolder<'_, F, EF, PV, V, E> {}

impl<'a, F, EF, PubVar, Var, Expr> AirBuilder
    for GenericVerifierConstraintFolder<'a, F, EF, PubVar, Var, Expr>
where
    F: Field,
    EF: ExtensionField<F>,
    Expr: FieldAlgebra
        + From<F>
        + Add<Var, Output = Expr>
        + Add<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<F, Output = Expr>
        + MulAssign<EF>,
    Var: Into<Expr>
        + Copy
        + Add<F, Output = Expr>
        + Add<Var, Output = Expr>
        + Add<Expr, Output = Expr>
        + Sub<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<Expr, Output = Expr>
        + Mul<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<Expr, Output = Expr>
        + Send
        + Sync,
    PubVar: Into<Expr> + Copy,
{
    type F = F;
    type Expr = Expr;
    type Var = Var;
    type M = VerticalPair<RowMajorMatrixView<'a, Var>, RowMajorMatrixView<'a, Var>>;

    fn main(&self) -> Self::M {
        self.main
    }

    fn is_first_row(&self) -> Self::Expr {
        self.is_first_row.into()
    }

    fn is_last_row(&self) -> Self::Expr {
        self.is_last_row.into()
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size == 2 {
            self.is_transition.into()
        } else {
            panic!("uni-stark only supports a window size of 2")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let x: Expr = x.into();
        self.accumulator *= self.alpha.into();
        self.accumulator += x;
    }
}

impl<F, EF, PubVar, Var, Expr> ExtensionBuilder
    for GenericVerifierConstraintFolder<'_, F, EF, PubVar, Var, Expr>
where
    F: Field,
    EF: ExtensionField<F>,
    Expr: FieldAlgebra<F = EF>
        + From<F>
        + Add<Var, Output = Expr>
        + Add<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<F, Output = Expr>
        + MulAssign<EF>,
    Var: Into<Expr>
        + Copy
        + Add<F, Output = Expr>
        + Add<Var, Output = Expr>
        + Add<Expr, Output = Expr>
        + Sub<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<Expr, Output = Expr>
        + Mul<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<Expr, Output = Expr>
        + Send
        + Sync,
    PubVar: Into<Expr> + Copy,
{
    type EF = EF;
    type ExprEF = Expr;
    type VarEF = Var;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.assert_zero(x);
    }
}

impl<'a, F, EF, PubVar, Var, Expr> PermutationBuilder
    for GenericVerifierConstraintFolder<'a, F, EF, PubVar, Var, Expr>
where
    F: Field,
    EF: ExtensionField<F>,
    Expr: FieldAlgebra<F = EF>
        + From<F>
        + Add<Var, Output = Expr>
        + Add<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<F, Output = Expr>
        + MulAssign<EF>,
    Var: Into<Expr>
        + Copy
        + Add<F, Output = Expr>
        + Add<Var, Output = Expr>
        + Add<Expr, Output = Expr>
        + Sub<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<Expr, Output = Expr>
        + Mul<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<Expr, Output = Expr>
        + Send
        + Sync,
    PubVar: Into<Expr> + Copy,
{
    type MP = VerticalPair<RowMajorMatrixView<'a, Var>, RowMajorMatrixView<'a, Var>>;
    type RandomVar = Var;

    fn permutation(&self) -> Self::MP {
        self.perm
    }

    fn permutation_randomness(&self) -> &[Self::Var] {
        self.perm_challenges
    }

    type RegionalSum = Var;
    type GlobalSum = PubVar;

    fn regional_cumulative_sum(&self) -> &'a Self::RegionalSum {
        self.regional_cumulative_sum
    }

    fn global_cumulative_sum(&self) -> &'a SepticDigest<Self::GlobalSum> {
        self.global_cumulative_sum
    }
}

impl<F, EF, PubVar, Var, Expr> PairBuilder
    for GenericVerifierConstraintFolder<'_, F, EF, PubVar, Var, Expr>
where
    F: Field,
    EF: ExtensionField<F>,
    Expr: FieldAlgebra<F = EF>
        + From<F>
        + Add<Var, Output = Expr>
        + Add<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<F, Output = Expr>
        + MulAssign<EF>,
    Var: Into<Expr>
        + Copy
        + Add<F, Output = Expr>
        + Add<Var, Output = Expr>
        + Add<Expr, Output = Expr>
        + Sub<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<Expr, Output = Expr>
        + Mul<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<Expr, Output = Expr>
        + Send
        + Sync,
    PubVar: Into<Expr> + Copy,
{
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

impl<F, EF, PubVar, Var, Expr> EmptyLookupBuilder
    for GenericVerifierConstraintFolder<'_, F, EF, PubVar, Var, Expr>
where
    F: Field,
    EF: ExtensionField<F>,
    Expr: FieldAlgebra<F = EF>
        + From<F>
        + Add<Var, Output = Expr>
        + Add<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<F, Output = Expr>
        + MulAssign<EF>,
    Var: Into<Expr>
        + Copy
        + Add<F, Output = Expr>
        + Add<Var, Output = Expr>
        + Add<Expr, Output = Expr>
        + Sub<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<Expr, Output = Expr>
        + Mul<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<Expr, Output = Expr>
        + Send
        + Sync,
    PubVar: Into<Expr> + Copy,
{
}

impl<F, EF, PubVar, Var, Expr> PublicValuesBuilder
    for GenericVerifierConstraintFolder<'_, F, EF, PubVar, Var, Expr>
where
    F: Field,
    EF: ExtensionField<F>,
    Expr: FieldAlgebra<F = EF>
        + From<F>
        + Add<Var, Output = Expr>
        + Add<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<F, Output = Expr>
        + MulAssign<EF>,
    Var: Into<Expr>
        + Copy
        + Add<F, Output = Expr>
        + Add<Var, Output = Expr>
        + Add<Expr, Output = Expr>
        + Sub<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<Expr, Output = Expr>
        + Mul<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<Expr, Output = Expr>
        + Send
        + Sync,
    PubVar: Into<Expr> + Copy,
{
    type PublicVar = PubVar;

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}

impl<F, EF, PubVar, Var, Expr> ChipBuilder<F>
    for GenericVerifierConstraintFolder<'_, F, EF, PubVar, Var, Expr>
where
    F: Field,
    EF: ExtensionField<F>,
    Expr: FieldAlgebra<F = EF>
        + From<F>
        + Add<Var, Output = Expr>
        + Add<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<F, Output = Expr>
        + MulAssign<EF>,
    Var: Into<Expr>
        + Copy
        + Add<F, Output = Expr>
        + Add<Var, Output = Expr>
        + Add<Expr, Output = Expr>
        + Sub<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<Expr, Output = Expr>
        + Mul<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<Expr, Output = Expr>
        + Send
        + Sync,
    PubVar: Into<Expr> + Copy,
{
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

#[derive(Debug)]
pub enum DebugConstraintFailure<F, EF> {
    FieldInequality(F, F),
    ExtensionNonzero(EF),
    NonBoolean(F),
}

/// A folder for debugging constraints.
pub struct DebugConstraintFolder<'a, F, EF> {
    pub(crate) preprocessed: ViewPair<'a, F>,
    pub(crate) main: ViewPair<'a, F>,
    pub(crate) permutation: ViewPair<'a, EF>,
    pub(crate) regional_cumulative_sum: EF,
    pub(crate) global_cumulative_sum: SepticDigest<F>,
    pub(crate) permutation_challenges: [EF; 2],
    pub(crate) is_first_row: F,
    pub(crate) is_last_row: F,
    pub(crate) is_transition: F,
    pub(crate) public_values: &'a [F],
    pub(crate) failures: Vec<(Vec<String>, DebugConstraintFailure<F, EF>)>,
    pub(crate) scopes: Vec<String>,
}

impl<F, EF> DebugConstraintFolder<'_, F, EF>
where
    F: Field,
{
    #[inline]
    fn debug_eq_constraint(&mut self, x: F, y: F) {
        if x != y {
            self.new_failure(DebugConstraintFailure::FieldInequality(x, y));
        }
    }

    #[inline]
    fn new_failure(&mut self, failure: DebugConstraintFailure<F, EF>) {
        self.failures.push((self.scopes.clone(), failure));
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
    type M = ViewPair<'a, F>;

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

    fn main(&self) -> Self::M {
        self.main
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

impl<'a, F, EF> PermutationBuilder for DebugConstraintFolder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type MP = ViewPair<'a, EF>;
    type RandomVar = EF;
    type RegionalSum = EF;
    type GlobalSum = F;

    fn permutation(&self) -> Self::MP {
        self.permutation
    }

    fn permutation_randomness(&self) -> &[Self::EF] {
        &self.permutation_challenges
    }

    fn regional_cumulative_sum(&self) -> &Self::RegionalSum {
        &self.regional_cumulative_sum
    }

    fn global_cumulative_sum(&self) -> &SepticDigest<Self::GlobalSum> {
        &self.global_cumulative_sum
    }
}

impl<F, EF> PairBuilder for DebugConstraintFolder<'_, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

impl<F, EF> ChipBuilder<F> for DebugConstraintFolder<'_, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

impl<F: Field, EF: ExtensionField<F>> PublicValuesBuilder for DebugConstraintFolder<'_, F, EF> {
    type PublicVar = F;

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}

impl<F: Field, EF: ExtensionField<F>> EmptyLookupBuilder for DebugConstraintFolder<'_, F, EF> {}
