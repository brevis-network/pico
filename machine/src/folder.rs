use crate::builder::{LookupBuilder, PermutationBuilder, PublicValuesBuilder};
use p3_air::{AirBuilder, ExtensionBuilder};
use p3_field::{AbstractField, Field};
use p3_matrix::{
    dense::{RowMajorMatrix, RowMajorMatrixView},
    stack::VerticalPair,
};
use p3_uni_stark::{Entry, SymbolicExpression, SymbolicVariable};
use pico_configs::config::{PackedChallenge, PackedVal, StarkGenericConfig, Val};

use crate::{
    builder::ChipBuilder,
    lookup::{symbolic_to_virtual_pair, SymbolicLookup, VirtualPairLookup},
};

// SymbolicConstraintFolder for lookup-related variables and constraints
// It also impls functions for SymbolicAirBuilder, thus replacing it
pub struct SymbolicConstraintFolder<F: Field> {
    preprocessed: RowMajorMatrix<SymbolicVariable<F>>,
    main: RowMajorMatrix<SymbolicVariable<F>>,
    looking: Vec<VirtualPairLookup<F>>,
    looked: Vec<VirtualPairLookup<F>>,
    constraints: Vec<SymbolicExpression<F>>,
    public_values: Vec<SymbolicVariable<F>>,
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

        Self {
            preprocessed: RowMajorMatrix::new(preprocessed_values, preprocessed_width),
            main: RowMajorMatrix::new(main_values, main_width),
            looking: vec![],
            looked: vec![],
            constraints: vec![],
            public_values: vec![],
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

impl<F: Field> LookupBuilder<SymbolicLookup<SymbolicExpression<F>>> for SymbolicConstraintFolder<F> {
    fn looking(&mut self, message: SymbolicLookup<SymbolicExpression<F>>) {
        let values = message
            .values
            .into_iter()
            .map(|v| symbolic_to_virtual_pair(&v))
            .collect::<Vec<_>>();

        let multiplicity = symbolic_to_virtual_pair(&message.multiplicity);

        self.looking
            .push(VirtualPairLookup::new(values, multiplicity, message.kind));
    }

    fn looked(&mut self, message: SymbolicLookup<SymbolicExpression<F>>) {
        let values = message
            .values
            .into_iter()
            .map(|v| symbolic_to_virtual_pair(&v))
            .collect::<Vec<_>>();

        let multiplicity = symbolic_to_virtual_pair(&message.multiplicity);

        self.looked
            .push(VirtualPairLookup::new(values, multiplicity, message.kind));
    }
}

impl<F: Field> ChipBuilder<F> for SymbolicConstraintFolder<F> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed.clone()
    }
}

/// Prover Constraint Folder
#[derive(Debug)]
pub struct ProverConstraintFolder<'a, SC: StarkGenericConfig> {
    pub preprocessed: RowMajorMatrix<PackedVal<SC>>,
    pub main: RowMajorMatrix<PackedVal<SC>>,
    pub perm: RowMajorMatrix<PackedChallenge<SC>>,
    pub public_values: &'a [Val<SC>],
    pub perm_challenges: &'a [PackedChallenge<SC>],
    pub cumulative_sum: SC::Challenge,
    pub is_first_row: PackedVal<SC>,
    pub is_last_row: PackedVal<SC>,
    pub is_transition: PackedVal<SC>,
    pub alpha: SC::Challenge,
    pub accumulator: PackedChallenge<SC>,
}

impl<'a, SC: StarkGenericConfig> AirBuilder for ProverConstraintFolder<'a, SC> {
    type F = Val<SC>;
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

impl<'a, SC: StarkGenericConfig> PublicValuesBuilder for ProverConstraintFolder<'a, SC> {
    type PublicVar = Self::F;

    fn public_values(&self) -> &[Self::F] {
        &self.public_values
    }
}

impl<'a, SC: StarkGenericConfig> PermutationBuilder for ProverConstraintFolder<'a, SC> {
    type MP = RowMajorMatrix<PackedChallenge<SC>>;
    type RandomVar = PackedChallenge<SC>;

    fn permutation(&self) -> Self::MP {
        self.perm.clone()
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        self.perm_challenges
    }

    type Sum = PackedChallenge<SC>;

    fn cumulative_sum(&self) -> Self::Sum {
        PackedChallenge::<SC>::from_f(self.cumulative_sum)
    }
}

impl<'a, SC: StarkGenericConfig> ExtensionBuilder for ProverConstraintFolder<'a, SC> {
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

impl<'a, SC: StarkGenericConfig> ChipBuilder<Val<SC>> for ProverConstraintFolder<'a, SC> {
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
    pub cumulative_sum: SC::Challenge,
    pub public_values: Vec<Val<SC>>,
    pub is_first_row: SC::Challenge,
    pub is_last_row: SC::Challenge,
    pub is_transition: SC::Challenge,
    pub alpha: SC::Challenge,
    pub accumulator: SC::Challenge,
}

impl<'a, SC: StarkGenericConfig> AirBuilder for VerifierConstraintFolder<'a, SC> {
    type F = Val<SC>;
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

impl<'a, SC: StarkGenericConfig> ExtensionBuilder for VerifierConstraintFolder<'a, SC> {
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

    type Sum = SC::Challenge;

    fn cumulative_sum(&self) -> Self::Sum {
        self.cumulative_sum
    }
}

impl<'a, SC: StarkGenericConfig> PublicValuesBuilder for VerifierConstraintFolder<'a, SC> {
    type PublicVar = Self::F;

    fn public_values(&self) -> &[Self::F] {
        &self.public_values
    }
}

impl<'a, SC: StarkGenericConfig> ChipBuilder<Val<SC>> for VerifierConstraintFolder<'a, SC> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed.clone()
    }
}
