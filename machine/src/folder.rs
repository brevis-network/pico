use crate::builder::PermSumAirBuilder;
use p3_air::{
    AirBuilder, AirBuilderWithPublicValues, ExtensionBuilder, PairBuilder, PermutationAirBuilder,
};
use p3_field::AbstractField;
use p3_matrix::{
    dense::{RowMajorMatrix, RowMajorMatrixView},
    stack::VerticalPair,
};
use pico_configs::config::{PackedChallenge, PackedVal, StarkGenericConfig, Val};

use crate::chip::ChipBuilder;
// from p3: uni-stark/src/folder.rs

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
            panic!("uni-stark only supports a window size of 2")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let x: PackedVal<SC> = x.into();
        self.accumulator *= PackedChallenge::<SC>::from_f(self.alpha);
        self.accumulator += x;
    }
}

impl<'a, SC: StarkGenericConfig> AirBuilderWithPublicValues for ProverConstraintFolder<'a, SC> {
    type PublicVar = Self::F;

    fn public_values(&self) -> &[Self::F] {
        &self.public_values
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

impl<'a, SC: StarkGenericConfig> PermutationAirBuilder for ProverConstraintFolder<'a, SC> {
    type MP = RowMajorMatrix<PackedChallenge<SC>>;
    type RandomVar = PackedChallenge<SC>;

    fn permutation(&self) -> Self::MP {
        self.perm.clone()
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        self.perm_challenges
    }
}

impl<'a, SC: StarkGenericConfig> PermSumAirBuilder for ProverConstraintFolder<'a, SC> {
    type Sum = PackedChallenge<SC>;

    fn cumulative_sum(&self) -> Self::Sum {
        PackedChallenge::<SC>::from_f(self.cumulative_sum)
    }
}

impl<'a, SC: StarkGenericConfig> PairBuilder for ProverConstraintFolder<'a, SC> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed.clone()
    }
}

impl<'a, SC: StarkGenericConfig> ChipBuilder<Val<SC>> for ProverConstraintFolder<'a, SC> {}

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
            panic!("uni-stark only supports a window size of 2")
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

impl<'a, SC: StarkGenericConfig> PermutationAirBuilder for VerifierConstraintFolder<'a, SC> {
    type MP = ViewPair<'a, SC::Challenge>;
    type RandomVar = SC::Challenge;

    fn permutation(&self) -> Self::MP {
        self.perm
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        self.perm_challenges
    }
}

impl<'a, SC: StarkGenericConfig> PermSumAirBuilder for VerifierConstraintFolder<'a, SC> {
    type Sum = SC::Challenge;

    fn cumulative_sum(&self) -> Self::Sum {
        self.cumulative_sum
    }
}

impl<'a, SC: StarkGenericConfig> PairBuilder for VerifierConstraintFolder<'a, SC> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

impl<'a, SC: StarkGenericConfig> AirBuilderWithPublicValues for VerifierConstraintFolder<'a, SC> {
    type PublicVar = Self::F;

    fn public_values(&self) -> &[Self::F] {
        &self.public_values
    }
}
