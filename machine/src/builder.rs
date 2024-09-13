use crate::{
    chip::ChipBuilder,
    folder::{ProverConstraintFolder, VerifierConstraintFolder},
    lookup::{symbolic_to_virtual_pair, AirInteraction, LookupPayload},
};
use p3_air::{AirBuilder, FilteredAirBuilder, PairBuilder, PairCol, PermutationAirBuilder};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{Entry, SymbolicAirBuilder, SymbolicExpression, SymbolicVariable};
use pico_configs::config::{StarkGenericConfig, Val};

/// A Proxy Builders for chip, impl the MessageBuilder, PairBuilder
// ChipProxyBuilder corresponding sp1 InteractionBuilder
pub struct ChipProxyBuilder<F: Field> {
    preprocessed: RowMajorMatrix<SymbolicVariable<F>>,
    main: RowMajorMatrix<SymbolicVariable<F>>,
    looking: Vec<LookupPayload<F>>,
    looked: Vec<LookupPayload<F>>,
}

/// message builder for the chips.
pub trait MessageBuilder<M> {
    fn looking(&mut self, message: M);

    fn looked(&mut self, message: M);
}

impl<F: Field> ChipProxyBuilder<F> {
    /// Creates a new [`InteractionBuilder`] with the given width.
    #[must_use]
    pub fn new(preprocessed_width: usize, main_width: usize) -> Self {
        let preprocessed_width = preprocessed_width.max(1);
        let prep_values = [0, 1]
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
            preprocessed: RowMajorMatrix::new(prep_values, preprocessed_width),
            main: RowMajorMatrix::new(main_values, main_width),
            looking: vec![],
            looked: vec![],
        }
    }

    /// Returns lookup messages
    #[must_use]
    pub fn lookup_message(self) -> (Vec<LookupPayload<F>>, Vec<LookupPayload<F>>) {
        (self.looking, self.looked)
    }
}

impl<F: Field> AirBuilder for ChipProxyBuilder<F> {
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
            panic!("uni-stark only supports a window size of 2")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, _x: I) {}
}

impl<F: Field> PairBuilder for ChipProxyBuilder<F> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed.clone()
    }
}

impl<F: Field> MessageBuilder<AirInteraction<SymbolicExpression<F>>> for ChipProxyBuilder<F> {
    fn looking(&mut self, message: AirInteraction<SymbolicExpression<F>>) {
        let values = message
            .values
            .into_iter()
            .map(|v| symbolic_to_virtual_pair(&v))
            .collect::<Vec<_>>();

        let multiplicity = symbolic_to_virtual_pair(&message.multiplicity);

        self.looking
            .push(LookupPayload::new(values, multiplicity, message.kind));
    }

    fn looked(&mut self, message: AirInteraction<SymbolicExpression<F>>) {
        let values = message
            .values
            .into_iter()
            .map(|v| symbolic_to_virtual_pair(&v))
            .collect::<Vec<_>>();

        let multiplicity = symbolic_to_virtual_pair(&message.multiplicity);

        self.looked
            .push(LookupPayload::new(values, multiplicity, message.kind));
    }
}

/// A builder that implements a permutation argument.
pub trait PermSumAirBuilder: PermutationAirBuilder {
    /// The type of the cumulative sum.
    type Sum: Into<Self::ExprEF>;

    /// Returns the cumulative sum of the permutation.
    fn cumulative_sum(&self) -> Self::Sum;
}

pub fn eval_symbolic_to_virtual_pair<F: Field>(
    expression: &SymbolicExpression<F>,
) -> (Vec<(PairCol, F)>, F) {
    match expression {
        SymbolicExpression::Constant(c) => (vec![], *c),
        SymbolicExpression::Variable(v) => match v.entry {
            Entry::Preprocessed { offset: 0 } => {
                (vec![(PairCol::Preprocessed(v.index), F::one())], F::zero())
            }
            Entry::Main { offset: 0 } => (vec![(PairCol::Main(v.index), F::one())], F::zero()),
            _ => panic!(
                "not an affine expression in current row elements {:?}",
                v.entry
            ),
        },
        SymbolicExpression::Add { x, y, .. } => {
            let (v_l, c_l) = eval_symbolic_to_virtual_pair(x);
            let (v_r, c_r) = eval_symbolic_to_virtual_pair(y);
            ([v_l, v_r].concat(), c_l + c_r)
        }
        SymbolicExpression::Sub { x, y, .. } => {
            let (v_l, c_l) = eval_symbolic_to_virtual_pair(x);
            let (v_r, c_r) = eval_symbolic_to_virtual_pair(y);
            let neg_v_r = v_r.iter().map(|(c, w)| (*c, -*w)).collect();
            ([v_l, neg_v_r].concat(), c_l - c_r)
        }
        SymbolicExpression::Neg { x, .. } => {
            let (v, c) = eval_symbolic_to_virtual_pair(x);
            (v.iter().map(|(c, w)| (*c, -*w)).collect(), -c)
        }
        SymbolicExpression::Mul { x, y, .. } => {
            let (v_l, c_l) = eval_symbolic_to_virtual_pair(x);
            let (v_r, c_r) = eval_symbolic_to_virtual_pair(y);

            let mut v = vec![];
            v.extend(v_l.iter().map(|(c, w)| (*c, *w * c_r)));
            v.extend(v_r.iter().map(|(c, w)| (*c, *w * c_l)));

            if !v_l.is_empty() && !v_r.is_empty() {
                panic!("Not an affine expression")
            }

            (v, c_l * c_r)
        }
        SymbolicExpression::IsFirstRow => {
            panic!("not an affine expression in current row elements for first row")
        }
        SymbolicExpression::IsLastRow => {
            panic!("not an affine expression in current row elements for last row")
        }
        SymbolicExpression::IsTransition => {
            panic!("not an affine expression in current row elements for transition row")
        }
    }
}
/// A message builder for which sending and receiving messages is a no-op.
pub trait EmptyMessageBuilder: AirBuilder {}

impl<AB: EmptyMessageBuilder, M> MessageBuilder<M> for AB {
    fn looking(&mut self, _message: M) {}

    fn looked(&mut self, _message: M) {}
}

// ChipBuilder: AirBuilder + MessageBuilder
// VerifierConstraintFolder/ProverConstraintFolder: ChipBuilder
// so VerifierConstraintFolder/VerifierConstraintFolder must impls all of AirBuilder + MessageBuilder trait functions
impl<'a, SC: StarkGenericConfig> ChipBuilder<Val<SC>> for VerifierConstraintFolder<'a, SC> {}
impl<'a, SC: StarkGenericConfig> EmptyMessageBuilder for ProverConstraintFolder<'a, SC> {}
impl<'a, SC: StarkGenericConfig> EmptyMessageBuilder for VerifierConstraintFolder<'a, SC> {}

impl<F: Field> ChipBuilder<F> for ChipProxyBuilder<F> {}
impl<F: Field> EmptyMessageBuilder for SymbolicAirBuilder<F> {}

impl<F: Field> ChipBuilder<F> for SymbolicAirBuilder<F> {}
impl<'a, F: Field, AB: AirBuilder<F = F>> ChipBuilder<F> for FilteredAirBuilder<'a, AB> {}

impl<'a, F: Field, AB: AirBuilder<F = F>> EmptyMessageBuilder for FilteredAirBuilder<'a, AB> {}
