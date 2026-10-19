use std::borrow::Borrow;

use crate::air::any_air::BaseAirWithPublicValues;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use super::columns::FibonacciSelectorCols;
use crate::{
    builder::LookupBuilder,
    lookup::{LookupScope, LookupType, SymbolicLookup},
    test_utils::dummy_airs::fib_air::columns::{FibonacciCols, NUM_FIBONACCI_COLS},
    PartitionedBaseAir,
};

pub struct FibonacciSelectorAir {
    sels: Vec<bool>,
    kind: Option<LookupType>,
}

impl FibonacciSelectorAir {
    pub fn new(sels: Vec<bool>, enable_interactions: bool) -> Self {
        Self {
            sels,
            kind: enable_interactions.then_some(LookupType::Byte),
        }
    }

    pub fn sels(&self) -> &[bool] {
        &self.sels
    }
}

impl<F: Field> PartitionedBaseAir<F> for FibonacciSelectorAir {}
impl<F: Field> BaseAir<F> for FibonacciSelectorAir {
    fn width(&self) -> usize {
        NUM_FIBONACCI_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let sels = self.sels.iter().map(|&s| F::from_bool(s)).collect();
        Some(RowMajorMatrix::new_col(sels))
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for FibonacciSelectorAir {
    fn num_public_values(&self) -> usize {
        3
    }
}

impl<AB: AirBuilder + LookupBuilder<SymbolicLookup<AB::Expr>>> Air<AB> for FibonacciSelectorAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let pis = builder.public_values();
        let preprocessed = builder.preprocessed().clone();
        let main = builder.main();

        let a = pis[0];
        let b = pis[1];
        let x = pis[2];

        let preprocessed_local = preprocessed.current_slice();
        let preprocessed_local: &FibonacciSelectorCols<AB::Var> = (*preprocessed_local).borrow();

        let (local, next) = (main.current_slice(), main.next_slice());
        let local: &FibonacciCols<AB::Var> = (*local).borrow();
        let next: &FibonacciCols<AB::Var> = (*next).borrow();

        let mut when_first_row = builder.when_first_row();

        when_first_row.assert_eq(local.left, a);
        when_first_row.assert_eq(local.right, b);

        // a' <- sel*b + (1 - sel)*a
        builder
            .when_transition()
            .when(preprocessed_local.sel)
            .assert_eq(local.right, next.left);
        builder
            .when_transition()
            .when_ne(preprocessed_local.sel, AB::Expr::ONE)
            .assert_eq(local.left, next.left);

        // b' <- sel*(a + b) + (1 - sel)*b
        builder
            .when_transition()
            .when(preprocessed_local.sel)
            .assert_eq(local.left + local.right, next.right);
        builder
            .when_transition()
            .when_ne(preprocessed_local.sel, AB::Expr::ONE)
            .assert_eq(local.right, next.right);

        builder.when_last_row().assert_eq(local.right, x);

        if let Some(kind) = self.kind {
            // Table/key side of a lookup: `looked` records the key with negated
            // multiplicity (the number of enabled lookups) and count_weight = 0.
            builder.looked(SymbolicLookup::new(
                vec![local.left + local.right],
                preprocessed_local.sel.into(),
                kind,
                LookupScope::Regional,
            ));
        }
    }
}
