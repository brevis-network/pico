use crate::air::any_air::BaseAirWithPublicValues;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::{air::PartitionedAirBuilder, PartitionedBaseAir};

#[derive(Clone)]
pub struct PreprocessedCachedAir {
    sels: Vec<bool>,
    num_cached_parts: usize,
}

impl PreprocessedCachedAir {
    pub fn new(sels: Vec<bool>, num_cached_parts: usize) -> Self {
        assert!(num_cached_parts > 0, "num_cached_parts must be at least 1");
        Self {
            sels,
            num_cached_parts,
        }
    }
}

impl<F: Field> PartitionedBaseAir<F> for PreprocessedCachedAir {
    fn cached_main_widths(&self) -> Vec<usize> {
        vec![1; self.num_cached_parts]
    }

    fn common_main_width(&self) -> usize {
        1
    }
}

impl<F: Field> BaseAir<F> for PreprocessedCachedAir {
    fn width(&self) -> usize {
        1 + self.num_cached_parts
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        Some(RowMajorMatrix::new_col(
            self.sels.iter().map(|&sel| F::from_bool(sel)).collect(),
        ))
    }
}

impl<F: Field> BaseAirWithPublicValues<F> for PreprocessedCachedAir {}

impl<AB: PartitionedAirBuilder> Air<AB> for PreprocessedCachedAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let preprocessed = builder.preprocessed().clone();
        let preprocessed_local = preprocessed.current_slice()[0];
        let preprocessed_next = preprocessed.next_slice()[0];
        let common_local = builder.common_main().current_slice()[0];
        let common_next = builder.common_main().next_slice()[0];
        let cached_rows: Vec<_> = builder
            .cached_mains()
            .iter()
            .map(|cached_main| {
                let local = cached_main.current_slice()[0];
                let next = cached_main.next_slice()[0];
                (local, next)
            })
            .collect();

        debug_assert_eq!(cached_rows.len(), self.num_cached_parts);

        builder.assert_zero(preprocessed_local * (preprocessed_local - AB::Expr::ONE));
        builder.when_first_row().assert_zero(common_local);
        builder
            .when_transition()
            .assert_one(common_next - common_local);

        // Each cached partition increments the previous partition by the selector bit.
        let mut prev_local = common_local;
        let mut prev_next = common_next;
        for (cached_local, cached_next) in cached_rows {
            builder.assert_eq(prev_local + preprocessed_local, cached_local);
            builder
                .when_transition()
                .assert_eq(prev_next + preprocessed_next, cached_next);
            prev_local = cached_local;
            prev_next = cached_next;
        }
    }
}
