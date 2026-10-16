use std::collections::{BTreeMap, HashMap};

use itertools::Itertools;
use p3_field::Field;
use p3_matrix::{dense::RowMajorMatrixView, Matrix};

use super::SymbolicInteraction;
use crate::{
    air::symbolic::{
        symbolic_expression::SymbolicEvaluator,
        symbolic_variable::{Entry, SymbolicVariable},
    },
    lookup::LookupType,
};

/// The actual interactions that are sent/received during a single run
/// of trace generation. For debugging purposes only.
#[derive(Default, Clone, Debug)]
pub struct LogicalInteractions<F: Field> {
    /// Lookup kind (bus) => (fields => (air_idx, count))
    #[allow(clippy::type_complexity)]
    pub at_bus: BTreeMap<LookupType, HashMap<Vec<F>, Vec<(usize, F)>>>,
}

pub fn generate_logical_interactions<F: Field>(
    air_idx: usize,
    all_interactions: &[SymbolicInteraction<F>],
    preprocessed: &Option<RowMajorMatrixView<F>>,
    partitioned_main: &[RowMajorMatrixView<F>],
    public_values: &[F],
    logical_interactions: &mut LogicalInteractions<F>,
) {
    if all_interactions.is_empty() {
        return;
    }

    let height = partitioned_main[0].height();

    for n in 0..height {
        let evaluator = Evaluator {
            preprocessed,
            partitioned_main,
            public_values,
            height,
            local_index: n,
        };
        for interaction in all_interactions {
            let fields = interaction
                .message
                .iter()
                .map(|expr| evaluator.eval_expr(expr))
                .collect_vec();
            let count = evaluator.eval_expr(&interaction.count);
            if count.is_zero() {
                continue;
            }
            logical_interactions
                .at_bus
                .entry(interaction.kind)
                .or_default()
                .entry(fields)
                .or_default()
                .push((air_idx, count));
        }
    }
}

struct Evaluator<'a, F: Field> {
    pub preprocessed: &'a Option<RowMajorMatrixView<'a, F>>,
    pub partitioned_main: &'a [RowMajorMatrixView<'a, F>],
    pub public_values: &'a [F],
    pub height: usize,
    pub local_index: usize,
}

impl<F: Field> SymbolicEvaluator<F, F> for Evaluator<'_, F> {
    fn eval_const(&self, c: F) -> F {
        c
    }
    fn eval_var(&self, symbolic_var: SymbolicVariable<F>) -> F {
        let n = self.local_index;
        let height = self.height;
        let index = symbolic_var.index;
        match symbolic_var.entry {
            Entry::Preprocessed { offset } => self
                .preprocessed
                .unwrap()
                .get((n + offset) % height, index)
                .unwrap(),
            Entry::Main { part_index, offset } => self.partitioned_main[part_index]
                .get((n + offset) % height, index)
                .unwrap(),
            Entry::Public => self.public_values[index],
        }
    }
    // The row selectors, so an interaction whose message or multiplicity uses one can be checked
    // here too. They used to be `unreachable!()`, which was fine only while no AIR put a selector
    // in a lookup: the Cpu row-linking bus counts its incoming edges as `is_real - is_first_row`,
    // and without these the multiset checker panics instead of checking it.
    fn eval_is_first_row(&self) -> F {
        F::from_bool(self.local_index == 0)
    }
    fn eval_is_last_row(&self) -> F {
        F::from_bool(self.local_index + 1 == self.height)
    }
    fn eval_is_transition(&self) -> F {
        F::from_bool(self.local_index + 1 != self.height)
    }
}

#[cfg(test)]
mod tests {
    use p3_field::{PrimeCharacteristicRing, PrimeField32};
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};

    use super::{generate_logical_interactions, LogicalInteractions};
    use crate::{
        air::symbolic::{
            symbolic_expression::SymbolicExpression,
            symbolic_variable::{Entry, SymbolicVariable},
        },
        interaction::Interaction,
        lookup::LookupType,
    };

    type F = KoalaBear;

    fn col(index: usize) -> SymbolicExpression<F> {
        SymbolicExpression::Variable(SymbolicVariable::new(
            Entry::Main {
                part_index: 0,
                offset: 0,
            },
            index,
        ))
    }

    /// The three row selectors, which an interaction may use in its message or multiplicity.
    ///
    /// They were `unreachable!()` until the Cpu row-chain bus counted its incoming edges as
    /// `is_real - is_first_row`; without them this checker panics instead of checking that bus.
    /// A height-3 trace pins all three at once, including the `is_transition = 1 - is_last_row`
    /// identity that the rest of the stack relies on.
    #[test]
    fn row_selectors_match_the_other_evaluators() {
        // One column, three rows, each holding its own row index as the message field. The count
        // is the selector under test, so a row contributes an entry only where it is 1.
        let trace = RowMajorMatrix::new(vec![F::ZERO, F::ONE, F::TWO], 1);
        let main = [trace.as_view()];
        let preprocessed: Option<RowMajorMatrixView<F>> = None;

        for (selector, expected_row) in [
            (SymbolicExpression::IsFirstRow, 0u32),
            (SymbolicExpression::IsLastRow, 2),
        ] {
            let mut seen = LogicalInteractions::<F>::default();
            generate_logical_interactions(
                0,
                &[Interaction {
                    message: vec![col(0)],
                    count: selector,
                    kind: LookupType::Byte,
                    count_weight: 1,
                }],
                &preprocessed,
                &main,
                &[],
                &mut seen,
            );
            let entries = &seen.at_bus[&LookupType::Byte];
            assert_eq!(entries.len(), 1, "exactly one row may carry the selector");
            let (fields, rows) = entries.iter().next().unwrap();
            assert_eq!(fields, &vec![F::from_u32(expected_row)]);
            assert_eq!(rows, &vec![(0, F::ONE)]);
        }

        // `is_transition` is the complement of `is_last_row`: rows 0 and 1, not row 2.
        let mut seen = LogicalInteractions::<F>::default();
        generate_logical_interactions(
            0,
            &[Interaction {
                message: vec![col(0)],
                count: SymbolicExpression::IsTransition,
                kind: LookupType::Byte,
                count_weight: 1,
            }],
            &preprocessed,
            &main,
            &[],
            &mut seen,
        );
        let mut carried: Vec<u32> = seen.at_bus[&LookupType::Byte]
            .keys()
            .map(|fields| fields[0].as_canonical_u32())
            .collect();
        carried.sort_unstable();
        assert_eq!(carried, vec![0, 1]);
    }

    /// A `send` records `+count` and a `receive` records `-count` for the same (bus, message);
    /// this signed-count convention is exactly what makes the per-bus LogUp multiset cancel.
    /// Pins the soundness-critical sign convention that `looking`/`looked` encode.
    #[test]
    fn send_and_receive_record_opposite_signed_counts() {
        // 2-column main trace, one row: col0 = count = 3, col1 = field = 42.
        let trace = RowMajorMatrix::new(vec![F::from_u32(3), F::from_u32(42)], 2);
        let main = [trace.as_view()];
        let preprocessed: Option<RowMajorMatrixView<F>> = None;
        let bus = LookupType::Byte;

        // send: count = +col0
        let send = vec![Interaction {
            message: vec![col(1)],
            count: col(0),
            kind: bus,
            count_weight: 1,
        }];
        // receive: count = -col0
        let recv = vec![Interaction {
            message: vec![col(1)],
            count: -col(0),
            kind: bus,
            count_weight: 1,
        }];

        let mut send_log = LogicalInteractions::<F>::default();
        generate_logical_interactions(0, &send, &preprocessed, &main, &[], &mut send_log);
        let mut recv_log = LogicalInteractions::<F>::default();
        generate_logical_interactions(0, &recv, &preprocessed, &main, &[], &mut recv_log);

        let msg = vec![F::from_u32(42)];
        assert_eq!(
            &send_log.at_bus[&bus][&msg],
            &vec![(0usize, F::from_u32(3))]
        );
        assert_eq!(
            &recv_log.at_bus[&bus][&msg],
            &vec![(0usize, -F::from_u32(3))]
        );
    }
}
