use super::lookup::LookupScope;
use crate::{
    iter::PicoScanIterator,
    machine::{
        builder::{ChipBuilder, PermutationBuilder},
        lookup::VirtualPairLookup,
    },
};
use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::{AirBuilder, ExtensionBuilder};
use p3_field::{ExtensionField, Field, FieldAlgebra, FieldExtensionAlgebra};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::*;
use std::borrow::Borrow;
use strum::IntoEnumIterator;

/// Computes the width of the permutation trace.
#[inline]
#[must_use]
pub const fn permutation_trace_width(num_interactions: usize, batch_size: usize) -> usize {
    num_interactions.div_ceil(batch_size) + 1
}

/// Returns the sends, receives, and permutation trace width grouped by scope.
#[allow(clippy::type_complexity)]
pub fn get_grouped_maps<F: Field>(
    sends: &[VirtualPairLookup<F>],
    receives: &[VirtualPairLookup<F>],
    batch_size: usize,
) -> (
    HashMap<LookupScope, Vec<VirtualPairLookup<F>>>,
    HashMap<LookupScope, Vec<VirtualPairLookup<F>>>,
    HashMap<LookupScope, usize>,
) {
    // Create a hashmap of scope -> vec<send interactions>.
    let mut sends = sends.to_vec();
    sends.sort_by_key(|k| k.scope);
    let grouped_sends: HashMap<_, _> = sends
        .iter()
        .chunk_by(|int| int.scope)
        .into_iter()
        .map(|(k, values)| (k, values.cloned().collect_vec()))
        .collect();

    // Create a hashmap of scope -> vec<receive interactions>.
    let mut receives = receives.to_vec();
    receives.sort_by_key(|k| k.scope);
    let grouped_receives: HashMap<_, _> = receives
        .iter()
        .chunk_by(|int| int.scope)
        .into_iter()
        .map(|(k, values)| (k, values.cloned().collect_vec()))
        .collect();

    // Create a hashmap of scope -> permutation trace width.
    let grouped_widths = LookupScope::iter()
        .map(|scope| {
            let empty_vec = vec![];
            let sends = grouped_sends.get(&scope).unwrap_or(&empty_vec);
            let receives = grouped_receives.get(&scope).unwrap_or(&empty_vec);
            (
                scope,
                permutation_trace_width(sends.len() + receives.len(), batch_size),
            )
        })
        .collect();

    (grouped_sends, grouped_receives, grouped_widths)
}

pub fn generate_permutation_trace<F: Field, EF: ExtensionField<F>>(
    looking: &[VirtualPairLookup<F>],
    looked: &[VirtualPairLookup<F>],
    preprocessed: Option<&RowMajorMatrix<F>>,
    main: &RowMajorMatrix<F>,
    random_elements: &[EF],
    batch_size: usize,
) -> (RowMajorMatrix<EF>, EF) {
    let (grouped_sends, grouped_receives, grouped_widths) =
        get_grouped_maps(looking, looked, batch_size);

    let empty_vec = vec![];
    let local_sends = grouped_sends
        .get(&LookupScope::Regional)
        .unwrap_or(&empty_vec);
    let local_receives = grouped_receives
        .get(&LookupScope::Regional)
        .unwrap_or(&empty_vec);

    let local_permutation_width = grouped_widths
        .get(&LookupScope::Regional)
        .cloned()
        .unwrap_or_default();

    let height = main.height();
    let permutation_trace_width = local_permutation_width;
    let mut permutation_trace = RowMajorMatrix::new(
        vec![EF::ZERO; permutation_trace_width * height],
        permutation_trace_width,
    );

    let mut regional_cumulative_sum = EF::ZERO;

    let random_elements = &random_elements[0..2];
    let local_row_range = 0..local_permutation_width;

    if local_sends.is_empty() && local_receives.is_empty() {
        return (permutation_trace, regional_cumulative_sum);
    }

    // Compute the permutation trace values in parallel.
    match preprocessed {
        Some(prep) => {
            permutation_trace
                .par_rows_mut()
                .zip_eq(prep.par_row_slices())
                .zip_eq(main.par_row_slices())
                .for_each(|((row, prep_row), main_row)| {
                    populate_permutation_row(
                        &mut row[0..local_permutation_width],
                        prep_row,
                        main_row,
                        local_sends,
                        local_receives,
                        random_elements,
                        batch_size,
                    );
                });
        }
        None => {
            permutation_trace
                .par_rows_mut()
                .zip_eq(main.par_row_slices())
                .for_each(|(row, main_row)| {
                    populate_permutation_row(
                        &mut row[0..local_permutation_width],
                        &[],
                        main_row,
                        local_sends,
                        local_receives,
                        random_elements,
                        batch_size,
                    );
                });
        }
    }

    let zero = EF::ZERO;
    let regional_cumulative_sums = permutation_trace
        .par_rows_mut()
        .map(|row| {
            row[local_row_range.start..local_row_range.end - 1]
                .iter()
                .copied()
                .sum::<EF>()
        })
        .collect::<Vec<_>>();

    let regional_cumulative_sums = regional_cumulative_sums
        .into_par_iter()
        .pico_scan(|a, b| *a + *b, zero)
        .collect::<Vec<_>>();

    regional_cumulative_sum = *regional_cumulative_sums.last().unwrap();

    permutation_trace
        .par_rows_mut()
        .zip_eq(regional_cumulative_sums.into_par_iter())
        .for_each(|(row, cumulative_sum)| {
            row[local_row_range.end - 1] = cumulative_sum;
        });

    (permutation_trace, regional_cumulative_sum)
}

/// Evaluates the permutation constraints for the given chip.
///
/// In particular, the constraints checked here are:
///     - The running sum column starts at zero.
///     - That the RLC per interaction is computed correctly.
///     - The running sum column ends at the (currently) given cumulative sum.
pub fn eval_permutation_constraints<F, AB>(
    looking: &[VirtualPairLookup<F>],
    looked: &[VirtualPairLookup<F>],
    batch_size: usize,
    lookup_scope: LookupScope,
    builder: &mut AB,
) where
    F: Field,
    AB::EF: ExtensionField<F>,
    AB: PermutationBuilder<F = F> + ChipBuilder<F>,
{
    let (grouped_sends, grouped_receives, grouped_widths) =
        get_grouped_maps(looking, looked, batch_size);

    let empty_vec = vec![];
    let local_sends = grouped_sends
        .get(&LookupScope::Regional)
        .unwrap_or(&empty_vec);
    let local_receives = grouped_receives
        .get(&LookupScope::Regional)
        .unwrap_or(&empty_vec);

    let local_permutation_width = grouped_widths
        .get(&LookupScope::Regional)
        .cloned()
        .unwrap_or_default();

    let preprocessed = builder.preprocessed();
    let main = builder.main();
    let perm = builder.permutation().to_row_major_matrix();

    let preprocessed_local = preprocessed.row_slice(0);
    let main_local = main.to_row_major_matrix();
    let main_local = main_local.row_slice(0);
    let main_local: &[AB::Var] = (*main_local).borrow();
    let perm_width = perm.width();
    let perm_local = perm.row_slice(0);
    let perm_local: &[AB::VarEF] = (*perm_local).borrow();
    let perm_next = perm.row_slice(1);
    let perm_next: &[AB::VarEF] = (*perm_next).borrow();

    // Assert that the permutation trace width is correct.
    if perm_width != local_permutation_width {
        panic!(
            "permutation trace width is incorrect: expected {local_permutation_width}, got {perm_width}",
        );
    }

    // Get the permutation challenges.
    let permutation_challenges = builder.permutation_randomness();
    let random_elements: Vec<AB::ExprEF> =
        permutation_challenges.iter().map(|x| (*x).into()).collect();
    let regional_cumulative_sum = *builder.regional_cumulative_sum();

    let random_elements = &random_elements[0..2];
    let (alpha, beta) = (&random_elements[0], &random_elements[1]);

    if !local_sends.is_empty() || !local_receives.is_empty() {
        // Ensure that each batch sum m_i/f_i is computed correctly.
        let interaction_chunks = &local_sends
            .iter()
            .map(|int| (int, true))
            .chain(local_receives.iter().map(|int| (int, false)))
            .chunks(batch_size);

        // Assert that the i-eth entry is equal to the sum_i m_i/rlc_i by constraints:
        // entry * \prod_i rlc_i = \sum_i m_i * \prod_{j!=i} rlc_j over all columns of the permutation
        // trace except the last column.
        for (entry, chunk) in perm_local[0..perm_local.len() - 1]
            .iter()
            .zip(interaction_chunks)
        {
            // First, we calculate the random linear combinations and multiplicities with the correct
            // sign depending on wetther the interaction is a send or a receive.
            let mut rlcs: Vec<AB::ExprEF> = Vec::with_capacity(batch_size);
            let mut multiplicities: Vec<AB::Expr> = Vec::with_capacity(batch_size);
            for (message, is_send) in chunk {
                let mut rlc = alpha.clone();
                let mut betas = beta.powers();

                rlc = rlc.clone()
                    + betas.next().unwrap()
                        * AB::ExprEF::from_canonical_usize(message.kind as usize);
                for (field, beta) in message.values.iter().zip(betas.clone()) {
                    let elem = field.apply::<AB::Expr, AB::Var>(&preprocessed_local, main_local);
                    rlc = rlc.clone() + beta * elem;
                }
                rlcs.push(rlc);

                let send_factor = if is_send { AB::F::ONE } else { -AB::F::ONE };
                multiplicities.push(
                    message
                        .mult
                        .apply::<AB::Expr, AB::Var>(&preprocessed_local, main_local)
                        * send_factor,
                );
            }

            // Now we can calculate the numerator and denominator of the combined batch.
            let mut product = AB::ExprEF::ONE;
            let mut numerator = AB::ExprEF::ZERO;
            for (i, (m, rlc)) in multiplicities.into_iter().zip(rlcs.iter()).enumerate() {
                // Calculate the running product of all rlcs.
                product *= rlc.clone();

                // Calculate the product of all but the current rlc.
                let mut all_but_current = AB::ExprEF::ONE;
                for other_rlc in rlcs
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| i != *j)
                    .map(|(_, rlc)| rlc)
                {
                    all_but_current *= other_rlc.clone();
                }
                numerator += AB::ExprEF::from_base(m) * all_but_current;
            }

            // Finally, assert that the entry is equal to the numerator divided by the product.
            let entry: AB::ExprEF = (*entry).into();
            builder.assert_eq_ext(product.clone() * entry.clone(), numerator);
        }

        // Compute the running local and next permutation sums.
        let sum_local = perm_local[..local_permutation_width - 1]
            .iter()
            .map(|x| (*x).into())
            .sum::<AB::ExprEF>();
        let sum_next = perm_next[..local_permutation_width - 1]
            .iter()
            .map(|x| (*x).into())
            .sum::<AB::ExprEF>();
        let phi_local: AB::ExprEF = (*perm_local.last().unwrap()).into();
        let phi_next: AB::ExprEF = (*perm_next.last().unwrap()).into();

        // Assert that cumulative sum is initialized to `phi_local` on the first row.
        builder
            .when_first_row()
            .assert_eq_ext(phi_local.clone(), sum_local);

        // Assert that the cumulative sum is constrained to `phi_next - phi_local` on the transition
        // rows.
        builder
            .when_transition()
            .assert_eq_ext(phi_next - phi_local.clone(), sum_next);
        builder
            .when_last_row()
            .assert_eq_ext(*perm_local.last().unwrap(), regional_cumulative_sum);
    }

    // Handle global permutations.
    let global_cumulative_sum = *builder.global_cumulative_sum();
    if lookup_scope == LookupScope::Global {
        for i in 0..7 {
            builder.when_last_row().assert_eq(
                main_local[main_local.len() - 14 + i],
                global_cumulative_sum.0.x.0[i],
            );
            builder.when_last_row().assert_eq(
                main_local[main_local.len() - 7 + i],
                global_cumulative_sum.0.y.0[i],
            );
        }
    }
}

#[inline]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_pass_by_value)]
pub fn populate_permutation_row<F: Field, EF: ExtensionField<F>>(
    row: &mut [EF],
    preprocessed_row: &[F],
    main_row: &[F],
    looking: &[VirtualPairLookup<F>],
    looked: &[VirtualPairLookup<F>],
    random_elements: &[EF],
    batch_size: usize,
) {
    let alpha = random_elements[0];

    // Generate the RLC elements to uniquely identify each item in the looked up tuple.
    let betas = random_elements[1].powers();

    let message_chunks = &looking
        .iter()
        .map(|int| (int, true))
        .chain(looked.iter().map(|int| (int, false)))
        .chunks(batch_size);

    // Compute the denominators \prod_{i\in B} row_fingerprint(alpha, beta).
    for (value, chunk) in row.iter_mut().zip(message_chunks) {
        *value = chunk
            .into_iter()
            .map(|(message, is_send)| {
                let mut denominator = alpha;
                let mut betas = betas.clone();
                denominator +=
                    betas.next().unwrap() * EF::from_canonical_usize(message.kind as usize);
                for (columns, beta) in message.values.iter().zip(betas) {
                    denominator += beta * columns.apply::<F, F>(preprocessed_row, main_row);
                }
                let mut mult = message.mult.apply::<F, F>(preprocessed_row, main_row);

                if !is_send {
                    mult = -mult;
                }

                EF::from_base(mult) / denominator
            })
            .sum();
    }
}
