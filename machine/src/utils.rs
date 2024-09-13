use core::iter;
use itertools::Itertools;
use std::any::type_name;

use p3_air::Air;
use p3_commit::PolynomialSpace;
use p3_field::{AbstractExtensionField, AbstractField, ExtensionField, Field, PackedValue, Powers};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::*;
use p3_util::log2_strict_usize;

use pico_configs::config::{Domain, PackedChallenge, PackedVal, StarkGenericConfig, Val};

use crate::{
    chip::{ChipBehavior, MetaChip},
    folder::ProverConstraintFolder,
    lookup::LookupPayload,
};

pub fn type_name_of<T>(_: &T) -> String {
    type_name::<T>().to_string()
}

pub fn pad_to_power_of_two<const N: usize, T: Clone + Default>(values: &mut Vec<T>) {
    debug_assert!(values.len() % N == 0);
    let mut n_real_rows = values.len() / N;
    if n_real_rows < 16 {
        n_real_rows = 16;
    }
    values.resize(n_real_rows.next_power_of_two() * N, T::default());
}

// /// Create a new prover.
// pub fn get_prover<SC, C>() -> BaseProver<SC, C>
// {
//     BaseProver::new(config, chips)
// }
//
// /// Create a new verifier.
// pub fn get_verifier<'a, SC, C>(
//     config: &'a SC,
//     chips: &'a [MetaChip<Val<SC>, C>],
// ) -> BaseVerifier<'a, SC, C>
// where
//     SC: StarkGenericConfig,
//     C: ChipBehavior<Val<SC>> + Air<VerifierConstraintFolder<'a, SC>>,
// {
//     BaseVerifier::new(config, chips)
// }

/// Compute quotient values for opening proof
pub fn compute_quotient_values<'a, SC, C, Mat>(
    chip: &MetaChip<Val<SC>, C>,
    public_values: &'a [Val<SC>],
    trace_domain: Domain<SC>,
    quotient_domain: Domain<SC>,
    preprocessed_on_quotient_domain: Mat,
    main_trace_on_quotient_domain: Mat,
    permutation_trace_on_quotient_domain: Mat,
    perm_challenges: &'a [PackedChallenge<SC>],
    cumulative_sum: SC::Challenge,
    alpha: SC::Challenge,
) -> Vec<SC::Challenge>
where
    SC: StarkGenericConfig,
    C: Air<ProverConstraintFolder<'a, SC>> + ChipBehavior<Val<SC>>,
    Mat: Matrix<Val<SC>> + Sync,
{
    let quotient_size = quotient_domain.size();
    let preprocessed_width = preprocessed_on_quotient_domain.width();
    let main_width = main_trace_on_quotient_domain.width();
    let permutation_width = permutation_trace_on_quotient_domain.width();
    let mut sels = trace_domain.selectors_on_coset(quotient_domain);

    let qdb = log2_strict_usize(quotient_domain.size()) - log2_strict_usize(trace_domain.size());
    let next_step = 1 << qdb;

    for _ in quotient_size..PackedVal::<SC>::WIDTH {
        sels.is_first_row.push(Val::<SC>::default());
        sels.is_last_row.push(Val::<SC>::default());
        sels.is_transition.push(Val::<SC>::default());
        sels.inv_zeroifier.push(Val::<SC>::default());
    }
    let ext_degree = SC::Challenge::D;

    (0..quotient_size)
        .into_par_iter()
        .step_by(PackedVal::<SC>::WIDTH)
        .flat_map_iter(|i_start| {
            // let wrap = |i| i % quotient_size;
            let i_range = i_start..i_start + PackedVal::<SC>::WIDTH;

            let is_first_row = *PackedVal::<SC>::from_slice(&sels.is_first_row[i_range.clone()]);
            let is_last_row = *PackedVal::<SC>::from_slice(&sels.is_last_row[i_range.clone()]);
            let is_transition = *PackedVal::<SC>::from_slice(&sels.is_transition[i_range.clone()]);
            let inv_zerofier = *PackedVal::<SC>::from_slice(&sels.inv_zeroifier[i_range.clone()]);

            let preprocessed_trace_on_quotient_domain = RowMajorMatrix::new(
                iter::empty()
                    .chain(preprocessed_on_quotient_domain.vertically_packed_row(i_start))
                    .chain(
                        preprocessed_on_quotient_domain.vertically_packed_row(i_start + next_step),
                    )
                    .collect_vec(),
                preprocessed_width,
            );

            let main_on_quotient_domain = RowMajorMatrix::new(
                iter::empty()
                    .chain(main_trace_on_quotient_domain.vertically_packed_row(i_start))
                    .chain(main_trace_on_quotient_domain.vertically_packed_row(i_start + next_step))
                    .collect_vec(),
                main_width,
            );

            let perm_local = (0..permutation_width).step_by(ext_degree).map(|c| {
                PackedChallenge::<SC>::from_base_fn(|i| {
                    PackedVal::<SC>::from_fn(|offset| {
                        permutation_trace_on_quotient_domain.get(
                            (i_start + offset) % permutation_trace_on_quotient_domain.height(),
                            c + i,
                        )
                    })
                })
            });

            let perm_next = (0..permutation_width).step_by(ext_degree).map(|c| {
                PackedChallenge::<SC>::from_base_fn(|i| {
                    PackedVal::<SC>::from_fn(|offset| {
                        permutation_trace_on_quotient_domain.get(
                            (i_start + next_step + offset)
                                % permutation_trace_on_quotient_domain.height(),
                            c + i,
                        )
                    })
                })
            });

            let perm_vertical_width = permutation_width / ext_degree;
            let permutation_on_quotient_domain = RowMajorMatrix::new(
                iter::empty()
                    .chain(perm_local)
                    .chain(perm_next)
                    .collect_vec(),
                perm_vertical_width,
            );

            let accumulator = PackedChallenge::<SC>::zero();

            let mut folder = ProverConstraintFolder {
                preprocessed: preprocessed_trace_on_quotient_domain,
                main: main_on_quotient_domain,
                perm: permutation_on_quotient_domain,
                public_values,
                perm_challenges,
                cumulative_sum,
                is_first_row,
                is_last_row,
                is_transition,
                alpha,
                accumulator,
            };
            chip.eval(&mut folder);

            let quotient = folder.accumulator * inv_zerofier;

            // todo: need to check this in detail
            (0..core::cmp::min(quotient_size, PackedVal::<SC>::WIDTH)).map(move |idx_in_packing| {
                let quotient_value = (0..<SC::Challenge as AbstractExtensionField<Val<SC>>>::D)
                    .map(|coeff_idx| quotient.as_base_slice()[coeff_idx].as_slice()[idx_in_packing])
                    .collect::<Vec<_>>();
                SC::Challenge::from_base_slice(&quotient_value)
            })
        })
        .collect()
}

#[inline]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_pass_by_value)]
pub fn populate_permutation_row<F: Field, EF: ExtensionField<F>>(
    row: &mut [EF],
    preprocessed_row: &[F],
    main_row: &[F],
    looking: &[LookupPayload<F>],
    looked: &[LookupPayload<F>],
    alpha: EF,
    betas: Powers<EF>,
    batch_size: usize,
) {
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
