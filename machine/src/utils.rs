use core::iter;
use itertools::Itertools;
use std::any::type_name;

use p3_air::Air;
use p3_commit::PolynomialSpace;
use p3_field::{AbstractExtensionField, AbstractField, PackedValue};
use p3_matrix::{dense::RowMajorMatrix, stack::VerticalPair, Matrix};
use p3_maybe_rayon::prelude::*;
use p3_util::log2_strict_usize;

use pico_configs::config::{Domain, PackedChallenge, PackedVal, StarkGenericConfig, Val};

use crate::{
    chip::{BaseChip, ChipBehavior},
    folder::{ProverConstraintFolder, VerifierConstraintFolder},
    prover::BaseProver,
    verifier::BaseVerifier,
};

pub fn pad_to_power_of_two<const N: usize, T: Clone + Default>(values: &mut Vec<T>) {
    debug_assert!(values.len() % N == 0);
    let mut n_real_rows = values.len() / N;
    if n_real_rows < 16 {
        n_real_rows = 16;
    }
    values.resize(n_real_rows.next_power_of_two() * N, T::default());
}

/// Create a new prover.
pub fn get_prover<'a, SC, C>(
    config: &'a SC,
    chips: Vec<BaseChip<Val<SC>, C>>,
) -> BaseProver<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>> + Air<ProverConstraintFolder<'a, SC>>,
{
    BaseProver::new(config, chips)
}

/// Create a new verifier.
pub fn get_verifier<'a, SC, C>(
    config: &'a SC,
    chips: Vec<BaseChip<Val<SC>, C>>,
) -> BaseVerifier<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>> + Air<VerifierConstraintFolder<'a, SC>>,
{
    BaseVerifier::new(config, chips)
}

/// Compute quotient values for opening proof
pub fn compute_quotient_values<'a, SC, C, Mat>(
    chip: &BaseChip<Val<SC>, C>,
    public_values: &'a [Val<SC>],
    trace_domain: Domain<SC>,
    quotient_domain: Domain<SC>,
    main_on_quotient_domain: Mat,
    alpha: SC::Challenge,
) -> Vec<SC::Challenge>
where
    SC: StarkGenericConfig,
    C: Air<ProverConstraintFolder<'a, SC>> + ChipBehavior<Val<SC>>,
    Mat: Matrix<Val<SC>> + Sync,
{
    let quotient_size = quotient_domain.size();
    let main_width = main_on_quotient_domain.width();
    let mut sels = trace_domain.selectors_on_coset(quotient_domain);

    let qdb = log2_strict_usize(quotient_domain.size()) - log2_strict_usize(trace_domain.size());
    let next_step = 1 << qdb;

    for _ in quotient_size..PackedVal::<SC>::WIDTH {
        sels.is_first_row.push(Val::<SC>::default());
        sels.is_last_row.push(Val::<SC>::default());
        sels.is_transition.push(Val::<SC>::default());
        sels.inv_zeroifier.push(Val::<SC>::default());
    }

    (0..quotient_size)
        .step_by(PackedVal::<SC>::WIDTH)
        .flat_map_iter(|i_start| {
            let i_range = i_start..i_start + PackedVal::<SC>::WIDTH;

            let is_first_row = *PackedVal::<SC>::from_slice(&sels.is_first_row[i_range.clone()]);
            let is_last_row = *PackedVal::<SC>::from_slice(&sels.is_last_row[i_range.clone()]);
            let is_transition = *PackedVal::<SC>::from_slice(&sels.is_transition[i_range.clone()]);
            let inv_zerofier = *PackedVal::<SC>::from_slice(&sels.inv_zeroifier[i_range.clone()]);

            let main = RowMajorMatrix::new(
                iter::empty()
                    .chain(main_on_quotient_domain.vertically_packed_row(i_start))
                    .chain(main_on_quotient_domain.vertically_packed_row(i_start + next_step))
                    .collect_vec(),
                main_width,
            );

            let accumulator = PackedChallenge::<SC>::zero();

            let mut folder = ProverConstraintFolder {
                main,
                public_values,
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
