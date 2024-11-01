use super::{
    keys::BaseVerifyingKeyVariable,
    p3::{
        challenger::{CanObserveVariable, DuplexChallengerVariable, FeltChallenger},
        commit::{PcsVariable, PolynomialSpaceVariable},
        fri::{
            types::{TwoAdicPcsMatsVariable, TwoAdicPcsRoundVariable},
            TwoAdicFriPcsVariable, TwoAdicMultiplicativeCosetVariable,
        },
    },
    proof::{BaseCommitmentsVariable, BaseProofVariable, QuotientDataVariable},
};
use crate::{
    compiler::recursion::ir::{Array, Builder, Ext, ExtConst, Usize, Var},
    configs::config::{Com, FieldGenericConfig, StarkGenericConfig},
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{
            ProverConstraintFolder, RecursiveVerifierConstraintFolder, VerifierConstraintFolder,
        },
    },
    primitives::consts::DIGEST_SIZE,
};
use p3_air::Air;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{AbstractField, TwoAdicField};

// todo: move and unify
pub const EMPTY: usize = 0x_1111_1111;

// TODO-Alan: refactor to make it more general
#[derive(Debug, Clone, Copy)]
pub struct StarkVerifier<FC: FieldGenericConfig, SC: StarkGenericConfig> {
    _phantom: std::marker::PhantomData<(FC, SC)>,
}

impl<FC: FieldGenericConfig, SC: StarkGenericConfig> StarkVerifier<FC, SC>
where
    FC::F: TwoAdicField,
    SC: StarkGenericConfig<
        Val = FC::F,
        Challenge = FC::EF,
        Domain = TwoAdicMultiplicativeCoset<FC::F>,
    >,
{
    pub fn verify_chunk<A>(
        builder: &mut Builder<FC>,
        vk: &BaseVerifyingKeyVariable<FC>,
        pcs: &TwoAdicFriPcsVariable<FC>,
        chips: &[MetaChip<FC::F, A>],
        preprocessed_chip_ids: &[usize],
        challenger: &mut DuplexChallengerVariable<FC>,
        proof: &BaseProofVariable<FC>,
        check_cumulative_sum: bool,
    ) where
        A: ChipBehavior<FC::F>
            // todo: make sure this is correct
            // + for<'a> Air<ProverConstraintFolder<'a, SC>>
            // + for<'a> Air<VerifierConstraintFolder<'a, SC>>
            + for<'a> Air<RecursiveVerifierConstraintFolder<'a, FC>>,
        FC::F: TwoAdicField,
        FC::EF: TwoAdicField,
        Com<SC>: Into<[SC::Val; DIGEST_SIZE]>,
    {
        builder.cycle_tracker("stage-c-verify-chunk-setup");
        let BaseProofVariable {
            commitment,
            opened_values,
            opening_proof,
            ..
        } = proof;

        let BaseCommitmentsVariable {
            main_commit,
            permutation_commit,
            quotient_commit,
        } = commitment;

        let permutation_challenges = (0..2)
            .map(|_| challenger.sample_ext(builder))
            .collect::<Vec<_>>();

        challenger.observe(builder, permutation_commit.clone());

        let alpha = challenger.sample_ext(builder);

        challenger.observe(builder, quotient_commit.clone());

        let zeta = challenger.sample_ext(builder);

        let num_chunk_chips = opened_values.chips_opened_values.len();
        let mut trace_domains =
            builder.dyn_array::<TwoAdicMultiplicativeCosetVariable<_>>(num_chunk_chips);
        let mut quotient_domains =
            builder.dyn_array::<TwoAdicMultiplicativeCosetVariable<_>>(num_chunk_chips);

        let num_preprocessed_chips = preprocessed_chip_ids.len();

        let mut prep_mats: Array<_, TwoAdicPcsMatsVariable<_>> =
            builder.dyn_array(num_preprocessed_chips);
        let mut main_mats: Array<_, TwoAdicPcsMatsVariable<_>> = builder.dyn_array(num_chunk_chips);
        let mut perm_mats: Array<_, TwoAdicPcsMatsVariable<_>> = builder.dyn_array(num_chunk_chips);

        let num_quotient_mats: Var<_> = builder.eval(FC::N::zero());
        builder.range(0, num_chunk_chips).for_each(|i, builder| {
            let num_quotient_chunks = builder.get(&proof.quotient_data, i).quotient_size;
            builder.assign(num_quotient_mats, num_quotient_mats + num_quotient_chunks);
        });

        let mut quotient_mats: Array<_, TwoAdicPcsMatsVariable<_>> =
            builder.dyn_array(num_quotient_mats);

        let mut qc_points = builder.dyn_array::<Ext<_, _>>(1);
        builder.set_value(&mut qc_points, 0, zeta);

        // Iterate through machine.chips filtered for preprocessed chips.
        for (preprocessed_id, &chip_id) in preprocessed_chip_ids.into_iter().enumerate() {
            // Get index within sorted preprocessed chips.
            let preprocessed_sorted_id = builder.get(&vk.preprocessed_sorted_idxs, preprocessed_id);
            // Get domain from witnessed domains. Array is ordered by machine.chips ordering.
            let domain = builder.get(&vk.preprocessed_domains, preprocessed_id);

            // Get index within all sorted chips.
            let chip_sorted_id = builder.get(&proof.sorted_indices, chip_id);
            // Get opening from proof.
            let opening = builder.get(&opened_values.chips_opened_values, chip_sorted_id);

            let mut trace_points = builder.dyn_array::<Ext<_, _>>(2);
            let zeta_next = domain.next_point(builder, zeta);

            builder.set_value(&mut trace_points, 0, zeta);
            builder.set_value(&mut trace_points, 1, zeta_next);

            let mut prep_values = builder.dyn_array::<Array<FC, _>>(2);
            builder.set_value(&mut prep_values, 0, opening.preprocessed_local);
            builder.set_value(&mut prep_values, 1, opening.preprocessed_next);
            let main_mat = TwoAdicPcsMatsVariable::<FC> {
                domain: domain.clone(),
                values: prep_values,
                points: trace_points.clone(),
            };
            builder.set_value(&mut prep_mats, preprocessed_sorted_id, main_mat);
        }

        let qc_index: Var<_> = builder.eval(FC::N::zero());
        builder.range(0, num_chunk_chips).for_each(|i, builder| {
            let opening = builder.get(&opened_values.chips_opened_values, i);
            let QuotientDataVariable {
                log_quotient_degree,
                quotient_size,
            } = builder.get(&proof.quotient_data, i);
            let domain =
                pcs.natural_domain_for_log_degree(builder, Usize::Var(opening.log_main_degree));
            builder.set_value(&mut trace_domains, i, domain.clone());

            let log_quotient_size: Usize<_> =
                builder.eval(opening.log_main_degree + log_quotient_degree);
            let quotient_domain =
                domain.create_disjoint_domain(builder, log_quotient_size, Some(pcs.config.clone()));
            builder.set_value(&mut quotient_domains, i, quotient_domain.clone());

            // Get trace_opening_points.
            let mut trace_points = builder.dyn_array::<Ext<_, _>>(2);
            let zeta_next = domain.next_point(builder, zeta);
            builder.set_value(&mut trace_points, 0, zeta);
            builder.set_value(&mut trace_points, 1, zeta_next);

            // Get the main matrix.
            let mut main_values = builder.dyn_array::<Array<FC, _>>(2);
            builder.set_value(&mut main_values, 0, opening.main_local);
            builder.set_value(&mut main_values, 1, opening.main_next);
            let main_mat = TwoAdicPcsMatsVariable::<FC> {
                domain: domain.clone(),
                values: main_values,
                points: trace_points.clone(),
            };
            builder.set_value(&mut main_mats, i, main_mat);

            // Get the permutation matrix.
            let mut perm_values = builder.dyn_array::<Array<FC, _>>(2);
            builder.set_value(&mut perm_values, 0, opening.permutation_local);
            builder.set_value(&mut perm_values, 1, opening.permutation_next);
            let perm_mat = TwoAdicPcsMatsVariable::<FC> {
                domain: domain.clone(),
                values: perm_values,
                points: trace_points,
            };
            builder.set_value(&mut perm_mats, i, perm_mat);

            // Get the quotient matrices and values.
            let qc_domains =
                quotient_domain.split_domains(builder, log_quotient_degree, quotient_size);

            builder.range(0, qc_domains.len()).for_each(|j, builder| {
                let qc_dom = builder.get(&qc_domains, j);
                let qc_vals_array = builder.get(&opening.quotient, j);
                let mut qc_values = builder.dyn_array::<Array<FC, _>>(1);
                builder.set_value(&mut qc_values, 0, qc_vals_array);
                let qc_mat = TwoAdicPcsMatsVariable::<FC> {
                    domain: qc_dom,
                    values: qc_values,
                    points: qc_points.clone(),
                };
                builder.set_value(&mut quotient_mats, qc_index, qc_mat);
                builder.assign(qc_index, qc_index + FC::N::one());
            });
        });

        // Create the pcs rounds.
        let mut rounds = builder.dyn_array::<TwoAdicPcsRoundVariable<_>>(4);
        let prep_commit = vk.commitment.clone();
        let prep_round = TwoAdicPcsRoundVariable {
            batch_commit: prep_commit,
            mats: prep_mats,
        };
        let main_round = TwoAdicPcsRoundVariable {
            batch_commit: main_commit.clone(),
            mats: main_mats,
        };
        let perm_round = TwoAdicPcsRoundVariable {
            batch_commit: permutation_commit.clone(),
            mats: perm_mats,
        };
        let quotient_round = TwoAdicPcsRoundVariable {
            batch_commit: quotient_commit.clone(),
            mats: quotient_mats,
        };
        builder.set_value(&mut rounds, 0, prep_round);
        builder.set_value(&mut rounds, 1, main_round);
        builder.set_value(&mut rounds, 2, perm_round);
        builder.set_value(&mut rounds, 3, quotient_round);
        builder.cycle_tracker("stage-c-verify-chunk-setup");

        // Verify the pcs proof
        builder.cycle_tracker("stage-d-verify-pcs");
        pcs.verify(builder, rounds, opening_proof.clone(), challenger);
        builder.cycle_tracker("stage-d-verify-pcs");

        builder.cycle_tracker("stage-e-verify-constraints");

        let num_chunk_chips_enabled: Var<_> = builder.eval(FC::N::zero());
        for (i, chip) in chips.iter().enumerate() {
            tracing::debug!("verifying constraints for chip: {}", chip.name());
            let index = builder.get(&proof.sorted_indices, i);

            if chip.preprocessed_width() > 0 {
                builder.assert_var_ne(index, FC::N::from_canonical_usize(EMPTY));
            }

            builder
                .if_ne(index, FC::N::from_canonical_usize(EMPTY))
                .then(|builder| {
                    let values = builder.get(&opened_values.chips_opened_values, index);
                    let trace_domain = builder.get(&trace_domains, index);
                    let quotient_domain: TwoAdicMultiplicativeCosetVariable<_> =
                        builder.get(&quotient_domains, index);

                    // Check that the quotient data matches the chip's data.
                    let log_quotient_degree = chip.get_log_quotient_degree();

                    let quotient_size = 1 << log_quotient_degree;
                    let chip_quotient_data = builder.get(&proof.quotient_data, index);
                    builder.assert_usize_eq(
                        chip_quotient_data.log_quotient_degree,
                        log_quotient_degree,
                    );
                    builder.assert_usize_eq(chip_quotient_data.quotient_size, quotient_size);

                    // Get the domains from the chip itself.
                    let qc_domains =
                        quotient_domain.split_domains_const(builder, log_quotient_degree);

                    // Verify the constraints.
                    stacker::maybe_grow(16 * 1024 * 1024, 16 * 1024 * 1024, || {
                        Self::verify_constraints(
                            builder,
                            chip,
                            &values,
                            proof.public_values.clone(),
                            trace_domain,
                            qc_domains,
                            zeta,
                            alpha,
                            &permutation_challenges,
                        );
                    });

                    // Increment the number of chunk chips that are enabled.
                    builder.assign(
                        num_chunk_chips_enabled,
                        num_chunk_chips_enabled + FC::N::one(),
                    );
                });
        }

        // Assert that the number of chips in `opened_values` matches the number of chunk chips
        // enabled.
        builder.assert_var_eq(num_chunk_chips_enabled, num_chunk_chips);

        // If we're checking the cumulative sum, assert that the sum of the cumulative sums is zero.
        if check_cumulative_sum {
            let sum: Ext<_, _> = builder.eval(FC::EF::zero().cons());
            builder
                .range(0, proof.opened_values.chips_opened_values.len())
                .for_each(|i, builder| {
                    let cumulative_sum = builder
                        .get(&proof.opened_values.chips_opened_values, i)
                        .cumulative_sum;
                    builder.assign(sum, sum + cumulative_sum);
                });
            builder.assert_ext_eq(sum, FC::EF::zero().cons());
        }

        builder.cycle_tracker("stage-e-verify-constraints");
    }
}
