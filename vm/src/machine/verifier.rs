use crate::{
    configs::config::StarkGenericConfig,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::VerifierConstraintFolder,
        keys::BaseVerifyingKey,
        proof::{BaseCommitments, BaseProof},
        utils::order_chips,
    },
};
use anyhow::{anyhow, Result};
use itertools::{izip, Itertools};
use p3_air::{Air, BaseAir};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{Field, FieldAlgebra, FieldExtensionAlgebra};
use p3_matrix::{dense::RowMajorMatrixView, stack::VerticalPair};
use tracing::debug;

/// struct of BaseVerifier where SC specifies type of config and C is not used
pub struct BaseVerifier<SC, C> {
    _phantom: std::marker::PhantomData<(SC, C)>,
}

impl<SC, C> Clone for BaseVerifier<SC, C> {
    fn clone(&self) -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<SC, C> BaseVerifier<SC, C>
where
    SC: StarkGenericConfig,
    C: for<'a> Air<VerifierConstraintFolder<'a, SC>> + ChipBehavior<SC::Val>,
{
    /// Initialize verifier with the same config and chips as prover.
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Verify the proof.
    /// Assumes that challenger has already observed vk, main commits and pvs
    pub fn verify(
        &self,
        config: &SC,
        chips: &[MetaChip<SC::Val, C>],
        vk: &BaseVerifyingKey<SC>,
        challenger: &mut SC::Challenger,
        proof: &BaseProof<SC>,
    ) -> Result<()> {
        let BaseProof {
            commitments,
            opened_values,
            opening_proof,
            log_main_degrees,
            log_quotient_degrees,
            main_chip_ordering,
            public_values,
        } = proof;

        let ordered_chips = order_chips::<SC, C>(chips, main_chip_ordering).collect::<Vec<_>>();

        let pcs = config.pcs();

        let BaseCommitments {
            main_commit,
            permutation_commit,
            quotient_commit,
        } = commitments;

        // get permutation challenges
        let permutation_challenges = (0..2)
            .map(|_| challenger.sample_ext_element::<SC::Challenge>())
            .collect::<Vec<_>>();

        debug!(
            "VERIFIER: permutation challenges: {:?}",
            permutation_challenges
        );

        challenger.observe(permutation_commit.clone());

        let alpha: SC::Challenge = challenger.sample_ext_element();

        debug!("VERIFIER: alpha: {:?}", alpha);

        challenger.observe(quotient_commit.clone());

        let zeta: SC::Challenge = challenger.sample_ext_element();

        debug!("VERIFIER: zeta: {:?}", zeta);

        // main opening
        let main_domains = log_main_degrees
            .iter()
            .map(|log_degree| pcs.natural_domain_for_degree(1 << log_degree))
            .collect::<Vec<_>>();

        let preprocessed_domains_points_and_opens = vk
            .preprocessed_info
            .iter()
            .map(|(name, domain, _)| {
                let i = main_chip_ordering[name];
                let values = opened_values.chips_opened_values[i].clone();
                (
                    *domain,
                    vec![
                        (zeta, values.preprocessed_local.clone()),
                        (
                            domain.next_point(zeta).unwrap(),
                            values.preprocessed_next.clone(),
                        ),
                    ],
                )
            })
            .collect::<Vec<_>>();

        let main_domains_and_opens = main_domains
            .iter()
            .zip_eq(opened_values.chips_opened_values.iter())
            .map(|(domain, values)| {
                (
                    *domain,
                    vec![
                        (zeta, values.main_local.clone()),
                        (domain.next_point(zeta).unwrap(), values.main_next.clone()),
                    ],
                )
            })
            .collect::<Vec<_>>();

        let permutation_domains_points_and_opens = main_domains
            .iter()
            .zip_eq(opened_values.chips_opened_values.iter())
            .map(|(domain, values)| {
                (
                    *domain,
                    vec![
                        (zeta, values.permutation_local.clone()),
                        (
                            domain.next_point(zeta).unwrap(),
                            values.permutation_next.clone(),
                        ),
                    ],
                )
            })
            .collect::<Vec<_>>();

        // quotient opening
        let quotient_chunk_domains = main_domains
            .iter()
            .zip_eq(log_main_degrees.iter())
            .zip_eq(log_quotient_degrees.iter())
            .map(|((domain, log_degree), log_quotient_degree)| {
                let whole_quotient_domain =
                    domain.create_disjoint_domain(1 << (log_degree + log_quotient_degree));
                whole_quotient_domain.split_domains(1 << log_quotient_degree)
            })
            .collect::<Vec<_>>();

        let quotient_domains_and_opens = quotient_chunk_domains
            .iter()
            .zip_eq(opened_values.chips_opened_values.iter())
            .flat_map(|(domains, values)| {
                domains
                    .iter()
                    .zip_eq(values.quotient.iter())
                    .map(|(domain, values)| (*domain, vec![(zeta, values.clone())]))
            })
            .collect::<Vec<_>>();

        // verify openings
        pcs.verify(
            vec![
                (vk.commit.clone(), preprocessed_domains_points_and_opens),
                (main_commit.clone(), main_domains_and_opens),
                (
                    permutation_commit.clone(),
                    permutation_domains_points_and_opens,
                ),
                (quotient_commit.clone(), quotient_domains_and_opens),
            ],
            opening_proof,
            challenger,
        )
        .map_err(|e| anyhow!("{e:?}"))?;

        for (chip, main_domain, quotient_chunk_domain, log_quotient_degree, values) in izip!(
            ordered_chips.iter(),
            main_domains,
            quotient_chunk_domains,
            log_quotient_degrees.iter(),
            opened_values.chips_opened_values.iter(),
        ) {
            // Verify shapes, really necessary?
            let valid_shape = values.preprocessed_local.len() == chip.preprocessed_width()
                && values.preprocessed_next.len() == chip.preprocessed_width()
                && values.main_local.len() == chip.width()
                && values.main_next.len() == chip.width()
                && values.permutation_local.len() == chip.permutation_width() * SC::Challenge::D
                && values.permutation_next.len() == chip.permutation_width() * SC::Challenge::D
                && values.quotient.len() == (1 << log_quotient_degree)
                && values
                    .quotient
                    .iter()
                    .all(|qc| qc.len() == <SC::Challenge as FieldExtensionAlgebra<SC::Val>>::D);

            if !valid_shape {
                panic!("Invalid proof shape");
            }

            let sels = main_domain.selectors_at_point(zeta);

            // Verify constraints
            let zps = quotient_chunk_domain
                .iter()
                .enumerate()
                .map(|(i, domain)| {
                    quotient_chunk_domain
                        .iter()
                        .enumerate()
                        .filter(|(j, _)| *j != i)
                        .map(|(_, other_domain)| {
                            other_domain.zp_at_point(zeta)
                                * other_domain.zp_at_point(domain.first_point()).inverse()
                        })
                        .product::<SC::Challenge>()
                })
                .collect_vec();

            let quotient = values
                .quotient
                .iter()
                .enumerate()
                .map(|(ch_i, ch)| {
                    ch.iter()
                        .enumerate()
                        .map(|(e_i, &c)| zps[ch_i] * SC::Challenge::monomial(e_i) * c)
                        .sum::<SC::Challenge>()
                })
                .sum::<SC::Challenge>();

            let preprocessed = VerticalPair::new(
                RowMajorMatrixView::new_row(&values.preprocessed_local),
                RowMajorMatrixView::new_row(&values.preprocessed_next),
            );

            let main = VerticalPair::new(
                RowMajorMatrixView::new_row(&values.main_local),
                RowMajorMatrixView::new_row(&values.main_next),
            );

            let unflatten = |v: &[SC::Challenge]| {
                v.chunks_exact(SC::Challenge::D)
                    .map(|chunk| {
                        chunk
                            .iter()
                            .enumerate()
                            .map(|(e_i, &x)| SC::Challenge::monomial(e_i) * x)
                            .sum()
                    })
                    .collect::<Vec<SC::Challenge>>()
            };

            let perm_local_ext = unflatten(&values.permutation_local.clone());
            let perm_next_ext = unflatten(&values.permutation_next.clone());
            let perm = VerticalPair::new(
                RowMajorMatrixView::new_row(&perm_local_ext),
                RowMajorMatrixView::new_row(&perm_next_ext),
            );

            let mut folder = VerifierConstraintFolder {
                preprocessed,
                main,
                perm,
                perm_challenges: &permutation_challenges,
                cumulative_sum: values.cumulative_sum,
                public_values,
                is_first_row: sels.is_first_row,
                is_last_row: sels.is_last_row,
                is_transition: sels.is_transition,
                alpha,
                accumulator: SC::Challenge::ZERO,
            };

            chip.eval(&mut folder);
            let folded_constraints = folder.accumulator;

            // todo: properly handle errors
            if folded_constraints * sels.inv_zeroifier != quotient {
                panic!("Constraint verification failed");
            }
        }

        Ok(())
    }
}

impl<SC, C> Default for BaseVerifier<SC, C>
where
    SC: StarkGenericConfig,
    C: for<'a> Air<VerifierConstraintFolder<'a, SC>> + ChipBehavior<SC::Val>,
{
    fn default() -> Self {
        Self::new()
    }
}

// from Plonky3 uni-machine/src/verifier.rs
#[derive(Debug)]
pub enum VerificationError<PcsErr> {
    InvalidProofShape,
    /// An error occurred while verifying the claimed openings.
    InvalidOpeningArgument(PcsErr),
    /// Out-of-domain evaluation mismatch, i.e. `constraints(zeta)` did not match
    /// `quotient(zeta) Z_H(zeta)`.
    OodEvaluationMismatch,
}
