use anyhow::{anyhow, Result};
use itertools::{izip, Itertools};
use p3_air::{Air, BaseAir};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{AbstractExtensionField, AbstractField, Field};
use p3_matrix::{
    dense::{RowMajorMatrix, RowMajorMatrixView},
    stack::VerticalPair,
};
use pico_configs::config::{StarkGenericConfig, Val};
use std::marker::PhantomData;

use crate::{
    chip::{ChipBehavior, MetaChip},
    folder::VerifierConstraintFolder,
    keys::{BaseProvingKey, BaseVerifyingKey},
    proof::{BaseCommitments, BaseOpenedValues, BaseProof, ChipOpenedValues, TraceCommitments},
};

/// struct of BaseVerifier where SC specifies type of config and C is not used
pub struct BaseVerifier<SC, C>
// where
//     SC: StarkGenericConfig,
//     C: Air<VerifierConstraintFolder<'a, SC>> + ChipBehavior<Val<SC>>,
{
    _phantom: std::marker::PhantomData<(SC, C)>,
}

impl<SC, C> BaseVerifier<SC, C>
where
    SC: StarkGenericConfig,
    C: for<'a> Air<VerifierConstraintFolder<'a, SC>> + ChipBehavior<Val<SC>>,
{
    /// Initialize verifier with the same config and chips as prover.
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn verify(
        &self,
        config: &SC,
        chips: &[MetaChip<Val<SC>, C>],
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
        } = proof;

        let pcs = config.pcs();

        // observe preprocessed traces
        challenger.observe(vk.commit.clone());

        log_main_degrees.iter().for_each(|log_main_degree| {
            challenger.observe(Val::<SC>::from_canonical_usize(*log_main_degree))
        });

        let BaseCommitments {
            main_commit,
            quotient_commit,
        } = commitments;

        // main commitment observation
        challenger.observe(main_commit.clone());

        let alpha: SC::Challenge = challenger.sample_ext_element();

        challenger.observe(quotient_commit.clone());

        let zeta: SC::Challenge = challenger.sample_ext_element();

        // main opening
        let main_domains = log_main_degrees
            .iter()
            .map(|log_degree| pcs.natural_domain_for_degree(1 << log_degree))
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
                (main_commit.clone(), main_domains_and_opens),
                (quotient_commit.clone(), quotient_domains_and_opens),
            ],
            opening_proof,
            challenger,
        )
        .map_err(|e| anyhow!("{e:?}"))?;

        for (chip, main_domain, quotient_chunk_domain, log_quotient_degree, values) in izip!(
            chips.iter(),
            main_domains,
            quotient_chunk_domains,
            log_quotient_degrees.iter(),
            opened_values.chips_opened_values.iter(),
        ) {
            // Verify shapes, really necessary?
            let valid_shape = values.main_local.len() == chip.width()
                && values.main_next.len() == chip.width()
                && values.quotient.len() == 1 << log_quotient_degree
                && values
                    .quotient
                    .iter()
                    .all(|qc| qc.len() == <SC::Challenge as AbstractExtensionField<Val<SC>>>::D);

            if !valid_shape {
                panic!("Invalid proof shape");
            }

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

            let sels = main_domain.selectors_at_point(zeta);
            let main = VerticalPair::new(
                RowMajorMatrixView::new_row(&values.main_local),
                RowMajorMatrixView::new_row(&values.main_next),
            );

            // todo: public values to be added later
            let public_values = vec![];
            let mut folder = VerifierConstraintFolder {
                main,
                public_values,
                is_first_row: sels.is_first_row,
                is_last_row: sels.is_last_row,
                is_transition: sels.is_transition,
                alpha,
                accumulator: SC::Challenge::zero(),
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

// from Plonky3 uni-stark/src/verifier.rs
#[derive(Debug)]
pub enum VerificationError<PcsErr> {
    InvalidProofShape,
    /// An error occurred while verifying the claimed openings.
    InvalidOpeningArgument(PcsErr),
    /// Out-of-domain evaluation mismatch, i.e. `constraints(zeta)` did not match
    /// `quotient(zeta) Z_H(zeta)`.
    OodEvaluationMismatch,
}
