use anyhow::Result;
use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::Air;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{AbstractExtensionField, AbstractField, PackedValue};
use p3_matrix::{dense::RowMajorMatrix, Dimensions, Matrix};
use p3_util::log2_strict_usize;

use pico_configs::config::{Com, PcsProof, StarkGenericConfig, Val};

use crate::{
    chip::{BaseChip, ChipBehavior},
    folder::ProverConstraintFolder,
    keys::{BaseProvingKey, BaseVerifyingKey},
    program::Program,
    proof::{ChipOpenedValues, ChunkCommitments, ChunkOpenedValues, ChunkProof, TraceCommitments},
    utils::compute_quotient_values,
};

pub struct BaseProver<SC: StarkGenericConfig, C> {
    config: SC,

    chips: Vec<BaseChip<Val<SC>, C>>,
}

impl<SC: StarkGenericConfig, C: ChipBehavior<Val<SC>>> BaseProver<SC, C>
where
    C: for<'a> Air<ProverConstraintFolder<'a, SC>> + ChipBehavior<Val<SC>>,
{
    pub fn config(&self) -> &SC {
        &self.config
    }

    pub fn chips(&self) -> &[BaseChip<Val<SC>, C>] {
        &self.chips
    }

    pub fn setup(&self) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>) {
        let pcs = self.config.pcs();
        let chips_and_preprocessed = self.generate_preprocessed();
        let domains_and_preprocessed = chips_and_preprocessed
            .clone()
            .into_iter()
            .map(|(_, trace)| (pcs.natural_domain_for_degree(trace.height()), trace))
            .collect::<Vec<_>>();
        let (commit, _) = pcs.commit(domains_and_preprocessed);

        (
            BaseProvingKey {
                commit: commit.clone(),
                chips_and_preprocessed,
            },
            BaseVerifyingKey { commit },
        )
    }

    pub fn generate_preprocessed(&self) -> Vec<(String, RowMajorMatrix<Val<SC>>)> {
        // todo: double check this to make sure it filters out none preprocessed traces
        self.chips
            .iter()
            .filter_map(|chip| {
                chip.generate_preprocessed()
                    .map(|trace| (chip.name(), trace))
            })
            .collect::<Vec<_>>()
    }

    pub fn generate_main(&self) -> Vec<(String, RowMajorMatrix<Val<SC>>)> {
        self.chips
            .iter()
            .map(|chip| (chip.name(), chip.generate_main()))
            .collect::<Vec<_>>()
    }

    pub fn commit(
        &self,
        chips_and_traces: Vec<(String, RowMajorMatrix<Val<SC>>)>,
    ) -> TraceCommitments<SC> {
        let pcs = self.config.pcs();
        let domains_and_traces = chips_and_traces
            .clone()
            .into_iter()
            .map(|(name, trace)| (pcs.natural_domain_for_degree(trace.height()), trace))
            .collect::<Vec<_>>();
        let (commitment, data) = pcs.commit(domains_and_traces);
        let traces = chips_and_traces
            .into_iter()
            .map(|(_, trace)| trace)
            .collect::<Vec<_>>();

        TraceCommitments {
            traces,
            commitment,
            data,
        }
    }

    pub fn prove(
        &self,
        pk: &BaseProvingKey<SC>,
        challenger: &mut SC::Challenger,
    ) -> Result<ChunkProof<SC>> {
        // setup pcs
        let pcs = self.config.pcs();

        // observe preprocessed traces
        challenger.observe(pk.commit.clone());

        /// Handle Main
        // get main commitments and degrees
        let main_commitments = self.commit(self.generate_main());
        let main_traces = main_commitments.traces;

        let degrees = main_traces
            .iter()
            .map(|trace| trace.height())
            .collect::<Vec<_>>();
        let log_degrees = degrees
            .iter()
            .map(|degree| log2_strict_usize(*degree))
            .collect::<Vec<_>>();

        let main_domains = degrees
            .iter()
            .map(|degree| pcs.natural_domain_for_degree(*degree))
            .collect::<Vec<_>>();

        // observation. is the first step necessary?
        log_degrees.iter().for_each(|log_degree| {
            challenger.observe(Val::<SC>::from_canonical_usize(*log_degree))
        });
        challenger.observe(main_commitments.commitment.clone());

        // todo: handle permutation here

        let alpha: SC::Challenge = challenger.sample_ext_element();

        /// Handle quotient
        // get quotient degrees
        let log_quotient_degrees = self
            .chips
            .iter()
            .map(|chip| chip.get_log_quotient_degree())
            .collect::<Vec<_>>();
        let quotient_degrees = log_quotient_degrees
            .iter()
            .map(|log_degree| 1 << log_degree)
            .collect::<Vec<_>>();

        // quotient domains and values
        let quotient_domains = main_domains
            .iter()
            .zip_eq(log_degrees.iter())
            .zip_eq(log_quotient_degrees.iter())
            .map(|((domain, log_degree), log_quotient_degree)| {
                domain.create_disjoint_domain(1 << (log_degree + log_quotient_degree))
            })
            .collect::<Vec<_>>();

        let quotient_values = quotient_domains
            .iter()
            .enumerate()
            .map(|(i, quotient_domain)| {
                let main_on_quotient_domain = pcs
                    .get_evaluations_on_domain(&main_commitments.data, i, *quotient_domain)
                    .to_row_major_matrix();
                compute_quotient_values(
                    &self.chips[i],
                    &vec![],
                    main_domains[i],
                    *quotient_domain,
                    main_on_quotient_domain,
                    alpha,
                )
            })
            .collect::<Vec<_>>();

        let quotient_domains_and_values = quotient_domains
            .into_iter()
            .zip_eq(quotient_values)
            .zip_eq(quotient_degrees.iter())
            .flat_map(|((domain, values), degree)| {
                let quotient_flat = RowMajorMatrix::new_col(values).flatten_to_base();
                let quotient_chunks = domain.split_evals(*degree, quotient_flat);
                let qc_domains = domain.split_domains(*degree);
                qc_domains.into_iter().zip_eq(quotient_chunks.into_iter())
            })
            .collect::<Vec<_>>();

        let (quotient_commit, quotient_data) = pcs.commit(quotient_domains_and_values);

        challenger.observe(quotient_commit.clone());

        // quotient argument
        let zeta: SC::Challenge = challenger.sample_ext_element();

        let main_opening_points = main_domains
            .iter()
            .map(|domain| vec![zeta, domain.next_point(zeta).unwrap()])
            .collect::<Vec<_>>();

        let quotient_opening_points = (0..quotient_degrees.len())
            .map(|_| vec![zeta])
            .collect::<Vec<_>>();

        // todo: need to check in more details
        let (opened_values, opening_proof) = pcs.open(
            vec![
                (&main_commitments.data, main_opening_points),
                (&quotient_data, quotient_opening_points),
            ],
            challenger,
        );

        let [main_values, mut quotient_values] = opened_values.try_into().unwrap();
        let main_opened_values = main_values
            .into_iter()
            .map(|v| {
                let [local, next] = v.try_into().unwrap();
                (local, next)
            })
            .collect::<Vec<_>>();

        let mut quotient_opened_values = Vec::with_capacity(quotient_degrees.len());
        for degree in quotient_degrees.iter() {
            let slice = quotient_values.drain(0..*degree);
            quotient_opened_values.push(slice.map(|mut v| v.pop().unwrap()).collect::<Vec<_>>());
        }

        let opened_values = main_opened_values
            .into_iter()
            .zip_eq(quotient_opened_values)
            .map(|((main_local, main_next), quotient)| ChipOpenedValues {
                main_local,
                main_next,
                quotient,
            })
            .collect::<Vec<_>>();

        // final chunk proof
        Ok(ChunkProof::<SC> {
            commitments: ChunkCommitments {
                main: main_commitments.commitment,
                quotient: quotient_commit,
            },
            opened_values: ChunkOpenedValues {
                chips_opened_values: opened_values,
            },
            opening_proof,
        })
    }
}
