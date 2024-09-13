use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::Air;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{AbstractField, PackedValue};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::*;
use p3_util::log2_strict_usize;
use std::cmp::Reverse;

use pico_configs::config::{Com, Domain, PackedChallenge, PcsProof, StarkGenericConfig, Val};
use pico_emulator::record::EmulationRecord;

use crate::{
    chip::{ChipBehavior, MetaChip},
    folder::ProverConstraintFolder,
    keys::{BaseProvingKey, BaseVerifyingKey},
    proof::{BaseCommitments, BaseOpenedValues, BaseProof, ChipOpenedValues, TraceCommitments},
    utils::compute_quotient_values,
};

pub struct BaseProver<SC, C>
// where
//     C: Air<ProverConstraintFolder<'a, SC>> + ChipBehavior<Val<SC>>,
{
    _phantom: std::marker::PhantomData<(SC, C)>,
}

impl<SC: StarkGenericConfig, C: ChipBehavior<Val<SC>>> BaseProver<SC, C>
where
    C: for<'a> Air<ProverConstraintFolder<'a, SC>> + ChipBehavior<Val<SC>>,
{
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn setup_keys(
        &self,
        config: &SC,
        chips: &[MetaChip<Val<SC>, C>],
        input: &EmulationRecord,
    ) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>) {
        let mut named_preprocessed_traces = chips
            .par_iter()
            .filter_map(|chip| {
                let chip_name = chip.name();
                let prep_trace = chip.generate_preprocessed(input);
                // Assert that the chip width data is correct.
                let expected_width = prep_trace.as_ref().map(|t| t.width()).unwrap_or(0);
                assert_eq!(
                    expected_width,
                    chip.preprocessed_width(),
                    "Incorrect number of preprocessed columns for chip {chip_name}"
                );
                prep_trace.map(move |t| (chip_name, t))
            })
            .collect::<Vec<_>>();

        // Get the chip ordering.
        let chip_indexes = named_preprocessed_traces
            .iter()
            .enumerate()
            .map(|(i, (name, _))| (name.to_owned(), i))
            .collect::<HashMap<_, _>>();

        named_preprocessed_traces.sort_by_key(|(_, trace)| Reverse(trace.height()));

        let pcs = config.pcs();

        let (preprocessed_info, domains_and_traces): (Vec<_>, Vec<_>) = named_preprocessed_traces
            .iter()
            .map(|(name, trace)| {
                let domain = pcs.natural_domain_for_degree(trace.height());
                (
                    (name.to_owned(), domain, trace.dimensions()),
                    (domain, trace.to_owned()),
                )
            })
            .unzip();

        // Commit to the batch of traces.
        let (commit, prover_data) = pcs.commit(domains_and_traces);

        let preprocessed_trace = named_preprocessed_traces.into_iter().map(|t| t.1).collect();

        (
            BaseProvingKey {
                commit: commit.clone(),
                preprocessed_trace,
                preprocessed_prover_data: prover_data,
                chip_indexes: chip_indexes.clone(),
            },
            BaseVerifyingKey {
                commit,
                preprocessed_info,
                chip_indexes,
            },
        )
    }

    pub fn generate_preprocessed(
        &self,
        chips: &[MetaChip<Val<SC>, C>],
        input: &EmulationRecord,
    ) -> Vec<(String, RowMajorMatrix<Val<SC>>)> {
        chips
            .iter()
            .filter_map(|chip| {
                chip.generate_preprocessed(input)
                    .map(|trace| (chip.name(), trace))
            })
            .collect::<Vec<_>>()
    }

    pub fn generate_main(
        &self,
        chips: &[MetaChip<Val<SC>, C>],
        input: &EmulationRecord,
    ) -> Vec<(String, RowMajorMatrix<Val<SC>>)> {
        chips
            .iter()
            .map(|chip| (chip.name(), chip.generate_main(input)))
            .collect::<Vec<_>>()
    }

    /// generate chips permutation traces and cumulative sums
    pub fn generate_permutation(
        &self,
        pk: &BaseProvingKey<SC>,
        chips: &[MetaChip<Val<SC>, C>],
        main_traces: Vec<RowMajorMatrix<Val<SC>>>,
        perm_challenges: &[SC::Challenge],
    ) -> (Vec<RowMajorMatrix<SC::Challenge>>, Vec<SC::Challenge>) {
        let pre_traces = chips
            .iter()
            .map(|chip| {
                pk.chip_indexes
                    .get(&chip.name())
                    .map(|index| &pk.preprocessed_trace[*index])
            })
            .collect::<Vec<_>>();

        let mut cumulative_sums = Vec::with_capacity(chips.len());
        let mut permutation_traces = Vec::with_capacity(chips.len());

        chips
            .par_iter()
            .zip(main_traces.clone().par_iter_mut())
            .zip(pre_traces.clone().par_iter_mut())
            .map(|((chip, main_trace), pre_trace)| {
                let perm_trace = chip.generate_permutation(*pre_trace, main_trace, perm_challenges);
                let cumulative_sum = perm_trace
                    .row_slice(main_trace.height() - 1)
                    .last()
                    .copied()
                    .unwrap();
                (perm_trace, cumulative_sum)
            })
            .unzip_into_vecs(&mut permutation_traces, &mut cumulative_sums);
        (permutation_traces, cumulative_sums)
    }

    pub fn commit(
        &self,
        config: &SC,
        chips_and_traces: Vec<(String, RowMajorMatrix<Val<SC>>)>,
    ) -> TraceCommitments<SC> {
        let pcs = config.pcs();
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
        config: &SC,
        chips: &[MetaChip<Val<SC>, C>],
        pk: &BaseProvingKey<SC>,
        challenger: &mut SC::Challenger,
        record: &EmulationRecord,
        //public_values: &'a [Val<SC>]
    ) -> BaseProof<SC> {
        // setup pcs
        let pcs = config.pcs();

        // observe preprocessed traces
        challenger.observe(pk.commit.clone());

        // Handle Main
        // get main commitments and degrees
        let main_commitments = self.commit(config, self.generate_main(chips, record));
        let main_traces = main_commitments.traces;

        let main_degrees = main_traces
            .iter()
            .map(|trace| trace.height())
            .collect::<Vec<_>>();
        let log_main_degrees = main_degrees
            .iter()
            .map(|degree| log2_strict_usize(*degree))
            .collect::<Vec<_>>();

        let main_domains = main_degrees
            .iter()
            .map(|degree| pcs.natural_domain_for_degree(*degree))
            .collect::<Vec<_>>();

        // observation. is the first step necessary?
        log_main_degrees.iter().for_each(|log_degree| {
            challenger.observe(Val::<SC>::from_canonical_usize(*log_degree))
        });
        challenger.observe(main_commitments.commitment.clone());

        let mut permutation_challenges: Vec<SC::Challenge> = Vec::new();
        for _ in 0..2 {
            permutation_challenges.push(challenger.sample_ext_element());
        }

        let (mut permutation_traces, mut cumulative_sums) =
            self.generate_permutation(pk, chips, main_traces.clone(), &permutation_challenges);

        // commit permutation traces on main domain
        let perm_domain = permutation_traces
            .into_iter()
            .zip(main_domains.iter())
            .map(|(perm_trace, domain)| {
                let trace = perm_trace.flatten_to_base();
                (*domain, trace.clone())
            })
            .collect::<Vec<_>>();

        let pcs = config.pcs();
        let (permutation_commit, permutation_data) = pcs.commit(perm_domain);
        challenger.observe(permutation_commit.clone());

        let alpha: SC::Challenge = challenger.sample_ext_element();

        // Handle quotient
        // get quotient degrees
        let log_quotient_degrees = chips
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
            .zip_eq(log_main_degrees.iter())
            .zip_eq(log_quotient_degrees.iter())
            .map(|((domain, log_degree), log_quotient_degree)| {
                domain.create_disjoint_domain(1 << (log_degree + log_quotient_degree))
            })
            .collect::<Vec<_>>();

        let quotient_values = quotient_domains
            .iter()
            .enumerate()
            .map(|(i, quotient_domain)| {
                let pre_trace_on_quotient_domains = pk
                    .chip_indexes
                    .get(&chips[i].name())
                    .map(|index| {
                        pcs.get_evaluations_on_domain(
                            &pk.preprocessed_prover_data,
                            *index,
                            *quotient_domain,
                        )
                        .to_row_major_matrix()
                    })
                    .unwrap_or_else(|| {
                        RowMajorMatrix::new_col(vec![<Val<SC>>::zero(); quotient_domain.size()])
                    });
                let main_on_quotient_domain = pcs
                    .get_evaluations_on_domain(&main_commitments.data, i, *quotient_domain)
                    .to_row_major_matrix();

                let permutation_trace_on_quotient_domains = pcs
                    .get_evaluations_on_domain(&permutation_data, i, *quotient_domain)
                    .to_row_major_matrix();

                let packed_perm_challenges = permutation_challenges
                    .iter()
                    .map(|c| PackedChallenge::<SC>::from_f(*c))
                    .collect::<Vec<_>>();

                compute_quotient_values(
                    &chips[i],
                    &[],
                    main_domains[i],
                    *quotient_domain,
                    pre_trace_on_quotient_domains,
                    main_on_quotient_domain,
                    permutation_trace_on_quotient_domains,
                    packed_perm_challenges.as_slice(),
                    cumulative_sums[i],
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
                qc_domains.into_iter().zip_eq(quotient_chunks)
            })
            .collect::<Vec<_>>();

        let (quotient_commit, quotient_data) = pcs.commit(quotient_domains_and_values);

        challenger.observe(quotient_commit.clone());

        // quotient argument
        let zeta: SC::Challenge = challenger.sample_ext_element();

        let preprocessed_opening_points = pk
            .preprocessed_trace
            .iter()
            .map(|trace| {
                let domain = pcs.natural_domain_for_degree(trace.height());
                vec![zeta, domain.next_point(zeta).unwrap()]
            })
            .collect::<Vec<_>>();

        let main_opening_points = main_domains
            .iter()
            .map(|domain| vec![zeta, domain.next_point(zeta).unwrap()])
            .collect::<Vec<_>>();

        let num_quotient_chunks = quotient_degrees.iter().sum();
        let quotient_opening_points = (0..num_quotient_chunks)
            .map(|_| vec![zeta])
            .collect::<Vec<_>>();

        let (opened_values, opening_proof) = pcs.open(
            vec![
                (&pk.preprocessed_prover_data, preprocessed_opening_points),
                (&main_commitments.data, main_opening_points.clone()),
                (&permutation_data, main_opening_points),
                (&quotient_data, quotient_opening_points),
            ],
            challenger,
        );

        let [preprocessed_values, main_values, permutation_values, mut quotient_values] =
            opened_values.try_into().unwrap();
        let preprocessed_opened_values = preprocessed_values
            .into_iter()
            .map(|op| {
                let [local, next] = op.try_into().unwrap();
                (local, next)
            })
            .collect::<Vec<_>>();
        let main_opened_values = main_values
            .into_iter()
            .map(|v| {
                let [local, next] = v.try_into().unwrap();
                (local, next)
            })
            .collect::<Vec<_>>();
        let permutation_opened_values = permutation_values
            .into_iter()
            .map(|op| {
                let [local, next] = op.try_into().unwrap();
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
            .zip_eq(permutation_opened_values)
            .zip_eq(quotient_opened_values)
            .zip_eq(cumulative_sums)
            .enumerate()
            .map(|(i, (((main, permutation), quotient), cumulative_sum))| {
                let preprocessed = pk
                    .chip_indexes
                    .get(&chips[i].name())
                    .map(|&index| preprocessed_opened_values[index].clone())
                    .unwrap_or((vec![], vec![]));

                let (preprocessed_local, preprocessed_next) = preprocessed;
                let (main_local, main_next) = main;
                let (permutation_local, permutation_next) = permutation;
                ChipOpenedValues {
                    preprocessed_local,
                    preprocessed_next,
                    main_local,
                    main_next,
                    permutation_local,
                    permutation_next,
                    quotient,
                    cumulative_sum,
                }
            })
            .collect::<Vec<_>>();

        // final base proof
        BaseProof::<SC> {
            commitments: BaseCommitments {
                main_commit: main_commitments.commitment,
                permutation_commit,
                quotient_commit,
            },
            opened_values: BaseOpenedValues {
                chips_opened_values: opened_values,
            },
            opening_proof,
            log_main_degrees,
            log_quotient_degrees,
            chip_indexes: pk.chip_indexes.clone(),
        }
    }
}
