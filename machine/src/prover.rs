use crate::{
    chip::{ChipBehavior, MetaChip},
    folder::ProverConstraintFolder,
    keys::{BaseProvingKey, BaseVerifyingKey},
    proof::{BaseCommitments, BaseOpenedValues, BaseProof, ChipOpenedValues, MainTraceCommitments},
    utils::{compute_quotient_values, order_chips},
};
use hashbrown::HashMap;
use itertools::Itertools;
use log::{debug, info};
use p3_air::Air;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{AbstractField, Field, PackedValue};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::*;
use p3_util::log2_strict_usize;
use pico_compiler::program::Program;
use pico_configs::config::{Com, Domain, PackedChallenge, PcsProof, StarkGenericConfig, Val};
use pico_emulator::record::RecordBehavior;
use std::{cmp::Reverse, time::Instant};

pub struct BaseProver<SC, C> {
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
        program: &Program,
    ) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>) {
        info!("setup keys: BEGIN");
        let begin = Instant::now();
        let chips_and_preprocessed = self.generate_preprocessed(chips, program);

        // Get the chip ordering.
        let preprocessed_chip_ordering = chips_and_preprocessed
            .iter()
            .enumerate()
            .map(|(i, (name, _))| (name.to_owned(), i))
            .collect::<HashMap<_, _>>();

        let pcs = config.pcs();

        let (preprocessed_info, domains_and_preprocessed): (Vec<_>, Vec<_>) =
            chips_and_preprocessed
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
        let (commit, preprocessed_prover_data) = pcs.commit(domains_and_preprocessed);

        let preprocessed_trace = chips_and_preprocessed
            .into_iter()
            .map(|t| t.1)
            .collect::<Vec<_>>();

        info!("setup keys: END in {:?}", begin.elapsed());
        (
            BaseProvingKey {
                commit: commit.clone(),
                preprocessed_trace,
                preprocessed_prover_data,
                preprocessed_chip_ordering: preprocessed_chip_ordering.clone(),
            },
            BaseVerifyingKey {
                commit,
                preprocessed_info,
                preprocessed_chip_ordering,
            },
        )
    }

    /// generate ordered preprocessed traces with chip names
    pub fn generate_preprocessed(
        &self,
        chips: &[MetaChip<Val<SC>, C>],
        program: &Program,
    ) -> Vec<(String, RowMajorMatrix<Val<SC>>)> {
        let mut durations = HashMap::new();
        let mut chips_and_preprocessed = chips
            .iter()
            .filter_map(|chip| {
                let begin = Instant::now();
                let trace = chip
                    .generate_preprocessed(program)
                    .map(|trace| (chip.name(), trace));
                durations.insert(chip.name(), begin.elapsed());
                trace
            })
            .collect::<Vec<_>>();
        chips_and_preprocessed.sort_by_key(|(_, trace)| Reverse(trace.height()));
        for cp in &chips_and_preprocessed {
            debug!(
                "generated preprocessed: {:<14} | width {:<2} rows {:<6} cells {:<7} | in {:?}",
                cp.0,
                cp.1.width(),
                cp.1.height(),
                cp.1.values.len(),
                durations.get(&cp.0).unwrap()
            )
        }
        chips_and_preprocessed
    }

    /// emulate to generate extra events
    /// should only be called after first emulator run and before generate_main
    pub fn complement_record(&self, chips: &[MetaChip<Val<SC>, C>], input: &mut C::Record) {
        chips.iter().for_each(|chip| {
            let mut extra = C::Record::default();
            chip.extra_record(input, &mut extra);
            input.append(&mut extra);
        });
    }

    /// generate ordered main traces with chip names
    pub fn generate_main(
        &self,
        chips: &[MetaChip<Val<SC>, C>],
        record: &C::Record,
    ) -> Vec<(String, RowMajorMatrix<Val<SC>>)> {
        info!("generate main traces: BEGIN");
        let start = Instant::now();
        let mut chips_and_main = chips
            .iter()
            .map(|chip| {
                let begin = Instant::now();
                let trace = chip.generate_main(record, &mut C::Record::default());
                debug!(
                    "generated main: {:<14} | width {:<4} rows {:<8} cells {:<11} | in {:?}",
                    chip.name(),
                    trace.width(),
                    trace.height(),
                    trace.values.len(),
                    begin.elapsed(),
                );
                (chip.name(), trace)
            })
            .collect::<Vec<_>>();
        chips_and_main.sort_by_key(|(_, trace)| Reverse(trace.height()));
        info!("generate main traces: END in {:?}", start.elapsed());
        chips_and_main
    }

    pub fn commit_main(
        &self,
        config: &SC,
        record: &C::Record,
        chips_and_main: Vec<(String, RowMajorMatrix<Val<SC>>)>,
    ) -> MainTraceCommitments<SC> {
        let begin = Instant::now();
        info!("commit main: BEGIN");
        let pcs = config.pcs();
        // todo: optimize in the future
        let domains_and_traces = chips_and_main
            .clone()
            .into_iter()
            .map(|(name, trace)| (pcs.natural_domain_for_degree(trace.height()), trace))
            .collect::<Vec<_>>();

        let (commitment, data) = pcs.commit(domains_and_traces);

        let main_chip_ordering = chips_and_main
            .iter()
            .enumerate()
            .map(|(i, (name, _))| (name.to_owned(), i))
            .collect::<HashMap<_, _>>();

        let main_traces = chips_and_main
            .into_iter()
            .map(|(_, trace)| trace)
            .collect::<Vec<_>>();

        info!("commit main: END {:?}", begin.elapsed());
        MainTraceCommitments {
            main_traces,
            main_chip_ordering,
            commitment,
            data,
            public_values: record.public_values(),
        }
    }

    /// generate chips permutation traces and cumulative sums
    pub fn generate_permutation(
        &self,
        ordered_chips: &[&MetaChip<Val<SC>, C>],
        pk: &BaseProvingKey<SC>,
        main_trace_commitments: &MainTraceCommitments<SC>,
        perm_challenges: &[SC::Challenge],
    ) -> (Vec<RowMajorMatrix<SC::Challenge>>, Vec<SC::Challenge>) {
        let preprocessed_traces = ordered_chips
            .iter()
            .map(|chip| {
                pk.preprocessed_chip_ordering
                    .get(&chip.name())
                    .map(|index| &pk.preprocessed_trace[*index])
            })
            .collect::<Vec<_>>();

        let (permutation_traces, cumulative_sums): (Vec<_>, Vec<_>) = ordered_chips
            .par_iter()
            .zip(main_trace_commitments.main_traces.par_iter())
            .zip(preprocessed_traces.into_par_iter())
            .map(|((chip, main_trace), preprocessed_trace)| {
                let permutation_trace =
                    chip.generate_permutation(preprocessed_trace, main_trace, perm_challenges);
                let cumulative_sum = permutation_trace
                    .row_slice(main_trace.height() - 1)
                    .last()
                    .copied()
                    .unwrap();
                (permutation_trace, cumulative_sum)
            })
            .unzip();

        (permutation_traces, cumulative_sums)
    }

    /// core proving function in BaseProver
    /// Note that it assumes preprocessed and main have already been
    /// generated and observed by challenger
    pub fn prove(
        &self,
        config: &SC,
        chips: &[MetaChip<Val<SC>, C>],
        pk: &BaseProvingKey<SC>,
        challenger: &mut SC::Challenger,
        main_commitments: MainTraceCommitments<SC>,
        //public_values: &'a [Val<SC>]
    ) -> BaseProof<SC> {
        let begin = Instant::now();
        info!("core prove - BEGIN");
        // setup pcs
        let pcs = config.pcs();

        // Get the ordered chip, will be used in all following operations on chips
        // No chips should be used from now on!
        let ordered_chips =
            order_chips::<SC, C>(chips, main_commitments.main_chip_ordering.clone())
                .collect::<Vec<_>>();

        // Handle Main
        // get main commitments and degrees
        let main_traces = &main_commitments.main_traces;

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
        // log_main_degrees.iter().for_each(|log_degree| {
        //     challenger.observe(Val::<SC>::from_canonical_usize(*log_degree))
        // });
        // challenger.observe(main_commitments.commitment.clone());

        let mut permutation_challenges: Vec<SC::Challenge> = Vec::new();
        for _ in 0..2 {
            permutation_challenges.push(challenger.sample_ext_element());
        }

        debug!("core prove - generate permutation");
        let (mut permutation_traces, mut cumulative_sums) = self.generate_permutation(
            &ordered_chips,
            pk,
            &main_commitments,
            &permutation_challenges,
        );

        // commit permutation traces on main domain
        debug!("core prove - commit permutation traces on main domain");
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
        debug!("core prove - handle quotient");
        let log_quotient_degrees = ordered_chips
            .iter()
            .map(|chip| chip.get_log_quotient_degree())
            .collect::<Vec<_>>();
        let quotient_degrees = log_quotient_degrees
            .iter()
            .map(|log_degree| 1 << log_degree)
            .collect::<Vec<_>>();

        // quotient domains and values
        debug!("core prove - handle quotient - commit domains and values");
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
                    .preprocessed_chip_ordering
                    .get(&ordered_chips[i].name())
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
                    &ordered_chips[i],
                    &main_commitments.public_values,
                    main_domains[i],
                    *quotient_domain,
                    pre_trace_on_quotient_domains,
                    main_on_quotient_domain,
                    permutation_trace_on_quotient_domains,
                    packed_perm_challenges.as_slice(),
                    cumulative_sums.clone()[i],
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
        debug!("core prove - handle quotient - open");
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
            .zip_eq(cumulative_sums.clone())
            .enumerate()
            .map(|(i, (((main, permutation), quotient), cumulative_sum))| {
                let preprocessed = pk
                    .preprocessed_chip_ordering
                    .get(&ordered_chips[i].name())
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

        let mut cumulative_sum = SC::Challenge::zero();
        cumulative_sum += cumulative_sums
            .clone()
            .iter()
            .copied()
            .sum::<SC::Challenge>();

        debug!("core prove - cumulative sum: {cumulative_sum}");

        // If the cumulative sum is not zero, debug the interactions.
        if !cumulative_sum.is_zero() {
            panic!("Lookup cumulative sum is not zero");
        }
        info!("core prove - END in {:?}", begin.elapsed());
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
            main_chip_ordering: main_commitments.main_chip_ordering,
            public_values: main_commitments.public_values,
        }
    }
}
