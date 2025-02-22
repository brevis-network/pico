use crate::{
    compiler::program::ProgramBehavior,
    configs::config::{PackedChallenge, StarkGenericConfig},
    emulator::record::RecordBehavior,
    iter::ThreadPoolBuilder,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::ProverConstraintFolder,
        keys::{BaseProvingKey, BaseVerifyingKey},
        lookup::LookupScope,
        proof::{
            BaseCommitments, BaseOpenedValues, BaseProof, ChipOpenedValues, MainTraceCommitments,
        },
        septic::{SepticCurve, SepticDigest, SepticExtension},
        utils::{compute_quotient_values, order_chips},
    },
};
use alloc::sync::Arc;
use dashmap::DashMap;
use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::Air;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{FieldAlgebra, FieldExtensionAlgebra};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::*;
use p3_util::log2_strict_usize;
use std::{array, cmp::Reverse, time::Instant};
use tracing::{debug, debug_span, instrument, Span};

pub struct BaseProver<SC, C> {
    _phantom: std::marker::PhantomData<(SC, C)>,
}

impl<SC, C> Clone for BaseProver<SC, C> {
    fn clone(&self) -> Self {
        Self {
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<SC, C> Default for BaseProver<SC, C> {
    fn default() -> Self {
        Self {
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<SC, C> BaseProver<SC, C> {
    pub fn new() -> Self {
        Self {
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<SC: StarkGenericConfig, C: ChipBehavior<SC::Val>> BaseProver<SC, C> {
    pub fn setup_keys(
        &self,
        config: &SC,
        chips: &[MetaChip<SC::Val, C>],
        program: &C::Program,
    ) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>) {
        let chips_and_preprocessed = self.generate_preprocessed(chips, program);

        let local_only = chips_and_preprocessed
            .iter()
            .map(|(_, local_only, _)| *local_only)
            .collect();

        // Get the chip ordering.
        let preprocessed_chip_ordering: HashMap<_, _> = chips_and_preprocessed
            .iter()
            .enumerate()
            .map(|(i, (name, _, _))| (name.to_owned(), i))
            .collect();
        let preprocessed_chip_ordering = Arc::new(preprocessed_chip_ordering);

        let pcs = config.pcs();

        //let (preprocessed_info, domains_and_preprocessed): (Arc<[_]>, Vec<_>) =
        let preprocessed_iter = chips_and_preprocessed.iter().map(|(name, _, trace)| {
            let domain = pcs.natural_domain_for_degree(trace.height());
            (name, trace, domain)
        });
        let preprocessed_info = preprocessed_iter
            .clone()
            .map(|(name, trace, domain)| (name.to_owned(), domain, trace.dimensions()))
            .collect();

        let domains_and_preprocessed = preprocessed_iter
            .map(|(_, trace, domain)| (domain, trace.to_owned()))
            .collect();

        // Commit to the batch of traces.
        let (commit, preprocessed_prover_data) = pcs.commit(domains_and_preprocessed);

        let preprocessed_trace = chips_and_preprocessed
            .into_iter()
            .map(|t| t.2)
            .collect::<Arc<[_]>>();

        let pc_start = program.pc_start();
        let initial_global_cumulative_sum = program.initial_global_cumulative_sum();

        (
            BaseProvingKey {
                commit: commit.clone(),
                pc_start,
                initial_global_cumulative_sum,
                preprocessed_trace,
                preprocessed_prover_data,
                preprocessed_chip_ordering: preprocessed_chip_ordering.clone(),
                local_only,
            },
            BaseVerifyingKey {
                commit,
                pc_start,
                initial_global_cumulative_sum,
                preprocessed_info,
                preprocessed_chip_ordering,
            },
        )
    }

    /// generate ordered preprocessed traces with chip names
    #[instrument(name = "generate_preprocessed", level = "debug", skip_all)]
    pub fn generate_preprocessed(
        &self,
        chips: &[MetaChip<SC::Val, C>],
        program: &C::Program,
    ) -> Vec<(String, bool, RowMajorMatrix<SC::Val>)> {
        let mut durations = HashMap::new();
        let mut chips_and_preprocessed = chips
            .iter()
            .filter_map(|chip| {
                let begin = Instant::now();
                let trace = chip
                    .generate_preprocessed(program)
                    .map(|trace| (chip.name(), chip.local_only(), trace));
                let elapsed_time = begin.elapsed();
                durations.insert(chip.name(), elapsed_time);
                trace
            })
            .collect::<Vec<_>>();
        chips_and_preprocessed
            .sort_by_key(|(name, _, trace)| (Reverse(trace.height()), name.clone()));
        for cp in &chips_and_preprocessed {
            debug!(
                "chip {:<17} | width {:<2} rows {:<6} cells {:<7} | in {:?}",
                cp.0,
                cp.2.width(),
                cp.2.height(),
                cp.2.values.len(),
                durations.get(&cp.0).unwrap()
            )
        }
        chips_and_preprocessed
    }

    /// generate ordered main traces with chip names
    #[instrument(name = "generate_main", level = "debug", skip_all)]
    pub fn generate_main(
        &self,
        chips: &[MetaChip<SC::Val, C>],
        record: &C::Record,
    ) -> Vec<(String, RowMajorMatrix<SC::Val>)> {
        let durations = DashMap::new();

        let generate_main_closure = || {
            let mut chips_and_main = chips
                .par_iter()
                .filter_map(|chip| {
                    if !(chip.is_active(record)) {
                        return None;
                    }

                    let begin = Instant::now();
                    let trace = chip.generate_main(record, &mut C::Record::default());
                    let elapsed_time = begin.elapsed();
                    durations.insert(chip.name(), elapsed_time);

                    Some((chip.name(), trace))
                })
                .collect::<Vec<_>>();
            chips_and_main.sort_by_key(|(name, trace)| (Reverse(trace.height()), name.clone()));

            chips_and_main
        };
        // Execute with or without thread pool based on the feature
        // TODO: figure out why deadlock if not using separate threadpool.
        let chips_and_main = {
            let num_threads = if cfg!(feature = "single-threaded") {
                1
            } else {
                num_cpus::get().max(1) // Get the number of logical cores
            };
            let pool = ThreadPoolBuilder::new()
                .num_threads(num_threads)
                .build()
                .unwrap();
            pool.install(generate_main_closure)
        };
        for cp in &chips_and_main {
            debug!(
                "chunk {:<2} chip {:<17} | width {:<4} rows {:<8} cells {:<11} | in {:?}",
                record.chunk_index(),
                cp.0,
                cp.1.width(),
                cp.1.height(),
                cp.1.values.len(),
                durations.get(&cp.0).unwrap().value()
            )
        }

        chips_and_main
    }

    #[instrument(name = "commit_main", level = "debug", skip_all)]
    pub fn commit_main(
        &self,
        config: &SC,
        record: &C::Record,
        chips_and_main: Vec<(String, RowMajorMatrix<SC::Val>)>,
    ) -> Option<MainTraceCommitments<SC>> {
        if chips_and_main.is_empty() {
            return None;
        }

        let pcs = config.pcs();
        // todo optimize: parallel
        let domains_and_traces = chips_and_main
            .clone()
            .into_iter()
            .map(|(_name, trace)| (pcs.natural_domain_for_degree(trace.height()), trace))
            .collect::<Vec<_>>();

        let (commitment, data) = pcs.commit(domains_and_traces);

        let main_chip_ordering = chips_and_main
            .iter()
            .enumerate()
            .map(|(i, (name, _))| (name.to_owned(), i))
            .collect::<HashMap<_, _>>()
            .into();

        let main_traces = chips_and_main
            .into_iter()
            .map(|(_, trace)| trace)
            .collect::<Arc<[_]>>();

        Some(MainTraceCommitments {
            main_traces,
            main_chip_ordering,
            commitment,
            data,
            public_values: record.public_values().into(),
        })
    }

    /// generate chips permutation traces and cumulative sums
    #[allow(clippy::type_complexity)]
    #[instrument(name = "generate_permutation", level = "debug", skip_all)]
    pub fn generate_permutation(
        &self,
        ordered_chips: &[&MetaChip<SC::Val, C>],
        pk: &BaseProvingKey<SC>,
        traces: &[RowMajorMatrix<SC::Val>],
        local_perm_challenges: &[SC::Challenge],
        chunk_index: usize,
    ) -> (
        Vec<RowMajorMatrix<SC::Challenge>>,
        Vec<SepticDigest<SC::Val>>,
        Vec<SC::Challenge>,
    ) {
        let durations = DashMap::new();
        let preprocessed_traces = ordered_chips
            .iter()
            .map(|chip| {
                pk.preprocessed_chip_ordering
                    .get(&chip.name())
                    .map(|index| &pk.preprocessed_trace[*index])
            })
            .collect::<Vec<_>>();

        let main_traces = traces;

        let generate_permutation_closure = || {
            ordered_chips
                .par_iter()
                .zip(main_traces.par_iter())
                .zip(preprocessed_traces.into_par_iter())
                .map(|((chip, main_trace), preprocessed_trace)| {
                    let begin = Instant::now();
                    let (permutation_trace, regional_sum) = chip.generate_permutation(
                        preprocessed_trace,
                        main_trace,
                        local_perm_challenges,
                    );

                    let global_sum = if chip.lookup_scope() == LookupScope::Regional {
                        SepticDigest::<SC::Val>::zero()
                    } else {
                        let main_trace_size = main_trace.height() * main_trace.width();
                        let last_row = &main_trace.values[main_trace_size - 14..main_trace_size];
                        SepticDigest(SepticCurve {
                            x: SepticExtension::<SC::Val>::from_base_fn(|i| last_row[i]),
                            y: SepticExtension::<SC::Val>::from_base_fn(|i| last_row[i + 7]),
                        })
                    };

                    let elapsed_time = begin.elapsed();
                    durations.insert(chip.name(), elapsed_time);

                    (permutation_trace, (global_sum, regional_sum))
                })
                .unzip()
        };
        // Execute the closure with or without a thread pool based on the feature
        let (permutation_traces, (global_sums, local_sums)): (Vec<_>, (Vec<_>, Vec<_>)) =
            if cfg!(feature = "single-threaded") {
                let pool = ThreadPoolBuilder::new().num_threads(1).build().unwrap();
                pool.install(generate_permutation_closure)
            } else {
                generate_permutation_closure()
            };

        for i in 0..ordered_chips.len() {
            debug!(
                "chunk {:<2} chip {:<17} | width {:<4} rows {:<8} cells {:<11} | in {:?}",
                chunk_index,
                ordered_chips[i].name(),
                permutation_traces[i].width(),
                permutation_traces[i].height(),
                permutation_traces[i].values.len(),
                durations.get(&ordered_chips[i].name()).unwrap().value()
            );
        }

        (permutation_traces, global_sums, local_sums)
    }

    /// core proving function in BaseProver
    /// Assumes pk, main and pvs have already been observed by challenger
    #[allow(clippy::too_many_arguments)]
    #[instrument(name = "core_prove", level = "debug", skip_all)]
    pub fn prove(
        &self,
        config: &SC,
        chips: &[MetaChip<SC::Val, C>],
        pk: &BaseProvingKey<SC>,
        data: MainTraceCommitments<SC>,
        challenger: &mut SC::Challenger,
        chunk_index: usize,
        num_public_values: usize,
    ) -> BaseProof<SC>
    where
        C: Air<ProverConstraintFolder<SC>>,
    {
        let chips = order_chips::<SC, C>(chips, &data.main_chip_ordering).collect_vec();
        let traces = data.main_traces;
        assert_eq!(chips.len(), traces.len());

        let main_degrees = traces.iter().map(|t| t.height()).collect_vec();
        let log_main_degrees = main_degrees
            .iter()
            .map(|degree| log2_strict_usize(*degree))
            .collect::<Arc<[_]>>();

        let pcs = config.pcs();
        let main_domains = main_degrees
            .iter()
            .map(|degree| pcs.natural_domain_for_degree(*degree))
            .collect_vec();

        // Observe the public values and the main commitment.
        challenger.observe_slice(&data.public_values[0..num_public_values]);
        challenger.observe(data.commitment.clone());

        // Obtain the challenges used for the regional permutation argument.
        let regional_permutation_challenges: [SC::Challenge; 2] =
            array::from_fn(|_| challenger.sample_ext_element());

        let packed_perm_challenges =
            regional_permutation_challenges.map(PackedChallenge::<SC>::from_f);

        // Generate the permutation traces.
        let (permutation_traces, global_cumulative_sums, regional_cumulative_sums) = self
            .generate_permutation(
                &chips,
                pk,
                &traces,
                &regional_permutation_challenges,
                chunk_index,
            );

        // commit permutation traces on main domain
        let perm_domain = permutation_traces
            .into_iter()
            .zip(main_domains.iter())
            .map(|(perm_trace, domain)| {
                let trace = perm_trace.flatten_to_base();
                (*domain, trace.clone())
            })
            .collect::<Vec<_>>();

        let (permutation_commit, permutation_data) = config.pcs().commit(perm_domain);

        // Observe the permutation commitment and cumulative sums.
        challenger.observe(permutation_commit.clone());
        for (regional_sum, global_sum) in regional_cumulative_sums
            .iter()
            .zip(global_cumulative_sums.iter())
        {
            challenger.observe_slice(regional_sum.as_base_slice());
            challenger.observe_slice(&global_sum.0.x.0);
            challenger.observe_slice(&global_sum.0.y.0);
        }

        let alpha: SC::Challenge = challenger.sample_ext_element();

        // Quotient
        let log_quotient_degrees = chips
            .iter()
            .map(|chip| chip.get_log_quotient_degree())
            .collect::<Arc<[_]>>();
        let quotient_degrees = log_quotient_degrees
            .iter()
            .map(|log_degree| 1 << log_degree)
            .collect::<Vec<_>>();

        // Compute quotient values
        let quotient_domains = main_domains
            .iter()
            .zip_eq(log_main_degrees.iter())
            .zip_eq(log_quotient_degrees.iter())
            .map(|((domain, log_degree), log_quotient_degree)| {
                domain.create_disjoint_domain(1 << (log_degree + log_quotient_degree))
            })
            .collect::<Vec<_>>();

        // pull out subreferences within pk, so that Pcs::Commitment from BaseProvingKey does not
        // have to be thread-safe
        let preprocessed_chip_ordering = &pk.preprocessed_chip_ordering;
        let preprocessed_prover_data = &pk.preprocessed_prover_data;
        let data_data = &data.data;
        let perm_data = &permutation_data;

        let quotient_values = {
            let quotient_values = debug_span!(parent: Span::current(), "compute_quotient_values")
                .in_scope(|| {
                    quotient_domains
                        .into_par_iter()
                        .enumerate()
                        .map(|(i, quotient_domain)| {
                            let pre_trace_on_quotient_domains = preprocessed_chip_ordering
                                .get(&chips[i].name())
                                .map(|index| {
                                    config
                                        .pcs()
                                        .get_evaluations_on_domain(
                                            preprocessed_prover_data,
                                            *index,
                                            *quotient_domain,
                                        )
                                        .to_row_major_matrix()
                                })
                                .unwrap_or_else(|| {
                                    RowMajorMatrix::new_col(vec![
                                        <SC::Val>::ZERO;
                                        quotient_domain.size()
                                    ])
                                });
                            let main_trace_on_quotient_domain = config
                                .pcs()
                                .get_evaluations_on_domain(data_data, i, *quotient_domain)
                                .to_row_major_matrix();

                            let permutation_trace_on_quotient_domains = config
                                .pcs()
                                .get_evaluations_on_domain(perm_data, i, *quotient_domain)
                                .to_row_major_matrix();

                            // todo: consider optimize quotient domain
                            compute_quotient_values(
                                chips[i],
                                data.public_values.clone(),
                                main_domains[i],
                                *quotient_domain,
                                pre_trace_on_quotient_domains,
                                main_trace_on_quotient_domain,
                                permutation_trace_on_quotient_domains,
                                packed_perm_challenges.into(),
                                &regional_cumulative_sums[i],
                                &global_cumulative_sums[i],
                                alpha,
                            )
                        })
                        .collect::<Vec<_>>()
                });

            quotient_values
        };

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

        // // Commit quotient
        // let quotient_domains_and_values = quotient_domains
        //     .into_iter()
        //     .zip_eq(quotient_values)
        //     .zip_eq(quotient_degrees.iter())
        //     .flat_map(|((domain, values), degree)| {
        //         let quotient_flat = RowMajorMatrix::new_col(values).flatten_to_base();
        //         let quotient_chunks = domain.split_evals(*degree, quotient_flat);
        //         let qc_domains = domain.split_domains(*degree);
        //         qc_domains.into_iter().zip_eq(quotient_chunks)
        //     })
        //     .collect::<Vec<_>>();

        let (quotient_commit, quotient_data) = pcs.commit(quotient_domains_and_values);

        challenger.observe(quotient_commit.clone());

        // quotient argument
        let zeta: SC::Challenge = challenger.sample_ext_element();

        let preprocessed_opening_points = pk
            .preprocessed_trace
            .iter()
            .zip(pk.local_only.iter())
            .map(|(trace, local_only)| {
                let domain = pcs.natural_domain_for_degree(trace.height());
                if !local_only {
                    vec![zeta, domain.next_point(zeta).unwrap()]
                } else {
                    vec![zeta]
                }
            })
            .collect_vec();

        let main_opening_points = main_domains
            .iter()
            .zip(chips.iter())
            .map(|(domain, chip)| {
                if !chip.local_only() {
                    vec![zeta, domain.next_point(zeta).unwrap()]
                } else {
                    vec![zeta]
                }
            })
            .collect_vec();

        let permutation_opening_points = main_domains
            .iter()
            .map(|domain| vec![zeta, domain.next_point(zeta).unwrap()])
            .collect_vec();

        let num_quotient_chunks = quotient_degrees.iter().sum();
        let quotient_opening_points = (0..num_quotient_chunks).map(|_| vec![zeta]).collect_vec();

        let rounds = vec![
            (&pk.preprocessed_prover_data, preprocessed_opening_points),
            (&data.data, main_opening_points),
            (&permutation_data, permutation_opening_points),
            (&quotient_data, quotient_opening_points),
        ];

        let (opened_values, opening_proof) = pcs.open(rounds, challenger);

        // Collect the opened values for each chip.
        let [preprocessed_values, main_values, permutation_values, mut quotient_values] =
            opened_values.try_into().unwrap();
        assert!(main_values.len() == chips.len());
        let preprocessed_opened_values = preprocessed_values
            .into_iter()
            .zip(pk.local_only.iter())
            .map(|(op, local_only)| {
                if !local_only {
                    let [local, next] = op.try_into().unwrap();
                    (local, next)
                } else {
                    let [local] = op.try_into().unwrap();
                    let width = local.len();
                    (local, vec![SC::Challenge::ZERO; width])
                }
            })
            .collect_vec();

        let main_opened_values = main_values
            .into_iter()
            .zip(chips.iter())
            .map(|(op, chip)| {
                if !chip.local_only() {
                    let [local, next] = op.try_into().unwrap();
                    (local, next)
                } else {
                    let [local] = op.try_into().unwrap();
                    let width = local.len();
                    (local, vec![SC::Challenge::ZERO; width])
                }
            })
            .collect_vec();
        let permutation_opened_values = permutation_values
            .into_iter()
            .map(|op| {
                let [local, next] = op.try_into().unwrap();
                (local, next)
            })
            .collect_vec();

        let mut quotient_opened_values = Vec::with_capacity(quotient_degrees.len());
        for degree in quotient_degrees.iter() {
            let slice = quotient_values.drain(0..*degree);
            quotient_opened_values.push(slice.map(|mut v| v.pop().unwrap()).collect::<Vec<_>>());
        }

        let opened_values = main_opened_values
            .into_iter()
            .zip_eq(permutation_opened_values)
            .zip_eq(quotient_opened_values)
            .zip_eq(regional_cumulative_sums)
            .zip_eq(global_cumulative_sums)
            .zip_eq(log_main_degrees.iter().copied())
            .enumerate()
            .map(
                |(
                    i,
                    (
                        (
                            (((main, permutation), quotient), regional_cumulative_sum),
                            global_cumulative_sum,
                        ),
                        log_main_degree,
                    ),
                )| {
                    let preprocessed = pk
                        .preprocessed_chip_ordering
                        .get(&chips[i].name())
                        .map(|&index| preprocessed_opened_values[index].clone())
                        .unwrap_or((vec![], vec![]));

                    let (preprocessed_local, preprocessed_next) = preprocessed;
                    let (main_local, main_next) = main;
                    let (permutation_local, permutation_next) = permutation;
                    Arc::new(ChipOpenedValues {
                        preprocessed_local,
                        preprocessed_next,
                        main_local,
                        main_next,
                        permutation_local,
                        permutation_next,
                        quotient,
                        global_cumulative_sum,
                        regional_cumulative_sum,
                        log_main_degree,
                    })
                },
            )
            .collect::<Arc<[_]>>();

        // final base proof
        BaseProof::<SC> {
            commitments: BaseCommitments {
                main_commit: data.commitment,
                permutation_commit,
                quotient_commit,
            },
            opened_values: BaseOpenedValues {
                chips_opened_values: opened_values,
            },
            opening_proof,
            log_main_degrees,
            log_quotient_degrees,
            main_chip_ordering: data.main_chip_ordering,
            public_values: data.public_values,
        }
    }
}

/// A merged prover data item from the global and local prover data.
pub struct MergedProverDataItem<'a, M> {
    /// The trace.
    pub trace: &'a M,
    /// The main data index.
    pub main_data_idx: usize,
}
