use crate::{
    compiler::program::ProgramBehavior,
    configs::config::{Com, PackedChallenge, PcsProverData, StarkGenericConfig, ZeroCommitment},
    emulator::record::RecordBehavior,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::ProverConstraintFolder,
        keys::{BaseProvingKey, BaseVerifyingKey},
        lookup::LookupScope,
        proof::{
            BaseCommitments, BaseOpenedValues, BaseProof, ChipOpenedValues, MainTraceCommitments,
        },
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
use p3_matrix::{
    dense::{DenseMatrix, RowMajorMatrix},
    Matrix,
};
use p3_maybe_rayon::prelude::*;
use p3_util::log2_strict_usize;
use rayon::ThreadPoolBuilder;
use std::{cmp::Reverse, time::Instant};
use tracing::{debug, debug_span, info, instrument, Span};

pub struct BaseProver<SC, C> {
    _phantom: std::marker::PhantomData<(SC, C)>,
}

impl<SC, C> Clone for BaseProver<SC, C> {
    fn clone(&self) -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

#[allow(clippy::new_without_default)]
impl<SC: StarkGenericConfig, C: ChipBehavior<SC::Val>> BaseProver<SC, C>
where
    C: for<'a> Air<ProverConstraintFolder<'a, SC>> + ChipBehavior<SC::Val>,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
{
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn setup_keys(
        &self,
        config: &SC,
        chips: &[MetaChip<SC::Val, C>],
        program: &C::Program,
    ) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>) {
        let chips_and_preprocessed = self.generate_preprocessed(chips, program);

        // Get the chip ordering.
        let preprocessed_chip_ordering = chips_and_preprocessed
            .iter()
            .enumerate()
            .map(|(i, (name, _))| (name.to_owned(), i))
            .collect::<HashMap<_, _>>();
        let preprocessed_chip_ordering = Arc::new(preprocessed_chip_ordering);

        let pcs = config.pcs();

        //let (preprocessed_info, domains_and_preprocessed): (Arc<[_]>, Vec<_>) =
        let preprocessed_iter = chips_and_preprocessed.iter().map(|(name, trace)| {
            let domain = pcs.natural_domain_for_degree(trace.height());
            (name, trace, domain)
        });
        let preprocessed_info: Arc<[_]> = preprocessed_iter
            .clone()
            .map(|(name, trace, domain)| (name.to_owned(), domain, trace.dimensions()))
            .collect();
        let domains_and_preprocessed: Vec<_> = preprocessed_iter
            .map(|(_, trace, domain)| (domain, trace.to_owned()))
            .collect();

        // Commit to the batch of traces.
        let (commit, preprocessed_prover_data) = pcs.commit(domains_and_preprocessed);

        let preprocessed_trace = chips_and_preprocessed
            .into_iter()
            .map(|t| t.1)
            .collect::<Vec<_>>();

        let pc_start = program.pc_start();

        (
            BaseProvingKey {
                commit: commit.clone(),
                pc_start,
                preprocessed_trace,
                preprocessed_prover_data,
                preprocessed_chip_ordering: preprocessed_chip_ordering.clone(),
            },
            BaseVerifyingKey {
                commit,
                pc_start,
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
    ) -> Vec<(String, RowMajorMatrix<SC::Val>)> {
        let begin = Instant::now();
        let mut durations = HashMap::new();
        let mut chips_and_preprocessed = chips
            .iter()
            .filter_map(|chip| {
                let begin = Instant::now();
                let trace = chip
                    .generate_preprocessed(program)
                    .map(|trace| (chip.name(), trace));
                let elapsed_time = begin.elapsed();
                durations.insert(chip.name(), elapsed_time);
                info!(
                    "PERF-step=generate_preprocessed-chip={}-cpu_time={}",
                    chip.name(),
                    elapsed_time.as_millis()
                );
                trace
            })
            .collect::<Vec<_>>();
        chips_and_preprocessed.sort_by_key(|(_, trace)| Reverse(trace.height()));
        for cp in &chips_and_preprocessed {
            debug!(
                "chip {:<14} | width {:<2} rows {:<6} cells {:<7} | in {:?}",
                cp.0,
                cp.1.width(),
                cp.1.height(),
                cp.1.values.len(),
                durations.get(&cp.0).unwrap()
            )
        }
        info!(
            "PERF-step=generate_preprocessed-user_time={}",
            begin.elapsed().as_millis(),
        );
        chips_and_preprocessed
    }

    /// generate ordered main traces with chip names
    #[instrument(name = "generate_main", level = "debug", skip_all)]
    pub fn generate_main(
        &self,
        chips: &[MetaChip<SC::Val, C>],
        record: &C::Record,
        lookup_scope: LookupScope,
    ) -> Vec<(String, RowMajorMatrix<SC::Val>)> {
        let begin = Instant::now();
        let durations = DashMap::new();

        let generate_main_closure = || {
            let mut chips_and_main = chips
                .par_iter()
                .filter_map(|chip| {
                    if !(chip.is_active(record) && chip.lookup_scope() == lookup_scope) {
                        return None;
                    }

                    let begin = Instant::now();
                    let trace = chip.generate_main(record, &mut C::Record::default());
                    let elapsed_time = begin.elapsed();
                    durations.insert(chip.name(), elapsed_time);
                    info!(
                        "PERF-step=generate_main-chunk={}-chip={}-cpu_time={}",
                        record.chunk_index(),
                        chip.name(),
                        elapsed_time.as_millis(),
                    );

                    Some((chip.name(), trace))
                })
                .collect::<Vec<_>>();
            chips_and_main.sort_by_key(|(_, trace)| Reverse(trace.height()));
            chips_and_main
        };
        // Execute with or without thread pool based on the feature
        let chips_and_main = if cfg!(feature = "single-threaded") {
            let pool = ThreadPoolBuilder::new().num_threads(1).build().unwrap();
            pool.install(generate_main_closure)
        } else {
            generate_main_closure()
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

        let elapsed_time = begin.elapsed();
        info!(
            "PERF-step=generate_main-chunk={}-user_time={}",
            record.chunk_index(),
            elapsed_time.as_millis(),
        );
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

        let begin = Instant::now();

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

        info!(
            "PERF-step=commit_main-chunk={}-user_time={}",
            record.chunk_index(),
            begin.elapsed().as_millis(),
        );
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
        traces: &[&RowMajorMatrix<SC::Val>],
        perm_challenges: &[SC::Challenge],
        chunk_index: usize,
    ) -> (Vec<RowMajorMatrix<SC::Challenge>>, Vec<[SC::Challenge; 2]>) {
        let begin = Instant::now();
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
                    let (permutation_traces, global_sum, regional_sum) =
                        chip.generate_permutation(preprocessed_trace, main_trace, perm_challenges);

                    let elapsed_time = begin.elapsed();
                    durations.insert(chip.name(), elapsed_time);

                    info!(
                        "PERF-step=generate_permutation-chunk={}-chip={}-cpu_time={}",
                        chunk_index,
                        chip.name(),
                        elapsed_time.as_millis()
                    );

                    (permutation_traces, [global_sum, regional_sum])
                })
                .unzip()
        };
        // Execute the closure with or without a thread pool based on the feature
        let (permutation_traces, cumulative_sums): (Vec<_>, Vec<_>) =
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
        info!(
            "PERF-step=generate_permutation-chunk={}-user_time={}",
            chunk_index,
            begin.elapsed().as_millis(),
        );

        (permutation_traces, cumulative_sums)
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
        local_data: MainTraceCommitments<SC>,
        global_data: Option<MainTraceCommitments<SC>>,
        challenger: &mut SC::Challenger,
        global_permutation_challenges: &[SC::Challenge],
        chunk_index: usize,
    ) -> BaseProof<SC> {
        let begin = Instant::now();

        // setup pcs
        let pcs = config.pcs();

        let (global_traces, global_main_commit, global_main_data, global_chip_ordering) =
            if let Some(global_data) = global_data {
                let MainTraceCommitments {
                    main_traces: global_traces,
                    commitment: global_main_commit,
                    data: global_main_data,
                    main_chip_ordering: global_chip_ordering,
                    public_values: _,
                } = global_data;
                (
                    global_traces.to_vec(),
                    global_main_commit,
                    Some(global_main_data),
                    global_chip_ordering,
                )
            } else {
                (
                    vec![],
                    pcs.zero_commitment(),
                    None,
                    Arc::new(HashMap::new()),
                )
            };
        let global_traces = Arc::from(global_traces);

        let MainTraceCommitments {
            main_traces: local_traces,
            commitment: regional_main_commit,
            data: local_main_data,
            main_chip_ordering: local_chip_ordering,
            public_values: local_public_values,
        } = local_data;

        // Merge the chip ordering and traces from the global and local data.
        let (all_chips_ordering, all_chip_scopes, all_shard_data) = self.merge_shard_traces(
            &global_traces,
            &global_chip_ordering,
            &local_traces,
            &local_chip_ordering,
        );

        // Get the ordered chip, will be used in all following operations on chips
        // No chips should be used from now on!
        let ordered_chips = order_chips::<SC, C>(chips, &all_chips_ordering).collect::<Vec<_>>();
        assert_eq!(ordered_chips.len(), all_shard_data.len());

        let main_degrees = all_shard_data
            .iter()
            .map(|shard_data| shard_data.trace.height())
            .collect::<Vec<_>>();

        let log_main_degrees = main_degrees
            .iter()
            .map(|degree| log2_strict_usize(*degree))
            .collect::<Arc<[_]>>();

        let main_domains = main_degrees
            .iter()
            .map(|degree| pcs.natural_domain_for_degree(*degree))
            .collect::<Vec<_>>();

        // Observe the regional main commitment.
        challenger.observe(regional_main_commit.clone());

        // Obtain the challenges used for the local permutation argument.
        let mut regional_permutation_challenges: Vec<SC::Challenge> = Vec::new();
        for _ in 0..2 {
            regional_permutation_challenges.push(challenger.sample_ext_element());
        }

        let permutation_challenges = global_permutation_challenges
            .iter()
            .chain(regional_permutation_challenges.iter())
            .copied()
            .collect::<Vec<_>>();

        let packed_perm_challenges = permutation_challenges
            .iter()
            .chain(regional_permutation_challenges.iter())
            .map(|c| PackedChallenge::<SC>::from_f(*c))
            .collect::<Vec<_>>();

        // Generate the permutation traces.
        let all_traces = all_shard_data.iter().map(|data| data.trace).collect_vec();
        let (permutation_traces, cumulative_sums) = self.generate_permutation(
            &ordered_chips,
            pk,
            &all_traces,
            &permutation_challenges,
            chunk_index,
        );

        // commit permutation traces on main domain
        let begin_commit_permutation = Instant::now();

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

        info!(
            "PERF-step=commit_permutation-chunk={}-user_time={}",
            chunk_index,
            begin_commit_permutation.elapsed().as_millis(),
        );

        // Observe the permutation commitment and cumulative sums.
        challenger.observe(permutation_commit.clone());

        for [global_sum, regional_sum] in cumulative_sums.iter() {
            challenger.observe_slice(global_sum.as_base_slice());
            challenger.observe_slice(regional_sum.as_base_slice());
        }

        let alpha: SC::Challenge = challenger.sample_ext_element();

        debug!("PROVER: alpha: {:?}", alpha);

        // Quotient
        let log_quotient_degrees = ordered_chips
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

        let quotient_values = {
            let begin = Instant::now();
            let quotient_values = debug_span!(parent: Span::current(), "compute_quotient_values")
                .in_scope(|| {
                    quotient_domains
                        .into_par_iter()
                        .enumerate()
                        .map(|(i, quotient_domain)| {
                            let begin_compute_quotient = Instant::now();

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
                                    RowMajorMatrix::new_col(vec![
                                        <SC::Val>::ZERO;
                                        quotient_domain.size()
                                    ])
                                });
                            let scope = all_chip_scopes[i];
                            let main_data = if scope == LookupScope::Global {
                                global_main_data
                                    .as_ref()
                                    .expect("Expected global_main_data to be Some")
                            } else {
                                &local_main_data
                            };
                            let main_on_quotient_domain = pcs
                                .get_evaluations_on_domain(
                                    main_data,
                                    all_shard_data[i].main_data_idx,
                                    *quotient_domain,
                                )
                                .to_row_major_matrix();

                            let permutation_trace_on_quotient_domains = pcs
                                .get_evaluations_on_domain(&permutation_data, i, *quotient_domain)
                                .to_row_major_matrix();

                            // todo: consider optimize quotient domain
                            let qv = compute_quotient_values(
                                ordered_chips[i],
                                &local_public_values,
                                main_domains[i],
                                *quotient_domain,
                                pre_trace_on_quotient_domains,
                                main_on_quotient_domain,
                                permutation_trace_on_quotient_domains,
                                packed_perm_challenges.as_slice(),
                                &cumulative_sums.clone()[i],
                                alpha,
                            );

                            info!(
                                "PERF-step=compute_quotient_values-chunk={}-chip={}-cpu_time={}",
                                chunk_index,
                                ordered_chips[i].name(),
                                begin_compute_quotient.elapsed().as_millis(),
                            );

                            qv
                        })
                        .collect::<Vec<_>>()
                });

            info!(
                "PERF-step=compute_quotient_values-chunk={}-user_time={}",
                chunk_index,
                begin.elapsed().as_millis(),
            );

            quotient_values
        };

        // Commit quotient
        let begin_commit_quotient = Instant::now();

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
        info!(
            "PERF-step=commit_quotient-chunk={}-user_time={}",
            chunk_index,
            begin_commit_quotient.elapsed().as_millis(),
        );

        challenger.observe(quotient_commit.clone());

        // quotient argument
        let begin_open = Instant::now();

        let zeta: SC::Challenge = challenger.sample_ext_element();

        debug!("PROVER: zeta: {:?}", zeta);

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

        // Split the trace_opening_points to the global and local chips.
        let mut global_trace_opening_points = Vec::with_capacity(global_chip_ordering.len());
        let mut local_trace_opening_points = Vec::with_capacity(local_chip_ordering.len());
        for (i, trace_opening_point) in main_opening_points.clone().into_iter().enumerate() {
            let scope = all_chip_scopes[i];
            if scope == LookupScope::Global {
                global_trace_opening_points.push(trace_opening_point);
            } else {
                local_trace_opening_points.push(trace_opening_point);
            }
        }

        let rounds = if let Some(global_main_data) = global_main_data.as_ref() {
            vec![
                (&pk.preprocessed_prover_data, preprocessed_opening_points),
                (global_main_data, global_trace_opening_points),
                (&local_main_data, local_trace_opening_points),
                (&permutation_data, main_opening_points),
                (&quotient_data, quotient_opening_points),
            ]
        } else {
            vec![
                (&pk.preprocessed_prover_data, preprocessed_opening_points),
                (&local_main_data, local_trace_opening_points),
                (&permutation_data, main_opening_points),
                (&quotient_data, quotient_opening_points),
            ]
        };

        let (opened_values, opening_proof) = pcs.open(rounds, challenger);

        // Collect the opened values for each chip.
        let (
            preprocessed_values,
            global_main_values,
            local_main_values,
            permutation_values,
            mut quotient_values,
        ) = if global_main_data.is_some() {
            let [preprocessed_values, global_main_values, local_main_values, permutation_values, quotient_values] =
                opened_values.try_into().unwrap();
            (
                preprocessed_values,
                Some(global_main_values),
                local_main_values,
                permutation_values,
                quotient_values,
            )
        } else {
            let [preprocessed_values, local_main_values, permutation_values, quotient_values] =
                opened_values.try_into().unwrap();
            (
                preprocessed_values,
                None,
                local_main_values,
                permutation_values,
                quotient_values,
            )
        };

        let preprocessed_opened_values = preprocessed_values
            .into_iter()
            .map(|op| {
                let [local, next] = op.try_into().unwrap();
                (local, next)
            })
            .collect::<Vec<_>>();
        // Merge the global and local main values.
        let mut main_values =
            Vec::with_capacity(global_chip_ordering.len() + local_chip_ordering.len());
        for chip in ordered_chips.iter() {
            let global_order = global_chip_ordering.get(&chip.name());
            let local_order = local_chip_ordering.get(&chip.name());
            match (global_order, local_order) {
                (Some(&global_order), None) => {
                    let global_main_values = global_main_values
                        .as_ref()
                        .expect("Global main values should be Some");
                    main_values.push(global_main_values[global_order].clone());
                }
                (None, Some(&local_order)) => {
                    main_values.push(local_main_values[local_order].clone());
                }
                _ => unreachable!(),
            }
        }
        assert!(main_values.len() == ordered_chips.len());

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
            .zip_eq(log_main_degrees.iter().copied())
            .enumerate()
            .map(
                |(i, ((((main, permutation), quotient), cumulative_sums), log_main_degree))| {
                    let preprocessed = pk
                        .preprocessed_chip_ordering
                        .get(&ordered_chips[i].name())
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
                        global_cumulative_sum: cumulative_sums[0],
                        regional_cumulative_sum: cumulative_sums[1],
                        log_main_degree,
                    })
                },
            )
            .collect::<Arc<[_]>>();

        info!(
            "PERF-step=open-chunk={}-user_time={}",
            chunk_index,
            begin_open.elapsed().as_millis(),
        );

        info!(
            "PERF-step=core_prove-chunk={}-user_time={}",
            chunk_index,
            begin.elapsed().as_millis(),
        );

        // final base proof
        BaseProof::<SC> {
            commitments: BaseCommitments {
                global_main_commit,
                regional_main_commit,
                permutation_commit,
                quotient_commit,
            },
            opened_values: BaseOpenedValues {
                chips_opened_values: opened_values,
            },
            opening_proof,
            log_main_degrees,
            log_quotient_degrees,
            main_chip_ordering: all_chips_ordering.into(),
            public_values: local_public_values,
        }
    }

    /// Merge the global and local chips' sorted traces.
    #[allow(clippy::type_complexity)]
    fn merge_shard_traces<'a, 'b>(
        &'a self,
        global_traces: &'b [RowMajorMatrix<SC::Val>],
        global_chip_ordering: &'b HashMap<String, usize>,
        regional_traces: &'b [RowMajorMatrix<SC::Val>],
        regional_chip_ordering: &'b HashMap<String, usize>,
    ) -> (
        HashMap<String, usize>,
        Vec<LookupScope>,
        Vec<MergedProverDataItem<'b, RowMajorMatrix<SC::Val>>>,
    )
    where
        'a: 'b,
    {
        // Get the sort order of the chips.
        let global_chips = global_chip_ordering
            .iter()
            .sorted_by_key(|(_, &i)| i)
            .map(|chip| chip.0.clone())
            .collect::<Vec<_>>();
        let regional_chips = regional_chip_ordering
            .iter()
            .sorted_by_key(|(_, &i)| i)
            .map(|chip| chip.0.clone())
            .collect::<Vec<_>>();

        let mut merged_chips = Vec::with_capacity(global_traces.len() + regional_traces.len());
        let mut merged_prover_data = Vec::with_capacity(global_chips.len() + regional_chips.len());

        assert!(global_traces.len() == global_chips.len());
        let mut global_iter = global_traces.iter().zip(global_chips.iter()).enumerate();
        assert!(regional_traces.len() == regional_chips.len());
        let mut regional_iter = regional_traces
            .iter()
            .zip(regional_chips.iter())
            .enumerate();

        let mut global_next = global_iter.next();
        let mut regional_next = regional_iter.next();

        let mut chip_scopes = Vec::new();

        while global_next.is_some() || regional_next.is_some() {
            match (global_next, regional_next) {
                (Some(global), Some(regional)) => {
                    let (global_prover_data_idx, (global_trace, global_chip)) = global;
                    let (regional_prover_data_idx, (regional_trace, regional_chip)) = regional;
                    if (Reverse(global_trace.height()), global_chip)
                        < (Reverse(regional_trace.height()), regional_chip)
                    {
                        merged_chips.push(global_chip.clone());
                        chip_scopes.push(LookupScope::Global);
                        merged_prover_data.push(MergedProverDataItem {
                            trace: global_trace,
                            main_data_idx: global_prover_data_idx,
                        });
                        global_next = global_iter.next();
                    } else {
                        merged_chips.push(regional_chip.clone());
                        chip_scopes.push(LookupScope::Regional);
                        merged_prover_data.push(MergedProverDataItem {
                            trace: regional_trace,
                            main_data_idx: regional_prover_data_idx,
                        });
                        regional_next = regional_iter.next();
                    }
                }
                (Some(global), None) => {
                    let (global_prover_data_idx, (global_trace, global_chip)) = global;
                    merged_chips.push(global_chip.clone());
                    chip_scopes.push(LookupScope::Global);
                    merged_prover_data.push(MergedProverDataItem {
                        trace: global_trace,
                        main_data_idx: global_prover_data_idx,
                    });
                    global_next = global_iter.next();
                }
                (None, Some(regional)) => {
                    let (regional_prover_data_idx, (regional_trace, regional_chip)) = regional;
                    merged_chips.push(regional_chip.clone());
                    chip_scopes.push(LookupScope::Regional);
                    merged_prover_data.push(MergedProverDataItem {
                        trace: regional_trace,
                        main_data_idx: regional_prover_data_idx,
                    });
                    regional_next = regional_iter.next();
                }
                (None, None) => break,
            }
        }

        let chip_ordering = merged_chips
            .iter()
            .enumerate()
            .map(|(i, name)| (name.clone(), i))
            .collect();

        (chip_ordering, chip_scopes, merged_prover_data)
    }
}

/// A merged prover data item from the global and local prover data.
pub struct MergedProverDataItem<'a, M> {
    /// The trace.
    pub trace: &'a M,
    /// The main data index.
    pub main_data_idx: usize,
}
