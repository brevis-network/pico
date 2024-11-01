use super::folder::DebugConstraintFolder;
use crate::{
    configs::config::{PackedChallenge, PackedVal, StarkGenericConfig},
    emulator::record::RecordBehavior,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{ProverConstraintFolder, SymbolicConstraintFolder},
        keys::BaseProvingKey,
    },
};
use core::iter;
use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::{Air, PairCol};
use p3_challenger::FieldChallenger;
use p3_commit::PolynomialSpace;
use p3_field::{AbstractExtensionField, AbstractField, ExtensionField, Field, PackedValue, Powers};
use p3_matrix::{
    dense::{RowMajorMatrix, RowMajorMatrixView},
    stack::VerticalPair,
    Matrix,
};
use p3_maybe_rayon::prelude::*;
use p3_uni_stark::{Entry, SymbolicExpression};
use p3_util::{log2_ceil_usize, log2_strict_usize};
use std::{
    any::type_name,
    panic::{self, AssertUnwindSafe},
    process::exit,
    time::Instant,
};
use tracing::{debug_span, instrument, Span};

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

pub fn order_chips<SC, C>(
    chips: &[MetaChip<SC::Val, C>],
    chip_ordering: HashMap<String, usize>,
) -> impl Iterator<Item = &MetaChip<SC::Val, C>>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>,
{
    chips
        .iter()
        .filter(|chip| chip_ordering.contains_key(&chip.name()))
        .sorted_by_key(|chip| chip_ordering.get(&chip.name()))
}

pub fn chunk_active_chips<'a, 'b, SC, C>(
    chips: &'a [MetaChip<SC::Val, C>],
    chunk: &'b C::Record,
) -> impl Iterator<Item = &'b MetaChip<SC::Val, C>>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>,
    'a: 'b, // Ensures that 'a outlives 'b
{
    chips.iter().filter(move |chip| chip.is_active(chunk))
}

pub fn eval_symbolic_to_virtual_pair<F: Field>(
    expression: &SymbolicExpression<F>,
) -> (Vec<(PairCol, F)>, F) {
    match expression {
        SymbolicExpression::Constant(c) => (vec![], *c),
        SymbolicExpression::Variable(v) => match v.entry {
            Entry::Preprocessed { offset: 0 } => {
                (vec![(PairCol::Preprocessed(v.index), F::one())], F::zero())
            }
            Entry::Main { offset: 0 } => (vec![(PairCol::Main(v.index), F::one())], F::zero()),
            _ => panic!(
                "not an affine expression in current row elements {:?}",
                v.entry
            ),
        },
        SymbolicExpression::Add { x, y, .. } => {
            let (v_l, c_l) = eval_symbolic_to_virtual_pair(x);
            let (v_r, c_r) = eval_symbolic_to_virtual_pair(y);
            ([v_l, v_r].concat(), c_l + c_r)
        }
        SymbolicExpression::Sub { x, y, .. } => {
            let (v_l, c_l) = eval_symbolic_to_virtual_pair(x);
            let (v_r, c_r) = eval_symbolic_to_virtual_pair(y);
            let neg_v_r = v_r.iter().map(|(c, w)| (*c, -*w)).collect();
            ([v_l, neg_v_r].concat(), c_l - c_r)
        }
        SymbolicExpression::Neg { x, .. } => {
            let (v, c) = eval_symbolic_to_virtual_pair(x);
            (v.iter().map(|(c, w)| (*c, -*w)).collect(), -c)
        }
        SymbolicExpression::Mul { x, y, .. } => {
            let (v_l, c_l) = eval_symbolic_to_virtual_pair(x);
            let (v_r, c_r) = eval_symbolic_to_virtual_pair(y);

            let mut v = vec![];
            v.extend(v_l.iter().map(|(c, w)| (*c, *w * c_r)));
            v.extend(v_r.iter().map(|(c, w)| (*c, *w * c_l)));

            if !v_l.is_empty() && !v_r.is_empty() {
                panic!("Not an affine expression")
            }

            (v, c_l * c_r)
        }
        SymbolicExpression::IsFirstRow => {
            panic!("not an affine expression in current row elements for first row")
        }
        SymbolicExpression::IsLastRow => {
            panic!("not an affine expression in current row elements for last row")
        }
        SymbolicExpression::IsTransition => {
            panic!("not an affine expression in current row elements for transition row")
        }
    }
}

/// Compute quotient values for opening proof
pub fn compute_quotient_values<'a, SC, C, Mat>(
    chip: &MetaChip<SC::Val, C>,
    public_values: &'a [SC::Val],
    trace_domain: SC::Domain,
    quotient_domain: SC::Domain,
    preprocessed_on_quotient_domain: Mat,
    main_trace_on_quotient_domain: Mat,
    permutation_trace_on_quotient_domain: Mat,
    perm_challenges: &'a [PackedChallenge<SC>],
    cumulative_sum: SC::Challenge,
    alpha: SC::Challenge,
) -> Vec<SC::Challenge>
where
    SC: StarkGenericConfig,
    C: Air<ProverConstraintFolder<'a, SC>> + ChipBehavior<SC::Val>,
    Mat: Matrix<SC::Val> + Sync,
{
    let quotient_size = quotient_domain.size();
    let preprocessed_width = preprocessed_on_quotient_domain.width();
    let main_width = main_trace_on_quotient_domain.width();
    let permutation_width = permutation_trace_on_quotient_domain.width();
    let mut sels = trace_domain.selectors_on_coset(quotient_domain);

    let qdb = log2_strict_usize(quotient_domain.size()) - log2_strict_usize(trace_domain.size());
    let next_step = 1 << qdb;

    for _ in quotient_size..PackedVal::<SC>::WIDTH {
        sels.is_first_row.push(SC::Val::default());
        sels.is_last_row.push(SC::Val::default());
        sels.is_transition.push(SC::Val::default());
        sels.inv_zeroifier.push(SC::Val::default());
    }
    let ext_degree = SC::Challenge::D;

    let quotient_values = debug_span!(parent: Span::current(), "chip_compute_quotient_values", chip = chip.name(), quotient_size = quotient_size, tag = "tag-chip").in_scope(|| {
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
                    let quotient_value = (0..<SC::Challenge as AbstractExtensionField<SC::Val>>::D)
                        .map(|coeff_idx| quotient.as_base_slice()[coeff_idx].as_slice()[idx_in_packing])
                        .collect::<Vec<_>>();
                    SC::Challenge::from_base_slice(&quotient_value)
                })
            })
            .collect()
    });

    quotient_values
}

// Infer log of constraint degree
// Originally from p3 for SymbolicAirBuilder
pub fn get_log_quotient_degree<F, A>(
    air: &A,
    preprocessed_width: usize,
    has_lookup: bool,
    //num_public_values: usize,
) -> usize
where
    F: Field,
    A: Air<SymbolicConstraintFolder<F>>,
{
    let base = if has_lookup { 3 } else { 2 };
    // We pad to at least degree 2, since a quotient argument doesn't make sense with smaller degrees.
    let constraint_degree = get_max_constraint_degree(air, preprocessed_width).max(base);

    // The quotient's actual degree is approximately (max_constraint_degree - 1) n,
    // where subtracting 1 comes from division by the zerofier.
    // But we pad it to a power of two so that we can efficiently decompose the quotient.
    log2_ceil_usize(constraint_degree - 1)
}

// infer constraint degree
// originally from p3 for SymbolicAirBuilder
pub fn get_max_constraint_degree<F, A>(
    air: &A,
    preprocessed_width: usize,
    //num_public_values: usize,
) -> usize
where
    F: Field,
    A: Air<SymbolicConstraintFolder<F>>,
{
    get_symbolic_constraints(air, preprocessed_width)
        .iter()
        .map(|c| c.degree_multiple())
        .max()
        .unwrap_or(0)
}

// evaluate constraints symbolically
// originally from p3 for SymbolicAirBuilder
pub fn get_symbolic_constraints<F, A>(
    air: &A,
    preprocessed_width: usize,
    //num_public_values: usize,
) -> Vec<SymbolicExpression<F>>
where
    F: Field,
    A: Air<SymbolicConstraintFolder<F>>,
{
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, air.width());
    air.eval(&mut builder);
    builder.constraints()
}

// Check the trace of a single chip
#[allow(clippy::needless_pass_by_value)]
pub fn debug_constraints<SC, C>(
    chip: &MetaChip<SC::Val, C>,
    preprocessed_trace: Option<&RowMajorMatrix<SC::Val>>,
    main_trace: &RowMajorMatrix<SC::Val>,
    permutation_trace: &RowMajorMatrix<SC::Challenge>,
    permutation_challenges: &[SC::Challenge],
    public_values: Vec<SC::Val>,
) where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val> + for<'a> Air<DebugConstraintFolder<'a, SC::Val, SC::Challenge>>,
{
    assert_eq!(main_trace.height(), permutation_trace.height());
    let height = main_trace.height();
    if height == 0 {
        return;
    }

    let cumulative_sum = permutation_trace
        .row_slice(permutation_trace.height() - 1)
        .last()
        .copied()
        .unwrap();

    // Check that constraints are satisfied.
    (0..height).for_each(|i| {
        let i_next = (i + 1) % height;

        let main_local = &*main_trace.row_slice(i);
        let main_next = &*main_trace.row_slice(i_next);

        let preprocessed_local = if let Some(preprocessed_trace) = preprocessed_trace {
            preprocessed_trace.row_slice(i).to_vec()
        } else {
            Vec::new()
        };

        let preprocessed_next = if let Some(preprocessed_trace) = preprocessed_trace {
            preprocessed_trace.row_slice(i_next).to_vec()
        } else {
            Vec::new()
        };

        let permutation_local = &*permutation_trace.row_slice(i);
        let permutation_next = &*permutation_trace.row_slice(i_next);

        let public_values = public_values.clone();
        let mut builder = DebugConstraintFolder {
            preprocessed: VerticalPair::new(
                RowMajorMatrixView::new_row(&preprocessed_local),
                RowMajorMatrixView::new_row(&preprocessed_next),
            ),
            main: VerticalPair::new(
                RowMajorMatrixView::new_row(main_local),
                RowMajorMatrixView::new_row(main_next),
            ),
            permutation: VerticalPair::new(
                RowMajorMatrixView::new_row(permutation_local),
                RowMajorMatrixView::new_row(permutation_next),
            ),
            permutation_challenges,
            cumulative_sum,
            is_first_row: SC::Val::zero(),
            is_last_row: SC::Val::zero(),
            is_transition: SC::Val::one(),
            public_values: &public_values,
        };
        if i == 0 {
            builder.is_first_row = SC::Val::one();
        }
        if i == height - 1 {
            builder.is_last_row = SC::Val::one();
            builder.is_transition = SC::Val::zero();
        }
        let result = catch_unwind_silent(AssertUnwindSafe(|| {
            chip.eval(&mut builder);
        }));
        if result.is_err() {
            eprintln!("local: {main_local:?}");
            eprintln!("next:  {main_next:?}");
            eprintln!("failed at row {} of chip {}", i, chip.name());
            exit(1);
        }
    });
}

fn catch_unwind_silent<F: FnOnce() -> R + panic::UnwindSafe, R>(f: F) -> std::thread::Result<R> {
    let previous_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let result = panic::catch_unwind(f);
    panic::set_hook(previous_hook);
    result
}

/// Debugs the constraints of the given records for the chips of a machine instance.
#[instrument("debug constraints", level = "debug", skip_all)]
pub fn debug_all_chips_constraints<SC, C>(
    chips: &[MetaChip<SC::Val, C>],
    pk: &BaseProvingKey<SC>,
    records: &[C::Record],
    challenger: &mut SC::Challenger,
) where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val> + for<'a> Air<DebugConstraintFolder<'a, SC::Val, SC::Challenge>>,
{
    tracing::debug!("Debugging constraints for each chunk");

    // Sample the challenges used for the permutation argument.
    let mut permutation_challenges: Vec<SC::Challenge> = Vec::new();
    for _ in 0..2 {
        permutation_challenges.push(challenger.sample_ext_element());
    }

    let mut cumulative_sum = SC::Challenge::zero();
    for chunk in records.iter() {
        // Filter the chips based on what is used.
        let chips = chunk_active_chips::<SC, C>(chips, chunk).collect::<Vec<_>>();

        // Generate the preprocessed trace and the main trace for each chip.
        let preprocessed_traces = chips
            .iter()
            .map(|chip| {
                pk.preprocessed_chip_ordering
                    .get(&chip.name())
                    .map(|index| &pk.preprocessed_trace[*index])
            })
            .collect::<Vec<_>>();
        let mut traces = chips
            .par_iter()
            .map(|chip| chip.generate_main(chunk, &mut C::Record::default()))
            .zip(preprocessed_traces)
            .collect::<Vec<_>>();

        // Generate the permutation traces.
        let mut permutation_traces = Vec::with_capacity(chips.len());
        let mut cumulative_sums = Vec::with_capacity(chips.len());
        tracing::debug_span!("generate permutation traces").in_scope(|| {
            chips
                .par_iter()
                .zip(traces.par_iter_mut())
                .map(|(chip, (main_trace, preprocessed_trace))| {
                    let permutation_trace = chip.generate_permutation(
                        *preprocessed_trace,
                        main_trace,
                        &permutation_challenges,
                    );
                    let cumulative_sum = permutation_trace
                        .row_slice(main_trace.height() - 1)
                        .last()
                        .copied()
                        .unwrap();
                    (permutation_trace, cumulative_sum)
                })
                .unzip_into_vecs(&mut permutation_traces, &mut cumulative_sums);
        });

        cumulative_sum += cumulative_sums.iter().copied().sum::<SC::Challenge>();

        // Compute some statistics.
        for i in 0..chips.len() {
            let main_width = traces[i].0.width();
            let preprocessed_width = traces[i].1.map_or(0, p3_matrix::Matrix::width);
            let permutation_width = permutation_traces[i].width()
                * <SC::Challenge as AbstractExtensionField<SC::Val>>::D;
            let total_width = main_width + preprocessed_width + permutation_width;
            tracing::debug!(
                "{:<11} | Main Cols = {:<5} | Preprocessed Cols = {:<5} | Permutation Cols = {:<5} | Rows = {:<10} | Cells = {:<10}",
                chips[i].name(),
                main_width,
                preprocessed_width,
                permutation_width,
                traces[i].0.height(),
                total_width * traces[i].0.height(),
            );
        }

        tracing::info_span!("debug constraints").in_scope(|| {
            for i in 0..chips.len() {
                let preprocessed_trace = pk
                    .preprocessed_chip_ordering
                    .get(&chips[i].name())
                    .map(|index| &pk.preprocessed_trace[*index]);
                debug_constraints::<SC, C>(
                    chips[i],
                    preprocessed_trace,
                    &traces[i].0,
                    &permutation_traces[i],
                    &permutation_challenges,
                    chunk.public_values(),
                );
            }
        });
    }

    tracing::info!("Debug Constraints verified successfully");

    tracing::info!("Cumulative sum in debug constraints : {cumulative_sum}");

    // If the cumulative sum is not zero, debug the lookups.
    if !cumulative_sum.is_zero() {
        // TODO: add debug function here
        panic!("Cumulative sum is not zero");
    }
}
