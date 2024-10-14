use crate::configs::config::{PackedChallenge, PackedVal, StarkGenericConfig};
use core::iter;
use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::{Air, PairCol};
use p3_commit::PolynomialSpace;
use p3_field::{AbstractExtensionField, AbstractField, ExtensionField, Field, PackedValue, Powers};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::*;
use p3_uni_stark::{Entry, SymbolicExpression};
use p3_util::{log2_ceil_usize, log2_strict_usize};
use std::any::type_name;

use crate::machine::{
    chip::{ChipBehavior, MetaChip},
    folder::{ProverConstraintFolder, SymbolicConstraintFolder},
    lookup::VirtualPairLookup,
};

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
