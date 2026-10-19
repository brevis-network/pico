use std::iter;

use itertools::Itertools;
use p3_air::{Air, AirBuilder, ExtensionBuilder};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use tracing::instrument;

use self::{
    symbolic_expression::SymbolicExpression,
    symbolic_variable::{Entry, SymbolicVariable},
};
use super::PartitionedAirBuilder;
use crate::{
    builder::{ChipBuilder, LookupBuilder, ScopedBuilder},
    interaction::{Interaction, SymbolicInteraction},
    keygen::types::TraceWidth,
    lookup::{LookupSummary, SymbolicLookup},
};

mod dag;
pub mod symbolic_expression;
pub mod symbolic_variable;

pub use dag::*;

/// Symbolic constraints for a single AIR with interactions.
#[derive(Clone, Debug)]
pub struct SymbolicConstraints<F> {
    /// All plain AIR constraints. These do **not** include interaction constraints that are proven
    /// via LogUp-GKR.
    pub constraints: Vec<SymbolicExpression<F>>,
    /// Symbolic representation of interactions. These are converted into a LogUp fractional sum
    /// which must be proven using GKR.
    pub interactions: Vec<SymbolicInteraction<F>>,
}

impl<F: Field> SymbolicConstraints<F> {
    pub fn max_constraint_degree(&self) -> usize {
        iter::empty()
            .chain(&self.constraints)
            .chain(
                self.interactions
                    .iter()
                    .flat_map(|i| iter::once(&i.count).chain(&i.message)),
            )
            .map(|expr| expr.degree_multiple())
            .max()
            .unwrap_or(0)
    }

    /// Returns the maximum field degree and count degree across all interactions
    pub fn max_interaction_degrees(&self) -> (usize, usize) {
        let max_field_degree = self
            .interactions
            .iter()
            .map(|interaction| {
                interaction
                    .message
                    .iter()
                    .map(|field| field.degree_multiple())
                    .max()
                    .unwrap_or(0)
            })
            .max()
            .unwrap_or(0);

        let max_count_degree = self
            .interactions
            .iter()
            .map(|interaction| interaction.count.degree_multiple())
            .max()
            .unwrap_or(0);

        (max_field_degree, max_count_degree)
    }
}

#[instrument(name = "evaluate constraints symbolically", skip_all, level = "debug")]
pub fn get_symbolic_builder<F, R>(rap: &R, width: &TraceWidth) -> SymbolicRapBuilder<F>
where
    F: Field,
    R: Air<SymbolicRapBuilder<F>> + crate::air::any_air::BaseAirWithPublicValues<F> + ?Sized,
{
    get_symbolic_builder_with_public_values(
        rap,
        width,
        crate::air::any_air::BaseAirWithPublicValues::num_public_values(rap),
    )
}

/// Same as [`get_symbolic_builder`], but with the number of public values supplied by the
/// caller — for AIRs that don't implement `BaseAirWithPublicValues` themselves.
pub fn get_symbolic_builder_with_public_values<F, R>(
    rap: &R,
    width: &TraceWidth,
    num_public_values: usize,
) -> SymbolicRapBuilder<F>
where
    F: Field,
    R: Air<SymbolicRapBuilder<F>> + ?Sized,
{
    let mut builder = SymbolicRapBuilder::new(width, num_public_values);
    Air::eval(rap, &mut builder);
    builder
}

/// An `AirBuilder` for evaluating constraints symbolically, and recording them for later use.
#[derive(Debug)]
pub struct SymbolicRapBuilder<F> {
    preprocessed: RowMajorMatrix<SymbolicVariable<F>>,
    partitioned_main: Vec<RowMajorMatrix<SymbolicVariable<F>>>,
    public_values: Vec<SymbolicVariable<F>>,
    constraints: Vec<SymbolicExpression<F>>,
    interactions: Vec<SymbolicInteraction<F>>,
    /// `(kind, scope)` of every `looking` / `looked` call, in order. `interactions` drops the scope,
    /// and the RISC-V machine needs it to count a chip's regional memory lookups.
    looking_summaries: Vec<LookupSummary>,
    looked_summaries: Vec<LookupSummary>,
    trace_width: TraceWidth,
}

impl<F: Field> SymbolicRapBuilder<F> {
    pub(crate) fn new(width: &TraceWidth, num_public_values: usize) -> Self {
        let preprocessed_width = width.preprocessed.unwrap_or(0);
        let prep_values = [0, 1]
            .into_iter()
            .flat_map(|offset| {
                (0..width.preprocessed.unwrap_or(0))
                    .map(move |index| SymbolicVariable::new(Entry::Preprocessed { offset }, index))
            })
            .collect();
        let preprocessed = RowMajorMatrix::new(prep_values, preprocessed_width);

        let mut partitioned_main: Vec<_> = width
            .cached_mains
            .iter()
            .enumerate()
            .map(|(part_index, &width)| gen_main_trace(part_index, width))
            .collect();
        if width.common_main != 0 {
            partitioned_main.push(gen_main_trace(width.cached_mains.len(), width.common_main));
        }
        let public_values = (0..num_public_values)
            .map(move |index| SymbolicVariable::new(Entry::Public, index))
            .collect();

        Self {
            preprocessed,
            partitioned_main,
            public_values,
            constraints: vec![],
            interactions: vec![],
            looking_summaries: vec![],
            looked_summaries: vec![],
            trace_width: width.clone(),
        }
    }

    pub fn constraints(self) -> SymbolicConstraints<F> {
        SymbolicConstraints {
            constraints: self.constraints,
            interactions: self.interactions,
        }
    }

    pub fn num_public_values(&self) -> usize {
        self.public_values.len()
    }

    /// `(looking, looked)` summaries in call order.
    pub fn lookup_summaries(&self) -> (&[LookupSummary], &[LookupSummary]) {
        (&self.looking_summaries, &self.looked_summaries)
    }

    pub fn width(&self) -> TraceWidth {
        self.trace_width.clone()
    }
}

impl<F: Field> AirBuilder for SymbolicRapBuilder<F> {
    type F = F;
    type Expr = SymbolicExpression<Self::F>;
    type Var = SymbolicVariable<Self::F>;
    type PreprocessedWindow = RowMajorMatrix<Self::Var>;
    type MainWindow = RowMajorMatrix<Self::Var>;
    type PublicVar = SymbolicVariable<F>;

    /// It is difficult to horizontally concatenate matrices when the main trace is partitioned, so
    /// we disable this method in that case.
    fn main(&self) -> Self::MainWindow {
        if self.partitioned_main.len() == 1 {
            self.partitioned_main[0].clone()
        } else {
            panic!("Main trace is either empty or partitioned. This function should not be used.")
        }
    }

    fn is_first_row(&self) -> Self::Expr {
        SymbolicExpression::IsFirstRow
    }

    fn is_last_row(&self) -> Self::Expr {
        SymbolicExpression::IsLastRow
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size == 2 {
            SymbolicExpression::IsTransition
        } else {
            panic!("uni-stark only supports a window size of 2")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.constraints.push(x.into());
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        &self.public_values
    }
}

impl<F: Field> ExtensionBuilder for SymbolicRapBuilder<F> {
    type EF = F;
    type ExprEF = SymbolicExpression<F>;
    type VarEF = SymbolicVariable<F>;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.constraints.push(x.into());
    }
}

impl<F: Field> PartitionedAirBuilder for SymbolicRapBuilder<F> {
    fn cached_mains(&self) -> &[Self::MainWindow] {
        &self.partitioned_main[..self.trace_width.cached_mains.len()]
    }
    fn common_main(&self) -> &Self::MainWindow {
        assert_ne!(
            self.trace_width.common_main, 0,
            "AIR doesn't have a common main trace"
        );
        &self.partitioned_main[self.trace_width.cached_mains.len()]
    }
}

fn gen_main_trace<F: Field>(
    part_index: usize,
    width: usize,
) -> RowMajorMatrix<SymbolicVariable<F>> {
    let mat_values = [0, 1]
        .into_iter()
        .flat_map(|offset| {
            (0..width)
                .map(move |index| SymbolicVariable::new(Entry::Main { part_index, offset }, index))
        })
        .collect_vec();
    RowMajorMatrix::new(mat_values, width)
}

// ───────────────────────── ChipBuilder trait stack ─────────────────────────
//
// These impls let chips' generic `Air<CB: ChipBuilder<F>>` run on this builder for keygen,
// recording `looking()`/`looked()` as interactions:
//
// | direction | bus (kind)   | count   | count_weight |
// |-----------|--------------|---------|--------------|
// | looking   | `LookupType` | `+mult` | 1            |
// | looked    | `LookupType` | `-mult` | 0            |
//
// `LookupType::Global` is a bus like any other type; `GlobalChip` receives it and the
// per-chunk septic digest is carried in `GlobalChip`'s public values. Its `kind` slot is the one
// exception: `looking` asserts the sender's kind is a bounded constant (see `lookup.rs`).

impl<F: Field> ScopedBuilder for SymbolicRapBuilder<F> {}

impl<F: Field> LookupBuilder<SymbolicLookup<SymbolicExpression<F>>> for SymbolicRapBuilder<F> {
    fn looking(&mut self, message: SymbolicLookup<SymbolicExpression<F>>) {
        // Query side: `count_weight = 1` counts each lookup toward the per-bus
        // trace-height bound that prevents mod-p wraparound.
        //
        // INVARIANT: because the weight is hardcoded to 1, the caller's AIR MUST
        // constrain `multiplicity` to {0, 1} — the weight is a static declaration
        // of the per-row integer mass, and nothing checks it cryptographically.
        // A chip that needs per-row multiplicity k > 1 must not use `looking`
        // as-is (split into k boolean interactions, or add an explicit-weight
        // entry point).
        // The Global chip no longer range-checks its `kind` column: boundedness comes from
        // every Global-bus SENDER passing a compile-time constant kind < 32, which the multiset
        // then pins on the receiver. Enforce that statically so a future sender cannot silently
        // violate it (the FRI path checks the same in `SymbolicConstraintFolder::looking`).
        if message.kind == crate::lookup::LookupType::Global {
            let kind = message
                .values
                .get(crate::lookup::GLOBAL_KIND_VALUE_INDEX)
                .and_then(|elem| match elem {
                    SymbolicExpression::Constant(c) => Some(*c),
                    _ => None,
                });
            crate::lookup::assert_global_kind_is_bounded_constant(kind, message.values.len());
        }
        self.looking_summaries.push(LookupSummary {
            kind: message.kind,
            scope: message.scope,
        });
        self.interactions.push(Interaction {
            message: message.values,
            count: message.multiplicity,
            kind: message.kind,
            count_weight: 1,
        });
    }

    fn looked(&mut self, message: SymbolicLookup<SymbolicExpression<F>>) {
        // Receive side: negate the multiplicity so the per-bus logup sum cancels;
        // `count_weight = 0` because only the query side needs the overflow bound.
        self.looked_summaries.push(LookupSummary {
            kind: message.kind,
            scope: message.scope,
        });
        self.interactions.push(Interaction {
            message: message.values,
            count: SymbolicExpression::<F>::ZERO - message.multiplicity,
            kind: message.kind,
            count_weight: 0,
        });
    }
}

impl<F: Field> ChipBuilder<F> for SymbolicRapBuilder<F> {}
