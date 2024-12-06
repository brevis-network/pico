use super::DebuggerMessageLevel;
use crate::{
    configs::config::StarkGenericConfig,
    emulator::record::RecordBehavior,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::DebugConstraintFolder,
        keys::BaseProvingKey,
        utils::chunk_active_chips,
    },
};
use p3_air::Air;
use p3_challenger::FieldChallenger;
use p3_field::{AbstractExtensionField, AbstractField, Field};
use p3_matrix::{
    dense::{RowMajorMatrix, RowMajorMatrixView},
    stack::VerticalPair,
    Matrix,
};
use p3_maybe_rayon::prelude::*;

pub struct IncrementalConstraintDebugger<'a, SC: StarkGenericConfig> {
    challenges: [SC::Challenge; 2],
    messages: Vec<(DebuggerMessageLevel, String)>,
    sum: SC::Challenge,
    pk: &'a BaseProvingKey<SC>,
}

impl<'a, SC: StarkGenericConfig> IncrementalConstraintDebugger<'a, SC> {
    pub fn new(pk: &'a BaseProvingKey<SC>, challenger: &mut SC::Challenger) -> Self {
        Self {
            challenges: [
                challenger.sample_ext_element(),
                challenger.sample_ext_element(),
            ],
            messages: Vec::new(),
            sum: SC::Challenge::zero(),
            pk,
        }
    }

    pub fn print_results(self) -> bool {
        let mut result = false;
        for message in self.messages {
            match message {
                (DebuggerMessageLevel::Info, msg) => log::info!("{}", msg),
                (DebuggerMessageLevel::Debug, msg) => log::debug!("{}", msg),
                (DebuggerMessageLevel::Error, msg) => {
                    eprintln!("{}", msg);
                    result = true;
                }
            }
        }

        tracing::info_span!("debug constraints").in_scope(|| {
            tracing::info!("Debug constraints verified successfully");
            tracing::info!("Cumulative sum in debug constraints : {}", self.sum);
            // If the cumulative sum is not zero, debug the lookups.
            if !self.sum.is_zero() {
                tracing::info!(
                    "Cumulative sum is not zero.\
                    Please set feature flag `debug-lookups` to debug the lookups."
                );
                result = true;
            }
        });
        result
    }

    pub fn debug_incremental<C>(&mut self, chips: &[MetaChip<SC::Val, C>], records: &[C::Record])
    where
        C: ChipBehavior<SC::Val> + for<'b> Air<DebugConstraintFolder<'b, SC::Val, SC::Challenge>>,
    {
        for chunk in records.iter() {
            // Filter the chips based on what is used.
            let chips = chunk_active_chips::<SC, C>(chips, chunk).collect::<Vec<_>>();

            // Generate the preprocessed trace and the main trace for each chip.
            let preprocessed_traces = chips
                .iter()
                .map(|chip| {
                    self.pk
                        .preprocessed_chip_ordering
                        .get(&chip.name())
                        .map(|index| &self.pk.preprocessed_trace[*index])
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
                            &self.challenges,
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

            self.sum += cumulative_sums.iter().copied().sum::<SC::Challenge>();

            // Compute some statistics.
            for i in 0..chips.len() {
                let main_width = traces[i].0.width();
                let preprocessed_width = traces[i].1.map_or(0, p3_matrix::Matrix::width);
                let permutation_width = permutation_traces[i].width()
                    * <SC::Challenge as AbstractExtensionField<SC::Val>>::D;
                let total_width = main_width + preprocessed_width + permutation_width;
                self.messages.push((DebuggerMessageLevel::Debug, format!(
                    "{:<11} | Main Cols = {:<5} | Preprocessed Cols = {:<5} | Permutation Cols = {:<5} | Rows = {:<10} | Cells = {:<10}",
                    chips[i].name(),
                    main_width,
                    preprocessed_width,
                    permutation_width,
                    traces[i].0.height(),
                    total_width * traces[i].0.height(),
                )));
            }

            tracing::info_span!(
                "debug constraints",
                chunk = chunk.chunk_index(),
                unconstrained = chunk.unconstrained()
            )
            .in_scope(|| {
                for i in 0..chips.len() {
                    let preprocessed_trace = self
                        .pk
                        .preprocessed_chip_ordering
                        .get(&chips[i].name())
                        .map(|index| &self.pk.preprocessed_trace[*index]);
                    self.debug_constraints_incremental(
                        chips[i],
                        preprocessed_trace,
                        &traces[i].0,
                        &permutation_traces[i],
                        chunk.public_values(),
                    );
                }
            });
        }
    }

    pub fn debug_constraints_incremental<C>(
        &mut self,
        chip: &MetaChip<SC::Val, C>,
        preprocessed_trace: Option<&RowMajorMatrix<SC::Val>>,
        main_trace: &RowMajorMatrix<SC::Val>,
        permutation_trace: &RowMajorMatrix<SC::Challenge>,
        public_values: Vec<SC::Val>,
    ) where
        C: ChipBehavior<SC::Val> + for<'b> Air<DebugConstraintFolder<'b, SC::Val, SC::Challenge>>,
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
                permutation_challenges: &self.challenges,
                cumulative_sum,
                is_first_row: SC::Val::zero(),
                is_last_row: SC::Val::zero(),
                is_transition: SC::Val::one(),
                public_values: &public_values,
                failures: Vec::new(),
            };
            if i == 0 {
                builder.is_first_row = SC::Val::one();
            }
            if i == height - 1 {
                builder.is_last_row = SC::Val::one();
                builder.is_transition = SC::Val::zero();
            }
            chip.eval(&mut builder);
            for err in builder.failures.drain(..) {
                self.messages
                    .push((DebuggerMessageLevel::Error, format!("local: {err:?}")));
                self.messages.push((
                    DebuggerMessageLevel::Error,
                    format!("local: {main_local:?}"),
                ));
                self.messages
                    .push((DebuggerMessageLevel::Error, format!("next:  {main_next:?}")));
                self.messages.push((
                    DebuggerMessageLevel::Error,
                    format!("failed at row {} of chip {}", i, chip.name()),
                ));
            }
        });
    }
}
