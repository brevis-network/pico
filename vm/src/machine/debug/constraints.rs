use super::DebuggerMessageLevel;
use crate::{
    configs::config::StarkGenericConfig,
    emulator::record::RecordBehavior,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::DebugConstraintFolder,
        keys::BaseProvingKey,
        lookup::LookupScope,
        septic::{SepticCurve, SepticDigest, SepticExtension},
        utils::chunk_active_chips,
    },
};
use log::{debug, error, info};
use p3_air::Air;
use p3_challenger::FieldChallenger;
use p3_field::{Field, FieldAlgebra, FieldExtensionAlgebra};
use p3_matrix::{
    dense::{RowMajorMatrix, RowMajorMatrixView},
    stack::VerticalPair,
    Matrix,
};
use p3_maybe_rayon::prelude::*;
use std::array;

pub struct IncrementalConstraintDebugger<'a, SC: StarkGenericConfig> {
    pk: &'a BaseProvingKey<SC>,
    global_sums: Vec<SepticDigest<SC::Val>>,
    challenges: [SC::Challenge; 2],
    messages: Vec<(DebuggerMessageLevel, String)>,
}

impl<'a, SC: StarkGenericConfig> IncrementalConstraintDebugger<'a, SC> {
    pub fn new(
        pk: &'a BaseProvingKey<SC>,
        challenger: &mut SC::Challenger,
        has_global: bool,
    ) -> Self {
        let mut global_sums = vec![];
        if has_global {
            global_sums.push(pk.initial_global_cumulative_sum);
        }

        let challenges = array::from_fn(|_| challenger.sample_ext_element());

        let messages = vec![];

        Self {
            pk,
            global_sums,
            challenges,
            messages,
        }
    }

    pub fn print_results(self) -> bool {
        let mut success = true;

        info!("\n******** Constraints Debugging START ********");

        for message in self.messages {
            match message {
                (DebuggerMessageLevel::Info, msg) => log::info!("{}", msg),
                (DebuggerMessageLevel::Debug, msg) => log::debug!("{}", msg),
                (DebuggerMessageLevel::Error, msg) => {
                    eprintln!("{}", msg);
                    success = false;
                }
            }
        }

        let global_sum: SepticDigest<SC::Val> = self.global_sums.iter().copied().sum();
        if !global_sum.is_zero() {
            error!("Cumulative global sum is not zero");
            success = false;
        }

        if success {
            info!("Constraints success!");
        } else {
            error!("Constraints failed!");
        }

        info!("\n******** Constraints Debugging END ********");

        success
    }

    pub fn debug_incremental<C>(&mut self, chips: &[MetaChip<SC::Val, C>], chunks: &[C::Record])
    where
        C: ChipBehavior<SC::Val> + for<'b> Air<DebugConstraintFolder<'b, SC::Val, SC::Challenge>>,
    {
        for chunk in chunks.iter() {
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
            chips
                .par_iter()
                .zip(traces.par_iter_mut())
                .map(|(chip, (main_trace, preprocessed_trace))| {
                    let (trace, regional_sum) = chip.generate_permutation(
                        *preprocessed_trace,
                        main_trace,
                        &self.challenges,
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
                    (trace, (global_sum, regional_sum))
                })
                .unzip_into_vecs(&mut permutation_traces, &mut cumulative_sums);

            let global_sum = cumulative_sums
                .iter()
                .map(|sum| sum.0)
                .sum::<SepticDigest<SC::Val>>();
            self.global_sums.push(global_sum);

            let regional_sum = cumulative_sums
                .iter()
                .map(|sum| sum.1)
                .sum::<SC::Challenge>();

            if !regional_sum.is_zero() {
                info!(
                    "Regional cumulative sum is not zero: chunk_index = {}.\n\t
                    Please enable `debug-lookups` feature to debug the lookups.",
                    chunk.chunk_index(),
                );
            }

            // Compute some statistics.
            for i in 0..chips.len() {
                let main_width = traces[i].0.width();
                let preprocessed_width = traces[i].1.map_or(0, p3_matrix::Matrix::width);
                let permutation_width = permutation_traces[i].width()
                    * <SC::Challenge as FieldExtensionAlgebra<SC::Val>>::D;
                let total_width = main_width + preprocessed_width + permutation_width;
                debug!(
                    "{:<11} | Main Cols = {:<5} | Preprocessed Cols = {:<5} | Permutation Cols = {:<5} | Rows = {:<10} | Cells = {:<10}",
                    chips[i].name(),
                    main_width,
                    preprocessed_width,
                    permutation_width,
                    traces[i].0.height(),
                    total_width * traces[i].0.height(),
                );
            }

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
                    &cumulative_sums[i].1,
                    &cumulative_sums[i].0,
                );
            }
        }

        info!("Constraints verified successfully");

        let global_sum: SepticDigest<SC::Val> = self.global_sums.iter().copied().sum();
        if !global_sum.is_zero() {
            info!(
                "Global cumulative sum is not zero.\n\t
                Please enable `debug-lookups` feature to debug the lookups.",
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn debug_constraints_incremental<C>(
        &mut self,
        chip: &MetaChip<SC::Val, C>,
        preprocessed_trace: Option<&RowMajorMatrix<SC::Val>>,
        main_trace: &RowMajorMatrix<SC::Val>,
        permutation_trace: &RowMajorMatrix<SC::Challenge>,
        public_values: Vec<SC::Val>,
        regional_cumulative_sum: &SC::Challenge,
        global_cumulative_sum: &SepticDigest<SC::Val>,
    ) where
        C: ChipBehavior<SC::Val> + for<'b> Air<DebugConstraintFolder<'b, SC::Val, SC::Challenge>>,
    {
        assert_eq!(main_trace.height(), permutation_trace.height());
        let height = main_trace.height();
        if height == 0 {
            return;
        }

        let _cumulative_sum = permutation_trace
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
                regional_cumulative_sum,
                global_cumulative_sum,
                is_first_row: SC::Val::ZERO,
                is_last_row: SC::Val::ZERO,
                is_transition: SC::Val::ONE,
                public_values: &public_values,
                failures: Vec::new(),
            };
            if i == 0 {
                builder.is_first_row = SC::Val::ONE;
            }
            if i == height - 1 {
                builder.is_last_row = SC::Val::ONE;
                builder.is_transition = SC::Val::ZERO;
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
