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
use std::{panic, panic::AssertUnwindSafe, process::exit};
use tracing::instrument;

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
pub fn debug_all_constraints<SC, C>(
    chips: &[MetaChip<SC::Val, C>],
    pk: &BaseProvingKey<SC>,
    records: &[C::Record],
    challenger: &mut SC::Challenger,
) where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val> + for<'a> Air<DebugConstraintFolder<'a, SC::Val, SC::Challenge>>,
{
    tracing::info_span!("debug constraints").in_scope(|| {
        tracing::info!("Debugging all constraints");
    });

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

    tracing::info_span!("debug constraints").in_scope(|| {
        tracing::info!("Debug constraints verified successfully");
        tracing::info!("Cumulative sum in debug constraints : {cumulative_sum}");
        // If the cumulative sum is not zero, debug the lookups.
        if !cumulative_sum.is_zero() {
            tracing::info!(
                "Cumulative sum is not zero.\
                Please set feature flag `debug-lookups` to debug the lookups."
            );
        }
    });
}
