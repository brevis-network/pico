use std::sync::Arc;

use itertools::{izip, Itertools};
use p3_air::{Air, BaseAir, RowWindow};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::{
    dense::{RowMajorMatrix, RowMajorMatrixView},
    Matrix,
};
use p3_maybe_rayon::prelude::*;

use crate::{
    air::{
        debug::{DebugConstraintBuilder, USE_DEBUG_BUILDER},
        symbolic::SymbolicConstraints,
    },
    config::{StarkProtocolConfig, Val},
    interaction::{
        debug::{generate_logical_interactions, LogicalInteractions},
        SymbolicInteraction,
    },
    keygen::types::StarkProvingKey,
    AirRef, PartitionedBaseAir,
};

/// Raw input data for debugging a single AIR.
pub struct AirProofRawInput<F> {
    pub cached_mains: Vec<Arc<RowMajorMatrix<F>>>,
    pub common_main: Option<Arc<RowMajorMatrix<F>>>,
    pub public_values: Vec<F>,
}

/// Check that all constraints vanish on the subgroup.
#[allow(clippy::too_many_arguments)]
pub fn check_constraints<R, SC>(
    rap: &R,
    rap_name: &str,
    preprocessed: &Option<RowMajorMatrixView<Val<SC>>>,
    partitioned_main: &[RowMajorMatrixView<Val<SC>>],
    public_values: &[Val<SC>],
) where
    R: for<'a> Air<DebugConstraintBuilder<'a, SC>>
        + BaseAir<Val<SC>>
        + PartitionedBaseAir<Val<SC>>
        + ?Sized,
    SC: StarkProtocolConfig,
{
    let height = partitioned_main[0].height();
    assert!(partitioned_main.iter().all(|mat| mat.height() == height));

    // Check that constraints are satisfied.
    (0..height).into_par_iter().for_each(|i| {
        let i_next = (i + 1) % height;

        let (preprocessed_local, preprocessed_next) = preprocessed
            .as_ref()
            .map(|preprocessed| {
                (
                    preprocessed.row_slice(i).unwrap().to_vec(),
                    preprocessed.row_slice(i_next).unwrap().to_vec(),
                )
            })
            .unwrap_or((vec![], vec![]));

        let partitioned_main_row_pair = partitioned_main
            .iter()
            .map(|part| (part.row_slice(i).unwrap(), part.row_slice(i_next).unwrap()))
            .collect::<Vec<_>>();
        let partitioned_main = partitioned_main_row_pair
            .iter()
            .map(|(local, next)| RowWindow::from_two_rows(&local[..], &next[..]))
            .collect::<Vec<_>>();

        let mut builder = DebugConstraintBuilder {
            air_name: rap_name,
            row_index: i,
            preprocessed: RowWindow::from_two_rows(
                preprocessed_local.as_slice(),
                preprocessed_next.as_slice(),
            ),
            partitioned_main,
            public_values,
            is_first_row: Val::<SC>::ZERO,
            is_last_row: Val::<SC>::ZERO,
            is_transition: Val::<SC>::ONE,
            has_common_main: rap.common_main_width() > 0,
        };
        if i == 0 {
            builder.is_first_row = Val::<SC>::ONE;
        }
        if i == height - 1 {
            builder.is_last_row = Val::<SC>::ONE;
            builder.is_transition = Val::<SC>::ZERO;
        }

        rap.eval(&mut builder);
    });
}

pub fn check_logup<F: Field>(
    air_names: &[String],
    interactions: &[Vec<SymbolicInteraction<F>>],
    preprocessed: &[Option<RowMajorMatrixView<F>>],
    partitioned_main: &[Vec<RowMajorMatrixView<F>>],
    public_values: &[Vec<F>],
) {
    let mut logical_interactions = LogicalInteractions::<F>::default();
    for (air_idx, (interactions, preprocessed, partitioned_main, public_values)) in
        izip!(interactions, preprocessed, partitioned_main, public_values).enumerate()
    {
        generate_logical_interactions(
            air_idx,
            interactions,
            preprocessed,
            partitioned_main,
            public_values,
            &mut logical_interactions,
        );
    }

    let mut logup_failed = false;
    // For each bus, check each `fields` key by summing up multiplicities.
    for (bus_idx, bus_interactions) in logical_interactions.at_bus.into_iter() {
        for (fields, connections) in bus_interactions.into_iter() {
            let sum: F = connections.iter().map(|(_, count)| *count).sum();
            if !sum.is_zero() {
                logup_failed = true;
                println!(
                    "Bus {:?} failed to balance the multiplicities for fields={:?}. The bus connections for this were:",
                    bus_idx, fields
                );
                for (air_idx, count) in connections {
                    println!(
                        "   Air idx: {}, Air name: {}, count: {:?}",
                        air_idx, air_names[air_idx], count
                    );
                }
            }
        }
    }
    if logup_failed {
        panic!("LogUp multiset equality check failed.");
    }
}

/// The debugging will check the main AIR constraints and then separately check LogUp constraints by
/// checking the actual multiset equalities. Currently it will not debug check any after challenge
/// phase constraints for implementation simplicity.
#[allow(clippy::too_many_arguments)]
pub fn debug_constraints_and_interactions<SC: StarkProtocolConfig>(
    airs: &[AirRef<SC>],
    pk: &[&StarkProvingKey<SC>],
    inputs: &[AirProofRawInput<SC::F>],
) {
    USE_DEBUG_BUILDER.with(|debug| {
        if *debug.lock().unwrap() {
            let (main_parts_per_air, pvs_per_air): (Vec<_>, Vec<_>) = inputs
                .iter()
                .map(|input| {
                    let mut main_parts = input
                        .cached_mains
                        .iter()
                        .map(|trace| trace.as_view())
                        .collect_vec();
                    if let Some(trace) = input.common_main.as_ref() {
                        main_parts.push(trace.as_view());
                    }
                    (main_parts, input.public_values.clone())
                })
                .unzip();
            let preprocessed = izip!(airs, pk, &main_parts_per_air, &pvs_per_air)
                .map(|(air, pk, main_parts, pvs)| {
                    let preprocessed_trace = pk
                        .preprocessed_data
                        .as_ref()
                        .map(|data| data.mat_view(0).to_row_major_matrix());
                    tracing::debug!("Checking constraints for {}", air.name());
                    check_constraints(
                        air.as_ref(),
                        &air.name(),
                        &preprocessed_trace.as_ref().map(|t| t.as_view()),
                        main_parts,
                        pvs,
                    );
                    preprocessed_trace
                })
                .collect_vec();

            let (air_names, interactions): (Vec<_>, Vec<_>) = pk
                .iter()
                .map(|pk| {
                    let sym_constraints = SymbolicConstraints::from(&pk.vk.symbolic_constraints);
                    (pk.air_name.clone(), sym_constraints.interactions)
                })
                .unzip();
            let preprocessed_views = preprocessed
                .iter()
                .map(|t| t.as_ref().map(|t| t.as_view()))
                .collect_vec();
            check_logup(
                &air_names,
                &interactions,
                &preprocessed_views,
                &main_parts_per_air,
                &pvs_per_air,
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use crate::{
        config::koala_bear_poseidon2::DuplexSponge,
        engine::koala_bear_poseidon2::KoalaBearPoseidon2RefEngine,
        test_utils::{test_system_params_small, InteractionsFixture11, TestFixture},
        StarkEngine,
    };

    type Engine = KoalaBearPoseidon2RefEngine<DuplexSponge>;

    /// A balanced 1-sender / 1-receiver interaction chip group passes the debug checker:
    /// every row satisfies its AIR constraints (`check_constraints`) and each bus's LogUp
    /// multiset nets to zero (`check_logup`).
    #[test]
    fn debug_passes_on_balanced_interaction_chips() {
        let engine = Engine::new(test_system_params_small(2, 5, 3));
        let fixture = InteractionsFixture11;
        engine.debug(&fixture.airs(), &fixture.generate_proving_ctx());
    }
}
