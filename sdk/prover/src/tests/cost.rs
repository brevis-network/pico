//! `estimate_cost`: per-AIR rows from an emulation, split into the three components.

use super::fixture::{small_builder, N, POSEIDON2_ELF, SMALL_CHUNK, SMALL_LOG_STACKED_HEIGHT};
use crate::{CostComponent, Prover, Stdin};

#[test]
fn fib_costs_the_instruction_set_and_the_system_tables() {
    let builder = small_builder().chunk_size(SMALL_CHUNK);
    let cost = builder.estimate_cost(Stdin::from(&N)).expect("estimate");
    let execution = builder.execute(Stdin::from(&N)).expect("execute");
    assert_eq!(cost.cycles, execution.cycles);
    assert!(cost.records > 1, "{} record(s)", cost.records);

    let rows = |name: &str| cost.chips.iter().find(|c| c.name == name).map(|c| c.rows);
    // The byte table is full in every record, the program table one row per instruction in each.
    assert_eq!(rows("Byte"), Some(cost.records as u64 * (1 << 17)));
    assert!(rows("Cpu").is_some_and(|n| n > 0));

    assert!(cost.cells(CostComponent::Rv64) > 0);
    assert!(cost.cells(CostComponent::System) > 0);
    assert_eq!(
        cost.total_cells(),
        [
            CostComponent::Rv64,
            CostComponent::Precompile,
            CostComponent::System
        ]
        .map(|c| cost.cells(c))
        .iter()
        .sum::<u64>()
    );
    for chip in &cost.chips {
        assert!(chip.width > 0, "{}: zero width", chip.name);
        assert_ne!(
            chip.component,
            CostComponent::Precompile,
            "fib calls no precompile, yet {} has {} rows",
            chip.name,
            chip.rows
        );
    }
}

#[test]
fn a_precompile_guest_costs_its_precompile() {
    let cost = Prover::builder(POSEIDON2_ELF)
        .log_stacked_height(SMALL_LOG_STACKED_HEIGHT)
        .estimate_cost(Stdin::from(&1u32))
        .expect("estimate");
    let permute = cost
        .chips
        .iter()
        .find(|c| c.name == "Poseidon2Permute")
        .expect("the Poseidon2 precompile is filled");
    assert_eq!(permute.component, CostComponent::Precompile);
    assert!(permute.rows > 0);
    assert!(cost.cells(CostComponent::Precompile) >= permute.cells());
}
