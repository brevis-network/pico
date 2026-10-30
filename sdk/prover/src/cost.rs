//! What proving a run would cost, from an emulation alone: per RISC-V AIR, the main-trace rows the
//! run fills and the AIR's width.

use std::collections::BTreeMap;

use pico_mle_core::p3_air::BaseAir;
use pico_vm::{
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::chip::ChipBehavior,
    mle::machine::riscv::{air_id, air_id_for, air_name, natural_air_rows},
};

use crate::{prover::Emulation, types::Kb};

/// The part of the machine a RISC-V AIR belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CostComponent {
    /// The instruction set: the CPU, the ALU tables, memory reads and writes, ecalls.
    Rv64,
    /// The precompiles and the syscall tables that dispatch to them.
    Precompile,
    /// Shared infrastructure: the byte and program tables, memory initialization and
    /// finalization, local memory, and the global lookup with the Poseidon2 table that hashes it.
    System,
}

impl CostComponent {
    /// The component of the RISC-V AIR `id`.
    pub fn of_air(id: usize) -> Self {
        match id {
            air_id::BYTE
            | air_id::PROGRAM
            | air_id::MEM_INIT
            | air_id::MEM_FINAL
            | air_id::MEM_LOCAL
            | air_id::GLOBAL
            | air_id::POSEIDON2 => Self::System,
            air_id::SYSCALL_RISCV
            | air_id::PRECOMPILE_FIRST..=air_id::PRECOMPILE_LAST
            | air_id::KECCAK_CONTROL
            | air_id::POSEIDON2_PERMUTE
            | air_id::ED_ADD
            | air_id::ED_DECOMPRESS => Self::Precompile,
            _ => Self::Rv64,
        }
    }
}

/// One RISC-V AIR's share of a run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChipCost {
    /// The chip's name, as the VM's air table spells it.
    pub name: &'static str,
    /// Main-trace rows summed over every record of the run, before padding.
    pub rows: u64,
    /// Main-trace columns.
    pub width: usize,
    pub component: CostComponent,
}

impl ChipCost {
    /// `rows × width`.
    pub fn cells(&self) -> u64 {
        self.rows * self.width as u64
    }
}

/// What [`crate::ProverBuilder::estimate_cost`] returns: every RISC-V AIR the run fills, in air
/// order.
///
/// Rows are natural, as `verify_keys(false)` proves them: what each chip's trace holds before
/// padding, after the extra-record pass proving runs. They depend on the run only; whitelist mode
/// pads each chunk further, to its bucket shape, and recursion is not counted. Rows and records
/// follow the CPU path's record split.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CostEstimate {
    pub chips: Vec<ChipCost>,
    /// The emulator's final global clock.
    pub cycles: u64,
    /// Records the run proves as, one RISC-V proof each.
    pub records: usize,
}

impl CostEstimate {
    /// Cells (`rows × width`) summed over the AIRs of `component`.
    pub fn cells(&self, component: CostComponent) -> u64 {
        self.chips
            .iter()
            .filter(|chip| chip.component == component)
            .map(ChipCost::cells)
            .sum()
    }

    /// [`Self::cells`] over all three components.
    pub fn total_cells(&self) -> u64 {
        self.chips.iter().map(ChipCost::cells).sum()
    }

    pub(crate) fn from_emulation(emulated: Emulation) -> Self {
        let (records, cycles) = (emulated.records, emulated.execution.cycles);
        let chips = RiscvChipType::<Kb>::all_chips();
        let widths: BTreeMap<usize, usize> = chips
            .iter()
            .filter_map(|chip| Some((air_id_for(&chip.name())?, BaseAir::<Kb>::width(chip))))
            .collect();
        let count = records.len();
        let mut rows: BTreeMap<usize, u64> = BTreeMap::new();
        // One record at a time, so the augmented copy of only one is alive.
        for record in records {
            for (id, n) in natural_air_rows(&chips, record) {
                *rows.entry(id).or_default() += n as u64;
            }
        }
        Self {
            chips: rows
                .into_iter()
                .map(|(id, rows)| ChipCost {
                    name: air_name(id).expect("an air id from the air table"),
                    rows,
                    width: widths[&id],
                    component: CostComponent::of_air(id),
                })
                .collect(),
            cycles,
            records: count,
        }
    }
}
