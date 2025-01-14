use super::EmulatorMode;
use crate::{
    chips::chips::riscv_memory::event::MemoryRecord,
    emulator::riscv::record::{EmulationRecord, MemoryAccessRecord},
};
use hashbrown::HashMap;

/// A struct that records states that must be restored after we exit unconstrained mode
#[derive(Clone, Debug, Default)]
pub struct UnconstrainedState {
    pub(crate) global_clk: u64,
    pub(crate) clk: u32,
    pub(crate) pc: u32,
    pub(crate) memory_diff: HashMap<u32, Option<MemoryRecord>>,
    pub(crate) op_record: MemoryAccessRecord,
    pub(crate) record: EmulationRecord,
    pub(crate) emulator_mode: EmulatorMode,
}
