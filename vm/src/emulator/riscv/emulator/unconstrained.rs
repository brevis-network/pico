use super::{EmulatorMode, RiscvEmulatorMode};
use crate::{
    chips::chips::riscv_memory::event::MemoryRecord,
    emulator::riscv::{
        emulator::RiscvEmulator,
        event_types::{RvAddr, RvClk},
        record::{EmulationRecord, MemoryAccessRecord},
        state::RuntimeRegisterRecord,
    },
};
use hashbrown::HashMap;

/// A struct that records states that must be restored after we exit unconstrained mode
#[derive(Clone, Debug)]
pub struct UnconstrainedState {
    pub(crate) global_clk: RvClk,
    pub(crate) clk: RvClk,
    pub(crate) pc: RvAddr,
    // Only *_diff maps need to be updated in unconstrained mode.
    // Keep registers and memory in separate namespaces to avoid address collisions.
    pub(crate) memory_diff: HashMap<u64, Option<MemoryRecord>>,
    pub(crate) register_diff: HashMap<u8, Option<RuntimeRegisterRecord>>,
    pub(crate) op_record: MemoryAccessRecord,
    pub(crate) record: EmulationRecord,
    pub(crate) prev_mode: EmulatorMode,
}

impl UnconstrainedState {
    #[must_use]
    pub fn new(rt: &mut RiscvEmulator) -> Self {
        let prev_mode = match &rt.mode {
            RiscvEmulatorMode::Simple => EmulatorMode::Simple,
            RiscvEmulatorMode::Trace => EmulatorMode::Trace,
            prev_mode => panic!(
                "Unsupported previous emulator mode enters the Unconstrained block: {prev_mode:?}",
            ),
        };

        Self {
            global_clk: rt.state.global_clk,
            clk: rt.state.clk,
            pc: rt.state.pc,
            memory_diff: HashMap::default(),
            register_diff: HashMap::default(),
            record: core::mem::take(&mut rt.record),
            op_record: core::mem::take(&mut rt.memory_accesses),
            prev_mode,
        }
    }
}
