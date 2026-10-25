use crate::{chips::chips::riscv_cpu::event::CpuEvent, emulator::riscv::record::EmulationRecord};

// TODO: Remove this
#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct FFIEmulationRecord {
    pub cpu_events: Vec<CpuEvent>,
}

impl Drop for FFIEmulationRecord {
    fn drop(&mut self) {
        unimplemented!()
    }
}

impl From<&EmulationRecord> for FFIEmulationRecord {
    fn from(_record: &EmulationRecord) -> Self {
        unimplemented!()
    }
}
