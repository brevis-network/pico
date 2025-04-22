use crate::{
    configs::config::StarkGenericConfig, emulator::riscv::record::EmulationRecord,
    machine::proof::BaseProof,
};
use derive_more::Constructor;

#[derive(Clone)]
pub enum RiscvMsg<SC: StarkGenericConfig> {
    Request(RiscvRequest),
    Response(RiscvResponse<SC>),
}

#[derive(Clone, Constructor)]
pub struct RiscvRequest {
    // TODO: add identifier
    pub chunk_index: usize,
    pub record: EmulationRecord,
}

#[derive(Clone, Constructor)]
pub struct RiscvResponse<SC: StarkGenericConfig> {
    // TODO: add identifier
    pub chunk_index: usize,
    pub proof: BaseProof<SC>,
}
