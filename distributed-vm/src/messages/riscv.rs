use crate::gateway::handler::proof_tree::IndexedProof;
use derive_more::Constructor;
use pico_vm::{
    configs::config::StarkGenericConfig, emulator::riscv::record::EmulationRecord,
    machine::proof::MetaProof,
};

// TODO: rename
#[allow(clippy::large_enum_variant)]
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
    pub proof: IndexedProof<MetaProof<SC>>,
}
