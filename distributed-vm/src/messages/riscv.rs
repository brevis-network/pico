use crate::gateway::handler::proof_tree::IndexedProof;
use derive_more::Constructor;
use pico_vm::{
    configs::config::StarkGenericConfig, emulator::riscv::record::EmulationRecord,
    machine::proof::MetaProof,
};

// TODO: rename
#[derive(Clone)]
pub enum RiscvMsg<SC: StarkGenericConfig> {
    Request(RiscvRequest),
    Response(RiscvResponse<SC>),
    // ConvertResponse(ConvertResponse<SC>),
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

// #[derive(Constructor)]
// pub struct ConvertResponse<SC: StarkGenericConfig> {
//     // TODO: add identifier
//     pub chunk_index: usize,
//     pub proof: MetaProof<SC>,
// }
