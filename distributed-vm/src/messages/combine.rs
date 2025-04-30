use crate::gateway::handler::proof_tree::IndexedProof;
use derive_more::Constructor;
use pico_vm::{configs::config::StarkGenericConfig, machine::proof::MetaProof};

#[derive(Clone)]
pub enum CombineMsg<SC: StarkGenericConfig> {
    Request(CombineRequest<SC>),
    Response(CombineResponse<SC>),
}

#[derive(Clone, Constructor)]
pub struct CombineRequest<SC: StarkGenericConfig> {
    pub flag_complete: bool,
    pub chunk_index: usize,
    pub proofs: Vec<IndexedProof<MetaProof<SC>>>,
}

#[derive(Clone, Constructor)]
pub struct CombineResponse<SC: StarkGenericConfig> {
    pub chunk_index: usize,
    pub proof: IndexedProof<MetaProof<SC>>,
}
