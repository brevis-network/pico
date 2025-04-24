use crate::{configs::config::StarkGenericConfig, machine::proof::MetaProof};
use derive_more::Constructor;

#[derive(Clone)]
pub enum CombineMsg<SC: StarkGenericConfig> {
    Request(CombineRequest),
    Response(CombineResponse<SC>),
}

#[derive(Clone, Constructor)]
pub struct CombineRequest {
    // TODO: add identifier
    pub chunk_index: usize,
}

#[derive(Clone, Constructor)]
pub struct CombineResponse<SC: StarkGenericConfig> {
    // TODO: add identifier
    pub chunk_index: usize,
    pub proof: MetaProof<SC>,
}
