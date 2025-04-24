use crate::{configs::config::StarkGenericConfig, machine::proof::MetaProof};
use derive_more::Constructor;
use std::sync::Arc;

#[derive(Clone)]
pub enum CombineMsg<SC: StarkGenericConfig> {
    Request(CombineRequest<SC>),
    Response(CombineResponse<SC>),
}

#[derive(Clone, Constructor)]
pub struct CombineRequest<SC: StarkGenericConfig> {
    pub flag_complete: bool,
    pub chunk_index: usize,
    pub proofs: Vec<Arc<MetaProof<SC>>>,
}

#[derive(Clone, Constructor)]
pub struct CombineResponse<SC: StarkGenericConfig> {
    pub chunk_index: usize,
    pub proof: MetaProof<SC>,
}
