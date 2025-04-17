use crate::{
    configs::config::StarkGenericConfig,
    emulator::riscv::record::EmulationRecord,
    machine::{keys::BaseProvingKey, proof::BaseProof},
};
use derive_more::Constructor;

pub enum RiscvMsg<SC: StarkGenericConfig> {
    Request(RiscvRequest<SC>),
    Response(RiscvResponse<SC>),
    Stop,
}

#[derive(Constructor)]
pub struct RiscvRequest<SC: StarkGenericConfig> {
    // TODO: add identifier
    pub chunk_index: usize,
    pub pk: BaseProvingKey<SC>,
    pub challenger: SC::Challenger,
    pub record: EmulationRecord,
}

#[derive(Constructor)]
pub struct RiscvResponse<SC: StarkGenericConfig> {
    // TODO: add identifier
    pub chunk_index: usize,
    pub proof: BaseProof<SC>,
}
