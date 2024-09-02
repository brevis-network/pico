use alloc::vec::Vec;
use p3_matrix::dense::RowMajorMatrix;
use pico_configs::config::{Com, PcsProof, PcsProverData, StarkGenericConfig, Val};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct ChunkProof<SC: StarkGenericConfig> {
    pub commitments: ChunkCommitments<Com<SC>>,
    pub opened_values: ChunkOpenedValues<SC::Challenge>,
    pub opening_proof: PcsProof<SC>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChunkCommitments<Com> {
    pub main: Com,
    pub quotient: Com,
}

pub struct TraceCommitments<SC: StarkGenericConfig> {
    pub traces: Vec<RowMajorMatrix<Val<SC>>>,
    pub commitment: Com<SC>,
    pub data: PcsProverData<SC>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChunkOpenedValues<Challenge> {
    pub chips_opened_values: Vec<ChipOpenedValues<Challenge>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChipOpenedValues<Challenge> {
    pub main_local: Vec<Challenge>,
    pub main_next: Vec<Challenge>,
    pub quotient: Vec<Vec<Challenge>>,
}
