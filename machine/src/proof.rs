use serde::{Deserialize, Serialize};

use pico_configs::config::{StarkGenericConfig, Com, PcsProof};


#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct ChunkProof<SC: StarkGenericConfig> {
    pub main_commit: ChunkCommitments<Com<SC>>,
    pub opened_values: ChunkOpenedValues<SC::Challenge>,
    pub opening_proof: PcsProof<SC>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChunkCommitments<Com> {
    pub trace: Com,
    pub quotient_chunks: Com,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChunkOpenedValues<Challenge> {
    pub chip_opened_values: Vec<ChipOpenedValues<Challenge>>,
}

pub struct ChipOpenedValues<Challenge> {
    pub main_local: Vec<Challenge>,
    pub main_next: Vec<Challenge>,
    pub quotient: Vec<Vec<Challenge>>,
}

