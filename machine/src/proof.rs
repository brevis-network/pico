use serde::{Deserialize, Serialize};
use alloc::vec::Vec;

use pico_configs::config::{StarkGenericConfig, Com, PcsProof};


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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChunkOpenedValues<Challenge> {
    pub chip_opened_values: Vec<ChipOpenedValues<Challenge>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChipOpenedValues<Challenge> {
    pub main_local: Vec<Challenge>,
    pub main_next: Vec<Challenge>,
    pub quotient: Vec<Vec<Challenge>>,
}

