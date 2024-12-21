use crate::{
    configs::config::{Com, PcsProof, PcsProverData, StarkGenericConfig},
    machine::keys::BaseVerifyingKey,
};
use alloc::{sync::Arc, vec::Vec};
use hashbrown::HashMap;
use p3_matrix::dense::RowMajorMatrix;
use serde::{Deserialize, Serialize};

/// Wrapper for all proof types
/// The top layer of abstraction (the most abstract layer)
pub struct MetaProof<SC>
where
    SC: StarkGenericConfig,
{
    /// The proof that impls ProofBehavior
    pub proofs: Arc<[BaseProof<SC>]>,

    pub vks: Arc<[BaseVerifyingKey<SC>]>,
}

impl<SC> MetaProof<SC>
where
    SC: StarkGenericConfig,
{
    /// Create a new MetaProof
    pub fn new(proofs: Arc<[BaseProof<SC>]>, vks: Arc<[BaseVerifyingKey<SC>]>) -> Self {
        Self { proofs, vks }
    }

    /// Get the number of the proof and config
    pub fn name(&self) -> String {
        format!("MetaProof of {} BaseProofs", self.proofs.len())
    }

    /// Get the proofs
    pub fn proofs(&self) -> Arc<[BaseProof<SC>]> {
        self.proofs.clone()
    }

    /// Get the vks
    pub fn vks(&self) -> &[BaseVerifyingKey<SC>] {
        self.vks.as_ref()
    }

    /// Get the number of proofs
    pub fn num_proofs(&self) -> usize {
        self.proofs.len()
    }
}

/// Base proof produced by base prover
/// Represents the bottom layer of abstraction (the most concrete layer)
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct BaseProof<SC: StarkGenericConfig> {
    pub commitments: BaseCommitments<Com<SC>>,
    pub opened_values: BaseOpenedValues<SC::Challenge>,
    pub opening_proof: PcsProof<SC>,
    pub log_main_degrees: Arc<[usize]>,
    pub log_quotient_degrees: Arc<[usize]>,
    pub main_chip_ordering: Arc<HashMap<String, usize>>,
    pub public_values: Arc<[SC::Val]>,
}

impl<SC: StarkGenericConfig> BaseProof<SC> {
    pub fn regional_cumulative_sum(&self) -> SC::Challenge {
        self.opened_values
            .chips_opened_values
            .iter()
            .map(|v| v.regional_cumulative_sum)
            .sum()
    }

    pub fn global_cumulative_sum(&self) -> SC::Challenge {
        self.opened_values
            .chips_opened_values
            .iter()
            .map(|v| v.global_cumulative_sum)
            .sum()
    }

    // judge weather the proof contains the chip by name
    pub fn includes_chip(&self, chip_name: &str) -> bool {
        self.main_chip_ordering.contains_key(chip_name)
    }

    // get log degree of cpu chip
    pub fn log_main_degree(&self) -> usize {
        let idx = self
            .main_chip_ordering
            .get("Cpu")
            .expect("Cpu chip not found");
        self.opened_values.chips_opened_values[*idx].log_main_degree
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BaseCommitments<Com> {
    pub global_main_commit: Com,
    pub regional_main_commit: Com,
    pub permutation_commit: Com,
    pub quotient_commit: Com,
}

pub struct MainTraceCommitments<SC: StarkGenericConfig> {
    pub main_traces: Arc<[RowMajorMatrix<SC::Val>]>,
    pub main_chip_ordering: Arc<HashMap<String, usize>>,
    pub commitment: Com<SC>,
    pub data: PcsProverData<SC>,
    pub public_values: Arc<[SC::Val]>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BaseOpenedValues<Challenge> {
    pub chips_opened_values: Arc<[Arc<ChipOpenedValues<Challenge>>]>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChipOpenedValues<Challenge> {
    pub preprocessed_local: Vec<Challenge>,
    pub preprocessed_next: Vec<Challenge>,
    pub main_local: Vec<Challenge>,
    pub main_next: Vec<Challenge>,
    pub permutation_local: Vec<Challenge>,
    pub permutation_next: Vec<Challenge>,
    pub quotient: Vec<Vec<Challenge>>,
    pub global_cumulative_sum: Challenge,
    pub regional_cumulative_sum: Challenge,
    pub log_main_degree: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotientData {
    pub log_quotient_degree: usize,
    pub quotient_size: usize,
}
