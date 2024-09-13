use crate::utils::type_name_of;
use alloc::vec::Vec;
use hashbrown::HashMap;
use p3_matrix::dense::RowMajorMatrix;
use pico_configs::config::{Com, PcsProof, PcsProverData, StarkGenericConfig, Val};
use serde::{Deserialize, Serialize};

/// Wrapper for all proof types
/// The top layer of abstraction (the most abstract layer)
pub struct MetaProof<'a, SC, P>
where
    SC: StarkGenericConfig,
{
    /// The configuration of the proof
    pub config: &'a SC,

    /// The proof that impls ProofBehavior
    pub proof: P,
}

impl<'a, SC, P> MetaProof<'a, SC, P>
where
    SC: StarkGenericConfig,
    P: ProofBehavior<SC>,
{
    /// Create a new MetaProof
    pub fn new(config: &'a SC, proof: P) -> Self {
        Self { config, proof }
    }

    /// Get the name of the proof and config
    pub fn name(&self) -> String {
        format!("{} with config {}", self.proof.name(), self.config.name(),)
    }
}

/// Each type of proof should impl ProofBehavior
/// Represents the middle layer of abstraction
pub trait ProofBehavior<SC: StarkGenericConfig> {
    fn name(&self) -> String;
}

/// Proof wrapper for an element (single chunk)
pub struct ElementProof<SC: StarkGenericConfig> {
    pub proof: BaseProof<SC>,
}

impl<SC: StarkGenericConfig> ProofBehavior<SC> for ElementProof<SC> {
    fn name(&self) -> String {
        "ElementProof".to_string()
    }
}

impl<SC: StarkGenericConfig> ElementProof<SC> {
    pub fn new(proof: BaseProof<SC>) -> Self {
        Self { proof }
    }
}

/// Proof wrapper for an ensemble (chunks)
pub struct EnsembleProof<SC: StarkGenericConfig> {
    pub proof: Vec<BaseProof<SC>>,
}

impl<SC: StarkGenericConfig> ProofBehavior<SC> for EnsembleProof<SC> {
    fn name(&self) -> String {
        format!("EnsembleProof of {} BaseProofs", self.proof.len())
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
    pub log_main_degrees: Vec<usize>,
    pub log_quotient_degrees: Vec<usize>,
    pub chip_indexes: HashMap<String, usize>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BaseCommitments<Com> {
    pub main_commit: Com,
    pub permutation_commit: Com,
    pub quotient_commit: Com,
}

pub struct TraceCommitments<SC: StarkGenericConfig> {
    pub traces: Vec<RowMajorMatrix<Val<SC>>>,
    pub commitment: Com<SC>,
    pub data: PcsProverData<SC>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BaseOpenedValues<Challenge> {
    pub chips_opened_values: Vec<ChipOpenedValues<Challenge>>,
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
    pub cumulative_sum: Challenge,
}
