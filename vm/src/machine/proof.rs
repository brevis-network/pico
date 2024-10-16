use crate::{
    configs::config::{Com, PcsProof, PcsProverData, StarkGenericConfig},
    machine::utils::type_name_of,
};
use alloc::vec::Vec;
use hashbrown::HashMap;
use p3_matrix::{
    dense::{RowMajorMatrix, RowMajorMatrixView},
    stack::VerticalPair,
};
use serde::{Deserialize, Serialize};

/// Wrapper for all proof types
/// The top layer of abstraction (the most abstract layer)
#[derive(Serialize)]
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

    pub fn proofs(&self) -> &[BaseProof<SC>] {
        self.proof.proofs()
    }
}

/// Each type of proof should impl ProofBehavior
/// Represents the middle layer of abstraction
pub trait ProofBehavior<SC: StarkGenericConfig> {
    fn name(&self) -> String;

    fn proofs(&self) -> &[BaseProof<SC>];
}

/// Proof wrapper for an element (single chunk)
#[derive(Serialize)]
pub struct UnitProof<SC: StarkGenericConfig> {
    pub proof: BaseProof<SC>,
}

impl<SC: StarkGenericConfig> ProofBehavior<SC> for UnitProof<SC> {
    fn name(&self) -> String {
        "UnitProof".to_string()
    }

    fn proofs(&self) -> &[BaseProof<SC>] {
        std::slice::from_ref(&self.proof)
    }
}

impl<SC: StarkGenericConfig> UnitProof<SC> {
    pub fn new(proof: BaseProof<SC>) -> Self {
        Self { proof }
    }
}

/// Proof wrapper for an ensemble (chunks)
#[derive(Serialize)]
pub struct EnsembleProof<SC: StarkGenericConfig> {
    pub proof: Vec<BaseProof<SC>>,
}

impl<SC: StarkGenericConfig> ProofBehavior<SC> for EnsembleProof<SC> {
    fn name(&self) -> String {
        format!("EnsembleProof of {} BaseProofs", self.proof.len())
    }

    fn proofs(&self) -> &[BaseProof<SC>] {
        &self.proof
    }
}

impl<SC: StarkGenericConfig> EnsembleProof<SC> {
    pub fn new(proof: Vec<BaseProof<SC>>) -> Self {
        Self { proof }
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
    pub main_chip_ordering: HashMap<String, usize>,
    pub public_values: Vec<SC::Val>,
}

impl<SC: StarkGenericConfig> BaseProof<SC> {
    pub fn cumulative_sum(&self) -> SC::Challenge {
        self.opened_values
            .chips_opened_values
            .iter()
            .map(|v| v.cumulative_sum)
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
    pub main_commit: Com,
    pub permutation_commit: Com,
    pub quotient_commit: Com,
}

pub struct MainTraceCommitments<SC: StarkGenericConfig> {
    pub main_traces: Vec<RowMajorMatrix<SC::Val>>,
    pub main_chip_ordering: HashMap<String, usize>,
    pub commitment: Com<SC>,
    pub data: PcsProverData<SC>,
    pub public_values: Vec<SC::Val>,
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
    pub log_main_degree: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotientData {
    pub log_quotient_degree: usize,
    pub quotient_size: usize,
}
