use crate::{
    configs::config::{Com, PcsProof, PcsProverData, StarkGenericConfig},
    instances::compiler::shapes::ProofShape,
    machine::{keys::BaseVerifyingKey, septic::SepticDigest},
};
use alloc::{sync::Arc, vec::Vec};
use hashbrown::HashMap;
use itertools::Itertools;
use p3_matrix::dense::RowMajorMatrix;
use serde::{Deserialize, Serialize};

/// Wrapper for all proof types
/// The top layer of abstraction (the most abstract layer)

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MetaProof<SC>
where
    SC: StarkGenericConfig,
{
    /// The proof that impls ProofBehavior
    pub proofs: Arc<[BaseProof<SC>]>,

    pub vks: Arc<[BaseVerifyingKey<SC>]>,

    pub pv_stream: Option<Vec<u8>>,
}

impl<SC> MetaProof<SC>
where
    SC: StarkGenericConfig,
{
    /// Create a new MetaProof
    pub fn new(
        proofs: Arc<[BaseProof<SC>]>,
        vks: Arc<[BaseVerifyingKey<SC>]>,
        pv_stream: Option<Vec<u8>>,
    ) -> Self {
        Self {
            proofs,
            vks,
            pv_stream,
        }
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

    pub fn split_into_individuals(&self) -> Vec<Self> {
        assert_eq!(self.proofs.len(), self.vks.len());
        self.proofs
            .iter()
            .cloned()
            .zip(self.vks.iter().cloned())
            .map(|(proof, vk)| MetaProof {
                proofs: Arc::from([proof]),
                vks: Arc::from([vk]),
                pv_stream: self.pv_stream.clone(),
            })
            .collect()
    }
}

pub fn merge_meta_proofs<I, SC>(meta_list: I) -> Option<MetaProof<SC>>
where
    I: IntoIterator<Item = MetaProof<SC>>,
    SC: StarkGenericConfig,
{
    let metas: Vec<MetaProof<SC>> = meta_list.into_iter().collect();
    if metas.is_empty() {
        return None;
    }

    let (mut proofs_cap, mut vks_cap, mut pv_cap) = (0, 0, 0);
    for m in &metas {
        proofs_cap += m.proofs.len();
        vks_cap += m.vks.len();
        pv_cap += m.pv_stream.as_ref().map_or(0, |s| s.len());
    }

    let combined_proofs: Arc<[BaseProof<SC>]> = {
        let mut vec = Vec::with_capacity(proofs_cap);
        for m in &metas {
            vec.extend_from_slice(&m.proofs);
        }
        Arc::from(vec)
    };

    let combined_vks: Arc<[BaseVerifyingKey<SC>]> = {
        let mut vec = Vec::with_capacity(vks_cap);
        for m in &metas {
            vec.extend_from_slice(&m.vks);
        }
        Arc::from(vec)
    };

    let mut pv_stream_buf = Vec::with_capacity(pv_cap);
    for mut m in metas {
        if let Some(mut s) = m.pv_stream.take() {
            pv_stream_buf.append(&mut s);
        }
    }
    let combined_pv_stream = if pv_stream_buf.is_empty() {
        None
    } else {
        Some(pv_stream_buf)
    };

    Some(MetaProof {
        proofs: combined_proofs,
        vks: combined_vks,
        pv_stream: combined_pv_stream,
    })
}

/// Base proof produced by base prover
/// Represents the bottom layer of abstraction (the most concrete layer)
#[derive(Serialize, Deserialize, Clone)]
#[serde(bound = "")]
pub struct BaseProof<SC: StarkGenericConfig>
where
    Com<SC>: Send + Sync,
    SC::Val: Send + Sync,
    SC::Challenge: Send + Sync,
    PcsProof<SC>: Send + Sync,
{
    pub commitments: BaseCommitments<Com<SC>>,
    pub opened_values: BaseOpenedValues<SC::Val, SC::Challenge>,
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

    pub fn global_cumulative_sum(&self) -> SepticDigest<SC::Val> {
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
    pub main_commit: Com,
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
pub struct BaseOpenedValues<Val, Challenge> {
    pub chips_opened_values: Arc<[Arc<ChipOpenedValues<Val, Challenge>>]>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChipOpenedValues<Val, Challenge> {
    pub preprocessed_local: Vec<Challenge>,
    pub preprocessed_next: Vec<Challenge>,
    pub main_local: Vec<Challenge>,
    pub main_next: Vec<Challenge>,
    pub permutation_local: Vec<Challenge>,
    pub permutation_next: Vec<Challenge>,
    pub quotient: Vec<Vec<Challenge>>,
    pub global_cumulative_sum: SepticDigest<Val>,
    pub regional_cumulative_sum: Challenge,
    pub log_main_degree: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotientData {
    pub log_quotient_degree: usize,
    pub quotient_size: usize,
}

impl<SC: StarkGenericConfig> BaseProof<SC> {
    pub fn shape(&self) -> ProofShape {
        ProofShape {
            chip_information: self
                .main_chip_ordering
                .iter()
                .sorted_by_key(|(_, idx)| *idx)
                .zip(self.opened_values.chips_opened_values.iter())
                .map(|((name, _), values)| (name.to_owned(), values.log_main_degree))
                .collect(),
        }
    }
}
