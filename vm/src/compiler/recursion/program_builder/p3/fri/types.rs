use super::TwoAdicMultiplicativeCosetVariable;
use crate::{
    compiler::{recursion::prelude::*, word::Word},
    configs::config::FieldGenericConfig,
    primitives::consts::{PV_DIGEST_NUM_WORDS, WORD_SIZE},
};
pub type DigestVariable<FC> = Array<FC, Felt<<FC as FieldGenericConfig>::F>>;

#[derive(DslVariable, Debug, Clone)]
pub struct Sha256DigestVariable<FC: FieldGenericConfig> {
    pub bytes: Array<FC, Felt<FC::F>>,
}

impl<FC: FieldGenericConfig> Sha256DigestVariable<FC> {
    pub fn from_words(builder: &mut Builder<FC>, words: &[Word<Felt<FC::F>>]) -> Self {
        let mut bytes = builder.array(PV_DIGEST_NUM_WORDS * WORD_SIZE);
        for (i, word) in words.iter().enumerate() {
            for j in 0..WORD_SIZE {
                let byte = word[j];
                builder.set(&mut bytes, i * WORD_SIZE + j, byte);
            }
        }
        Sha256DigestVariable { bytes }
    }
}

#[derive(DslVariable, Clone)]
pub struct FriConfigVariable<FC: FieldGenericConfig> {
    pub log_blowup: Var<FC::N>,
    pub blowup: Var<FC::N>,
    pub num_queries: Var<FC::N>,
    pub proof_of_work_bits: Var<FC::N>,
    pub generators: Array<FC, Felt<FC::F>>,
    pub subgroups: Array<FC, TwoAdicMultiplicativeCosetVariable<FC>>,
}

impl<FC: FieldGenericConfig> FriConfigVariable<FC> {
    pub fn get_subgroup(
        &self,
        builder: &mut Builder<FC>,
        log_degree: impl Into<Usize<FC::N>>,
    ) -> TwoAdicMultiplicativeCosetVariable<FC> {
        builder.get(&self.subgroups, log_degree)
    }

    pub fn get_two_adic_generator(
        &self,
        builder: &mut Builder<FC>,
        bits: impl Into<Usize<FC::N>>,
    ) -> Felt<FC::F> {
        builder.get(&self.generators, bits)
    }
}

#[derive(DslVariable, Clone)]
pub struct FriProofVariable<FC: FieldGenericConfig> {
    pub commit_phase_commits: Array<FC, DigestVariable<FC>>,
    pub query_proofs: Array<FC, FriQueryProofVariable<FC>>,
    pub final_poly: Ext<FC::F, FC::EF>,
    pub pow_witness: Felt<FC::F>,
}

#[derive(DslVariable, Clone)]
pub struct FriQueryProofVariable<FC: FieldGenericConfig> {
    pub commit_phase_openings: Array<FC, FriCommitPhaseProofStepVariable<FC>>,
}

#[derive(DslVariable, Clone)]
pub struct FriCommitPhaseProofStepVariable<FC: FieldGenericConfig> {
    pub sibling_value: Ext<FC::F, FC::EF>,
    pub opening_proof: Array<FC, DigestVariable<FC>>,
}

#[derive(DslVariable, Clone)]
pub struct FriChallengesVariable<FC: FieldGenericConfig> {
    pub query_indices: Array<FC, Array<FC, Var<FC::N>>>,
    pub betas: Array<FC, Ext<FC::F, FC::EF>>,
}

#[derive(DslVariable, Clone)]
pub struct DimensionsVariable<FC: FieldGenericConfig> {
    pub height: Var<FC::N>,
}

#[derive(DslVariable, Clone)]
pub struct PcsProofVariable<FC: FieldGenericConfig> {
    pub fri_proof: FriProofVariable<FC>,
    pub query_openings: Array<FC, Array<FC, BatchOpeningVariable<FC>>>,
}

#[derive(DslVariable, Clone)]
pub struct BatchOpeningVariable<FC: FieldGenericConfig> {
    pub opened_values: Array<FC, Array<FC, Ext<FC::F, FC::EF>>>,
    pub opening_proof: Array<FC, Array<FC, Felt<FC::F>>>,
}

#[derive(DslVariable, Clone)]
pub struct TwoAdicPcsRoundVariable<FC: FieldGenericConfig> {
    pub batch_commit: DigestVariable<FC>,
    pub mats: Array<FC, TwoAdicPcsMatsVariable<FC>>,
}

#[allow(clippy::type_complexity)]
#[derive(DslVariable, Clone)]
pub struct TwoAdicPcsMatsVariable<FC: FieldGenericConfig> {
    pub domain: TwoAdicMultiplicativeCosetVariable<FC>,
    pub points: Array<FC, Ext<FC::F, FC::EF>>,
    pub values: Array<FC, Array<FC, Ext<FC::F, FC::EF>>>,
}
