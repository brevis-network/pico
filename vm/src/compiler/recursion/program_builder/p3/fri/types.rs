use super::TwoAdicMultiplicativeCosetVariable;
use crate::{
    compiler::{recursion::prelude::*, word::Word},
    configs::config::RecursionGenericConfig,
    primitives::consts::{PV_DIGEST_NUM_WORDS, WORD_SIZE},
};
pub type DigestVariable<RC> = Array<RC, Felt<<RC as RecursionGenericConfig>::F>>;

#[derive(DslVariable, Debug, Clone)]
pub struct Sha256DigestVariable<RC: RecursionGenericConfig> {
    pub bytes: Array<RC, Felt<RC::F>>,
}

impl<RC: RecursionGenericConfig> Sha256DigestVariable<RC> {
    pub fn from_words(builder: &mut Builder<RC>, words: &[Word<Felt<RC::F>>]) -> Self {
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
pub struct FriConfigVariable<RC: RecursionGenericConfig> {
    pub log_blowup: Var<RC::N>,
    pub blowup: Var<RC::N>,
    pub num_queries: Var<RC::N>,
    pub proof_of_work_bits: Var<RC::N>,
    pub generators: Array<RC, Felt<RC::F>>,
    pub subgroups: Array<RC, TwoAdicMultiplicativeCosetVariable<RC>>,
}

impl<RC: RecursionGenericConfig> FriConfigVariable<RC> {
    pub fn get_subgroup(
        &self,
        builder: &mut Builder<RC>,
        log_degree: impl Into<Usize<RC::N>>,
    ) -> TwoAdicMultiplicativeCosetVariable<RC> {
        builder.get(&self.subgroups, log_degree)
    }

    pub fn get_two_adic_generator(
        &self,
        builder: &mut Builder<RC>,
        bits: impl Into<Usize<RC::N>>,
    ) -> Felt<RC::F> {
        builder.get(&self.generators, bits)
    }
}

#[derive(DslVariable, Clone)]
pub struct FriProofVariable<RC: RecursionGenericConfig> {
    pub commit_phase_commits: Array<RC, DigestVariable<RC>>,
    pub query_proofs: Array<RC, FriQueryProofVariable<RC>>,
    pub final_poly: Ext<RC::F, RC::EF>,
    pub pow_witness: Felt<RC::F>,
}

#[derive(DslVariable, Clone)]
pub struct FriQueryProofVariable<RC: RecursionGenericConfig> {
    pub commit_phase_openings: Array<RC, FriCommitPhaseProofStepVariable<RC>>,
}

#[derive(DslVariable, Clone)]
pub struct FriCommitPhaseProofStepVariable<RC: RecursionGenericConfig> {
    pub sibling_value: Ext<RC::F, RC::EF>,
    pub opening_proof: Array<RC, DigestVariable<RC>>,
}

#[derive(DslVariable, Clone)]
pub struct FriChallengesVariable<RC: RecursionGenericConfig> {
    pub query_indices: Array<RC, Array<RC, Var<RC::N>>>,
    pub betas: Array<RC, Ext<RC::F, RC::EF>>,
}

#[derive(DslVariable, Clone)]
pub struct DimensionsVariable<RC: RecursionGenericConfig> {
    pub height: Var<RC::N>,
}

#[derive(DslVariable, Clone)]
pub struct PcsProofVariable<RC: RecursionGenericConfig> {
    pub fri_proof: FriProofVariable<RC>,
    pub query_openings: Array<RC, Array<RC, BatchOpeningVariable<RC>>>,
}

#[derive(DslVariable, Clone)]
pub struct BatchOpeningVariable<RC: RecursionGenericConfig> {
    pub opened_values: Array<RC, Array<RC, Ext<RC::F, RC::EF>>>,
    pub opening_proof: Array<RC, Array<RC, Felt<RC::F>>>,
}

#[derive(DslVariable, Clone)]
pub struct TwoAdicPcsRoundVariable<RC: RecursionGenericConfig> {
    pub batch_commit: DigestVariable<RC>,
    pub mats: Array<RC, TwoAdicPcsMatsVariable<RC>>,
}

#[allow(clippy::type_complexity)]
#[derive(DslVariable, Clone)]
pub struct TwoAdicPcsMatsVariable<RC: RecursionGenericConfig> {
    pub domain: TwoAdicMultiplicativeCosetVariable<RC>,
    pub points: Array<RC, Ext<RC::F, RC::EF>>,
    pub values: Array<RC, Array<RC, Ext<RC::F, RC::EF>>>,
}
