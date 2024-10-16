use super::TwoAdicMultiplicativeCosetVariable;
use crate::{
    compiler::{recursion::prelude::*, word::Word},
    primitives::consts::{PV_DIGEST_NUM_WORDS, WORD_SIZE},
};

pub type DigestVariable<CF> = Array<CF, Felt<<CF as Config>::F>>;

#[derive(DslVariable, Debug, Clone)]
pub struct Sha256DigestVariable<CF: Config> {
    pub bytes: Array<CF, Felt<CF::F>>,
}

impl<CF: Config> Sha256DigestVariable<CF> {
    pub fn from_words(builder: &mut Builder<CF>, words: &[Word<Felt<CF::F>>]) -> Self {
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
pub struct FriConfigVariable<CF: Config> {
    pub log_blowup: Var<CF::N>,
    pub blowup: Var<CF::N>,
    pub num_queries: Var<CF::N>,
    pub proof_of_work_bits: Var<CF::N>,
    pub generators: Array<CF, Felt<CF::F>>,
    pub subgroups: Array<CF, TwoAdicMultiplicativeCosetVariable<CF>>,
}

impl<CF: Config> FriConfigVariable<CF> {
    pub fn get_subgroup(
        &self,
        builder: &mut Builder<CF>,
        log_degree: impl Into<Usize<CF::N>>,
    ) -> TwoAdicMultiplicativeCosetVariable<CF> {
        builder.get(&self.subgroups, log_degree)
    }

    pub fn get_two_adic_generator(
        &self,
        builder: &mut Builder<CF>,
        bits: impl Into<Usize<CF::N>>,
    ) -> Felt<CF::F> {
        builder.get(&self.generators, bits)
    }
}

#[derive(DslVariable, Clone)]
pub struct FriProofVariable<CF: Config> {
    pub commit_phase_commits: Array<CF, DigestVariable<CF>>,
    pub query_proofs: Array<CF, FriQueryProofVariable<CF>>,
    pub final_poly: Ext<CF::F, CF::EF>,
    pub pow_witness: Felt<CF::F>,
}

#[derive(DslVariable, Clone)]
pub struct FriQueryProofVariable<CF: Config> {
    pub commit_phase_openings: Array<CF, FriCommitPhaseProofStepVariable<CF>>,
}

#[derive(DslVariable, Clone)]
pub struct FriCommitPhaseProofStepVariable<CF: Config> {
    pub sibling_value: Ext<CF::F, CF::EF>,
    pub opening_proof: Array<CF, DigestVariable<CF>>,
}

#[derive(DslVariable, Clone)]
pub struct FriChallengesVariable<CF: Config> {
    pub query_indices: Array<CF, Array<CF, Var<CF::N>>>,
    pub betas: Array<CF, Ext<CF::F, CF::EF>>,
}

#[derive(DslVariable, Clone)]
pub struct DimensionsVariable<CF: Config> {
    pub height: Var<CF::N>,
}

#[derive(DslVariable, Clone)]
pub struct PcsProofVariable<CF: Config> {
    pub fri_proof: FriProofVariable<CF>,
    pub query_openings: Array<CF, Array<CF, BatchOpeningVariable<CF>>>,
}

#[derive(DslVariable, Clone)]
pub struct BatchOpeningVariable<CF: Config> {
    pub opened_values: Array<CF, Array<CF, Ext<CF::F, CF::EF>>>,
    pub opening_proof: Array<CF, Array<CF, Felt<CF::F>>>,
}

#[derive(DslVariable, Clone)]
pub struct TwoAdicPcsRoundVariable<CF: Config> {
    pub batch_commit: DigestVariable<CF>,
    pub mats: Array<CF, TwoAdicPcsMatsVariable<CF>>,
}

#[allow(clippy::type_complexity)]
#[derive(DslVariable, Clone)]
pub struct TwoAdicPcsMatsVariable<CF: Config> {
    pub domain: TwoAdicMultiplicativeCosetVariable<CF>,
    pub points: Array<CF, Ext<CF::F, CF::EF>>,
    pub values: Array<CF, Array<CF, Ext<CF::F, CF::EF>>>,
}
