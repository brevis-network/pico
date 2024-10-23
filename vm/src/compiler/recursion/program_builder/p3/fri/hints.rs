use super::types::{
    BatchOpeningVariable, DigestVariable, FriCommitPhaseProofStepVariable, FriProofVariable,
    FriQueryProofVariable, PcsProofVariable,
};
use crate::{
    compiler::recursion::{
        ir::{Array, Builder},
        program_builder::hints::hintable::Hintable,
    },
    configs::config::FieldGenericConfig,
    instances::configs::recur_config as rcf,
    primitives::consts::DIGEST_SIZE,
    recursion::air::Block,
};
use p3_field::{AbstractExtensionField, AbstractField};

impl Hintable<rcf::FieldConfig> for rcf::Digest {
    type HintVariable = DigestVariable<rcf::FieldConfig>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        builder.hint_felts()
    }

    fn write(&self) -> Vec<Vec<Block<rcf::Val>>> {
        let h: [rcf::Val; DIGEST_SIZE] = *self;
        vec![h.iter().map(|x| Block::from(*x)).collect()]
    }
}

impl Hintable<rcf::FieldConfig> for Vec<rcf::Digest> {
    type HintVariable = Array<rcf::FieldConfig, DigestVariable<rcf::FieldConfig>>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = rcf::Digest::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<rcf::Val>>> {
        let mut stream = Vec::new();

        let len = rcf::Val::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = rcf::Digest::write(arr);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<rcf::FieldConfig> for rcf::CommitPhaseStep {
    type HintVariable = FriCommitPhaseProofStepVariable<rcf::FieldConfig>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let sibling_value = builder.hint_ext();
        let opening_proof = Vec::<rcf::Digest>::read(builder);
        Self::HintVariable {
            sibling_value,
            opening_proof,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();

        let sibling_value: &[rcf::Val] = self.sibling_value.as_base_slice();
        let sibling_value = Block::from(sibling_value);
        stream.push(vec![sibling_value]);

        stream.extend(Vec::<rcf::Digest>::write(&self.opening_proof));

        stream
    }
}

impl Hintable<rcf::FieldConfig> for Vec<rcf::CommitPhaseStep> {
    type HintVariable = Array<rcf::FieldConfig, FriCommitPhaseProofStepVariable<rcf::FieldConfig>>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = rcf::CommitPhaseStep::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();

        let len = rcf::Val::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = rcf::CommitPhaseStep::write(arr);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<rcf::FieldConfig> for rcf::QueryProof {
    type HintVariable = FriQueryProofVariable<rcf::FieldConfig>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let commit_phase_openings = Vec::<rcf::CommitPhaseStep>::read(builder);
        Self::HintVariable {
            commit_phase_openings,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();

        stream.extend(Vec::<rcf::CommitPhaseStep>::write(
            &self.commit_phase_openings,
        ));

        stream
    }
}

impl Hintable<rcf::FieldConfig> for Vec<rcf::QueryProof> {
    type HintVariable = Array<rcf::FieldConfig, FriQueryProofVariable<rcf::FieldConfig>>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = rcf::QueryProof::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();

        let len = rcf::Val::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = rcf::QueryProof::write(arr);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<rcf::FieldConfig> for rcf::FriProof {
    type HintVariable = FriProofVariable<rcf::FieldConfig>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let commit_phase_commits = Vec::<rcf::Digest>::read(builder);
        let query_proofs = Vec::<rcf::QueryProof>::read(builder);
        let final_poly = builder.hint_ext();
        let pow_witness = builder.hint_felt();
        Self::HintVariable {
            commit_phase_commits,
            query_proofs,
            final_poly,
            pow_witness,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();

        stream.extend(Vec::<rcf::Digest>::write(
            &self
                .commit_phase_commits
                .iter()
                .map(|x| (*x).into())
                .collect(),
        ));
        stream.extend(Vec::<rcf::QueryProof>::write(&self.query_proofs));
        let final_poly: &[rcf::Val] = self.final_poly.as_base_slice();
        let final_poly = Block::from(final_poly);
        stream.push(vec![final_poly]);
        let pow_witness = Block::from(self.pow_witness);
        stream.push(vec![pow_witness]);

        stream
    }
}

impl Hintable<rcf::FieldConfig> for rcf::BatchOpening {
    type HintVariable = BatchOpeningVariable<rcf::FieldConfig>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let opened_values = Vec::<Vec<rcf::Challenge>>::read(builder);
        let opening_proof = Vec::<rcf::Digest>::read(builder);
        Self::HintVariable {
            opened_values,
            opening_proof,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();
        stream.extend(Vec::<Vec<rcf::Challenge>>::write(
            &self
                .opened_values
                .iter()
                .map(|v| v.iter().map(|x| rcf::Challenge::from_base(*x)).collect())
                .collect(),
        ));
        stream.extend(Vec::<rcf::Digest>::write(&self.opening_proof));
        stream
    }
}

impl Hintable<rcf::FieldConfig> for Vec<rcf::BatchOpening> {
    type HintVariable = Array<rcf::FieldConfig, BatchOpeningVariable<rcf::FieldConfig>>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = rcf::BatchOpening::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();

        let len = rcf::Val::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = rcf::BatchOpening::write(arr);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<rcf::FieldConfig> for Vec<Vec<rcf::BatchOpening>> {
    type HintVariable =
        Array<rcf::FieldConfig, Array<rcf::FieldConfig, BatchOpeningVariable<rcf::FieldConfig>>>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = Vec::<rcf::BatchOpening>::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();

        let len = rcf::Val::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = Vec::<rcf::BatchOpening>::write(arr);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<rcf::FieldConfig> for rcf::PcsProof {
    type HintVariable = PcsProofVariable<rcf::FieldConfig>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let fri_proof = rcf::FriProof::read(builder);
        let query_openings = Vec::<Vec<rcf::BatchOpening>>::read(builder);
        Self::HintVariable {
            fri_proof,
            query_openings,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();
        stream.extend(self.fri_proof.write());
        stream.extend(self.query_openings.write());
        stream
    }
}
