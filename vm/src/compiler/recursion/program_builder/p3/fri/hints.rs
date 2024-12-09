use super::types::{
    BatchOpeningVariable, DigestVariable, FriCommitPhaseProofStepVariable, FriProofVariable,
    QueryProofVariable,
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
use p3_field::{FieldAlgebra, FieldExtensionAlgebra};

impl Hintable<rcf::FieldConfig> for rcf::SC_Digest {
    type HintVariable = DigestVariable<rcf::FieldConfig>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        builder.hint_felts()
    }

    fn write(&self) -> Vec<Vec<Block<rcf::SC_Val>>> {
        let h: [rcf::SC_Val; DIGEST_SIZE] = *self;
        vec![h.iter().map(|x| Block::from(*x)).collect()]
    }
}

impl Hintable<rcf::FieldConfig> for Vec<rcf::SC_Digest> {
    type HintVariable = Array<rcf::FieldConfig, DigestVariable<rcf::FieldConfig>>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = rcf::SC_Digest::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<rcf::SC_Val>>> {
        let mut stream = Vec::new();

        let len = rcf::SC_Val::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = rcf::SC_Digest::write(arr);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<rcf::FieldConfig> for rcf::SC_CommitPhaseStep {
    type HintVariable = FriCommitPhaseProofStepVariable<rcf::FieldConfig>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let sibling_value = builder.hint_ext();
        let opening_proof = Vec::<rcf::SC_Digest>::read(builder);
        Self::HintVariable {
            sibling_value,
            opening_proof,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();

        let sibling_value: &[rcf::SC_Val] = self.sibling_value.as_base_slice();
        let sibling_value = Block::from(sibling_value);
        stream.push(vec![sibling_value]);

        stream.extend(Vec::<rcf::SC_Digest>::write(&self.opening_proof));

        stream
    }
}

impl Hintable<rcf::FieldConfig> for Vec<rcf::SC_CommitPhaseStep> {
    type HintVariable = Array<rcf::FieldConfig, FriCommitPhaseProofStepVariable<rcf::FieldConfig>>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = rcf::SC_CommitPhaseStep::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();

        let len = rcf::SC_Val::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = rcf::SC_CommitPhaseStep::write(arr);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<rcf::FieldConfig> for rcf::SC_QueryProof {
    type HintVariable = QueryProofVariable<rcf::FieldConfig>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let input_proof = Vec::<rcf::SC_BatchOpening>::read(builder);
        let commit_phase_openings = Vec::<rcf::SC_CommitPhaseStep>::read(builder);
        Self::HintVariable {
            input_proof,
            commit_phase_openings,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();

        stream.extend(Vec::<rcf::SC_BatchOpening>::write(&self.input_proof));

        stream.extend(Vec::<rcf::SC_CommitPhaseStep>::write(
            &self.commit_phase_openings,
        ));

        stream
    }
}

impl Hintable<rcf::FieldConfig> for Vec<rcf::SC_QueryProof> {
    type HintVariable = Array<rcf::FieldConfig, QueryProofVariable<rcf::FieldConfig>>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = rcf::SC_QueryProof::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();

        let len = rcf::SC_Val::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = rcf::SC_QueryProof::write(arr);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<rcf::FieldConfig> for rcf::SC_PcsProof {
    type HintVariable = FriProofVariable<rcf::FieldConfig>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let commit_phase_commits = Vec::<rcf::SC_Digest>::read(builder);
        let query_proofs = Vec::<rcf::SC_QueryProof>::read(builder);
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

        stream.extend(Vec::<rcf::SC_Digest>::write(
            &self
                .commit_phase_commits
                .iter()
                .map(|x| (*x).into())
                .collect(),
        ));
        stream.extend(Vec::<rcf::SC_QueryProof>::write(&self.query_proofs));
        let final_poly: &[rcf::SC_Val] = self.final_poly.as_base_slice();
        let final_poly = Block::from(final_poly);
        stream.push(vec![final_poly]);
        let pow_witness = Block::from(self.pow_witness);
        stream.push(vec![pow_witness]);

        stream
    }
}

impl Hintable<rcf::FieldConfig> for rcf::SC_BatchOpening {
    type HintVariable = BatchOpeningVariable<rcf::FieldConfig>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let opened_values = Vec::<Vec<rcf::SC_Challenge>>::read(builder);
        let opening_proof = Vec::<rcf::SC_Digest>::read(builder);
        Self::HintVariable {
            opened_values,
            opening_proof,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();
        stream.extend(Vec::<Vec<rcf::SC_Challenge>>::write(
            &self
                .opened_values
                .iter()
                .map(|v| v.iter().map(|x| rcf::SC_Challenge::from_base(*x)).collect())
                .collect(),
        ));
        stream.extend(Vec::<rcf::SC_Digest>::write(&self.opening_proof));
        stream
    }
}

impl Hintable<rcf::FieldConfig> for Vec<rcf::SC_BatchOpening> {
    type HintVariable = Array<rcf::FieldConfig, BatchOpeningVariable<rcf::FieldConfig>>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = rcf::SC_BatchOpening::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();

        let len = rcf::SC_Val::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = rcf::SC_BatchOpening::write(arr);
            stream.extend(comm);
        });

        stream
    }
}

// impl Hintable<rcf::FieldConfig> for Vec<Vec<rcf::SC_BatchOpening>> {
//     type HintVariable =
//         Array<rcf::FieldConfig, Array<rcf::FieldConfig, BatchOpeningVariable<rcf::FieldConfig>>>;
//
//     fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
//         let len = builder.hint_var();
//         let mut arr = builder.dyn_array(len);
//         builder.range(0, len).for_each(|i, builder| {
//             let hint = Vec::<rcf::SC_BatchOpening>::read(builder);
//             builder.set(&mut arr, i, hint);
//         });
//         arr
//     }
//
//     fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
//         let mut stream = Vec::new();
//
//         let len = rcf::SC_Val::from_canonical_usize(self.len());
//         stream.push(vec![len.into()]);
//
//         self.iter().for_each(|arr| {
//             let comm = Vec::<rcf::SC_BatchOpening>::write(arr);
//             stream.extend(comm);
//         });
//
//         stream
//     }
// }
