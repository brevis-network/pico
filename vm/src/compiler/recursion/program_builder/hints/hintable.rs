use super::{keys::VerifyingKeyHint, proof::BaseProofHint};
use crate::{
    compiler::{
        recursion::{
            ir::{Array, Builder, Ext, Felt, MemVariable, Var, Variable},
            program_builder::{
                keys::BaseVerifyingKeyVariable,
                p3::{
                    challenger::DuplexChallengerVariable,
                    fri::{types::Sha256DigestVariable, TwoAdicMultiplicativeCosetVariable},
                },
                proof::{
                    BaseCommitmentsVariable, BaseOpenedValuesVariable, BaseProofVariable,
                    ChipOpenedValuesVariable, QuotientDataVariable,
                },
                utils::{get_chip_quotient_data, get_preprocessed_data, get_sorted_indices},
            },
        },
        word::Word,
    },
    configs::config::{Com, FieldGenericConfig},
    instances::configs::{recur_config as rcf, riscv_config::StarkConfig as RiscvSC},
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        proof::{BaseCommitments, BaseOpenedValues, ChipOpenedValues, QuotientData},
    },
    primitives::consts::{PERMUTATION_RATE, PV_DIGEST_NUM_WORDS},
    recursion::air::Block,
};
use alloc::sync::Arc;
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{FieldAlgebra, FieldExtensionAlgebra, TwoAdicField};

// TODO: Walkthrough
pub trait Hintable<FC: FieldGenericConfig> {
    type HintVariable: Variable<FC>;

    fn read(builder: &mut Builder<FC>) -> Self::HintVariable;

    fn write(&self) -> Vec<Vec<Block<FC::F>>>;

    fn witness(variable: &Self::HintVariable, builder: &mut Builder<FC>) {
        let target = Self::read(builder);
        builder.assign(variable.clone(), target);
    }
}

impl Hintable<rcf::FieldConfig> for usize {
    type HintVariable = Var<rcf::SC_Val>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        builder.hint_var()
    }

    fn write(&self) -> Vec<Vec<Block<rcf::SC_Val>>> {
        vec![vec![Block::from(rcf::SC_Val::from_canonical_usize(*self))]]
    }
}

impl Hintable<rcf::FieldConfig> for rcf::SC_Val {
    type HintVariable = Felt<rcf::SC_Val>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        builder.hint_felt()
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        vec![vec![Block::from(*self)]]
    }
}

impl Hintable<rcf::FieldConfig> for rcf::SC_Challenge {
    type HintVariable = Ext<rcf::SC_Val, rcf::SC_Challenge>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        builder.hint_ext()
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        vec![vec![Block::from((*self).as_base_slice())]]
    }
}

impl Hintable<rcf::FieldConfig> for [Word<BabyBear>; PV_DIGEST_NUM_WORDS] {
    type HintVariable = Sha256DigestVariable<rcf::FieldConfig>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let bytes = builder.hint_felts();
        Sha256DigestVariable { bytes }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        vec![self
            .iter()
            .flat_map(|w| w.0.iter().map(|f| Block::from(*f)))
            .collect::<Vec<_>>()]
    }
}

impl Hintable<rcf::FieldConfig> for QuotientData {
    type HintVariable = QuotientDataVariable<rcf::FieldConfig>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let log_quotient_degree = usize::read(builder);
        let quotient_size = usize::read(builder);

        QuotientDataVariable {
            log_quotient_degree,
            quotient_size,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut buffer = Vec::new();
        buffer.extend(usize::write(&self.log_quotient_degree));
        buffer.extend(usize::write(&self.quotient_size));

        buffer
    }
}

impl Hintable<rcf::FieldConfig> for TwoAdicMultiplicativeCoset<rcf::SC_Val> {
    type HintVariable = TwoAdicMultiplicativeCosetVariable<rcf::FieldConfig>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let log_n = usize::read(builder);
        let shift = rcf::SC_Val::read(builder);
        let g_val = rcf::SC_Val::read(builder);
        let size = usize::read(builder);

        // Initialize a domain.
        TwoAdicMultiplicativeCosetVariable::<rcf::FieldConfig> {
            log_n,
            size,
            shift,
            g: g_val,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut vec = Vec::new();
        vec.extend(usize::write(&self.log_n));
        vec.extend(rcf::SC_Val::write(&self.shift));
        vec.extend(rcf::SC_Val::write(&rcf::SC_Val::two_adic_generator(
            self.log_n,
        )));
        vec.extend(usize::write(&(1usize << (self.log_n))));
        vec
    }
}

trait VecAutoHintable<FC: FieldGenericConfig>: Hintable<rcf::FieldConfig> {}

impl<'a, A> VecAutoHintable<rcf::FieldConfig> for BaseProofHint<'a, RiscvSC, A> where
    A: ChipBehavior<BabyBear>
        + for<'b> Air<ProverConstraintFolder<'b, RiscvSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RiscvSC>>
{
}
impl VecAutoHintable<rcf::FieldConfig> for TwoAdicMultiplicativeCoset<rcf::SC_Val> {}
impl VecAutoHintable<rcf::FieldConfig> for Vec<usize> {}
impl VecAutoHintable<rcf::FieldConfig> for QuotientData {}
impl VecAutoHintable<rcf::FieldConfig> for Vec<QuotientData> {}
impl VecAutoHintable<rcf::FieldConfig> for Vec<rcf::SC_Val> {}

impl<I: VecAutoHintable<rcf::FieldConfig>> VecAutoHintable<rcf::FieldConfig> for &I {}

impl<H: Hintable<rcf::FieldConfig>> Hintable<rcf::FieldConfig> for &H {
    type HintVariable = H::HintVariable;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        H::read(builder)
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        H::write(self)
    }
}

impl<I: VecAutoHintable<rcf::FieldConfig>> Hintable<rcf::FieldConfig> for Vec<I>
where
    <I as Hintable<rcf::FieldConfig>>::HintVariable: MemVariable<rcf::FieldConfig>,
{
    type HintVariable = Array<rcf::FieldConfig, I::HintVariable>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = I::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();

        let len = rcf::SC_Val::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|i| {
            let comm = I::write(i);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<rcf::FieldConfig> for Vec<usize> {
    type HintVariable = Array<rcf::FieldConfig, Var<rcf::SC_Val>>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        builder.hint_vars()
    }

    fn write(&self) -> Vec<Vec<Block<rcf::SC_Val>>> {
        vec![self
            .iter()
            .map(|x| Block::from(rcf::SC_Val::from_canonical_usize(*x)))
            .collect()]
    }
}

impl Hintable<rcf::FieldConfig> for &[rcf::SC_Val] {
    type HintVariable = Array<rcf::FieldConfig, Felt<rcf::SC_Val>>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        builder.hint_felts()
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        vec![self.iter().map(|x| Block::from(*x)).collect()]
    }
}

impl Hintable<rcf::FieldConfig> for Vec<rcf::SC_Val> {
    type HintVariable = Array<rcf::FieldConfig, Felt<rcf::SC_Val>>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        builder.hint_felts()
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        self.as_slice().write()
    }
}

impl Hintable<rcf::FieldConfig> for Vec<rcf::SC_Challenge> {
    type HintVariable = Array<rcf::FieldConfig, Ext<rcf::SC_Val, rcf::SC_Challenge>>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        builder.hint_exts()
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        vec![self
            .iter()
            .map(|x| Block::from((*x).as_base_slice()))
            .collect()]
    }
}

impl Hintable<rcf::FieldConfig> for Vec<Vec<rcf::SC_Challenge>> {
    type HintVariable =
        Array<rcf::FieldConfig, Array<rcf::FieldConfig, Ext<rcf::SC_Val, rcf::SC_Challenge>>>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = Vec::<rcf::SC_Challenge>::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();

        let len = rcf::SC_Val::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = Vec::<rcf::SC_Challenge>::write(arr);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<rcf::FieldConfig> for ChipOpenedValues<rcf::SC_Challenge> {
    type HintVariable = ChipOpenedValuesVariable<rcf::FieldConfig>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let preprocessed_local = Vec::<rcf::SC_Challenge>::read(builder);
        let preprocessed_next = Vec::<rcf::SC_Challenge>::read(builder);
        let main_local = Vec::<rcf::SC_Challenge>::read(builder);
        let main_next = Vec::<rcf::SC_Challenge>::read(builder);
        let permutation_local = Vec::<rcf::SC_Challenge>::read(builder);
        let permutation_next = Vec::<rcf::SC_Challenge>::read(builder);
        let quotient = Vec::<Vec<rcf::SC_Challenge>>::read(builder);
        let cumulative_sum = rcf::SC_Challenge::read(builder);
        let log_main_degree = builder.hint_var();
        ChipOpenedValuesVariable {
            preprocessed_local,
            preprocessed_next,
            main_local,
            main_next,
            permutation_local,
            permutation_next,
            quotient,
            cumulative_sum,
            log_main_degree,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();
        stream.extend(self.preprocessed_local.write());
        stream.extend(self.preprocessed_next.write());
        stream.extend(self.main_local.write());
        stream.extend(self.main_next.write());
        stream.extend(self.permutation_local.write());
        stream.extend(self.permutation_next.write());
        stream.extend(self.quotient.write());
        stream.extend(self.cumulative_sum.write());
        stream.extend(self.log_main_degree.write());
        stream
    }
}

impl Hintable<rcf::FieldConfig> for &[Arc<ChipOpenedValues<rcf::SC_Challenge>>] {
    type HintVariable = Array<rcf::FieldConfig, ChipOpenedValuesVariable<rcf::FieldConfig>>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = ChipOpenedValues::<rcf::SC_Challenge>::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();

        let len = rcf::SC_Val::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = ChipOpenedValues::<rcf::SC_Challenge>::write(arr);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<rcf::FieldConfig> for BaseOpenedValues<rcf::SC_Challenge> {
    type HintVariable = BaseOpenedValuesVariable<rcf::FieldConfig>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let chips_opened_values = <&[Arc<ChipOpenedValues<rcf::SC_Challenge>>]>::read(builder);
        BaseOpenedValuesVariable {
            chips_opened_values,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        self.chips_opened_values.as_ref().write()
    }
}

impl Hintable<rcf::FieldConfig> for BaseCommitments<rcf::SC_DigestHash> {
    type HintVariable = BaseCommitmentsVariable<rcf::FieldConfig>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let main_commit = rcf::SC_Digest::read(builder);
        let permutation_commit = rcf::SC_Digest::read(builder);
        let quotient_commit = rcf::SC_Digest::read(builder);
        BaseCommitmentsVariable {
            main_commit,
            permutation_commit,
            quotient_commit,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();
        let h: rcf::SC_Digest = self.main_commit.into();
        stream.extend(h.write());
        let h: rcf::SC_Digest = self.permutation_commit.into();
        stream.extend(h.write());
        let h: rcf::SC_Digest = self.quotient_commit.into();
        stream.extend(h.write());
        stream
    }
}

impl Hintable<rcf::FieldConfig> for DuplexChallenger<rcf::SC_Val, rcf::SC_Perm, 16, 8> {
    type HintVariable = DuplexChallengerVariable<rcf::FieldConfig>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let sponge_state = builder.hint_felts();
        let nb_inputs = builder.hint_var();
        let input_buffer = builder.hint_felts();
        let nb_outputs = builder.hint_var();
        let output_buffer = builder.hint_felts();
        DuplexChallengerVariable {
            sponge_state,
            nb_inputs,
            input_buffer,
            nb_outputs,
            output_buffer,
        }
    }

    // todo: update for permutation
    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();
        stream.extend(self.sponge_state.to_vec().write());
        stream.extend(self.input_buffer.len().write());
        let mut input_padded = self.input_buffer.to_vec();
        input_padded.resize(PERMUTATION_RATE, rcf::SC_Val::ZERO);
        stream.extend(input_padded.write());
        stream.extend(self.output_buffer.len().write());
        let mut output_padded = self.output_buffer.to_vec();
        output_padded.resize(PERMUTATION_RATE, rcf::SC_Val::ZERO);
        stream.extend(output_padded.write());
        stream
    }
}

impl<C: ChipBehavior<BabyBear>> Hintable<rcf::FieldConfig> for VerifyingKeyHint<RiscvSC, C>
where
    C: ChipBehavior<BabyBear>
        + for<'b> Air<ProverConstraintFolder<'b, RiscvSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RiscvSC>>,
{
    type HintVariable = BaseVerifyingKeyVariable<rcf::FieldConfig>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let commitment = rcf::SC_Digest::read(builder);
        let pc_start = rcf::SC_Val::read(builder);
        let preprocessed_sorted_idxs = Vec::<usize>::read(builder);
        let prep_domains = Vec::<TwoAdicMultiplicativeCoset<rcf::SC_Val>>::read(builder);
        BaseVerifyingKeyVariable {
            commitment,
            pc_start,
            preprocessed_sorted_idxs,
            preprocessed_domains: prep_domains,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let (preprocessed_sorted_idxs, prep_domains) =
            get_preprocessed_data(&self.chips, &self.preprocessed_chip_ids, &self.vk);

        let mut stream = Vec::new();
        let h: rcf::SC_Digest = self.vk.commit.into();
        stream.extend(h.write());
        stream.extend(self.vk.pc_start.write());
        stream.extend(preprocessed_sorted_idxs.write());
        stream.extend(prep_domains.write());
        stream
    }
}

// Implement Hintable<C> for BaseProof where SC is equivalent to RiscvSC
impl<'a, A> Hintable<rcf::FieldConfig> for BaseProofHint<'a, RiscvSC, A>
where
    A: ChipBehavior<BabyBear>
        + for<'b> Air<ProverConstraintFolder<'b, RiscvSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RiscvSC>>,
    BaseCommitments<Com<RiscvSC>>: Hintable<rcf::FieldConfig>,
{
    type HintVariable = BaseProofVariable<rcf::FieldConfig>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let commitment = BaseCommitments::read(builder);
        let opened_values = BaseOpenedValues::read(builder);
        let opening_proof = rcf::SC_PcsProof::read(builder);
        let public_values = Vec::<rcf::SC_Val>::read(builder);
        let quotient_data = Vec::<QuotientData>::read(builder);
        let sorted_indices = Vec::<usize>::read(builder);
        BaseProofVariable {
            commitment,
            opened_values,
            opening_proof,
            public_values,
            quotient_data,
            sorted_indices,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let quotient_data = get_chip_quotient_data(&self.chips, self.proof);
        let sorted_indices = get_sorted_indices(&self.chips, self.proof);

        [
            self.proof.commitments.write(),
            self.proof.opened_values.write(),
            self.proof.opening_proof.write(),
            self.proof.public_values.as_ref().write(),
            quotient_data.write(),
            sorted_indices.write(),
        ]
        .concat()
    }
}
