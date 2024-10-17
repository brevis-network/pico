use super::{keys::VerifyingKeyHint, proof::BaseProofHint};
use crate::{
    compiler::{
        recursion::{
            config::InnerConfig,
            ir::{Array, Builder, Config, Ext, Felt, MemVariable, Var, Variable},
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
    configs::{
        bb_poseidon2::{
            BabyBearPoseidon2, InnerChallenge, InnerDigest, InnerDigestHash, InnerPcsProof,
            InnerPerm, InnerVal,
        },
        config::{Com, StarkGenericConfig},
    },
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        machine::MachineBehavior,
        proof::{BaseCommitments, BaseOpenedValues, ChipOpenedValues, QuotientData},
    },
    primitives::consts::PV_DIGEST_NUM_WORDS,
    recursion::{air::Block, runtime::PERMUTATION_WIDTH},
};
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{AbstractExtensionField, AbstractField, TwoAdicField};

// TODO: Walkthrough
pub trait Hintable<CF: Config> {
    type HintVariable: Variable<CF>;

    fn read(builder: &mut Builder<CF>) -> Self::HintVariable;

    fn write(&self) -> Vec<Vec<Block<CF::F>>>;

    fn witness(variable: &Self::HintVariable, builder: &mut Builder<CF>) {
        let target = Self::read(builder);
        builder.assign(variable.clone(), target);
    }
}

impl Hintable<InnerConfig> for usize {
    type HintVariable = Var<InnerVal>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        builder.hint_var()
    }

    fn write(&self) -> Vec<Vec<Block<InnerVal>>> {
        vec![vec![Block::from(InnerVal::from_canonical_usize(*self))]]
    }
}

impl Hintable<InnerConfig> for InnerVal {
    type HintVariable = Felt<InnerVal>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        builder.hint_felt()
    }

    fn write(&self) -> Vec<Vec<Block<<InnerConfig as Config>::F>>> {
        vec![vec![Block::from(*self)]]
    }
}

impl Hintable<InnerConfig> for InnerChallenge {
    type HintVariable = Ext<InnerVal, InnerChallenge>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        builder.hint_ext()
    }

    fn write(&self) -> Vec<Vec<Block<<InnerConfig as Config>::F>>> {
        vec![vec![Block::from((*self).as_base_slice())]]
    }
}

impl Hintable<InnerConfig> for [Word<BabyBear>; PV_DIGEST_NUM_WORDS] {
    type HintVariable = Sha256DigestVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let bytes = builder.hint_felts();
        Sha256DigestVariable { bytes }
    }

    fn write(&self) -> Vec<Vec<Block<<InnerConfig as Config>::F>>> {
        vec![self
            .iter()
            .flat_map(|w| w.0.iter().map(|f| Block::from(*f)))
            .collect::<Vec<_>>()]
    }
}

impl Hintable<InnerConfig> for QuotientData {
    type HintVariable = QuotientDataVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let log_quotient_degree = usize::read(builder);
        let quotient_size = usize::read(builder);

        QuotientDataVariable {
            log_quotient_degree,
            quotient_size,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<InnerConfig as Config>::F>>> {
        let mut buffer = Vec::new();
        buffer.extend(usize::write(&self.log_quotient_degree));
        buffer.extend(usize::write(&self.quotient_size));

        buffer
    }
}

impl Hintable<InnerConfig> for TwoAdicMultiplicativeCoset<InnerVal> {
    type HintVariable = TwoAdicMultiplicativeCosetVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let log_n = usize::read(builder);
        let shift = InnerVal::read(builder);
        let g_val = InnerVal::read(builder);
        let size = usize::read(builder);

        // Initialize a domain.
        TwoAdicMultiplicativeCosetVariable::<InnerConfig> {
            log_n,
            size,
            shift,
            g: g_val,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<InnerConfig as Config>::F>>> {
        let mut vec = Vec::new();
        vec.extend(usize::write(&self.log_n));
        vec.extend(InnerVal::write(&self.shift));
        vec.extend(InnerVal::write(&InnerVal::two_adic_generator(self.log_n)));
        vec.extend(usize::write(&(1usize << (self.log_n))));
        vec
    }
}

trait VecAutoHintable<CF: Config>: Hintable<InnerConfig> {}

impl<'a, A> VecAutoHintable<InnerConfig> for BaseProofHint<'a, BabyBearPoseidon2, A> where
    A: ChipBehavior<BabyBear>
        + for<'b> Air<ProverConstraintFolder<'b, BabyBearPoseidon2>>
        + for<'b> Air<VerifierConstraintFolder<'b, BabyBearPoseidon2>>
{
}
impl VecAutoHintable<InnerConfig> for TwoAdicMultiplicativeCoset<InnerVal> {}
impl VecAutoHintable<InnerConfig> for Vec<usize> {}
impl VecAutoHintable<InnerConfig> for QuotientData {}
impl VecAutoHintable<InnerConfig> for Vec<QuotientData> {}
impl VecAutoHintable<InnerConfig> for Vec<InnerVal> {}

impl<I: VecAutoHintable<InnerConfig>> VecAutoHintable<InnerConfig> for &I {}

impl<H: Hintable<InnerConfig>> Hintable<InnerConfig> for &H {
    type HintVariable = H::HintVariable;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        H::read(builder)
    }

    fn write(&self) -> Vec<Vec<Block<<InnerConfig as Config>::F>>> {
        H::write(self)
    }
}

impl<I: VecAutoHintable<InnerConfig>> Hintable<InnerConfig> for Vec<I>
where
    <I as Hintable<InnerConfig>>::HintVariable: MemVariable<InnerConfig>,
{
    type HintVariable = Array<InnerConfig, I::HintVariable>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = I::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<InnerConfig as Config>::F>>> {
        let mut stream = Vec::new();

        let len = InnerVal::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|i| {
            let comm = I::write(i);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<InnerConfig> for Vec<usize> {
    type HintVariable = Array<InnerConfig, Var<InnerVal>>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        builder.hint_vars()
    }

    fn write(&self) -> Vec<Vec<Block<InnerVal>>> {
        vec![self
            .iter()
            .map(|x| Block::from(InnerVal::from_canonical_usize(*x)))
            .collect()]
    }
}

impl Hintable<InnerConfig> for Vec<InnerVal> {
    type HintVariable = Array<InnerConfig, Felt<InnerVal>>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        builder.hint_felts()
    }

    fn write(&self) -> Vec<Vec<Block<<InnerConfig as Config>::F>>> {
        vec![self.iter().map(|x| Block::from(*x)).collect()]
    }
}

impl Hintable<InnerConfig> for Vec<InnerChallenge> {
    type HintVariable = Array<InnerConfig, Ext<InnerVal, InnerChallenge>>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        builder.hint_exts()
    }

    fn write(&self) -> Vec<Vec<Block<<InnerConfig as Config>::F>>> {
        vec![self
            .iter()
            .map(|x| Block::from((*x).as_base_slice()))
            .collect()]
    }
}

impl Hintable<InnerConfig> for Vec<Vec<InnerChallenge>> {
    type HintVariable = Array<InnerConfig, Array<InnerConfig, Ext<InnerVal, InnerChallenge>>>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = Vec::<InnerChallenge>::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<InnerConfig as Config>::F>>> {
        let mut stream = Vec::new();

        let len = InnerVal::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = Vec::<InnerChallenge>::write(arr);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<InnerConfig> for ChipOpenedValues<InnerChallenge> {
    type HintVariable = ChipOpenedValuesVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let preprocessed_local = Vec::<InnerChallenge>::read(builder);
        let preprocessed_next = Vec::<InnerChallenge>::read(builder);
        let main_local = Vec::<InnerChallenge>::read(builder);
        let main_next = Vec::<InnerChallenge>::read(builder);
        let permutation_local = Vec::<InnerChallenge>::read(builder);
        let permutation_next = Vec::<InnerChallenge>::read(builder);
        let quotient = Vec::<Vec<InnerChallenge>>::read(builder);
        let cumulative_sum = InnerChallenge::read(builder);
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

    fn write(&self) -> Vec<Vec<Block<<InnerConfig as Config>::F>>> {
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

impl Hintable<InnerConfig> for Vec<ChipOpenedValues<InnerChallenge>> {
    type HintVariable = Array<InnerConfig, ChipOpenedValuesVariable<InnerConfig>>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = ChipOpenedValues::<InnerChallenge>::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<InnerConfig as Config>::F>>> {
        let mut stream = Vec::new();

        let len = InnerVal::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = ChipOpenedValues::<InnerChallenge>::write(arr);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<InnerConfig> for BaseOpenedValues<InnerChallenge> {
    type HintVariable = BaseOpenedValuesVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let chips_opened_values = Vec::<ChipOpenedValues<InnerChallenge>>::read(builder);
        BaseOpenedValuesVariable {
            chips_opened_values,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<InnerConfig as Config>::F>>> {
        let mut stream = Vec::new();
        stream.extend(self.chips_opened_values.write());
        stream
    }
}

impl Hintable<InnerConfig> for BaseCommitments<InnerDigestHash> {
    type HintVariable = BaseCommitmentsVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let main_commit = InnerDigest::read(builder);
        let permutation_commit = InnerDigest::read(builder);
        let quotient_commit = InnerDigest::read(builder);
        BaseCommitmentsVariable {
            main_commit,
            permutation_commit,
            quotient_commit,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<InnerConfig as Config>::F>>> {
        let mut stream = Vec::new();
        let h: InnerDigest = self.main_commit.into();
        stream.extend(h.write());
        let h: InnerDigest = self.permutation_commit.into();
        stream.extend(h.write());
        let h: InnerDigest = self.quotient_commit.into();
        stream.extend(h.write());
        stream
    }
}

impl Hintable<InnerConfig> for DuplexChallenger<InnerVal, InnerPerm, 16, 8> {
    type HintVariable = DuplexChallengerVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
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

    fn write(&self) -> Vec<Vec<Block<<InnerConfig as Config>::F>>> {
        let mut stream = Vec::new();
        stream.extend(self.sponge_state.to_vec().write());
        stream.extend(self.input_buffer.len().write());
        let mut input_padded = self.input_buffer.to_vec();
        input_padded.resize(PERMUTATION_WIDTH, InnerVal::zero());
        stream.extend(input_padded.write());
        stream.extend(self.output_buffer.len().write());
        let mut output_padded = self.output_buffer.to_vec();
        output_padded.resize(PERMUTATION_WIDTH, InnerVal::zero());
        stream.extend(output_padded.write());
        stream
    }
}

impl<'a, A: ChipBehavior<BabyBear>> Hintable<InnerConfig>
    for VerifyingKeyHint<'a, BabyBearPoseidon2, A>
where
    A: ChipBehavior<BabyBear>
        + for<'b> Air<ProverConstraintFolder<'b, BabyBearPoseidon2>>
        + for<'b> Air<VerifierConstraintFolder<'b, BabyBearPoseidon2>>,
{
    type HintVariable = BaseVerifyingKeyVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let commitment = InnerDigest::read(builder);
        let pc_start = InnerVal::read(builder);
        let preprocessed_sorted_idxs = Vec::<usize>::read(builder);
        let prep_domains = Vec::<TwoAdicMultiplicativeCoset<InnerVal>>::read(builder);
        BaseVerifyingKeyVariable {
            commitment,
            pc_start,
            preprocessed_sorted_idxs,
            preprocessed_domains: prep_domains,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<InnerConfig as Config>::F>>> {
        let (preprocessed_sorted_idxs, prep_domains) =
            get_preprocessed_data(self.chips, &self.preprocessed_chip_ids, self.vk);

        let mut stream = Vec::new();
        let h: InnerDigest = self.vk.commit.into();
        stream.extend(h.write());
        stream.extend(self.vk.pc_start.write());
        stream.extend(preprocessed_sorted_idxs.write());
        stream.extend(prep_domains.write());
        stream
    }
}

// Implement Hintable<C> for BaseProof where SC is equivalent to BabyBearPoseidon2
impl<'a, A> Hintable<InnerConfig> for BaseProofHint<'a, BabyBearPoseidon2, A>
where
    A: ChipBehavior<BabyBear>
        + for<'b> Air<ProverConstraintFolder<'b, BabyBearPoseidon2>>
        + for<'b> Air<VerifierConstraintFolder<'b, BabyBearPoseidon2>>,
    BaseCommitments<Com<BabyBearPoseidon2>>: Hintable<InnerConfig>,
{
    type HintVariable = BaseProofVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let commitment = BaseCommitments::read(builder);
        let opened_values = BaseOpenedValues::read(builder);
        let opening_proof = InnerPcsProof::read(builder);
        let public_values = Vec::<InnerVal>::read(builder);
        let quotient_data = Vec::<QuotientData>::read(builder);
        let sorted_idxs = Vec::<usize>::read(builder);
        BaseProofVariable {
            commitment,
            opened_values,
            opening_proof,
            public_values,
            quotient_data,
            sorted_idxs,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<InnerConfig as Config>::F>>> {
        let quotient_data = get_chip_quotient_data(self.chips, self.proof);
        let sorted_indices = get_sorted_indices(self.chips, self.proof);

        [
            self.proof.commitments.write(),
            self.proof.opened_values.write(),
            self.proof.opening_proof.write(),
            self.proof.public_values.write(),
            quotient_data.write(),
            sorted_indices.write(),
        ]
        .concat()
    }
}
