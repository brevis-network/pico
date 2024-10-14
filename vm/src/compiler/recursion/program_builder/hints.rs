use super::{
    challenger::DuplexChallengerVariable,
    fri::TwoAdicMultiplicativeCosetVariable,
    stark::{BaseProofHint, VerifyingKeyHint},
    types::{
        /*AirOpenedValuesVariable,*/ BaseCommitmentsVariable, BaseOpenedValuesVariable,
        BaseProofVariable, ChipOpenedValuesVariable, QuotientData, QuotientDataValues,
        Sha256DigestVariable, VerifyingKeyVariable,
    },
    utils::{get_chip_quotient_data, get_preprocessed_data, get_sorted_indices},
};
use crate::{
    compiler::{
        recursion::{
            config::InnerConfig,
            ir::{Array, Builder, Config, Ext, Felt, MemVariable, Var, Variable},
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
        proof::{BaseCommitments, BaseOpenedValues, ChipOpenedValues},
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
pub trait Hintable<C: Config> {
    type HintVariable: Variable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable;

    fn write(&self) -> Vec<Vec<Block<C::F>>>;

    fn witness(variable: &Self::HintVariable, builder: &mut Builder<C>) {
        let target = Self::read(builder);
        builder.assign(variable.clone(), target);
    }
}

type C = InnerConfig;

impl Hintable<C> for usize {
    type HintVariable = Var<InnerVal>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        builder.hint_var()
    }

    fn write(&self) -> Vec<Vec<Block<InnerVal>>> {
        vec![vec![Block::from(InnerVal::from_canonical_usize(*self))]]
    }
}

impl Hintable<C> for InnerVal {
    type HintVariable = Felt<InnerVal>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        builder.hint_felt()
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        vec![vec![Block::from(*self)]]
    }
}

impl Hintable<C> for InnerChallenge {
    type HintVariable = Ext<InnerVal, InnerChallenge>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        builder.hint_ext()
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        vec![vec![Block::from((*self).as_base_slice())]]
    }
}

impl Hintable<C> for [Word<BabyBear>; PV_DIGEST_NUM_WORDS] {
    type HintVariable = Sha256DigestVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let bytes = builder.hint_felts();
        Sha256DigestVariable { bytes }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        vec![self
            .iter()
            .flat_map(|w| w.0.iter().map(|f| Block::from(*f)))
            .collect::<Vec<_>>()]
    }
}

impl Hintable<C> for QuotientDataValues {
    type HintVariable = QuotientData<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let log_quotient_degree = usize::read(builder);
        let quotient_size = usize::read(builder);

        QuotientData {
            log_quotient_degree,
            quotient_size,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut buffer = Vec::new();
        buffer.extend(usize::write(&self.log_quotient_degree));
        buffer.extend(usize::write(&self.quotient_size));

        buffer
    }
}

impl Hintable<C> for TwoAdicMultiplicativeCoset<InnerVal> {
    type HintVariable = TwoAdicMultiplicativeCosetVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let log_n = usize::read(builder);
        let shift = InnerVal::read(builder);
        let g_val = InnerVal::read(builder);
        let size = usize::read(builder);

        // Initialize a domain.
        TwoAdicMultiplicativeCosetVariable::<C> {
            log_n,
            size,
            shift,
            g: g_val,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut vec = Vec::new();
        vec.extend(usize::write(&self.log_n));
        vec.extend(InnerVal::write(&self.shift));
        vec.extend(InnerVal::write(&InnerVal::two_adic_generator(self.log_n)));
        vec.extend(usize::write(&(1usize << (self.log_n))));
        vec
    }
}

trait VecAutoHintable<C: Config>: Hintable<C> {}

impl<'a, A> VecAutoHintable<C> for BaseProofHint<'a, BabyBearPoseidon2, A> where
    A: ChipBehavior<BabyBear>
        + for<'b> Air<ProverConstraintFolder<'b, BabyBearPoseidon2>>
        + for<'b> Air<VerifierConstraintFolder<'b, BabyBearPoseidon2>>
{
}
impl VecAutoHintable<C> for TwoAdicMultiplicativeCoset<InnerVal> {}
impl VecAutoHintable<C> for Vec<usize> {}
impl VecAutoHintable<C> for QuotientDataValues {}
impl VecAutoHintable<C> for Vec<QuotientDataValues> {}
impl VecAutoHintable<C> for Vec<InnerVal> {}

impl<I: VecAutoHintable<C>> VecAutoHintable<C> for &I {}

impl<H: Hintable<C>> Hintable<C> for &H {
    type HintVariable = H::HintVariable;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        H::read(builder)
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        H::write(self)
    }
}

impl<I: VecAutoHintable<C>> Hintable<C> for Vec<I>
where
    <I as Hintable<C>>::HintVariable: MemVariable<C>,
{
    type HintVariable = Array<C, I::HintVariable>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = I::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
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

impl Hintable<C> for Vec<usize> {
    type HintVariable = Array<C, Var<InnerVal>>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        builder.hint_vars()
    }

    fn write(&self) -> Vec<Vec<Block<InnerVal>>> {
        vec![self
            .iter()
            .map(|x| Block::from(InnerVal::from_canonical_usize(*x)))
            .collect()]
    }
}

impl Hintable<C> for Vec<InnerVal> {
    type HintVariable = Array<C, Felt<InnerVal>>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        builder.hint_felts()
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        vec![self.iter().map(|x| Block::from(*x)).collect()]
    }
}

impl Hintable<C> for Vec<InnerChallenge> {
    type HintVariable = Array<C, Ext<InnerVal, InnerChallenge>>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        builder.hint_exts()
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        vec![self
            .iter()
            .map(|x| Block::from((*x).as_base_slice()))
            .collect()]
    }
}

// impl Hintable<C> for AirOpenedValues<InnerChallenge> {
//     type HintVariable = AirOpenedValuesVariable<C>;

//     fn read(builder: &mut Builder<C>) -> Self::HintVariable {
//         let local = Vec::<InnerChallenge>::read(builder);
//         let next = Vec::<InnerChallenge>::read(builder);
//         AirOpenedValuesVariable { local, next }
//     }

//     fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
//         let mut stream = Vec::new();
//         stream.extend(self.local.write());
//         stream.extend(self.next.write());
//         stream
//     }
// }

impl Hintable<C> for Vec<Vec<InnerChallenge>> {
    type HintVariable = Array<C, Array<C, Ext<InnerVal, InnerChallenge>>>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = Vec::<InnerChallenge>::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
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

impl Hintable<C> for ChipOpenedValues<InnerChallenge> {
    type HintVariable = ChipOpenedValuesVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
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

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
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

impl Hintable<C> for Vec<ChipOpenedValues<InnerChallenge>> {
    type HintVariable = Array<C, ChipOpenedValuesVariable<C>>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = ChipOpenedValues::<InnerChallenge>::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
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

impl Hintable<C> for BaseOpenedValues<InnerChallenge> {
    type HintVariable = BaseOpenedValuesVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let chips = Vec::<ChipOpenedValues<InnerChallenge>>::read(builder);
        BaseOpenedValuesVariable { chips }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();
        stream.extend(self.chips_opened_values.write());
        stream
    }
}

impl Hintable<C> for BaseCommitments<InnerDigestHash> {
    type HintVariable = BaseCommitmentsVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let main_commit = InnerDigest::read(builder);
        let permutation_commit = InnerDigest::read(builder);
        let quotient_commit = InnerDigest::read(builder);
        BaseCommitmentsVariable {
            main_commit,
            permutation_commit,
            quotient_commit,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
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

impl Hintable<C> for DuplexChallenger<InnerVal, InnerPerm, 16, 8> {
    type HintVariable = DuplexChallengerVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
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

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
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

impl<'a, A: ChipBehavior<BabyBear>> Hintable<C> for VerifyingKeyHint<'a, BabyBearPoseidon2, A>
where
    A: ChipBehavior<BabyBear>
        + for<'b> Air<ProverConstraintFolder<'b, BabyBearPoseidon2>>
        + for<'b> Air<VerifierConstraintFolder<'b, BabyBearPoseidon2>>,
{
    type HintVariable = VerifyingKeyVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let commitment = InnerDigest::read(builder);
        let pc_start = InnerVal::read(builder);
        let preprocessed_sorted_idxs = Vec::<usize>::read(builder);
        let prep_domains = Vec::<TwoAdicMultiplicativeCoset<InnerVal>>::read(builder);
        VerifyingKeyVariable {
            commitment,
            pc_start,
            preprocessed_sorted_idxs,
            prep_domains,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let (preprocessed_sorted_idxs, prep_domains) = get_preprocessed_data(self.machine, self.vk);

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
impl<'a, A> Hintable<C> for BaseProofHint<'a, BabyBearPoseidon2, A>
where
    A: ChipBehavior<BabyBear>
        + for<'b> Air<ProverConstraintFolder<'b, BabyBearPoseidon2>>
        + for<'b> Air<VerifierConstraintFolder<'b, BabyBearPoseidon2>>,
    BaseCommitments<Com<BabyBearPoseidon2>>: Hintable<C>,
{
    type HintVariable = BaseProofVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let commitment = BaseCommitments::read(builder);
        let opened_values = BaseOpenedValues::read(builder);
        let opening_proof = InnerPcsProof::read(builder);
        let public_values = Vec::<InnerVal>::read(builder);
        let quotient_data = Vec::<QuotientDataValues>::read(builder);
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

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let quotient_data = get_chip_quotient_data(self.machine, self.proof);
        let sorted_indices = get_sorted_indices(self.machine, self.proof);

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
