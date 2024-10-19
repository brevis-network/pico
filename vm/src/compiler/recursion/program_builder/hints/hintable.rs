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
    configs::config::{Com, RecursionGenericConfig},
    instances::configs::{recur_config as rcf, riscv_config::StarkConfig as RiscvSC},
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
pub trait Hintable<RC: RecursionGenericConfig> {
    type HintVariable: Variable<RC>;

    fn read(builder: &mut Builder<RC>) -> Self::HintVariable;

    fn write(&self) -> Vec<Vec<Block<RC::F>>>;

    fn witness(variable: &Self::HintVariable, builder: &mut Builder<RC>) {
        let target = Self::read(builder);
        builder.assign(variable.clone(), target);
    }
}

impl Hintable<rcf::RecursionConfig> for usize {
    type HintVariable = Var<rcf::Val>;

    fn read(builder: &mut Builder<rcf::RecursionConfig>) -> Self::HintVariable {
        builder.hint_var()
    }

    fn write(&self) -> Vec<Vec<Block<rcf::Val>>> {
        vec![vec![Block::from(rcf::Val::from_canonical_usize(*self))]]
    }
}

impl Hintable<rcf::RecursionConfig> for rcf::Val {
    type HintVariable = Felt<rcf::Val>;

    fn read(builder: &mut Builder<rcf::RecursionConfig>) -> Self::HintVariable {
        builder.hint_felt()
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::RecursionConfig as RecursionGenericConfig>::F>>> {
        vec![vec![Block::from(*self)]]
    }
}

impl Hintable<rcf::RecursionConfig> for rcf::Challenge {
    type HintVariable = Ext<rcf::Val, rcf::Challenge>;

    fn read(builder: &mut Builder<rcf::RecursionConfig>) -> Self::HintVariable {
        builder.hint_ext()
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::RecursionConfig as RecursionGenericConfig>::F>>> {
        vec![vec![Block::from((*self).as_base_slice())]]
    }
}

impl Hintable<rcf::RecursionConfig> for [Word<BabyBear>; PV_DIGEST_NUM_WORDS] {
    type HintVariable = Sha256DigestVariable<rcf::RecursionConfig>;

    fn read(builder: &mut Builder<rcf::RecursionConfig>) -> Self::HintVariable {
        let bytes = builder.hint_felts();
        Sha256DigestVariable { bytes }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::RecursionConfig as RecursionGenericConfig>::F>>> {
        vec![self
            .iter()
            .flat_map(|w| w.0.iter().map(|f| Block::from(*f)))
            .collect::<Vec<_>>()]
    }
}

impl Hintable<rcf::RecursionConfig> for QuotientData {
    type HintVariable = QuotientDataVariable<rcf::RecursionConfig>;

    fn read(builder: &mut Builder<rcf::RecursionConfig>) -> Self::HintVariable {
        let log_quotient_degree = usize::read(builder);
        let quotient_size = usize::read(builder);

        QuotientDataVariable {
            log_quotient_degree,
            quotient_size,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::RecursionConfig as RecursionGenericConfig>::F>>> {
        let mut buffer = Vec::new();
        buffer.extend(usize::write(&self.log_quotient_degree));
        buffer.extend(usize::write(&self.quotient_size));

        buffer
    }
}

impl Hintable<rcf::RecursionConfig> for TwoAdicMultiplicativeCoset<rcf::Val> {
    type HintVariable = TwoAdicMultiplicativeCosetVariable<rcf::RecursionConfig>;

    fn read(builder: &mut Builder<rcf::RecursionConfig>) -> Self::HintVariable {
        let log_n = usize::read(builder);
        let shift = rcf::Val::read(builder);
        let g_val = rcf::Val::read(builder);
        let size = usize::read(builder);

        // Initialize a domain.
        TwoAdicMultiplicativeCosetVariable::<rcf::RecursionConfig> {
            log_n,
            size,
            shift,
            g: g_val,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::RecursionConfig as RecursionGenericConfig>::F>>> {
        let mut vec = Vec::new();
        vec.extend(usize::write(&self.log_n));
        vec.extend(rcf::Val::write(&self.shift));
        vec.extend(rcf::Val::write(&rcf::Val::two_adic_generator(self.log_n)));
        vec.extend(usize::write(&(1usize << (self.log_n))));
        vec
    }
}

trait VecAutoHintable<RC: RecursionGenericConfig>: Hintable<rcf::RecursionConfig> {}

impl<'a, A> VecAutoHintable<rcf::RecursionConfig> for BaseProofHint<'a, RiscvSC, A> where
    A: ChipBehavior<BabyBear>
        + for<'b> Air<ProverConstraintFolder<'b, RiscvSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RiscvSC>>
{
}
impl VecAutoHintable<rcf::RecursionConfig> for TwoAdicMultiplicativeCoset<rcf::Val> {}
impl VecAutoHintable<rcf::RecursionConfig> for Vec<usize> {}
impl VecAutoHintable<rcf::RecursionConfig> for QuotientData {}
impl VecAutoHintable<rcf::RecursionConfig> for Vec<QuotientData> {}
impl VecAutoHintable<rcf::RecursionConfig> for Vec<rcf::Val> {}

impl<I: VecAutoHintable<rcf::RecursionConfig>> VecAutoHintable<rcf::RecursionConfig> for &I {}

impl<H: Hintable<rcf::RecursionConfig>> Hintable<rcf::RecursionConfig> for &H {
    type HintVariable = H::HintVariable;

    fn read(builder: &mut Builder<rcf::RecursionConfig>) -> Self::HintVariable {
        H::read(builder)
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::RecursionConfig as RecursionGenericConfig>::F>>> {
        H::write(self)
    }
}

impl<I: VecAutoHintable<rcf::RecursionConfig>> Hintable<rcf::RecursionConfig> for Vec<I>
where
    <I as Hintable<rcf::RecursionConfig>>::HintVariable: MemVariable<rcf::RecursionConfig>,
{
    type HintVariable = Array<rcf::RecursionConfig, I::HintVariable>;

    fn read(builder: &mut Builder<rcf::RecursionConfig>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = I::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::RecursionConfig as RecursionGenericConfig>::F>>> {
        let mut stream = Vec::new();

        let len = rcf::Val::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|i| {
            let comm = I::write(i);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<rcf::RecursionConfig> for Vec<usize> {
    type HintVariable = Array<rcf::RecursionConfig, Var<rcf::Val>>;

    fn read(builder: &mut Builder<rcf::RecursionConfig>) -> Self::HintVariable {
        builder.hint_vars()
    }

    fn write(&self) -> Vec<Vec<Block<rcf::Val>>> {
        vec![self
            .iter()
            .map(|x| Block::from(rcf::Val::from_canonical_usize(*x)))
            .collect()]
    }
}

impl Hintable<rcf::RecursionConfig> for Vec<rcf::Val> {
    type HintVariable = Array<rcf::RecursionConfig, Felt<rcf::Val>>;

    fn read(builder: &mut Builder<rcf::RecursionConfig>) -> Self::HintVariable {
        builder.hint_felts()
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::RecursionConfig as RecursionGenericConfig>::F>>> {
        vec![self.iter().map(|x| Block::from(*x)).collect()]
    }
}

impl Hintable<rcf::RecursionConfig> for Vec<rcf::Challenge> {
    type HintVariable = Array<rcf::RecursionConfig, Ext<rcf::Val, rcf::Challenge>>;

    fn read(builder: &mut Builder<rcf::RecursionConfig>) -> Self::HintVariable {
        builder.hint_exts()
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::RecursionConfig as RecursionGenericConfig>::F>>> {
        vec![self
            .iter()
            .map(|x| Block::from((*x).as_base_slice()))
            .collect()]
    }
}

impl Hintable<rcf::RecursionConfig> for Vec<Vec<rcf::Challenge>> {
    type HintVariable =
        Array<rcf::RecursionConfig, Array<rcf::RecursionConfig, Ext<rcf::Val, rcf::Challenge>>>;

    fn read(builder: &mut Builder<rcf::RecursionConfig>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = Vec::<rcf::Challenge>::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::RecursionConfig as RecursionGenericConfig>::F>>> {
        let mut stream = Vec::new();

        let len = rcf::Val::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = Vec::<rcf::Challenge>::write(arr);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<rcf::RecursionConfig> for ChipOpenedValues<rcf::Challenge> {
    type HintVariable = ChipOpenedValuesVariable<rcf::RecursionConfig>;

    fn read(builder: &mut Builder<rcf::RecursionConfig>) -> Self::HintVariable {
        let preprocessed_local = Vec::<rcf::Challenge>::read(builder);
        let preprocessed_next = Vec::<rcf::Challenge>::read(builder);
        let main_local = Vec::<rcf::Challenge>::read(builder);
        let main_next = Vec::<rcf::Challenge>::read(builder);
        let permutation_local = Vec::<rcf::Challenge>::read(builder);
        let permutation_next = Vec::<rcf::Challenge>::read(builder);
        let quotient = Vec::<Vec<rcf::Challenge>>::read(builder);
        let cumulative_sum = rcf::Challenge::read(builder);
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

    fn write(&self) -> Vec<Vec<Block<<rcf::RecursionConfig as RecursionGenericConfig>::F>>> {
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

impl Hintable<rcf::RecursionConfig> for Vec<ChipOpenedValues<rcf::Challenge>> {
    type HintVariable = Array<rcf::RecursionConfig, ChipOpenedValuesVariable<rcf::RecursionConfig>>;

    fn read(builder: &mut Builder<rcf::RecursionConfig>) -> Self::HintVariable {
        let len = builder.hint_var();
        let mut arr = builder.dyn_array(len);
        builder.range(0, len).for_each(|i, builder| {
            let hint = ChipOpenedValues::<rcf::Challenge>::read(builder);
            builder.set(&mut arr, i, hint);
        });
        arr
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::RecursionConfig as RecursionGenericConfig>::F>>> {
        let mut stream = Vec::new();

        let len = rcf::Val::from_canonical_usize(self.len());
        stream.push(vec![len.into()]);

        self.iter().for_each(|arr| {
            let comm = ChipOpenedValues::<rcf::Challenge>::write(arr);
            stream.extend(comm);
        });

        stream
    }
}

impl Hintable<rcf::RecursionConfig> for BaseOpenedValues<rcf::Challenge> {
    type HintVariable = BaseOpenedValuesVariable<rcf::RecursionConfig>;

    fn read(builder: &mut Builder<rcf::RecursionConfig>) -> Self::HintVariable {
        let chips_opened_values = Vec::<ChipOpenedValues<rcf::Challenge>>::read(builder);
        BaseOpenedValuesVariable {
            chips_opened_values,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::RecursionConfig as RecursionGenericConfig>::F>>> {
        let mut stream = Vec::new();
        stream.extend(self.chips_opened_values.write());
        stream
    }
}

impl Hintable<rcf::RecursionConfig> for BaseCommitments<rcf::DigestHash> {
    type HintVariable = BaseCommitmentsVariable<rcf::RecursionConfig>;

    fn read(builder: &mut Builder<rcf::RecursionConfig>) -> Self::HintVariable {
        let main_commit = rcf::Digest::read(builder);
        let permutation_commit = rcf::Digest::read(builder);
        let quotient_commit = rcf::Digest::read(builder);
        BaseCommitmentsVariable {
            main_commit,
            permutation_commit,
            quotient_commit,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::RecursionConfig as RecursionGenericConfig>::F>>> {
        let mut stream = Vec::new();
        let h: rcf::Digest = self.main_commit.into();
        stream.extend(h.write());
        let h: rcf::Digest = self.permutation_commit.into();
        stream.extend(h.write());
        let h: rcf::Digest = self.quotient_commit.into();
        stream.extend(h.write());
        stream
    }
}

impl Hintable<rcf::RecursionConfig> for DuplexChallenger<rcf::Val, rcf::Perm, 16, 8> {
    type HintVariable = DuplexChallengerVariable<rcf::RecursionConfig>;

    fn read(builder: &mut Builder<rcf::RecursionConfig>) -> Self::HintVariable {
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

    fn write(&self) -> Vec<Vec<Block<<rcf::RecursionConfig as RecursionGenericConfig>::F>>> {
        let mut stream = Vec::new();
        stream.extend(self.sponge_state.to_vec().write());
        stream.extend(self.input_buffer.len().write());
        let mut input_padded = self.input_buffer.to_vec();
        input_padded.resize(PERMUTATION_WIDTH, rcf::Val::zero());
        stream.extend(input_padded.write());
        stream.extend(self.output_buffer.len().write());
        let mut output_padded = self.output_buffer.to_vec();
        output_padded.resize(PERMUTATION_WIDTH, rcf::Val::zero());
        stream.extend(output_padded.write());
        stream
    }
}

impl<'a, C: ChipBehavior<BabyBear>> Hintable<rcf::RecursionConfig>
    for VerifyingKeyHint<'a, RiscvSC, C>
where
    C: ChipBehavior<BabyBear>
        + for<'b> Air<ProverConstraintFolder<'b, RiscvSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RiscvSC>>,
{
    type HintVariable = BaseVerifyingKeyVariable<rcf::RecursionConfig>;

    fn read(builder: &mut Builder<rcf::RecursionConfig>) -> Self::HintVariable {
        let commitment = rcf::Digest::read(builder);
        let pc_start = rcf::Val::read(builder);
        let preprocessed_sorted_idxs = Vec::<usize>::read(builder);
        let prep_domains = Vec::<TwoAdicMultiplicativeCoset<rcf::Val>>::read(builder);
        BaseVerifyingKeyVariable {
            commitment,
            pc_start,
            preprocessed_sorted_idxs,
            preprocessed_domains: prep_domains,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::RecursionConfig as RecursionGenericConfig>::F>>> {
        let (preprocessed_sorted_idxs, prep_domains) =
            get_preprocessed_data(self.chips, &self.preprocessed_chip_ids, self.vk);

        let mut stream = Vec::new();
        let h: rcf::Digest = self.vk.commit.into();
        stream.extend(h.write());
        stream.extend(self.vk.pc_start.write());
        stream.extend(preprocessed_sorted_idxs.write());
        stream.extend(prep_domains.write());
        stream
    }
}

// Implement Hintable<C> for BaseProof where SC is equivalent to RiscvSC
impl<'a, A> Hintable<rcf::RecursionConfig> for BaseProofHint<'a, RiscvSC, A>
where
    A: ChipBehavior<BabyBear>
        + for<'b> Air<ProverConstraintFolder<'b, RiscvSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RiscvSC>>,
    BaseCommitments<Com<RiscvSC>>: Hintable<rcf::RecursionConfig>,
{
    type HintVariable = BaseProofVariable<rcf::RecursionConfig>;

    fn read(builder: &mut Builder<rcf::RecursionConfig>) -> Self::HintVariable {
        let commitment = BaseCommitments::read(builder);
        let opened_values = BaseOpenedValues::read(builder);
        let opening_proof = rcf::PcsProof::read(builder);
        let public_values = Vec::<rcf::Val>::read(builder);
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

    fn write(&self) -> Vec<Vec<Block<<rcf::RecursionConfig as RecursionGenericConfig>::F>>> {
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
