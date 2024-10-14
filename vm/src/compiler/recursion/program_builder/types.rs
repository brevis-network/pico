use super::fri::{
    types::{DigestVariable, FriConfigVariable, TwoAdicPcsProofVariable},
    TwoAdicMultiplicativeCosetVariable,
};
use crate::{
    compiler::{recursion::prelude::*, word::Word},
    machine::{
        chip::{ChipBehavior, MetaChip},
        proof::ChipOpenedValues,
    },
    primitives::consts::{POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS, WORD_SIZE},
};
use p3_air::BaseAir;
use p3_field::{AbstractExtensionField, AbstractField};

/// Reference: [pico_machine::stark::BaseProof]
#[derive(DslVariable, Clone)]
pub struct BaseProofVariable<C: Config> {
    pub commitment: BaseCommitmentsVariable<C>,
    pub opened_values: BaseOpenedValuesVariable<C>,
    pub opening_proof: TwoAdicPcsProofVariable<C>,
    pub public_values: Array<C, Felt<C::F>>,
    pub quotient_data: Array<C, QuotientData<C>>,
    pub sorted_idxs: Array<C, Var<C::N>>,
}

#[derive(DslVariable, Clone, Copy)]
pub struct QuotientData<C: Config> {
    pub log_quotient_degree: Var<C::N>,
    pub quotient_size: Var<C::N>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotientDataValues {
    pub log_quotient_degree: usize,
    pub quotient_size: usize,
}

/// Reference: [pico_machine::stark::VerifyingKey]
#[derive(DslVariable, Clone)]
pub struct VerifyingKeyVariable<C: Config> {
    pub commitment: DigestVariable<C>,
    pub pc_start: Felt<C::F>,
    pub preprocessed_sorted_idxs: Array<C, Var<C::N>>,
    pub prep_domains: Array<C, TwoAdicMultiplicativeCosetVariable<C>>,
}

/// Reference: [pico_machine::BaseCommitments]
#[derive(DslVariable, Clone)]
pub struct BaseCommitmentsVariable<C: Config> {
    pub main_commit: DigestVariable<C>,
    pub permutation_commit: DigestVariable<C>,
    pub quotient_commit: DigestVariable<C>,
}

/// Reference: [pico_machine::BaseOpenedValues]
#[derive(DslVariable, Debug, Clone)]
pub struct BaseOpenedValuesVariable<C: Config> {
    pub chips: Array<C, ChipOpenedValuesVariable<C>>,
}

/// Reference: [pico_machine::proof::ChipOpenedValues]
#[derive(Debug, Clone)]
pub struct ChipOpening<C: Config> {
    pub preprocessed_local: Vec<Ext<C::F, C::EF>>,
    pub preprocessed_next: Vec<Ext<C::F, C::EF>>,
    pub main_local: Vec<Ext<C::F, C::EF>>,
    pub main_next: Vec<Ext<C::F, C::EF>>,
    pub permutation_local: Vec<Ext<C::F, C::EF>>,
    pub permutation_next: Vec<Ext<C::F, C::EF>>,
    pub quotient: Vec<Vec<Ext<C::F, C::EF>>>,
    pub cumulative_sum: Ext<C::F, C::EF>,
    pub log_main_degree: Var<C::N>,
}

/// Reference: [pico_machine::stark::ChipOpenedValues]
#[derive(DslVariable, Debug, Clone)]
pub struct ChipOpenedValuesVariable<C: Config> {
    pub preprocessed_local: Array<C, Ext<C::F, C::EF>>,
    pub preprocessed_next: Array<C, Ext<C::F, C::EF>>,
    pub main_local: Array<C, Ext<C::F, C::EF>>,
    pub main_next: Array<C, Ext<C::F, C::EF>>,
    pub permutation_local: Array<C, Ext<C::F, C::EF>>,
    pub permutation_next: Array<C, Ext<C::F, C::EF>>,
    pub quotient: Array<C, Array<C, Ext<C::F, C::EF>>>,
    pub cumulative_sum: Ext<C::F, C::EF>,
    pub log_main_degree: Var<C::N>,
}

#[derive(DslVariable, Debug, Clone)]
pub struct Sha256DigestVariable<C: Config> {
    pub bytes: Array<C, Felt<C::F>>,
}

impl<C: Config> Sha256DigestVariable<C> {
    pub fn from_words(builder: &mut Builder<C>, words: &[Word<Felt<C::F>>]) -> Self {
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

impl<C: Config> ChipOpening<C> {
    /// Collect opening values from a dynamic array into vectors.
    ///
    /// This method is used to convert a `ChipOpenedValuesVariable` into a `ChipOpenedValues`, which
    /// are the same values but with each opening converted from a dynamic array into a Rust vector.
    ///
    /// *Safety*: This method also verifies that the length of the dynamic arrays match the expected
    /// length of the vectors.
    pub fn from_variable<A>(
        builder: &mut Builder<C>,
        chip: &MetaChip<C::F, A>,
        opening: &ChipOpenedValuesVariable<C>,
    ) -> Self
    where
        A: ChipBehavior<C::F>,
    {
        let mut preprocessed_local = vec![];
        let mut preprocessed_next = vec![];
        let preprocessed_width = chip.preprocessed_width();
        // Assert that the length of the dynamic arrays match the expected length of the vectors.
        builder.assert_usize_eq(preprocessed_width, opening.preprocessed_local.len());
        builder.assert_usize_eq(preprocessed_width, opening.preprocessed_next.len());
        // Collect the preprocessed values into vectors.
        for i in 0..preprocessed_width {
            preprocessed_local.push(builder.get(&opening.preprocessed_local, i));
            preprocessed_next.push(builder.get(&opening.preprocessed_next, i));
        }

        let mut main_local = vec![];
        let mut main_next = vec![];
        let main_width = chip.width();
        // Assert that the length of the dynamic arrays match the expected length of the vectors.
        builder.assert_usize_eq(main_width, opening.main_local.len());
        builder.assert_usize_eq(main_width, opening.main_next.len());
        // Collect the main values into vectors.
        for i in 0..main_width {
            main_local.push(builder.get(&opening.main_local, i));
            main_next.push(builder.get(&opening.main_next, i));
        }

        let mut permutation_local = vec![];
        let mut permutation_next = vec![];
        let permutation_width = C::EF::D * chip.permutation_width();
        // Assert that the length of the dynamic arrays match the expected length of the vectors.
        builder.assert_usize_eq(permutation_width, opening.permutation_local.len());
        builder.assert_usize_eq(permutation_width, opening.permutation_next.len());
        // Collect the permutation values into vectors.
        for i in 0..permutation_width {
            permutation_local.push(builder.get(&opening.permutation_local, i));
            permutation_next.push(builder.get(&opening.permutation_next, i));
        }

        let num_quotient_chunks = 1 << chip.get_log_quotient_degree();
        let mut quotient = vec![];
        // Assert that the length of the quotient chunk arrays match the expected length.
        builder.assert_usize_eq(num_quotient_chunks, opening.quotient.len());
        // Collect the quotient values into vectors.
        for i in 0..num_quotient_chunks {
            let chunk = builder.get(&opening.quotient, i);
            // Assert that the chunk length matches the expected length.
            builder.assert_usize_eq(C::EF::D, chunk.len());
            // Collect the quotient values into vectors.
            let mut quotient_vals = vec![];
            for j in 0..C::EF::D {
                let value = builder.get(&chunk, j);
                quotient_vals.push(value);
            }
            quotient.push(quotient_vals);
        }

        ChipOpening {
            preprocessed_local,
            preprocessed_next,
            main_local,
            main_next,
            permutation_local,
            permutation_next,
            quotient,
            cumulative_sum: opening.cumulative_sum,
            log_main_degree: opening.log_main_degree,
        }
    }
}

impl<C: Config> FromConstant<C> for ChipOpenedValuesVariable<C> {
    type Constant = ChipOpenedValues<C::EF>;

    fn constant(value: Self::Constant, builder: &mut Builder<C>) -> Self {
        ChipOpenedValuesVariable {
            preprocessed_local: builder.constant(value.preprocessed_local),
            preprocessed_next: builder.constant(value.preprocessed_next),
            main_local: builder.constant(value.main_local),
            main_next: builder.constant(value.main_next),
            permutation_local: builder.constant(value.permutation_local),
            permutation_next: builder.constant(value.permutation_next),
            quotient: builder.constant(value.quotient),
            cumulative_sum: builder.eval(value.cumulative_sum.cons()),
            log_main_degree: builder.eval(C::N::from_canonical_usize(value.log_main_degree)),
        }
    }
}

impl<C: Config> FriConfigVariable<C> {
    pub fn get_subgroup(
        &self,
        builder: &mut Builder<C>,
        log_degree: impl Into<Usize<C::N>>,
    ) -> TwoAdicMultiplicativeCosetVariable<C> {
        builder.get(&self.subgroups, log_degree)
    }

    pub fn get_two_adic_generator(
        &self,
        builder: &mut Builder<C>,
        bits: impl Into<Usize<C::N>>,
    ) -> Felt<C::F> {
        builder.get(&self.generators, bits)
    }
}
