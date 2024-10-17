use super::p3::fri::types::{DigestVariable, PcsProofVariable};
use crate::{
    compiler::recursion::{
        ir::{Array, Builder, Config, Ext, ExtConst, Felt, FromConstant, Var},
        prelude::*,
    },
    machine::{
        chip::{ChipBehavior, MetaChip},
        proof::ChipOpenedValues,
    },
};
use p3_air::BaseAir;
use p3_field::{AbstractExtensionField, AbstractField};
use pico_derive::DslVariable;

/// Reference: [pico_machine::stark::BaseProof]
#[derive(DslVariable, Clone)]
pub struct BaseProofVariable<CF: Config> {
    pub commitment: BaseCommitmentsVariable<CF>,
    pub opened_values: BaseOpenedValuesVariable<CF>,
    pub opening_proof: PcsProofVariable<CF>,
    pub public_values: Array<CF, Felt<CF::F>>,
    pub quotient_data: Array<CF, QuotientDataVariable<CF>>,
    pub sorted_idxs: Array<CF, Var<CF::N>>,
    // todo: public values?
}

/// Reference: [pico_machine::BaseCommitments]
#[derive(DslVariable, Clone)]
pub struct BaseCommitmentsVariable<CF: Config> {
    pub main_commit: DigestVariable<CF>,
    pub permutation_commit: DigestVariable<CF>,
    pub quotient_commit: DigestVariable<CF>,
}

/// Reference: [pico_machine::BaseOpenedValues]
#[derive(DslVariable, Debug, Clone)]
pub struct BaseOpenedValuesVariable<CF: Config> {
    pub chips_opened_values: Array<CF, ChipOpenedValuesVariable<CF>>,
}

// todo: consider necessity
/// Reference: [pico_machine::proof::ChipOpenedValues]
#[derive(Debug, Clone)]
pub struct ChipOpening<CF: Config> {
    pub preprocessed_local: Vec<Ext<CF::F, CF::EF>>,
    pub preprocessed_next: Vec<Ext<CF::F, CF::EF>>,
    pub main_local: Vec<Ext<CF::F, CF::EF>>,
    pub main_next: Vec<Ext<CF::F, CF::EF>>,
    pub permutation_local: Vec<Ext<CF::F, CF::EF>>,
    pub permutation_next: Vec<Ext<CF::F, CF::EF>>,
    pub quotient: Vec<Vec<Ext<CF::F, CF::EF>>>,
    pub cumulative_sum: Ext<CF::F, CF::EF>,
    pub log_main_degree: Var<CF::N>,
}

/// Reference: [pico_machine::stark::ChipOpenedValues]
#[derive(DslVariable, Debug, Clone)]
pub struct ChipOpenedValuesVariable<CF: Config> {
    pub preprocessed_local: Array<CF, Ext<CF::F, CF::EF>>,
    pub preprocessed_next: Array<CF, Ext<CF::F, CF::EF>>,
    pub main_local: Array<CF, Ext<CF::F, CF::EF>>,
    pub main_next: Array<CF, Ext<CF::F, CF::EF>>,
    pub permutation_local: Array<CF, Ext<CF::F, CF::EF>>,
    pub permutation_next: Array<CF, Ext<CF::F, CF::EF>>,
    pub quotient: Array<CF, Array<CF, Ext<CF::F, CF::EF>>>,
    pub cumulative_sum: Ext<CF::F, CF::EF>,
    pub log_main_degree: Var<CF::N>,
}

#[derive(DslVariable, Clone, Copy)]
pub struct QuotientDataVariable<CF: Config> {
    pub log_quotient_degree: Var<CF::N>,
    pub quotient_size: Var<CF::N>,
}

impl<CF: Config> ChipOpening<CF> {
    /// Collect opening values from a dynamic array into vectors.
    ///
    /// This method is used to convert a `ChipOpenedValuesVariable` into a `ChipOpenedValues`, which
    /// are the same values but with each opening converted from a dynamic array into a Rust vector.
    ///
    /// *Safety*: This method also verifies that the length of the dynamic arrays match the expected
    /// length of the vectors.
    pub fn from_variable<A>(
        builder: &mut Builder<CF>,
        chip: &MetaChip<CF::F, A>,
        opening: &ChipOpenedValuesVariable<CF>,
    ) -> Self
    where
        A: ChipBehavior<CF::F>,
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
        let permutation_width = CF::EF::D * chip.permutation_width();
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
            builder.assert_usize_eq(CF::EF::D, chunk.len());
            // Collect the quotient values into vectors.
            let mut quotient_vals = vec![];
            for j in 0..CF::EF::D {
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

impl<CF: Config> FromConstant<CF> for ChipOpenedValuesVariable<CF> {
    type Constant = ChipOpenedValues<CF::EF>;

    fn constant(value: Self::Constant, builder: &mut Builder<CF>) -> Self {
        ChipOpenedValuesVariable {
            preprocessed_local: builder.constant(value.preprocessed_local),
            preprocessed_next: builder.constant(value.preprocessed_next),
            main_local: builder.constant(value.main_local),
            main_next: builder.constant(value.main_next),
            permutation_local: builder.constant(value.permutation_local),
            permutation_next: builder.constant(value.permutation_next),
            quotient: builder.constant(value.quotient),
            cumulative_sum: builder.eval(value.cumulative_sum.cons()),
            log_main_degree: builder.eval(CF::N::from_canonical_usize(value.log_main_degree)),
        }
    }
}
