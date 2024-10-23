use super::p3::fri::types::{DigestVariable, PcsProofVariable};
use crate::{
    compiler::recursion::prelude::*,
    configs::config::FieldGenericConfig,
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
pub struct BaseProofVariable<RC: FieldGenericConfig> {
    pub commitment: BaseCommitmentsVariable<RC>,
    pub opened_values: BaseOpenedValuesVariable<RC>,
    pub opening_proof: PcsProofVariable<RC>,
    pub public_values: Array<RC, Felt<RC::F>>,
    pub quotient_data: Array<RC, QuotientDataVariable<RC>>,
    pub sorted_indices: Array<RC, Var<RC::N>>,
    // todo: public values?
}

/// Reference: [pico_machine::BaseCommitments]
#[derive(DslVariable, Clone)]
pub struct BaseCommitmentsVariable<RC: FieldGenericConfig> {
    pub main_commit: DigestVariable<RC>,
    pub permutation_commit: DigestVariable<RC>,
    pub quotient_commit: DigestVariable<RC>,
}

/// Reference: [pico_machine::BaseOpenedValues]
#[derive(DslVariable, Debug, Clone)]
pub struct BaseOpenedValuesVariable<RC: FieldGenericConfig> {
    pub chips_opened_values: Array<RC, ChipOpenedValuesVariable<RC>>,
}

// todo: consider necessity
/// Reference: [pico_machine::proof::ChipOpenedValues]
#[derive(Debug, Clone)]
pub struct ChipOpening<RC: FieldGenericConfig> {
    pub preprocessed_local: Vec<Ext<RC::F, RC::EF>>,
    pub preprocessed_next: Vec<Ext<RC::F, RC::EF>>,
    pub main_local: Vec<Ext<RC::F, RC::EF>>,
    pub main_next: Vec<Ext<RC::F, RC::EF>>,
    pub permutation_local: Vec<Ext<RC::F, RC::EF>>,
    pub permutation_next: Vec<Ext<RC::F, RC::EF>>,
    pub quotient: Vec<Vec<Ext<RC::F, RC::EF>>>,
    pub cumulative_sum: Ext<RC::F, RC::EF>,
    pub log_main_degree: Var<RC::N>,
}

/// Reference: [pico_machine::stark::ChipOpenedValues]
#[derive(DslVariable, Debug, Clone)]
pub struct ChipOpenedValuesVariable<RC: FieldGenericConfig> {
    pub preprocessed_local: Array<RC, Ext<RC::F, RC::EF>>,
    pub preprocessed_next: Array<RC, Ext<RC::F, RC::EF>>,
    pub main_local: Array<RC, Ext<RC::F, RC::EF>>,
    pub main_next: Array<RC, Ext<RC::F, RC::EF>>,
    pub permutation_local: Array<RC, Ext<RC::F, RC::EF>>,
    pub permutation_next: Array<RC, Ext<RC::F, RC::EF>>,
    pub quotient: Array<RC, Array<RC, Ext<RC::F, RC::EF>>>,
    pub cumulative_sum: Ext<RC::F, RC::EF>,
    pub log_main_degree: Var<RC::N>,
}

#[derive(DslVariable, Clone, Copy)]
pub struct QuotientDataVariable<RC: FieldGenericConfig> {
    pub log_quotient_degree: Var<RC::N>,
    pub quotient_size: Var<RC::N>,
}

impl<RC: FieldGenericConfig> ChipOpening<RC> {
    /// Collect opening values from a dynamic array into vectors.
    ///
    /// This method is used to convert a `ChipOpenedValuesVariable` into a `ChipOpenedValues`, which
    /// are the same values but with each opening converted from a dynamic array into a Rust vector.
    ///
    /// *Safety*: This method also verifies that the length of the dynamic arrays match the expected
    /// length of the vectors.
    pub fn from_variable<A>(
        builder: &mut Builder<RC>,
        chip: &MetaChip<RC::F, A>,
        opening: &ChipOpenedValuesVariable<RC>,
    ) -> Self
    where
        A: ChipBehavior<RC::F>,
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
        let permutation_width = RC::EF::D * chip.permutation_width();
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
            builder.assert_usize_eq(RC::EF::D, chunk.len());
            // Collect the quotient values into vectors.
            let mut quotient_vals = vec![];
            for j in 0..RC::EF::D {
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

impl<RC: FieldGenericConfig> FromConstant<RC> for ChipOpenedValuesVariable<RC> {
    type Constant = ChipOpenedValues<RC::EF>;

    fn constant(value: Self::Constant, builder: &mut Builder<RC>) -> Self {
        ChipOpenedValuesVariable {
            preprocessed_local: builder.constant(value.preprocessed_local),
            preprocessed_next: builder.constant(value.preprocessed_next),
            main_local: builder.constant(value.main_local),
            main_next: builder.constant(value.main_next),
            permutation_local: builder.constant(value.permutation_local),
            permutation_next: builder.constant(value.permutation_next),
            quotient: builder.constant(value.quotient),
            cumulative_sum: builder.eval(value.cumulative_sum.cons()),
            log_main_degree: builder.eval(RC::N::from_canonical_usize(value.log_main_degree)),
        }
    }
}
