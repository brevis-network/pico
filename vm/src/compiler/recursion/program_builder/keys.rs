use crate::{
    compiler::recursion::{
        prelude::*,
        program_builder::p3::fri::{types::DigestVariable, TwoAdicMultiplicativeCosetVariable},
    },
    configs::config::RecursionGenericConfig,
};
use pico_derive::DslVariable;

/// Reference: [pico_machine::stark::VerifyingKey]
#[derive(DslVariable, Clone)]
pub struct BaseVerifyingKeyVariable<RC: RecursionGenericConfig> {
    pub commitment: DigestVariable<RC>,
    pub pc_start: Felt<RC::F>,
    pub preprocessed_sorted_idxs: Array<RC, Var<RC::N>>,
    pub preprocessed_domains: Array<RC, TwoAdicMultiplicativeCosetVariable<RC>>,
}
