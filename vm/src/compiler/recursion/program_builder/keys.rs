use crate::{
    compiler::recursion::{
        prelude::*,
        program_builder::p3::fri::{types::DigestVariable, TwoAdicMultiplicativeCosetVariable},
    },
    configs::config::FieldGenericConfig,
};
use pico_derive::DslVariable;

/// Reference: [pico_machine::stark::VerifyingKey]
#[derive(DslVariable, Clone)]
pub struct BaseVerifyingKeyVariable<FC: FieldGenericConfig> {
    pub commitment: DigestVariable<FC>,
    pub pc_start: Felt<FC::F>,
    pub preprocessed_sorted_idxs: Array<FC, Var<FC::N>>,
    pub preprocessed_domains: Array<FC, TwoAdicMultiplicativeCosetVariable<FC>>,
}
