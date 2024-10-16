use crate::compiler::recursion::{
    ir::{Array, Config, Felt, Var},
    prelude::*,
    program_builder::p3::fri::{types::DigestVariable, TwoAdicMultiplicativeCosetVariable},
};
use pico_derive::DslVariable;

/// Reference: [pico_machine::stark::VerifyingKey]
#[derive(DslVariable, Clone)]
pub struct BaseVerifyingKeyVariable<CF: Config> {
    pub commitment: DigestVariable<CF>,
    pub pc_start: Felt<CF::F>,
    pub preprocessed_sorted_idxs: Array<CF, Var<CF::N>>,
    pub preprocessed_domains: Array<CF, TwoAdicMultiplicativeCosetVariable<CF>>,
}
