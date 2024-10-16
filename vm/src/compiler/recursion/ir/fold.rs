use pico_derive::DslVariable;

use super::{Ext, Felt, Var};
use crate::compiler::recursion::ir::{
    Array, Builder, Config, MemIndex, MemVariable, Ptr, Variable,
};

#[derive(DslVariable, Debug, Clone)]
pub struct FriFoldInput<CF: Config> {
    pub z: Ext<CF::F, CF::EF>,
    pub alpha: Ext<CF::F, CF::EF>,
    pub x: Felt<CF::F>,
    pub log_height: Var<CF::N>,
    pub mat_opening: Array<CF, Ext<CF::F, CF::EF>>,
    pub ps_at_z: Array<CF, Ext<CF::F, CF::EF>>,
    pub alpha_pow: Array<CF, Ext<CF::F, CF::EF>>,
    pub ro: Array<CF, Ext<CF::F, CF::EF>>,
}

#[derive(Debug, Clone)]
pub struct CircuitV2FriFoldInput<CF: Config> {
    pub z: Ext<CF::F, CF::EF>,
    pub alpha: Ext<CF::F, CF::EF>,
    pub x: Felt<CF::F>,
    pub mat_opening: Vec<Ext<CF::F, CF::EF>>,
    pub ps_at_z: Vec<Ext<CF::F, CF::EF>>,
    pub alpha_pow_input: Vec<Ext<CF::F, CF::EF>>,
    pub ro_input: Vec<Ext<CF::F, CF::EF>>,
}

#[derive(Debug, Clone)]
pub struct CircuitV2FriFoldOutput<CF: Config> {
    pub alpha_pow_output: Vec<Ext<CF::F, CF::EF>>,
    pub ro_output: Vec<Ext<CF::F, CF::EF>>,
}
