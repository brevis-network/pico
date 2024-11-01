use super::{Array, Builder, Ext, Felt, MemIndex, MemVariable, Ptr, Var, Variable};
use crate::configs::config::FieldGenericConfig;
use pico_derive::DslVariable;

#[derive(DslVariable, Debug, Clone)]
pub struct FriFoldInput<FC: FieldGenericConfig> {
    pub z: Ext<FC::F, FC::EF>,
    pub alpha: Ext<FC::F, FC::EF>,
    pub x: Felt<FC::F>,
    pub log_height: Var<FC::N>,
    pub mat_opening: Array<FC, Ext<FC::F, FC::EF>>,
    pub ps_at_z: Array<FC, Ext<FC::F, FC::EF>>,
    pub alpha_pow: Array<FC, Ext<FC::F, FC::EF>>,
    pub ro: Array<FC, Ext<FC::F, FC::EF>>,
}

#[derive(Debug, Clone)]
pub struct CircuitV2FriFoldInput<FC: FieldGenericConfig> {
    pub z: Ext<FC::F, FC::EF>,
    pub alpha: Ext<FC::F, FC::EF>,
    pub x: Felt<FC::F>,
    pub mat_opening: Vec<Ext<FC::F, FC::EF>>,
    pub ps_at_z: Vec<Ext<FC::F, FC::EF>>,
    pub alpha_pow_input: Vec<Ext<FC::F, FC::EF>>,
    pub ro_input: Vec<Ext<FC::F, FC::EF>>,
}

#[derive(Debug, Clone)]
pub struct CircuitV2FriFoldOutput<FC: FieldGenericConfig> {
    pub alpha_pow_output: Vec<Ext<FC::F, FC::EF>>,
    pub ro_output: Vec<Ext<FC::F, FC::EF>>,
}
