use super::{Array, Builder, Ext, Felt, MemIndex, MemVariable, Ptr, Var, Variable};
use crate::configs::config::FieldGenericConfig;
use pico_derive::DslVariable;

#[derive(DslVariable, Debug, Clone)]
pub struct FriFoldInput<RC: FieldGenericConfig> {
    pub z: Ext<RC::F, RC::EF>,
    pub alpha: Ext<RC::F, RC::EF>,
    pub x: Felt<RC::F>,
    pub log_height: Var<RC::N>,
    pub mat_opening: Array<RC, Ext<RC::F, RC::EF>>,
    pub ps_at_z: Array<RC, Ext<RC::F, RC::EF>>,
    pub alpha_pow: Array<RC, Ext<RC::F, RC::EF>>,
    pub ro: Array<RC, Ext<RC::F, RC::EF>>,
}

#[derive(Debug, Clone)]
pub struct CircuitV2FriFoldInput<RC: FieldGenericConfig> {
    pub z: Ext<RC::F, RC::EF>,
    pub alpha: Ext<RC::F, RC::EF>,
    pub x: Felt<RC::F>,
    pub mat_opening: Vec<Ext<RC::F, RC::EF>>,
    pub ps_at_z: Vec<Ext<RC::F, RC::EF>>,
    pub alpha_pow_input: Vec<Ext<RC::F, RC::EF>>,
    pub ro_input: Vec<Ext<RC::F, RC::EF>>,
}

#[derive(Debug, Clone)]
pub struct CircuitV2FriFoldOutput<RC: FieldGenericConfig> {
    pub alpha_pow_output: Vec<Ext<RC::F, RC::EF>>,
    pub ro_output: Vec<Ext<RC::F, RC::EF>>,
}
