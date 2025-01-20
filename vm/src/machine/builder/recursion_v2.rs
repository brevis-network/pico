//! Recursion associating builder functions

use super::ChipBuilder;
use crate::{
    compiler::recursion_v2::{ir::Block, types::Address},
    machine::lookup::{LookupScope, LookupType, SymbolicLookup},
};
use p3_field::{Field, FieldAlgebra};
use std::iter::once;

pub trait RecursionBuilder<F: Field>: ChipBuilder<F> {
    fn looking_single<E: Into<Self::Expr>>(
        &mut self,
        addr: Address<E>,
        val: E,
        mult: impl Into<Self::Expr>,
    ) {
        let mut padded_value = core::array::from_fn(|_| Self::Expr::ZERO);
        padded_value[0] = val.into();
        self.looking_block(Address(addr.0.into()), Block(padded_value), mult)
    }

    fn looking_block<E: Into<Self::Expr>>(
        &mut self,
        addr: Address<E>,
        val: Block<E>,
        mult: impl Into<Self::Expr>,
    ) {
        self.looking(SymbolicLookup::new(
            once(addr.0).chain(val).map(Into::into).collect(),
            mult.into(),
            LookupType::Memory,
            LookupScope::Regional,
        ));
    }

    fn looked_single<E: Into<Self::Expr>>(
        &mut self,
        addr: Address<E>,
        val: E,
        mult: impl Into<Self::Expr>,
    ) {
        let mut padded_value = core::array::from_fn(|_| Self::Expr::ZERO);
        padded_value[0] = val.into();
        self.looked_block(Address(addr.0.into()), Block(padded_value), mult)
    }

    fn looked_block<E: Into<Self::Expr>>(
        &mut self,
        addr: Address<E>,
        val: Block<E>,
        mult: impl Into<Self::Expr>,
    ) {
        self.looked(SymbolicLookup::new(
            once(addr.0).chain(val).map(Into::into).collect(),
            mult.into(),
            LookupType::Memory,
            LookupScope::Regional,
        ));
    }
}
