//! Recursion associating builder functions

use super::ChipBuilder;
use crate::{
    machine::lookup::{LookupType, SymbolicLookup},
    recursion_v2::{air::Block, types::Address},
};
use p3_field::{AbstractField, Field};
use std::iter::once;

pub trait RecursionBuilder<F: Field>: ChipBuilder<F> {
    fn looking_single<E: Into<Self::Expr>>(
        &mut self,
        addr: Address<E>,
        val: E,
        mult: impl Into<Self::Expr>,
    ) {
        let mut padded_value = core::array::from_fn(|_| Self::Expr::zero());
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
        ));
    }

    fn looked_single<E: Into<Self::Expr>>(
        &mut self,
        addr: Address<E>,
        val: E,
        mult: impl Into<Self::Expr>,
    ) {
        let mut padded_value = core::array::from_fn(|_| Self::Expr::zero());
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
        ));
    }
}
