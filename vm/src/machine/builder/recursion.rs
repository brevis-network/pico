//! Recursion associating builder functions

use super::ChipBuilder;
use crate::{
    compiler::recursion::{ir::Block, types::Address},
    machine::lookup::{LookupScope, LookupType, SymbolicLookup},
    primitives::consts::PACK_LANES,
};
use p3_field::{Field, PrimeCharacteristicRing};
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

    /// Memory write of a packed block: `lanes` in lanes `0..PACK_LANES`, the constant zero in
    /// the remaining lanes (`Block::packed`). Every producer of a packed block goes through here.
    fn looking_packed<E: Into<Self::Expr>>(
        &mut self,
        addr: Address<E>,
        lanes: [E; PACK_LANES],
        mult: impl Into<Self::Expr>,
    ) {
        let val = Block::<Self::Expr>::packed(lanes.map(Into::into));
        self.looking_block(Address(addr.0.into()), val, mult)
    }

    /// Memory read of a packed block, lane `PACK_LANES..` pinned to the constant zero on the bus:
    /// a hinted block whose padding lanes are not zero does not balance. Every hinted packed
    /// block has at least one reader that goes through here (Poseidon2Packed, DigestSelect,
    /// ExtDotProduct); UnpackBlock reads a block with `looked_block` and only forwards its lanes.
    fn looked_packed<E: Into<Self::Expr>>(
        &mut self,
        addr: Address<E>,
        lanes: [E; PACK_LANES],
        mult: impl Into<Self::Expr>,
    ) {
        let val = Block::<Self::Expr>::packed(lanes.map(Into::into));
        self.looked_block(Address(addr.0.into()), val, mult)
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
