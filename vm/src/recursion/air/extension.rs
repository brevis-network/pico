use super::Block;
use crate::{machine::extension::BinomialExtension, primitives::consts::EXTENSION_DEGREE};
use p3_field::{
    extension::{BinomialExtensionField, BinomiallyExtendable},
    Field, FieldExtensionAlgebra,
};

pub trait BinomialExtensionUtils<T> {
    fn from_block(block: Block<T>) -> Self;

    fn as_block(&self) -> Block<T>;
}

impl<T: Clone> BinomialExtensionUtils<T> for BinomialExtension<T> {
    fn from_block(block: Block<T>) -> Self {
        Self(block.0)
    }

    fn as_block(&self) -> Block<T> {
        Block(self.0.clone())
    }
}

impl<AF> BinomialExtensionUtils<AF> for BinomialExtensionField<AF, EXTENSION_DEGREE>
where
    AF: Field,
    AF::F: BinomiallyExtendable<EXTENSION_DEGREE>,
{
    fn from_block(block: Block<AF>) -> Self {
        Self::from_base_slice(&block.0)
    }

    fn as_block(&self) -> Block<AF> {
        Block(self.as_base_slice().try_into().unwrap())
    }
}
