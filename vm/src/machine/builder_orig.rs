use crate::{
    compiler::word::Word,
    machine::{
        builder::{LookupBuilder, PublicValuesBuilder},
        extension::BinomialExtension,
        lookup::{LookupType, SymbolicLookup},
    },
};
use core::iter::once;
use itertools::Itertools;
use p3_air::{AirBuilder, FilteredAirBuilder};
use p3_field::AbstractField;
use std::array;

/// A trait which contains basic methods for building an AIR.
pub trait BaseAirBuilder: AirBuilder + LookupBuilder<SymbolicLookup<Self::Expr>> {
    /// Returns a sub-builder whose constraints are enforced only when `condition` is not one.
    fn when_not<I: Into<Self::Expr>>(&mut self, condition: I) -> FilteredAirBuilder<Self> {
        self.when_ne(condition, Self::F::one())
    }

    /// Asserts that an iterator of expressions are all equal.
    fn assert_all_eq<I1: Into<Self::Expr>, I2: Into<Self::Expr>>(
        &mut self,
        left: impl IntoIterator<Item = I1>,
        right: impl IntoIterator<Item = I2>,
    ) {
        for (left, right) in left.into_iter().zip_eq(right) {
            self.assert_eq(left, right);
        }
    }

    /// Asserts that an iterator of expressions are all zero.
    fn assert_all_zero<I: Into<Self::Expr>>(&mut self, iter: impl IntoIterator<Item = I>) {
        iter.into_iter().for_each(|expr| self.assert_zero(expr));
    }

    /// Will return `a` if `condition` is 1, else `b`.  This assumes that `condition` is already
    /// checked to be a boolean.
    #[inline]
    fn if_else(
        &mut self,
        condition: impl Into<Self::Expr> + Clone,
        a: impl Into<Self::Expr> + Clone,
        b: impl Into<Self::Expr> + Clone,
    ) -> Self::Expr {
        condition.clone().into() * a.into() + (Self::Expr::one() - condition.into()) * b.into()
    }

    /// Index an array of expressions using an index bitmap.  This function assumes that the
    /// `EIndex` type is a boolean and that `index_bitmap`'s entries sum to 1.
    fn index_array(
        &mut self,
        array: &[impl Into<Self::Expr> + Clone],
        index_bitmap: &[impl Into<Self::Expr> + Clone],
    ) -> Self::Expr {
        let mut result = Self::Expr::zero();

        for (value, i) in array.iter().zip_eq(index_bitmap) {
            result += value.clone().into() * i.clone().into();
        }

        result
    }
}
/// A trait which contains methods for byte interactions in an AIR.
pub trait ByteAirBuilder: BaseAirBuilder {
    /// Sends a byte operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn send_byte(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        chunk: impl Into<Self::Expr>,
        channel: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.send_byte_pair(
            opcode,
            a,
            Self::Expr::zero(),
            b,
            c,
            chunk,
            channel,
            multiplicity,
        );
    }

    /// Sends a byte operation with two outputs to be processed.
    #[allow(clippy::too_many_arguments)]
    fn send_byte_pair(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a1: impl Into<Self::Expr>,
        a2: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        chunk: impl Into<Self::Expr>,
        channel: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.looking(SymbolicLookup::new(
            vec![
                opcode.into(),
                a1.into(),
                a2.into(),
                b.into(),
                c.into(),
                chunk.into(),
                channel.into(),
            ],
            multiplicity.into(),
            LookupType::Byte,
        ));
    }

    /// Receives a byte operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn receive_byte(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        chunk: impl Into<Self::Expr>,
        channel: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.receive_byte_pair(
            opcode,
            a,
            Self::Expr::zero(),
            b,
            c,
            chunk,
            channel,
            multiplicity,
        );
    }

    /// Receives a byte operation with two outputs to be processed.
    #[allow(clippy::too_many_arguments)]
    fn receive_byte_pair(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a1: impl Into<Self::Expr>,
        a2: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        chunk: impl Into<Self::Expr>,
        channel: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.looked(SymbolicLookup::new(
            vec![
                opcode.into(),
                a1.into(),
                a2.into(),
                b.into(),
                c.into(),
                chunk.into(),
                channel.into(),
            ],
            multiplicity.into(),
            LookupType::Byte,
        ));
    }
}

/// A trait which contains methods related to ALU interactions in an AIR.
pub trait AluAirBuilder: BaseAirBuilder {
    /// Sends an ALU operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn send_alu(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: Word<impl Into<Self::Expr>>,
        b: Word<impl Into<Self::Expr>>,
        c: Word<impl Into<Self::Expr>>,
        chunk: impl Into<Self::Expr>,
        channel: impl Into<Self::Expr>,
        nonce: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values = once(opcode.into())
            .chain(a.0.into_iter().map(Into::into))
            .chain(b.0.into_iter().map(Into::into))
            .chain(c.0.into_iter().map(Into::into))
            .chain(once(chunk.into()))
            .chain(once(channel.into()))
            .chain(once(nonce.into()))
            .collect();

        self.looking(SymbolicLookup::new(
            values,
            multiplicity.into(),
            LookupType::Alu,
        ));
    }

    /// Receives an ALU operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn receive_alu(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: Word<impl Into<Self::Expr>>,
        b: Word<impl Into<Self::Expr>>,
        c: Word<impl Into<Self::Expr>>,
        chunk: impl Into<Self::Expr>,
        channel: impl Into<Self::Expr>,
        nonce: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values = once(opcode.into())
            .chain(a.0.into_iter().map(Into::into))
            .chain(b.0.into_iter().map(Into::into))
            .chain(c.0.into_iter().map(Into::into))
            .chain(once(chunk.into()))
            .chain(once(channel.into()))
            .chain(once(nonce.into()))
            .collect();

        self.looked(SymbolicLookup::new(
            values,
            multiplicity.into(),
            LookupType::Alu,
        ));
    }

    /// Sends an syscall operation to be processed (with "ECALL" opcode).
    #[allow(clippy::too_many_arguments)]
    fn send_syscall(
        &mut self,
        chunk: impl Into<Self::Expr> + Clone,
        channel: impl Into<Self::Expr> + Clone,
        clk: impl Into<Self::Expr> + Clone,
        nonce: impl Into<Self::Expr> + Clone,
        syscall_id: impl Into<Self::Expr> + Clone,
        arg1: impl Into<Self::Expr> + Clone,
        arg2: impl Into<Self::Expr> + Clone,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.looking(SymbolicLookup::new(
            vec![
                chunk.clone().into(),
                channel.clone().into(),
                clk.clone().into(),
                nonce.clone().into(),
                syscall_id.clone().into(),
                arg1.clone().into(),
                arg2.clone().into(),
            ],
            multiplicity.into(),
            LookupType::Syscall,
        ));
    }

    /// Receives a syscall operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn receive_syscall(
        &mut self,
        chunk: impl Into<Self::Expr> + Clone,
        channel: impl Into<Self::Expr> + Clone,
        clk: impl Into<Self::Expr> + Clone,
        nonce: impl Into<Self::Expr> + Clone,
        syscall_id: impl Into<Self::Expr> + Clone,
        arg1: impl Into<Self::Expr> + Clone,
        arg2: impl Into<Self::Expr> + Clone,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.looked(SymbolicLookup::new(
            vec![
                chunk.clone().into(),
                channel.clone().into(),
                clk.clone().into(),
                nonce.clone().into(),
                syscall_id.clone().into(),
                arg1.clone().into(),
                arg2.clone().into(),
            ],
            multiplicity.into(),
            LookupType::Syscall,
        ));
    }
}

/// A builder that can operation on extension elements.
pub trait ExtensionAirBuilder: BaseAirBuilder {
    /// Asserts that the two field extensions are equal.
    fn assert_ext_eq<I: Into<Self::Expr>>(
        &mut self,
        left: BinomialExtension<I>,
        right: BinomialExtension<I>,
    ) {
        for (left, right) in left.0.into_iter().zip(right.0) {
            self.assert_eq(left, right);
        }
    }

    /// Checks if an extension element is a base element.
    fn assert_is_base_element<I: Into<Self::Expr> + Clone>(
        &mut self,
        element: BinomialExtension<I>,
    ) {
        let base_slice = element.as_base_slice();
        let degree = base_slice.len();
        base_slice[1..degree].iter().for_each(|coeff| {
            self.assert_zero(coeff.clone().into());
        });
    }

    /// Performs an if else on extension elements.
    fn if_else_ext(
        &mut self,
        condition: impl Into<Self::Expr> + Clone,
        a: BinomialExtension<impl Into<Self::Expr> + Clone>,
        b: BinomialExtension<impl Into<Self::Expr> + Clone>,
    ) -> BinomialExtension<Self::Expr> {
        BinomialExtension(array::from_fn(|i| {
            self.if_else(condition.clone(), a.0[i].clone(), b.0[i].clone())
        }))
    }
}

/// A trait that contains the common helper methods for building `Pico recursion` and Pico machine
/// AIRs.
pub trait MachineAirBuilder: BaseAirBuilder + ExtensionAirBuilder + PublicValuesBuilder {}

/// A trait which contains all helper methods for building Pico machine AIRs.
pub trait PicoAirBuilder: MachineAirBuilder + ByteAirBuilder + AluAirBuilder {}

impl<AB: AirBuilder + LookupBuilder<SymbolicLookup<AB::Expr>>> BaseAirBuilder for AB {}
impl<AB: BaseAirBuilder> ByteAirBuilder for AB {}
impl<AB: BaseAirBuilder> AluAirBuilder for AB {}

impl<AB: BaseAirBuilder> ExtensionAirBuilder for AB {}
impl<AB: BaseAirBuilder + PublicValuesBuilder> MachineAirBuilder for AB {}
impl<AB: BaseAirBuilder + PublicValuesBuilder> PicoAirBuilder for AB {}
