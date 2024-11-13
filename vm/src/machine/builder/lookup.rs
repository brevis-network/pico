//! Lookup associating builder functions

use super::ChipBuilder;
use crate::{
    compiler::{riscv::opcode::RangeCheckOpcode, word::Word},
    configs::config::StarkGenericConfig,
    machine::{
        builder::{AirBuilder, FilteredAirBuilder},
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        lookup::{LookupType, SymbolicLookup},
    },
};
use p3_field::{AbstractField, Field};
use std::iter::once;

/// message builder for the chips.
pub trait LookupBuilder<M> {
    fn looking(&mut self, message: M);

    fn looked(&mut self, message: M);
}

/// A message builder for which sending and receiving messages is a no-op.
pub trait EmptyLookupBuilder: AirBuilder {}

impl<AB: EmptyLookupBuilder, M> LookupBuilder<M> for AB {
    fn looking(&mut self, _message: M) {}

    fn looked(&mut self, _message: M) {}
}

impl<'a, SC: StarkGenericConfig> EmptyLookupBuilder for ProverConstraintFolder<'a, SC> {}
impl<'a, SC: StarkGenericConfig> EmptyLookupBuilder for VerifierConstraintFolder<'a, SC> {}
impl<'a, F: Field, AB: AirBuilder<F = F>> EmptyLookupBuilder for FilteredAirBuilder<'a, AB> {}

pub trait ChipLookupBuilder<F: Field>: ChipBuilder<F> {
    /// Looking for an instruction to be processed.
    #[allow(clippy::too_many_arguments)]
    fn looking_instruction(
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
            LookupType::Instruction,
        ));
    }

    /// Looked for an instruction to be processed.
    #[allow(clippy::too_many_arguments)]
    fn looked_instruction(
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
            LookupType::Instruction,
        ));
    }

    /// Looking for  an ALU operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn looking_alu(
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

    /// Looked for an ALU operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn looked_alu(
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

    /// Sends a byte operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn looking_byte(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        chunk: impl Into<Self::Expr>,
        channel: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.looking_byte_pair(
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
    fn looking_byte_pair(
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

    /// Sends a new range lookup
    fn looking_rangecheck(
        &mut self,
        opcode: RangeCheckOpcode,
        value: impl Into<Self::Expr>,
        chunk: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.looking(SymbolicLookup::new(
            vec![
                Self::Expr::from_canonical_u8(opcode as u8),
                value.into(),
                chunk.into(),
            ],
            multiplicity.into(),
            LookupType::RangeUnified,
        ))
    }

    /// Receives a new range lookup
    fn looked_rangecheck(
        &mut self,
        opcode: RangeCheckOpcode,
        value: impl Into<Self::Expr>,
        chunk: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.looked(SymbolicLookup::new(
            vec![
                Self::Expr::from_canonical_u8(opcode as u8),
                value.into(),
                chunk.into(),
            ],
            multiplicity.into(),
            LookupType::RangeUnified,
        ))
    }

    /// Receives a byte operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn looked_byte(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        chunk: impl Into<Self::Expr>,
        channel: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.looked_byte_pair(
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
    fn looked_byte_pair(
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

    fn looking_syscall(
        &mut self,
        chunk: impl Into<Self::Expr> + Clone,
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
                clk.clone().into(),
                nonce.clone().into(),
                syscall_id.clone().into(),
                arg1.clone().into(),
                arg2.clone().into(),
            ],
            multiplicity.into(),
            LookupType::Syscall,
        ))
    }

    fn looked_syscall(
        &mut self,
        chunk: impl Into<Self::Expr> + Clone,
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
                clk.clone().into(),
                nonce.clone().into(),
                syscall_id.clone().into(),
                arg1.clone().into(),
                arg2.clone().into(),
            ],
            multiplicity.into(),
            LookupType::Syscall,
        ))
    }
}
