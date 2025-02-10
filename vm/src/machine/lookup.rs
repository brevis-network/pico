use crate::machine::utils::eval_symbolic_to_virtual_pair;
use p3_air::VirtualPairCol;
use p3_field::Field;
use p3_uni_stark::SymbolicExpression;
use serde::{Deserialize, Serialize};
use strum_macros::{Display, EnumIter};

#[derive(Clone, Debug)]
pub struct VirtualPairLookup<F: Field> {
    /// The values of the interaction.
    pub values: Vec<VirtualPairCol<F>>,
    /// The multiplicity of the interaction.
    pub mult: VirtualPairCol<F>,
    /// The kind of interaction.
    pub kind: LookupType,
    /// The scope of the interaction.
    pub scope: LookupScope,
}

impl<F: Field> VirtualPairLookup<F> {
    pub fn new(
        values: Vec<VirtualPairCol<F>>,
        mult: VirtualPairCol<F>,
        kind: LookupType,
        scope: LookupScope,
    ) -> Self {
        Self {
            values,
            mult,
            kind,
            scope,
        }
    }
}

/// message type enum for lookups
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LookupType {
    /// Interaction with the memory table, such as read and write.
    Memory = 1,

    /// Interaction with the program table, loading an instruction at a given pc address.
    Program = 2,

    /// Interaction with instruction oracle.
    Instruction = 3,

    /// Interaction with the ALU operations.
    Alu = 4,

    /// Interaction with the byte lookup table for byte operations.
    Byte = 5,

    /// Requesting a range check for a given value and range.
    Range = 6,

    /// Interaction with the field op table for field operations.
    Field = 7,

    /// Interaction with a syscall.
    Syscall = 8,

    /// Interaction with the Poseidon2.
    Poseidon2 = 9,

    /// Interaction with the global table.
    Global = 10,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Display,
    EnumIter,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
pub enum LookupScope {
    /// Global scope
    Global = 0,
    /// Regional scope
    Regional,
}

pub(crate) fn symbolic_to_virtual_pair<F: Field>(
    expression: &SymbolicExpression<F>,
) -> VirtualPairCol<F> {
    if expression.degree_multiple() > 1 {
        panic!("degree multiple is too high");
    }

    let (column_weights, constant) = eval_symbolic_to_virtual_pair(expression);

    let column_weights = column_weights.into_iter().collect();

    VirtualPairCol::new(column_weights, constant)
}

/// An interaction is a cross-table lookup.
pub struct SymbolicLookup<E> {
    /// The values of the interaction.
    pub values: Vec<E>,
    /// The multiplicity of the interaction.
    pub multiplicity: E,
    /// The kind of interaction.
    pub kind: LookupType,
    /// The scope of the interaction.
    pub scope: LookupScope,
}

impl<E> SymbolicLookup<E> {
    /// Create a new [`SymbolicLookup`].
    pub const fn new(
        values: Vec<E>,
        multiplicity: E,
        kind: LookupType,
        scope: LookupScope,
    ) -> Self {
        Self {
            values,
            multiplicity,
            kind,
            scope,
        }
    }
}
