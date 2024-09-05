use crate::opcode::Opcode;
use serde::{Deserialize, Serialize};

/// Arithmetic Logic Unit (ALU) Event
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AluEvent {
    /// The opcode.
    pub opcode: Opcode,
    /// The first operand.
    pub a: u32,
    /// The second operand.
    pub b: u32,
    /// The third operand.
    pub c: u32,
}

impl AluEvent {
    /// Create a new [`AluEvent`].
    #[must_use]
    pub const fn new(opcode: Opcode, a: u32, b: u32, c: u32) -> Self {
        Self { opcode, a, b, c }
    }
}
