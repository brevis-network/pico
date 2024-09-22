pub mod alu;
pub mod byte;
pub mod cpu;
pub mod examples;
pub mod memory;
pub mod memory_program;
pub mod program;

use pico_compiler::opcode::Opcode;

// Mark the opcodes which support lookup Temporarily.
// TODO: Finally we will support all.
pub(crate) const SUPPORTED_ALU_LOOKUP_OPCODES: [Opcode; 1] = [Opcode::MUL];
