pub mod alu;
pub mod byte;
pub mod cpu;
pub mod examples;
pub mod lt;
pub mod memory;
pub mod memory_program;
pub mod program;
pub mod sll;
pub mod sr;

use pico_compiler::opcode::Opcode;

// Mark the opcodes which support lookup Temporarily.
// TODO: Finally we will support all.
pub(crate) const SUPPORTTED_ALU_LOOKUP_OPCODES: [Opcode; 18] = [
    Opcode::ADD,
    Opcode::SUB,
    Opcode::MUL,
    Opcode::MULH,
    Opcode::MULHU,
    Opcode::MULHSU,
    Opcode::DIV,
    Opcode::DIVU,
    Opcode::REM,
    Opcode::REMU,
    Opcode::AND,
    Opcode::OR,
    Opcode::XOR,
    Opcode::SLT,
    Opcode::SLTU,
    Opcode::SLL,
    Opcode::SRL,
    Opcode::SRA,
];
