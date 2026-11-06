//! AOT Code Generation for Pico VM
//!
//! This crate provides build-time code generation infrastructure for compiling
//! RISC-V programs to native Rust code.

pub mod block_analysis;
pub mod cfg_analysis;
pub mod compiler;
pub mod config;
pub mod constants;
pub mod elf_parser;
pub mod instruction_translator;
pub mod metrics;
pub mod pure_translator;
pub mod types;

// Re-export key types for convenience
pub use block_analysis::BlockAnalyzer;
pub use compiler::{
    pure_dispatch_package, AotCompiler, RuntimeSpec, CODEGEN_STAMP, GENERATOR_FINGERPRINT,
};
pub use config::AotConfig;
pub use elf_parser::{parse_elf, try_parse_elf};
pub use instruction_translator::InstructionTranslator;
pub use types::{Instruction, Opcode, ProgramInfo};
