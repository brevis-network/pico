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
pub mod post_processor;
pub mod types;

// Re-export key types for convenience
pub use block_analysis::BlockAnalyzer;
pub use compiler::AotCompiler;
pub use config::AotConfig;
pub use elf_parser::parse_elf;
pub use instruction_translator::InstructionTranslator;
pub use post_processor::AotPostProcessor;
pub use types::{Instruction, Opcode, ProgramInfo};
