use crate::compiler::riscv::{disassembler::Elf, program::Program};
use alloc::sync::Arc;
use tracing::debug;

pub enum SourceType {
    RISCV,
}

pub enum Compilable {
    RISCV(Elf),
}

impl Compilable {
    fn compile(&self) -> Arc<Program> {
        // match on self
        match self {
            Compilable::RISCV(elf) => elf.compile(),
        }
    }
}

pub struct Compiler {
    pub source_type: SourceType,
    pub source: Compilable,
}

impl Compiler {
    pub fn new(source_type: SourceType, source_code: &[u8]) -> Self {
        match source_type {
            SourceType::RISCV => {
                let source = Elf::new(source_code).unwrap();
                // construct the compiler
                Self {
                    source_type,
                    source: Compilable::RISCV(source),
                }
            }
        }
    }

    pub fn name(&self) -> String {
        match self.source_type {
            SourceType::RISCV => "RISCV ELF Compiler".to_string(),
        }
    }

    pub fn compile(&self) -> Arc<Program> {
        debug!("Compiling {} source...", self.name());
        self.source.compile()
    }
}
