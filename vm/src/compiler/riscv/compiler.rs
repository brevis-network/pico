use crate::compiler::riscv::{disassembler::Elf, program::Program};
use alloc::sync::Arc;
use tracing::debug;

pub enum SourceType {
    RiscV,
}

pub enum Compilable {
    RiscV(Elf),
}

impl Compilable {
    fn compile(&self) -> Arc<Program> {
        // match on self
        match self {
            Compilable::RiscV(elf) => elf.compile(),
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
            SourceType::RiscV => {
                let source = Elf::new(source_code).unwrap();
                // construct the compiler
                Self {
                    source_type,
                    source: Compilable::RiscV(source),
                }
            }
        }
    }

    pub fn name(&self) -> String {
        match self.source_type {
            SourceType::RiscV => "RISCV ELF Compiler".to_string(),
        }
    }

    pub fn compile(&self) -> Arc<Program> {
        debug!("Compiling {} source...", self.name());
        self.source.compile()
    }
}
