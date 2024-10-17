use super::{config::AsmConfig, AsmCompiler};
use crate::compiler::recursion::{prelude::Builder, program::RecursionProgram};
use p3_field::{ExtensionField, PrimeField32, TwoAdicField};

/// A builder that compiles assembly code.
pub type AsmBuilder<F, EF> = Builder<AsmConfig<F, EF>>;

impl<F: PrimeField32 + TwoAdicField, EF: ExtensionField<F> + TwoAdicField> AsmBuilder<F, EF> {
    /// Compile to a program that can be executed in the recursive zkVM.
    pub fn compile_program(self) -> RecursionProgram<F> {
        let mut compiler = AsmCompiler::new();
        compiler.build(self.operations);
        compiler.compile()
    }
}
