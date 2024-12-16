use super::{AsmCompiler, AsmConfig};
use crate::compiler::recursion::{ir::Builder, program::RecursionProgram};
use p3_field::{ExtensionField, PrimeField32, TwoAdicField};

/// A builder that compiles recursion program assembly code.
impl<F, EF> Builder<AsmConfig<F, EF>>
where
    F: PrimeField32 + TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
{
    /// Compile to a program that can be executed in the recursive zkVM.
    pub fn compile_program(self) -> RecursionProgram<F> {
        let mut compiler = AsmCompiler::new();
        compiler.build(self.operations);
        compiler.compile()
    }
}
