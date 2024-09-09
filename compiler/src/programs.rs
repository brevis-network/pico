//! RV32IM ELFs used for testing.

#[allow(dead_code)]
#[allow(missing_docs)]
pub mod tests {
    use crate::Program;

    const ELF: &[u8] = include_bytes!("../test_data/riscv32im-succinct-zkvm-elf");

    #[must_use]
    #[allow(clippy::unreadable_literal)]
    pub fn simple_fibo_program() -> Program {
        Program::from(ELF).unwrap()
    }
}
