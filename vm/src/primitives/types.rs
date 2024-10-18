#[derive(Debug, Clone, Copy)]
pub enum RecursionProgramType {
    Riscv,
    Deferred,
    Compress,
    Shrink,
    Wrap,
}
