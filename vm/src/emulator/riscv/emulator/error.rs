use crate::compiler::riscv::opcode::Opcode;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that the [``Emulator``] can throw.
#[derive(Error, Debug, Serialize, Deserialize)]
pub enum EmulationError {
    /// The emulation failed with a non-zero exit code.
    #[error("emulation failed with exit code {0}")]
    HaltWithNonZeroExitCode(u32),

    /// The emulation failed with an invalid memory access.
    #[error("invalid memory access for opcode {0} and address {1}")]
    InvalidMemoryAccess(Opcode, u32),

    /// The emulation failed with an unimplemented syscall.
    #[error("unimplemented syscall {0}")]
    UnsupportedSyscall(u32),

    /// The emulation failed with a breakpoint.
    #[error("breakpoint encountered")]
    Breakpoint(),

    /// The emulation failed with an exceeded cycle limit.
    #[error("exceeded cycle limit of {0}")]
    ExceededCycleLimit(u64),

    /// The emulation failed because the syscall was called in unconstrained mode.
    #[error("syscall called in unconstrained mode")]
    InvalidSyscallUsage(u64),

    /// The emulation failed with an unimplemented feature.
    #[error("got unimplemented as opcode")]
    Unimplemented(),

    /// The emulation ended in unconstrained mode
    #[error("ended in unconstrained mode")]
    UnconstrainedEnd,
}
