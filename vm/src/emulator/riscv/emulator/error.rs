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
    InvalidMemoryAccess(Opcode, u64),

    /// The emulation failed with an unimplemented syscall.
    #[error("unimplemented syscall {0}")]
    UnsupportedSyscall(u32),

    /// The guest asked for an input element the host never supplied. A caller error, not a guest
    /// fault, so it has to reach the caller as a value rather than abort the process it is
    /// embedded in.
    #[error(
        "guest read past the end of stdin: element {stream_ptr} requested, {stream_len} supplied"
    )]
    InsufficientInput {
        stream_ptr: usize,
        stream_len: usize,
    },

    /// A `hint_read` the emulator cannot service: the pointer or the length the guest passed does
    /// not describe a writable hint destination, or that destination was written already. Every
    /// input to the check is guest- or host-supplied, so it reaches the caller as a value for the
    /// same reason [`EmulationError::InsufficientInput`] does.
    #[error("invalid hint read: {0}")]
    InvalidHintRead(String),

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

    /// The AOT batch runner failed before producing a snapshot.
    #[error("aot snapshot execution failed: {0}")]
    AotExecutionFailed(String),

    /// The AOT batch runner returned without advancing and without finishing.
    #[error(
        "aot snapshot batch made no progress (start_cycle={start_cycle}, chunk_batch_target={chunk_batch_target})"
    )]
    AotBatchNoProgress {
        start_cycle: u64,
        chunk_batch_target: u32,
    },

    /// The emulation ended in unconstrained mode
    #[error("ended in unconstrained mode")]
    UnconstrainedEnd,

    /// The AOT runtime or adapter returned a failure. The payload is the
    /// adapter-provided message; callers should propagate or log it rather
    /// than collapse to a generic variant.
    #[error("AOT emulation error: {0}")]
    Aot(String),

    /// The snapshot pipeline was asked for more replay workers than this machine has cores.
    /// Refused before any thread starts: once the snapshot thread runs, a pipeline whose workers
    /// never start fills the snapshot memory pool and waits on it forever.
    #[error("{workers} snapshot pipeline workers requested, but this machine has {cores} cores")]
    TooManyWorkers { workers: usize, cores: usize },

    /// The snapshot pipeline's memory pool, as the environment sizes it, cannot serve the run: it
    /// would wait on the pool forever. Refused before any thread starts, for the same reason.
    #[error("the snapshot pipeline would wait on its memory pool forever: {0}")]
    PipelineMemoryPool(String),
}
