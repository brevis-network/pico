use crate::compiler::riscv::opcode::Opcode;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// A run that ended abnormally: why, and the exit code the host reports for it. Guest halts with
/// a non-zero code and the faults the emulator detects both end here. No proof of such a run
/// verifies (Pico is Type 1 under the zkevm-standards termination semantics); see
/// `docs/guest-runtime.md` for the codes.
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[error("{reason} (exit code {exit_code})")]
pub struct AbnormalTermination {
    pub reason: TerminationReason,
    pub exit_code: u32,
}

impl AbnormalTermination {
    /// A guest halt with a non-zero `exit_code`, and the reason tag it passed in `a1`.
    pub fn halt(exit_code: u32, reason_tag: u64) -> Self {
        Self {
            reason: TerminationReason::from_halt_tag(reason_tag),
            exit_code,
        }
    }

    /// A fault the emulator detected, with the exit code a native process gets for it.
    pub fn fault(reason: TerminationReason) -> Self {
        Self {
            exit_code: reason.fault_exit_code(),
            reason,
        }
    }
}

/// The reason tags a guest passes in `a1` to `HALT`. Only read when the exit code is non-zero.
/// Anything else in `a1` reads as [`TerminationReason::Exit`]; the tags carry a prefix so that a
/// value an older runtime left there is not taken for one.
pub mod halt_reason {
    const PREFIX: u64 = 0x7069_636f << 32; // "pico"
    pub const EXIT: u64 = 0;
    pub const PANIC: u64 = PREFIX | 1;
    pub const ABORT: u64 = PREFIX | 2;
    pub const OUT_OF_MEMORY: u64 = PREFIX | 3;
}

/// The exit codes the guest runtime halts with for its own failures: what a native process
/// reports for the same failure.
pub mod exit_code {
    /// A Rust panic, as a panicking Rust process exits.
    pub const PANIC: u32 = 101;
    /// `abort()` and an exhausted heap: 128 + SIGABRT.
    pub const ABORT: u32 = 134;
}

/// Why a run ended abnormally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TerminationReason {
    /// The guest halted with a non-zero code of its own: `main`'s return value, or a direct
    /// `syscall_halt`.
    Exit,
    /// A Rust panic.
    Panic,
    /// `abort()`, or a failed C `assert()`.
    Abort,
    /// The heap is exhausted.
    OutOfMemory,
    /// An access past the top of guest memory.
    InvalidMemoryAccess { opcode: Opcode, addr: u64 },
    /// An access below the lowest segment address: no segment loads there, and no access there is
    /// provable.
    NullAccess { opcode: Opcode, addr: u64 },
    /// An access into the stack guard, the gap between the heap and the stack: the stack ran past
    /// its bottom, or the heap past its end.
    StackOverflow { opcode: Opcode, addr: u64 },
    /// A store into the program's code.
    StoreToCode { opcode: Opcode, addr: u64 },
    /// `unimp` at `pc`, which is also what `core::intrinsics::abort` and `std::process::abort`
    /// emit.
    IllegalInstruction { pc: u64 },
    /// `ebreak` at `pc`.
    Breakpoint { pc: u64 },
    /// A jump or taken branch at `pc` to `target`, which is not 4-aligned: RISC-V's
    /// instruction-address-misaligned exception, raised on the jump. Never rounded down.
    MisalignedJumpTarget { pc: u64, target: u64 },
    /// Execution would continue at `pc`, which holds none of the program's instructions: a jump
    /// or branch out of the code, or a fall-through past its last instruction.
    OutsideProgram { pc: u64 },
}

impl TerminationReason {
    fn from_halt_tag(tag: u64) -> Self {
        match tag {
            halt_reason::PANIC => Self::Panic,
            halt_reason::ABORT => Self::Abort,
            halt_reason::OUT_OF_MEMORY => Self::OutOfMemory,
            _ => Self::Exit,
        }
    }

    /// The exit code for a fault the emulator detects: 128 + the signal a native process gets.
    fn fault_exit_code(&self) -> u32 {
        match self {
            Self::Exit => 1,
            Self::Panic => exit_code::PANIC,
            Self::Abort | Self::OutOfMemory => exit_code::ABORT,
            Self::InvalidMemoryAccess { .. }
            | Self::NullAccess { .. }
            | Self::StackOverflow { .. }
            | Self::StoreToCode { .. }
            | Self::OutsideProgram { .. } => 128 + 11, // SIGSEGV
            Self::IllegalInstruction { .. } => 128 + 4, // SIGILL
            Self::Breakpoint { .. } => 128 + 5,         // SIGTRAP
            Self::MisalignedJumpTarget { .. } => 128 + 7, // SIGBUS
        }
    }
}

impl fmt::Display for TerminationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exit => f.write_str("the guest exited with a non-zero code"),
            Self::Panic => f.write_str("the guest panicked"),
            Self::Abort => f.write_str("the guest aborted"),
            Self::OutOfMemory => f.write_str("the guest ran out of heap"),
            Self::InvalidMemoryAccess { opcode, addr } => {
                write!(f, "invalid memory access: {opcode} at {addr:#x}")
            }
            Self::NullAccess { opcode, addr } => {
                write!(f, "null access: {opcode} at {addr:#x}")
            }
            Self::StackOverflow { opcode, addr } => {
                write!(
                    f,
                    "stack overflow: {opcode} at {addr:#x}, in the stack guard"
                )
            }
            Self::StoreToCode { opcode, addr } => {
                write!(f, "store into code: {opcode} at {addr:#x}")
            }
            Self::IllegalInstruction { pc } => write!(f, "illegal instruction at {pc:#x}"),
            Self::Breakpoint { pc } => write!(f, "breakpoint at {pc:#x}"),
            Self::MisalignedJumpTarget { pc, target } => {
                write!(f, "jump at {pc:#x} to the misaligned address {target:#x}")
            }
            Self::OutsideProgram { pc } => {
                write!(f, "execution reached {pc:#x}, outside the program")
            }
        }
    }
}

/// Errors that the [``Emulator``] can throw.
#[derive(Error, Debug, Serialize, Deserialize)]
pub enum EmulationError {
    /// The guest halted with a non-zero exit code, or the emulator found a fault in it.
    #[error("abnormal termination: {0}")]
    AbnormalTermination(AbnormalTermination),

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

    /// The emulation failed with an exceeded cycle limit.
    #[error("exceeded cycle limit of {0}")]
    ExceededCycleLimit(u64),

    /// The emulation failed because the syscall was called in unconstrained mode.
    #[error("syscall called in unconstrained mode")]
    InvalidSyscallUsage(u64),

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

    /// The process holds fewer records at once than the snapshot pipeline's chunks have segments,
    /// each of which holds a history slot until the chunk is whole: a chunk would wait for a slot
    /// forever. Refused before any thread starts, for the same reason.
    #[error("the snapshot pipeline would wait for a history slot forever: {0}")]
    PipelineHistorySlots(String),

    /// The snapshot pipeline was asked for AOT replay workers it cannot run as asked. Refused
    /// before any thread starts, rather than run on interpreters under an AOT label.
    #[error("the snapshot pipeline cannot run AOT replay workers: {0}")]
    UnsupportedReplayWorkers(String),
}

// By hand rather than `#[from]`, which would also make the termination the error's source and
// print its reason a second time in every error chain.
impl From<AbnormalTermination> for EmulationError {
    fn from(termination: AbnormalTermination) -> Self {
        Self::AbnormalTermination(termination)
    }
}

impl EmulationError {
    /// A load or store the emulator does not allow.
    pub fn invalid_memory_access(opcode: Opcode, addr: u64) -> Self {
        AbnormalTermination::fault(TerminationReason::InvalidMemoryAccess { opcode, addr }).into()
    }

    /// A jump or taken branch at `pc` to a `target` that is not 4-aligned.
    pub fn misaligned_jump(pc: u64, target: u64) -> Self {
        AbnormalTermination::fault(TerminationReason::MisalignedJumpTarget { pc, target }).into()
    }

    /// Execution reaching `pc`, outside the program's instructions.
    pub fn outside_program(pc: u64) -> Self {
        AbnormalTermination::fault(TerminationReason::OutsideProgram { pc }).into()
    }

    /// An `unimp` at `pc`.
    pub fn illegal_instruction(pc: u64) -> Self {
        AbnormalTermination::fault(TerminationReason::IllegalInstruction { pc }).into()
    }

    /// Why the run ended and its exit code, for a run that ended abnormally.
    pub fn abnormal_termination(&self) -> Option<&AbnormalTermination> {
        match self {
            Self::AbnormalTermination(t) => Some(t),
            _ => None,
        }
    }

    /// The exit code the host reports, for a run that ended abnormally.
    pub fn exit_code(&self) -> Option<u32> {
        self.abnormal_termination().map(|t| t.exit_code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_halt_reads_its_reason_from_the_tag() {
        for (tag, reason) in [
            (halt_reason::EXIT, TerminationReason::Exit),
            (halt_reason::PANIC, TerminationReason::Panic),
            (halt_reason::ABORT, TerminationReason::Abort),
            (halt_reason::OUT_OF_MEMORY, TerminationReason::OutOfMemory),
        ] {
            assert_eq!(AbnormalTermination::halt(7, tag).reason, reason);
        }
    }

    /// What an older runtime leaves in `a1` (the old `sys_panic` left the message length there)
    /// must not read as a runtime failure.
    #[test]
    fn an_untagged_halt_is_a_plain_exit() {
        for stray in [1, 2, 3, 42, u64::MAX] {
            let t = AbnormalTermination::halt(1, stray);
            assert_eq!(t.reason, TerminationReason::Exit);
            assert_eq!(t.exit_code, 1, "the guest's code is kept as given");
        }
    }

    #[test]
    fn a_fault_takes_the_code_a_native_process_gets() {
        let code = |reason| AbnormalTermination::fault(reason).exit_code;
        assert_eq!(code(TerminationReason::IllegalInstruction { pc: 0 }), 132);
        assert_eq!(code(TerminationReason::Breakpoint { pc: 0 }), 133);
        assert_eq!(code(TerminationReason::OutOfMemory), 134);
        let misaligned = TerminationReason::MisalignedJumpTarget { pc: 0, target: 2 };
        assert_eq!(code(misaligned), 135);
        assert_eq!(code(TerminationReason::OutsideProgram { pc: 0 }), 139);
        let access = TerminationReason::InvalidMemoryAccess {
            opcode: Opcode::LW,
            addr: 0x10,
        };
        assert_eq!(code(access), 139);
        assert_eq!(
            EmulationError::from(AbnormalTermination::fault(access)).exit_code(),
            Some(139)
        );
    }
}
