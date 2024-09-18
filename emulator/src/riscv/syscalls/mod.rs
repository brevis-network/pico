//! Syscall definitions & implementations for the [`crate::Emulator`].

mod code;
mod commit;
mod deferred;
mod halt;
mod hint;
pub mod syscall_context;
mod write;

use std::sync::Arc;

use hashbrown::HashMap;

pub use code::*;
use hint::{HintLenSyscall, HintReadSyscall};

use crate::riscv::syscalls::{
    commit::CommitSyscall, deferred::CommitDeferredSyscall, halt::HaltSyscall,
    syscall_context::SyscallContext,
};
use write::WriteSyscall;

/// A system call in the Pico RISC-V zkVM.
///
/// This trait implements methods needed to emulate a system call inside the [`crate::Emulator`].
pub trait Syscall: Send + Sync {
    /// Emulates the syscall.
    ///
    /// Returns the resulting value of register a0. `arg1` and `arg2` are the values in registers
    /// X10 and X11, respectively. While not a hard requirement, the convention is that the return
    /// value is only for system calls such as `HALT`. Most precompiles use `arg1` and `arg2` to
    /// denote the addresses of the input data, and write the result to the memory at `arg1`.
    fn emulate(&self, ctx: &mut SyscallContext, arg1: u32, arg2: u32) -> Option<u32>;

    /// The number of extra cycles that the syscall takes to emulate.
    ///
    /// Unless this syscall is complex and requires many cycles, this should be zero.
    fn num_extra_cycles(&self) -> u32 {
        0
    }
}

/// Creates the default syscall map.
#[must_use]
pub fn default_syscall_map() -> HashMap<SyscallCode, Arc<dyn Syscall>> {
    let mut syscall_map = HashMap::<SyscallCode, Arc<dyn Syscall>>::default();

    syscall_map.insert(SyscallCode::WRITE, Arc::new(WriteSyscall));

    syscall_map.insert(SyscallCode::HINT_LEN, Arc::new(HintLenSyscall));

    syscall_map.insert(SyscallCode::HINT_READ, Arc::new(HintReadSyscall));

    syscall_map.insert(SyscallCode::COMMIT, Arc::new(CommitSyscall));

    syscall_map.insert(
        SyscallCode::COMMIT_DEFERRED_PROOFS,
        Arc::new(CommitDeferredSyscall),
    );

    syscall_map.insert(SyscallCode::HALT, Arc::new(HaltSyscall));

    syscall_map
}
