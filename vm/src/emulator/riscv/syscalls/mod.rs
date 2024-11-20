//! Syscall definitions & implementations for the [`crate::Emulator`].

pub mod code;
mod commit;
mod deferred;
mod halt;
mod hint;
pub mod precompiles;
pub mod syscall_context;
mod write;

use std::sync::Arc;

pub use code::*;
use hashbrown::HashMap;
use hint::{HintLenSyscall, HintReadSyscall};
use precompiles::keccak256::permute::Keccak256PermuteSyscall;
use serde::{Deserialize, Serialize};

use crate::emulator::riscv::syscalls::{
    commit::CommitSyscall,
    deferred::CommitDeferredSyscall,
    halt::HaltSyscall,
    precompiles::sha256::{compress::Sha256CompressSyscall, extend::Sha256ExtendSyscall},
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
    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32>;

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

    syscall_map.insert(SyscallCode::SHA_EXTEND, Arc::new(Sha256ExtendSyscall));

    syscall_map.insert(SyscallCode::SHA_COMPRESS, Arc::new(Sha256CompressSyscall));

    syscall_map.insert(
        SyscallCode::COMMIT_DEFERRED_PROOFS,
        Arc::new(CommitDeferredSyscall),
    );

    syscall_map.insert(SyscallCode::HALT, Arc::new(HaltSyscall));

    syscall_map.insert(
        SyscallCode::KECCAK_PERMUTE,
        Arc::new(Keccak256PermuteSyscall),
    );

    syscall_map
}

/// Syscall Event.
///
/// This object encapsulated the information needed to prove a syscall invocation from the CPU table.
/// This includes its shard, clk, syscall id, arguments, other relevant information.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SyscallEvent {
    /// The chunk number.
    pub chunk: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The lookup id.
    pub lookup_id: u128,
    /// The syscall id.
    pub syscall_id: u32,
    /// The first argument.
    pub arg1: u32,
    /// The second operand.
    pub arg2: u32,
    /// The nonce for the syscall.
    pub nonce: u32,
}
