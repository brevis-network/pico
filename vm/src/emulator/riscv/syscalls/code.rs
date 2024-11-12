use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

/// System Calls.
///
/// A system call is invoked by the the `ecall` instruction with a specific value in register t0.
/// The syscall number is a 32-bit integer with the following little-endian layout:
///
/// | Byte 0 | Byte 1 | Byte 2 | Byte 3 |
/// | ------ | ------ | ------ | ------ |
/// |   ID   | Table  | Cycles | Unused |
///
/// where:
/// - Byte 0: The system call identifier.
/// - Byte 1: Whether the handler of the system call has its own table. This is used in the CPU
///   table to determine whether to lookup the syscall using the syscall interaction.
/// - Byte 2: The number of additional cycles the syscall uses. This is used to make sure the # of
///   memory accesses is bounded.
/// - Byte 3: Currently unused.
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, EnumIter, Ord, PartialOrd, Serialize, Deserialize,
)]
#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
pub enum SyscallCode {
    /// Halts the program.
    HALT = 0x00_00_00_00,

    /// Write to the output buffer.
    WRITE = 0x00_00_00_02,

    /// Enter unconstrained block.
    ENTER_UNCONSTRAINED = 0x00_00_00_03,

    /// Exit unconstrained block.
    EXIT_UNCONSTRAINED = 0x00_00_00_04,

    /// Emulates the `COMMIT` precompile.
    COMMIT = 0x00_00_00_10,

    /// Emulates the `COMMIT_DEFERRED_PROOFS` precompile.
    COMMIT_DEFERRED_PROOFS = 0x00_00_00_1A,

    /// Emulates the `VERIFY_PICO_PROOF` precompile.
    VERIFY_PICO_PROOF = 0x00_00_00_1B,

    /// Emulates the `HINT_LEN` precompile.
    HINT_LEN = 0x00_00_00_F0,

    /// Emulates the `HINT_READ` precompile.
    HINT_READ = 0x00_00_00_F1,
}

impl SyscallCode {
    /// Create a [`SyscallCode`] from a u32.
    #[must_use]
    pub fn from_u32(value: u32) -> Self {
        match value {
            0x00_00_00_00 => SyscallCode::HALT,
            0x00_00_00_02 => SyscallCode::WRITE,
            0x00_00_00_03 => SyscallCode::ENTER_UNCONSTRAINED,
            0x00_00_00_04 => SyscallCode::EXIT_UNCONSTRAINED,
            0x00_00_00_10 => SyscallCode::COMMIT,
            0x00_00_00_1A => SyscallCode::COMMIT_DEFERRED_PROOFS,
            0x00_00_00_1B => SyscallCode::VERIFY_PICO_PROOF,
            0x00_00_00_F0 => SyscallCode::HINT_LEN,
            0x00_00_00_F1 => SyscallCode::HINT_READ,
            _ => panic!("invalid syscall number: {value}"),
        }
    }

    /// Get the system call identifier.
    #[must_use]
    pub fn syscall_id(self) -> u32 {
        (self as u32).to_le_bytes()[0].into()
    }

    /// Get whether the handler of the system call has its own table.
    #[must_use]
    pub fn should_send(self) -> u32 {
        (self as u32).to_le_bytes()[1].into()
    }

    /// Get the number of additional cycles the syscall uses.
    #[must_use]
    pub fn num_cycles(self) -> u32 {
        (self as u32).to_le_bytes()[2].into()
    }

    /// Map a syscall to another one in order to coalesce their counts.
    #[must_use]
    #[allow(clippy::match_same_arms)]
    pub fn count_map(&self) -> Self {
        *self
    }
}

impl std::fmt::Display for SyscallCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
