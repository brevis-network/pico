use crate::compiler::addr::Addr;
use pico_derive::AlignedBorrow;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct SyscallCols<T> {
    /// The chunk the syscall was issued in.
    ///
    /// Carried on both the syscall bus and the global message, so the precompile's chunk is
    /// pinned to the CPU's. `clk` alone cannot do this: it restarts at zero every chunk.
    pub chunk: T,

    /// The clk of the syscall.
    pub clk: T,

    /// The syscall_id of the syscall.
    pub syscall_id: T,

    /// The arg1 (48-bit address, 3 x 16-bit limbs).
    pub arg1: Addr<T>,

    /// The arg2 (48-bit address, 3 x 16-bit limbs).
    pub arg2: Addr<T>,

    pub is_real: T,
}
