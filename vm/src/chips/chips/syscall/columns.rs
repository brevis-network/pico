use pico_derive::AlignedBorrow;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct SyscallCols<T> {
    /// The chunk number of the syscall.
    pub chunk: T,

    /// The clk of the syscall.
    pub clk: T,

    /// The syscall_id of the syscall.
    pub syscall_id: T,

    /// The arg1.
    pub arg1: T,

    /// The arg2.
    pub arg2: T,

    pub is_real: T,
}
