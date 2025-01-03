mod columns;
mod constraints;
mod traces;

use crate::chips::chips::syscall::columns::SyscallCols;
use core::fmt;
use p3_field::PrimeField32;
use std::{marker::PhantomData, mem::size_of};

/// The number of main trace columns for `SyscallChip`.
pub const NUM_SYSCALL_COLS: usize = size_of::<SyscallCols<u8>>();

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SyscallChunkKind {
    Riscv,
    Precompile,
}

impl fmt::Display for SyscallChunkKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyscallChunkKind::Riscv => write!(f, "Riscv"),
            SyscallChunkKind::Precompile => write!(f, "Precompile"),
        }
    }
}

/// A chip that stores the syscall invocations.
pub struct SyscallChip<F> {
    chunk_kind: SyscallChunkKind,
    phantom: PhantomData<F>,
}

impl<F: PrimeField32> SyscallChip<F> {
    pub const fn new(chunk_kind: SyscallChunkKind) -> Self {
        Self {
            chunk_kind,
            phantom: PhantomData,
        }
    }

    pub const fn riscv() -> Self {
        Self::new(SyscallChunkKind::Riscv)
    }

    pub const fn precompile() -> Self {
        Self::new(SyscallChunkKind::Precompile)
    }
}
