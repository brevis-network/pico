//! The loads and stores whose address is not a multiple of their width (Zicclsm).
//!
//! `MemoryReadWrite` proves the aligned ones and refuses the rest through its alignment
//! constraints. This chip receives the same dispatch from the Cpu chip, so a misaligned access can
//! be proven here and nowhere else. It is correct for an aligned access too, so which of the two
//! chips takes an aligned one changes nothing.
//!
//! A row reads the dword that holds the access's first byte, at `clk + Memory`, as
//! `MemoryReadWrite` does. An access that runs past that dword also reads or writes the next one,
//! at `clk + C`: a load or a store leaves that position free, since its `c` is an immediate. The
//! two are different dwords, and the next instruction starts at `clk + 4`, so the memory
//! argument's strictly increasing timestamps per address hold.

use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
pub mod traces;

#[cfg(test)]
mod tests;

/// The chip for misaligned loads and stores.
#[derive(Default)]
pub struct MemoryUnalignedChip<F>(PhantomData<F>);
