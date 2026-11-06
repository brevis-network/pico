pub mod ec;
pub mod fptower;
pub mod keccak256;
pub mod limb_math;
pub mod poseidon2;
pub mod sha256;
pub mod uint256;

use crate::emulator::AotEmulatorCore;

/// The guest memory a precompile reads and writes, as the compute-only implementations here use it.
///
/// [`AotEmulatorCore`] implements it with its access metadata and snapshots, for proving;
/// [`crate::pure`] implements it on plain memory, for pure execution. One implementation of each
/// precompile serves both.
pub trait PrecompileMemory {
    /// The clock the syscall runs at; reads and writes are stamped relative to it.
    fn clk(&self) -> u32;
    fn read_mem_dword_span_at_clk(&mut self, addr: u64, out: &mut [u64], clk: u32);
    fn write_mem_dword_span_at_clk(&mut self, addr: u64, values: &[u64], clk: u32);
    /// A precompile's first operand, read as one access: a span that runs into memory no guest
    /// access may reach is refused at its start and reads as zero.
    fn read_mem_dword_span_snapshot_syscall(&mut self, addr: u64, out: &mut [u64]);
    /// Whether `dwords` 8-byte slots at `addr` may be loaded as one access; an empty span always
    /// may. A refusal ends the run when the syscall returns.
    fn load_span_allowed(&mut self, addr: u64, dwords: usize) -> bool;
    /// Low 32-bit values stored in 8-byte slots.
    fn read_mem_low32_slot_at_clk(&mut self, addr: u64, clk: u32) -> u32;
    fn write_mem_low32_slot_at_clk(&mut self, addr: u64, value: u32, clk: u32);
    fn read_mem_low32_slot_span_at_clk(&mut self, addr: u64, out: &mut [u32], clk: u32);
    fn write_mem_low32_slot_span_at_clk(&mut self, addr: u64, values: &[u32], clk: u32);
    /// A dword without any access bookkeeping.
    fn read_mem_dword_unsafe(&self, addr: u64) -> u64;
    /// Counts memory events a syscall makes beyond its dword accesses, for chunk splitting.
    fn account_syscall_memory_events(&mut self, count: usize);
}

impl PrecompileMemory for AotEmulatorCore {
    #[inline(always)]
    fn clk(&self) -> u32 {
        self.clk
    }
    #[inline(always)]
    fn read_mem_dword_span_at_clk(&mut self, addr: u64, out: &mut [u64], clk: u32) {
        AotEmulatorCore::read_mem_dword_span_at_clk(self, addr, out, clk)
    }
    #[inline(always)]
    fn write_mem_dword_span_at_clk(&mut self, addr: u64, values: &[u64], clk: u32) {
        AotEmulatorCore::write_mem_dword_span_at_clk(self, addr, values, clk)
    }
    #[inline(always)]
    fn read_mem_dword_span_snapshot_syscall(&mut self, addr: u64, out: &mut [u64]) {
        AotEmulatorCore::read_mem_dword_span_snapshot_syscall(self, addr, out)
    }
    #[inline(always)]
    fn load_span_allowed(&mut self, addr: u64, dwords: usize) -> bool {
        AotEmulatorCore::load_span_allowed(self, addr, dwords)
    }
    #[inline(always)]
    fn read_mem_low32_slot_at_clk(&mut self, addr: u64, clk: u32) -> u32 {
        AotEmulatorCore::read_mem_low32_slot_at_clk(self, addr, clk)
    }
    #[inline(always)]
    fn write_mem_low32_slot_at_clk(&mut self, addr: u64, value: u32, clk: u32) {
        AotEmulatorCore::write_mem_low32_slot_at_clk(self, addr, value, clk)
    }
    #[inline(always)]
    fn read_mem_low32_slot_span_at_clk(&mut self, addr: u64, out: &mut [u32], clk: u32) {
        AotEmulatorCore::read_mem_low32_slot_span_at_clk(self, addr, out, clk)
    }
    #[inline(always)]
    fn write_mem_low32_slot_span_at_clk(&mut self, addr: u64, values: &[u32], clk: u32) {
        AotEmulatorCore::write_mem_low32_slot_span_at_clk(self, addr, values, clk)
    }
    #[inline(always)]
    fn read_mem_dword_unsafe(&self, addr: u64) -> u64 {
        AotEmulatorCore::read_mem_dword_unsafe(self, addr)
    }
    #[inline(always)]
    fn account_syscall_memory_events(&mut self, count: usize) {
        if self.in_syscall() {
            self.chunk_split_state.add_syscall_memory_events(count);
        }
    }
}
