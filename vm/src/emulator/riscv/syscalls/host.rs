//! What a precompile sees of the emulator running it.
//!
//! A precompile reads and writes guest memory at a clock of its own, may add to the chunk's split
//! budget, and appends one event to the record. [`SyscallHost`] is every one of those effects and
//! nothing else, so a [`Precompile`] emits the same events on any emulator that implements it; the
//! interpreter's implementation is [`SyscallContext`]. The host-side syscalls (hints, writes,
//! commits, deferred proofs, unconstrained blocks, halt, verify) reach the interpreter's state
//! directly and stay plain [`Syscall`]s: another emulator keeps its own handlers for those.
//!
//! What an implementation owes, because the records and the chunk cut are built from it:
//! - [`SyscallHost::clk`] starts at the ECALL's clock, and [`SyscallHost::advance_clk`] moves
//!   only that copy: it stamps the syscall's memory accesses, and the emulator's own clock moves
//!   on by `4 +` [`Syscall::num_extra_cycles`] once the ECALL returns, past every stamp used.
//! - Every recorded access counts towards the chunk's split budget exactly as the interpreter
//!   counts it: a different count is a cut in a different place.
//! - [`SyscallHost::postprocess`] runs once, after the syscall's last access. It returns the
//!   syscall's local-memory windows for its event and moves the CPU's window on each of those
//!   addresses into the record.

use super::{syscall_context::SyscallContext, Syscall, SyscallCode, SyscallEvent};
use crate::{
    chips::chips::riscv_memory::event::{MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord},
    emulator::riscv::{
        event_types::{RvAddr, RvChunk, RvClk, RvValue},
        record::EmulationRecord,
    },
};

/// The emulator as a precompile reaches it. See the module docs for the contract.
pub trait SyscallHost {
    /// The chunk the syscall runs in.
    fn current_chunk(&self) -> RvChunk;

    /// The clock the syscall's memory accesses are stamped with.
    fn clk(&self) -> RvClk;

    /// Move the syscall's clock on, so later accesses to an address already touched land on a
    /// later timestamp.
    fn advance_clk(&mut self, cycles: RvClk);

    // The slices are defined once, here, so every host walks an address range in the same order
    // and the records list the accesses alike.

    /// Read the 8-byte dword at `addr`.
    fn mr_dword(&mut self, addr: RvAddr) -> (MemoryReadRecord, RvValue);

    /// Read `len` consecutive dwords.
    fn mr_dword_slice(
        &mut self,
        addr: RvAddr,
        len: usize,
    ) -> (Vec<MemoryReadRecord>, Vec<RvValue>) {
        let mut records = Vec::with_capacity(len);
        let mut values = Vec::with_capacity(len);
        for i in 0..len {
            let dword_addr = addr.wrapping_add((i as u64) * 8);
            let (record, value) = self.mr_dword(dword_addr);
            records.push(record);
            values.push(value);
        }
        (records, values)
    }

    /// Write the 8-byte dword at `addr`.
    fn mw_dword(&mut self, addr: RvAddr, value: RvValue) -> MemoryWriteRecord;

    /// Write consecutive dwords.
    fn mw_dword_slice(&mut self, addr: RvAddr, values: &[RvValue]) -> Vec<MemoryWriteRecord> {
        let mut records = Vec::with_capacity(values.len());
        for (i, &value) in values.iter().enumerate() {
            let dword_addr = addr.wrapping_add((i as u64) * 8);
            records.push(self.mw_dword(dword_addr, value));
        }
        records
    }

    /// `len` consecutive dwords, unrecorded.
    fn dword_slice_unsafe(&mut self, addr: RvAddr, len: usize) -> Vec<RvValue>;

    /// Count `count` syscall memory events no access counted: a precompile whose ABI is in
    /// words but which reads them a dword at a time owes the difference.
    fn add_syscall_memory_events(&mut self, count: usize);

    /// The record the syscall's event goes into.
    fn record_mut(&mut self) -> &mut EmulationRecord;

    /// The syscall's local-memory windows; see the module docs.
    fn postprocess(&mut self) -> Vec<MemoryLocalEvent>;

    /// The syscall event that pairs with the precompile event, stamped with the current chunk.
    fn syscall_event(
        &self,
        clk: RvClk,
        syscall_id: u32,
        arg1: RvValue,
        arg2: RvValue,
    ) -> SyscallEvent;
}

/// A syscall whose every effect goes through [`SyscallHost`].
///
/// Generic over the host rather than taking `&mut dyn SyscallHost`: the interpreter's precompile
/// path compiles to direct calls, as it did before the trait, and [`Syscall`] keeps taking the
/// interpreter's context because the host-side syscalls need its state.
pub trait Precompile: Send + Sync {
    /// Emulates the precompile; see [`Syscall::emulate`].
    fn emulate<H: SyscallHost>(
        &self,
        ctx: &mut H,
        syscall_code: SyscallCode,
        arg1: RvValue,
        arg2: RvValue,
    ) -> Option<RvValue>;

    /// See [`Syscall::num_extra_cycles`].
    fn num_extra_cycles(&self) -> u32 {
        0
    }
}

impl<P: Precompile> Syscall for P {
    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: RvValue,
        arg2: RvValue,
    ) -> Option<RvValue> {
        Precompile::emulate(self, ctx, syscall_code, arg1, arg2)
    }

    fn num_extra_cycles(&self) -> u32 {
        Precompile::num_extra_cycles(self)
    }
}
