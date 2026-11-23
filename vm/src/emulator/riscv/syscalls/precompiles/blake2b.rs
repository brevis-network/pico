//! `BLAKE2B_ROUNDS`: rounds `0..n` of BLAKE2b's schedule on a working vector in guest memory. The
//! buffer layout and what the chips prove are in [`crate::chips::precompiles::blake2b`].

use crate::{
    chips::{
        chips::riscv_memory::event::{MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord},
        precompiles::blake2b::{rounds, MAX_ROUNDS_PER_CALL, MESSAGE_DWORDS, STATE_DWORDS},
    },
    emulator::riscv::{
        event_types::{RvAddr, RvChunk, RvClk, RvValue},
        syscalls::{
            host::{Precompile, SyscallHost},
            precompiles::{assert_dword_aligned_precompile, PrecompileEvent},
            SyscallCode,
        },
    },
};
use serde::{Deserialize, Serialize};

/// One `BLAKE2B_ROUNDS` call. Every access is at `clk`: `v` is read and written back in one
/// access a dword, `m` is read.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Blake2bRoundsEvent {
    pub chunk: RvChunk,
    pub clk: RvClk,
    /// The buffer: `v` at `ptr`, `m` at `ptr + 128`.
    pub ptr: RvAddr,
    /// Rounds run, `1..=MAX_ROUNDS_PER_CALL`.
    pub rounds: u32,
    /// `v` before the call.
    pub v_in: [RvValue; STATE_DWORDS],
    /// The message block.
    pub m: [RvValue; MESSAGE_DWORDS],
    /// `v` after the call, as written back.
    pub v_out: [RvValue; STATE_DWORDS],
    pub v_records: Vec<MemoryWriteRecord>,
    pub m_records: Vec<MemoryReadRecord>,
    pub local_mem_access: Vec<MemoryLocalEvent>,
}

pub struct Blake2bRoundsSyscall;

impl Precompile for Blake2bRoundsSyscall {
    fn emulate<H: SyscallHost>(
        &self,
        rt: &mut H,
        syscall_code: SyscallCode,
        ptr: RvValue,
        n: RvValue,
    ) -> Option<RvValue> {
        let start_clk = rt.clk();
        assert_dword_aligned_precompile(ptr, "BLAKE2b rounds buffer");
        assert!(
            (1..=u64::from(MAX_ROUNDS_PER_CALL)).contains(&n),
            "BLAKE2b rounds: a call runs 1 to {MAX_ROUNDS_PER_CALL} rounds, got {n}"
        );
        let rounds_run = n as u32;

        let v_in: [u64; STATE_DWORDS] =
            rt.dword_slice_unsafe(ptr, STATE_DWORDS).try_into().unwrap();
        let (m_records, m) = rt.mr_dword_slice(ptr + 8 * STATE_DWORDS as u64, MESSAGE_DWORDS);
        let m: [u64; MESSAGE_DWORDS] = m.try_into().unwrap();
        let mut v = v_in;
        rounds(&mut v, &m, rounds_run);
        let v_records = rt.mw_dword_slice(ptr, &v);

        let event = Blake2bRoundsEvent {
            chunk: rt.current_chunk(),
            clk: start_clk,
            ptr,
            rounds: rounds_run,
            v_in,
            m,
            v_out: v,
            v_records,
            m_records,
            local_mem_access: rt.postprocess(),
        };
        let syscall_event = rt.syscall_event(start_clk, syscall_code.syscall_id(), ptr, n);
        rt.record_mut().add_precompile_event(
            syscall_code,
            syscall_event,
            PrecompileEvent::Blake2bRounds(event),
        );
        None
    }

    fn num_extra_cycles(&self) -> u32 {
        0
    }
}
