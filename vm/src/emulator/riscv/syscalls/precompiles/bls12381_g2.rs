//! `BLS12381_G2_ADD` and `BLS12381_G2_DOUBLE`. The point layout and the inputs the chips can
//! prove are in [`crate::chips::precompiles::bls12381_g2`].

use crate::{
    chips::precompiles::bls12381_g2::{
        g2_add_checked, g2_double_checked, point_from_dwords, point_to_dwords, G2_POINT_DWORDS,
    },
    emulator::riscv::{
        event_types::RvValue,
        syscalls::{
            host::{Precompile, SyscallHost},
            precompiles::{
                assert_dword_aligned_precompile, EllipticCurveAddEvent, EllipticCurveDoubleEvent,
                PrecompileEvent,
            },
            SyscallCode,
        },
    },
};

pub struct Bls12381G2AddSyscall;

impl Precompile for Bls12381G2AddSyscall {
    fn emulate<H: SyscallHost>(
        &self,
        rt: &mut H,
        syscall_code: SyscallCode,
        p_ptr: RvValue,
        q_ptr: RvValue,
    ) -> Option<RvValue> {
        let start_clk = rt.clk();
        assert_dword_aligned_precompile(p_ptr, "G2 add p_ptr");
        assert_dword_aligned_precompile(q_ptr, "G2 add q_ptr");
        let p = rt.dword_slice_unsafe(p_ptr, G2_POINT_DWORDS);
        let (q_memory_records, q) = rt.mr_dword_slice(q_ptr, G2_POINT_DWORDS);
        // `p` is written a cycle later, as `p` and `q` may be the same.
        rt.advance_clk(1);

        let sum = g2_add_checked(&point_from_dwords(&p), &point_from_dwords(&q));
        let p_memory_records = rt.mw_dword_slice(p_ptr, &point_to_dwords(&sum));

        let event = EllipticCurveAddEvent {
            chunk: rt.current_chunk(),
            clk: start_clk,
            p_ptr,
            p,
            q_ptr,
            q,
            p_memory_records,
            q_memory_records,
            local_mem_access: rt.postprocess(),
        };
        let syscall_event = rt.syscall_event(start_clk, syscall_code.syscall_id(), p_ptr, q_ptr);
        rt.record_mut().add_precompile_event(
            syscall_code,
            syscall_event,
            PrecompileEvent::Bls12381G2Add(event),
        );
        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}

pub struct Bls12381G2DoubleSyscall;

impl Precompile for Bls12381G2DoubleSyscall {
    fn emulate<H: SyscallHost>(
        &self,
        rt: &mut H,
        syscall_code: SyscallCode,
        p_ptr: RvValue,
        arg2: RvValue,
    ) -> Option<RvValue> {
        let start_clk = rt.clk();
        assert_dword_aligned_precompile(p_ptr, "G2 double p_ptr");
        let p = rt.dword_slice_unsafe(p_ptr, G2_POINT_DWORDS);
        let doubled = g2_double_checked(&point_from_dwords(&p));
        let p_memory_records = rt.mw_dword_slice(p_ptr, &point_to_dwords(&doubled));

        let event = EllipticCurveDoubleEvent {
            chunk: rt.current_chunk(),
            clk: start_clk,
            p_ptr,
            p,
            p_memory_records,
            local_mem_access: rt.postprocess(),
        };
        let syscall_event = rt.syscall_event(start_clk, syscall_code.syscall_id(), p_ptr, arg2);
        rt.record_mut().add_precompile_event(
            syscall_code,
            syscall_event,
            PrecompileEvent::Bls12381G2Double(event),
        );
        None
    }

    fn num_extra_cycles(&self) -> u32 {
        0
    }
}
