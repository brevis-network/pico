use crate::{
    chips::precompiles::checked_u64_to_u32,
    emulator::riscv::{
        event_types::RvValue,
        syscalls::{
            precompiles::{PrecompileEvent, ShaExtendEvent},
            syscall_context::SyscallContext,
            Syscall, SyscallCode,
        },
    },
};

pub(crate) struct Sha256ExtendSyscall;

impl Syscall for Sha256ExtendSyscall {
    fn num_extra_cycles(&self) -> u32 {
        48
    }

    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: RvValue,
        arg2: RvValue,
    ) -> Option<RvValue> {
        let clk_init = ctx.clk;
        let w_ptr = arg1;
        assert!(arg2 == 0, "arg2 must be 0");
        SyscallContext::assert_dword_aligned_precompile(w_ptr, "sha extend w_ptr");

        // Initial clk increment
        ctx.clk += 1;

        let w_ptr_init = w_ptr;
        let mut w_i_minus_15_reads = Vec::new();
        let mut w_i_minus_2_reads = Vec::new();
        let mut w_i_minus_16_reads = Vec::new();
        let mut w_i_minus_7_reads = Vec::new();
        let mut w_i_writes = Vec::new();

        // The SDK ABI exposes the schedule as `[u64; 64]`, with each logical SHA word stored in
        // the low 32 bits of one 64-bit slot.
        for i in 16u64..64 {
            // Read w[i-15].
            let (record, val) = ctx.mr_dword(w_ptr + (i - 15) * 8);
            let w_i_minus_15 = checked_u64_to_u32(val, "sha256 extend w word");
            w_i_minus_15_reads.push(record);

            // Compute `s0`.
            let s0 =
                w_i_minus_15.rotate_right(7) ^ w_i_minus_15.rotate_right(18) ^ (w_i_minus_15 >> 3);

            // Read w[i-2].
            let (record, val) = ctx.mr_dword(w_ptr + (i - 2) * 8);
            let w_i_minus_2 = checked_u64_to_u32(val, "sha256 extend w word");
            w_i_minus_2_reads.push(record);

            // Compute `s1`.
            let s1 =
                w_i_minus_2.rotate_right(17) ^ w_i_minus_2.rotate_right(19) ^ (w_i_minus_2 >> 10);

            // Read w[i-16].
            let (record, val) = ctx.mr_dword(w_ptr + (i - 16) * 8);
            let w_i_minus_16 = checked_u64_to_u32(val, "sha256 extend w word");
            w_i_minus_16_reads.push(record);

            // Read w[i-7].
            let (record, val) = ctx.mr_dword(w_ptr + (i - 7) * 8);
            let w_i_minus_7 = checked_u64_to_u32(val, "sha256 extend w word");
            w_i_minus_7_reads.push(record);

            // Compute `w_i`.
            let w_i = s1
                .wrapping_add(w_i_minus_16)
                .wrapping_add(s0)
                .wrapping_add(w_i_minus_7);

            // Write w[i].
            w_i_writes.push(ctx.mw_dword(w_ptr + i * 8, u64::from(w_i)));
            ctx.clk += 1;
        }

        // Push the SHA extend event.
        let chunk = ctx.current_chunk();

        let event = PrecompileEvent::ShaExtend(ShaExtendEvent {
            chunk,
            clk: clk_init,
            w_ptr: w_ptr_init,
            w_i_minus_15_reads,
            w_i_minus_2_reads,
            w_i_minus_16_reads,
            w_i_minus_7_reads,
            w_i_writes,
            local_mem_access: ctx.postprocess(),
        });

        let syscall_event = ctx
            .rt
            .syscall_event(clk_init, syscall_code.syscall_id(), arg1, arg2);
        ctx.record_mut()
            .add_precompile_event(syscall_code, syscall_event, event);

        None
    }
}
