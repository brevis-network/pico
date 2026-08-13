use crate::emulator::riscv::{
    event_types::RvValue,
    syscalls::{
        precompiles::{PrecompileEvent, ShaCompressEvent},
        syscall_context::SyscallContext,
        Syscall, SyscallCode,
    },
};

pub const SHA_COMPRESS_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub(crate) struct Sha256CompressSyscall;

impl Syscall for Sha256CompressSyscall {
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    #[allow(clippy::too_many_lines)]
    #[allow(clippy::many_single_char_names)]
    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: RvValue,
        arg2: RvValue,
    ) -> Option<RvValue> {
        let w_ptr = arg1;
        let h_ptr = arg2;
        assert_ne!(w_ptr, h_ptr);
        SyscallContext::assert_dword_aligned_precompile(w_ptr, "sha compress w_ptr");
        SyscallContext::assert_dword_aligned_precompile(h_ptr, "sha compress h_ptr");

        let start_clk = ctx.clk;
        let mut h_read_records = Vec::new();
        let mut w_i_read_records = Vec::new();
        let mut h_write_records = Vec::new();

        // The SDK ABI exposes both buffers as packed `[u64; N]`, with each logical SHA word stored
        // in the low 32 bits of one 64-bit slot.

        // Execute the "initialize" phase where we read in the h values.
        let mut hx = [0u32; 8];
        for i in 0..8 {
            let (record, value) = ctx.mr_dword(h_ptr + (i as u64) * 8);
            h_read_records.push(record);
            hx[i] = u32::try_from(value).unwrap();
        }

        // Give the `w` reads their own timestamp.
        //
        // The memory argument requires strictly increasing timestamps per address. Reading
        // `h` and `w` at the same clk makes any *overlap* between the two buffers
        // unprovable — the second read of a shared address would carry
        // `current_ts == prev_ts`. `assert_ne!(w_ptr, h_ptr)` above only rules out exact
        // equality; partial overlap such as `h_ptr = w_ptr + 32` slips through, emulates
        // fine, and then fails at proving time. Hence three distinct timestamps, one per
        // phase.
        //
        // This costs no extra CPU cycle and no syscall-ABI change: a syscall instruction
        // advances `state.clk` by `4 + num_extra_cycles` (= 5 here, see
        // `chunk_clk/constraints.rs:48`), while `SyscallContext::clk` is a private copy
        // used only for record timestamps. Offsets 0/1/2 all stay below the next
        // instruction's clk, so `num_extra_cycles` (encoded in byte 2 of the syscall id,
        // which the guest SDK hardcodes) stays at 1.
        ctx.clk += 1;

        let mut original_w = Vec::new();
        // Execute the "compress" phase.
        let mut a = hx[0];
        let mut b = hx[1];
        let mut c = hx[2];
        let mut d = hx[3];
        let mut e = hx[4];
        let mut f = hx[5];
        let mut g = hx[6];
        let mut h = hx[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let (record, w_i_val) = ctx.mr_dword(w_ptr + (i as u64) * 8);
            let w_i = u32::try_from(w_i_val).unwrap();
            original_w.push(w_i);
            w_i_read_records.push(record);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA_COMPRESS_K[i])
                .wrapping_add(w_i);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        // Increment the clk again before writing to h: `h` was read at `start_clk` and `w`
        // at `start_clk + 1`, so the writes land on `start_clk + 2`.
        ctx.clk += 1;

        // Execute the "finalize" phase.
        let v = [a, b, c, d, e, f, g, h];
        for i in 0..8 {
            let record = ctx.mw_dword(h_ptr + (i as u64) * 8, u64::from(hx[i].wrapping_add(v[i])));
            h_write_records.push(record);
        }

        // Push the SHA extend event.
        let chunk = ctx.current_chunk();

        let event = PrecompileEvent::ShaCompress(ShaCompressEvent {
            chunk,
            clk: start_clk,
            w_ptr,
            h_ptr,
            w: original_w.into_iter().collect(),
            h: hx,
            h_read_records: h_read_records.try_into().unwrap(),
            w_i_read_records,
            h_write_records: h_write_records.try_into().unwrap(),
            local_mem_access: ctx.postprocess(),
        });
        let syscall_event = ctx
            .rt
            .syscall_event(start_clk, syscall_code.syscall_id(), arg1, arg2);
        ctx.record_mut()
            .add_precompile_event(syscall_code, syscall_event, event);

        None
    }
}
