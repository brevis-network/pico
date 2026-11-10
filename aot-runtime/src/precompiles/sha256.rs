use super::PrecompileMemory;
use pico_vm::chips::precompiles::sha256::compress::SHA_COMPRESS_K;

/// SHA256 compress syscall implementation.
#[allow(clippy::too_many_lines)]
#[allow(clippy::many_single_char_names)]
pub fn sha256_compress(core: &mut impl PrecompileMemory, w_ptr: u64, h_ptr: u64) {
    assert_ne!(w_ptr, h_ptr);
    assert!(w_ptr.is_multiple_of(8), "w_ptr is unaligned");
    assert!(h_ptr.is_multiple_of(8), "h_ptr is unaligned");

    let clk = core.clk();

    // Execute the "initialize" phase where we read in the h values.
    let mut hx = [0u32; 8];
    core.read_mem_low32_slot_span_at_clk(h_ptr, &mut hx, clk);

    // Execute the "compress" phase.
    let mut a = hx[0];
    let mut b = hx[1];
    let mut c = hx[2];
    let mut d = hx[3];
    let mut e = hx[4];
    let mut f = hx[5];
    let mut g = hx[6];
    let mut h = hx[7];
    let mut w = [0u32; 64];
    // `w` reads take their own timestamp so that a `w`/`h` overlap stays provable.
    // Must mirror the interpreter exactly
    // (`vm/src/emulator/riscv/syscalls/precompiles/sha256/compress.rs`) -- the AOT
    // emulator stamps this clk into the per-dword memory metadata that is handed to the
    // prover via `RiscvEmulationState` snapshots, so any disagreement shows up as a
    // non-zero global memory cumulative sum at a batch boundary.
    core.read_mem_low32_slot_span_at_clk(w_ptr, &mut w, clk + 1);
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let w_i = w[i as usize];
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA_COMPRESS_K[i as usize])
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

    // Execute the "finalize" phase.
    let v = [a, b, c, d, e, f, g, h];
    let mut result = [0u32; 8];
    for i in 0..8 {
        result[i] = hx[i].wrapping_add(v[i]);
    }
    core.write_mem_low32_slot_span_at_clk(h_ptr, &result, clk + 2);
}

/// SHA256 extend syscall implementation.
pub fn sha256_extend(core: &mut impl PrecompileMemory, w_ptr: u64) {
    assert!(w_ptr.is_multiple_of(8), "w_ptr is unaligned");
    for (clk, i) in (core.clk()..).zip(16u64..64) {
        // Read w[i-15].
        let w_i_minus_15 = core.read_mem_low32_slot_at_clk(w_ptr + (i - 15) * 8, clk);

        // Compute `s0`.
        let s0 = w_i_minus_15.rotate_right(7) ^ w_i_minus_15.rotate_right(18) ^ (w_i_minus_15 >> 3);

        // Read w[i-2].
        let w_i_minus_2 = core.read_mem_low32_slot_at_clk(w_ptr + (i - 2) * 8, clk);

        // Compute `s1`.
        let s1 = w_i_minus_2.rotate_right(17) ^ w_i_minus_2.rotate_right(19) ^ (w_i_minus_2 >> 10);

        // Read w[i-16].
        let w_i_minus_16 = core.read_mem_low32_slot_at_clk(w_ptr + (i - 16) * 8, clk);

        // Read w[i-7].
        let w_i_minus_7 = core.read_mem_low32_slot_at_clk(w_ptr + (i - 7) * 8, clk);

        // Compute `w_i`.
        let w_i = s1
            .wrapping_add(w_i_minus_16)
            .wrapping_add(s0)
            .wrapping_add(w_i_minus_7);

        // Write w[i].
        core.write_mem_low32_slot_at_clk(w_ptr + i * 8, w_i, clk);
    }
}
