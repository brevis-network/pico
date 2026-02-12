use crate::emulator::AotEmulatorCore;

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

/// SHA256 compress syscall implementation.
#[allow(clippy::too_many_lines)]
#[allow(clippy::many_single_char_names)]
pub fn sha256_compress(core: &mut AotEmulatorCore, w_ptr: u32, h_ptr: u32) {
    assert_ne!(w_ptr, h_ptr);

    let clk = core.clk;

    // Execute the "initialize" phase where we read in the h values.
    let mut hx = [0u32; 8];
    core.read_mem_span_at_clk(h_ptr, &mut hx, clk);

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
    core.read_mem_span_at_clk(w_ptr, &mut w, clk);
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
    core.write_mem_span_at_clk(h_ptr, &result, clk + 1);
}

/// SHA256 extend syscall implementation.
pub fn sha256_extend(core: &mut AotEmulatorCore, w_ptr: u32) {
    let mut clk = core.clk;

    for i in 16..64 {
        // Read w[i-15].
        let w_i_minus_15 = core.read_mem_fast_at_clk(w_ptr + (i - 15) * 4, clk);

        // Compute `s0`.
        let s0 = w_i_minus_15.rotate_right(7) ^ w_i_minus_15.rotate_right(18) ^ (w_i_minus_15 >> 3);

        // Read w[i-2].
        let w_i_minus_2 = core.read_mem_fast_at_clk(w_ptr + (i - 2) * 4, clk);

        // Compute `s1`.
        let s1 = w_i_minus_2.rotate_right(17) ^ w_i_minus_2.rotate_right(19) ^ (w_i_minus_2 >> 10);

        // Read w[i-16].
        let w_i_minus_16 = core.read_mem_fast_at_clk(w_ptr + (i - 16) * 4, clk);

        // Read w[i-7].
        let w_i_minus_7 = core.read_mem_fast_at_clk(w_ptr + (i - 7) * 4, clk);

        // Compute `w_i`.
        let w_i = s1
            .wrapping_add(w_i_minus_16)
            .wrapping_add(s0)
            .wrapping_add(w_i_minus_7);

        // Write w[i].
        core.write_mem_fast_at_clk(w_ptr + i * 4, w_i, clk);
        clk += 1;
    }
}
