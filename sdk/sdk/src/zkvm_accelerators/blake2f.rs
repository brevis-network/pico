//! BLAKE2b's compression function F with a caller-chosen round count (EIP-152), in software.

use super::{arg, out, ZkvmStatus, ZKVM_EFAIL, ZKVM_EOK};

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// `zkvm_status zkvm_blake2f(uint32_t rounds, zkvm_blake2f_state* h, const zkvm_blake2f_message*
/// m, const zkvm_blake2f_offset* t, uint8_t f)`: updates `h` in place. `rounds` is the count
/// itself (EIP-152 sends it big-endian; the caller has decoded it). A final-block flag other than
/// 0 or 1 fails and leaves `h` as it was.
///
/// # Safety
///
/// `h` points to 64 bytes, `m` to 128, `t` to 16, each eight little-endian words.
#[cfg_attr(target_os = "zkvm", no_mangle)]
pub unsafe extern "C" fn zkvm_blake2f(
    rounds: u32,
    h: *mut [u8; 64],
    m: *const [u8; 128],
    t: *const [u8; 16],
    f: u8,
) -> ZkvmStatus {
    const F: &str = "zkvm_blake2f";
    let state = arg(h, F, "h");
    let m = arg(m, F, "m");
    let t = arg(t, F, "t");
    if f > 1 {
        return ZKVM_EFAIL;
    }
    let mut state = words::<8>(&state);
    compress(
        rounds,
        &mut state,
        &words::<16>(&m),
        &words::<2>(&t),
        f == 1,
    );
    let mut bytes = [0u8; 64];
    for (b, word) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(state) {
        *b = word.to_le_bytes();
    }
    out(h, F, "h").write(bytes);
    ZKVM_EOK
}

fn words<const N: usize>(bytes: &[u8]) -> [u64; N] {
    core::array::from_fn(|i| u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap()))
}

/// RFC 7693 section 3.2, with `rounds` rounds.
pub(super) fn compress(rounds: u32, h: &mut [u64; 8], m: &[u64; 16], t: &[u64; 2], last: bool) {
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t[0];
    v[13] ^= t[1];
    if last {
        v[14] = !v[14];
    }
    // Ten rounds unrolled, each with its SIGMA row as a constant, so `v` stays in registers and
    // every message index folds to an immediate.
    let mut remaining = rounds;
    macro_rules! unrolled {
        ($($r:literal),*) => {$(
            if remaining == 0 {
                break;
            }
            remaining -= 1;
            round::<$r>(&mut v, m);
        )*};
    }
    loop {
        unrolled!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

#[inline(always)]
fn round<const R: usize>(v: &mut [u64; 16], m: &[u64; 16]) {
    let s = &SIGMA[R];
    g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
    g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
    g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
    g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
    g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
    g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
    g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
}

#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}
