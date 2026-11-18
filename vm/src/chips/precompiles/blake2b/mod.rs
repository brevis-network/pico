//! BLAKE2b's round function (RFC 7693 §3.2) and the `BLAKE2B_ROUNDS` precompile that proves it.
//!
//! EIP-152's compression function F takes a caller-chosen round count, one gas a round, and runs
//! BLAKE2b's round that many times over the 16-word working vector. Done in RV64 instructions a
//! round costs about 250 of them (every 64-bit rotation is two shifts and an OR), so a call with
//! millions of rounds outgrows any proof budget a block was priced for (mainnet block 26426155:
//! 10,500,000 rounds for 10.5M gas).
//!
//! The syscall. `a0` points at a [`BUFFER_BYTES`]-byte buffer, 8-byte aligned: the working vector
//! `v` ([`STATE_DWORDS`] dwords) then the message block `m` ([`MESSAGE_DWORDS`] dwords). `a1` is a
//! round count `n` in `1..=`[`MAX_ROUNDS_PER_CALL`]. The syscall runs rounds `0..n` of the
//! schedule on `v` ([`rounds`]) and writes `v` back; `m` is only read. F's initialization and
//! finalization stay in the guest, a few dozen instructions however many rounds run between them,
//! and a longer F is a run of calls of at most [`MAX_ROUNDS_PER_CALL`] rounds each (a multiple of
//! ten, so every call starts at round 0 of the schedule).
//!
//! Two chips prove it, on the pattern of Keccak's (`keccak256`):
//!
//! - [`Blake2bControlChip`], one row per call, receives the syscall and does the memory: `v` read
//!   and written back at `clk`, `m` read at `clk`. It starts the call's chain of rounds on the
//!   [`LookupType::Blake2bRound`](crate::machine::lookup::LookupType) bus with `v` at round 0 and
//!   ends it by receiving `v` at round `n`, which is what it writes. It also sends `m` in each of
//!   the ten schedule orders, as many times as the call has rounds in that order.
//! - [`Blake2bRoundChip`], one row per round, receives `v` at round `k` and the schedule-ordered
//!   message for `k % 10`, mixes, and sends `v` at round `k + 1`.
//!
//! The memory accesses, the costly part of a precompile row, happen once a call rather than once
//! a round, so a call's local-memory footprint is its 32 dwords whatever its length; a round row
//! raises only its byte lookups and three bus messages.
//!
//! This module is also the reference both the emulator and trace generation compute rounds with.

pub mod control;
pub mod round;

use core::marker::PhantomData;

/// Dwords of the working vector `v`, at the start of the syscall's buffer.
pub const STATE_DWORDS: usize = 16;
/// Dwords of the message block `m`, right after `v`.
pub const MESSAGE_DWORDS: usize = 16;
/// Bytes of `v`: what the syscall writes back.
pub const STATE_BYTES: u32 = 8 * STATE_DWORDS as u32;
/// Bytes of the syscall's buffer, `v` then `m`.
pub const BUFFER_BYTES: u32 = 8 * (STATE_DWORDS + MESSAGE_DWORDS) as u32;
/// The most rounds one syscall runs. A multiple of ten, so a caller that runs a long F as
/// back-to-back calls of this many rounds starts every call at round 0 of the schedule, which is
/// where the syscall starts. The emulator refuses a call outside `1..=MAX_ROUNDS_PER_CALL` and the
/// control chip range-checks the count to the same bounds. The size is the record split's: it
/// packs whole calls, so a call this long is the most a full block can fall short of its round
/// budget by.
pub const MAX_ROUNDS_PER_CALL: u32 = 1000;

/// A full block of the record split: at most `2^19` rounds. A round row raises 259 interactions,
/// so the block's round chip holds 136M of the 2^28 logUp-GKR leaves a precompile record is held
/// under (`TAIL_MERGE_MAX_GKR_LEAVES`), which 2^20 rows would cross.
pub const ROUNDS_PER_BLOCK_LOG: usize = 19;
/// A full block of the record split holds at most `2^14` calls, the control chip's ceiling. With
/// every call at least one round, a block's calls also fit under its rounds, so the control chip
/// and the precompile syscall table pad to `2^min(h, 14)` for a round chip of `2^h`
/// (`mle::machine::shape::blake2b_call_log_height`).
pub const CALLS_PER_BLOCK_LOG: usize = 14;

/// Tags of the two kinds of `LookupType::Blake2bRound` message, `[chunk, clk, tag, k, s, 64
/// limbs]`: the working vector entering round `k` (whose schedule row is `s = k % 10`), and the
/// message block in schedule order `s` (with `k = 0`). The tag keeps the two multisets apart.
pub(crate) const BUS_STATE_TAG: u32 = 0;
pub(crate) const BUS_MESSAGE_TAG: u32 = 1;

/// One row per `BLAKE2B_ROUNDS` call: the syscall, the buffer pointer, the 48 memory accesses and
/// the ends of the call's chain of rounds. See the module docs.
#[derive(Default)]
pub struct Blake2bControlChip<F>(PhantomData<fn(F) -> F>);

/// One row per BLAKE2b round. See the module docs.
#[derive(Default)]
pub struct Blake2bRoundChip<F>(PhantomData<fn(F) -> F>);

/// BLAKE2b's initialization vector (RFC 7693 §2.6).
pub const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// The message schedule (RFC 7693 §2.7): round `r` reads the message words in the order
/// `SIGMA[r % 10]`.
pub const SIGMA: [[usize; 16]; 10] = [
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

/// The working-vector indices `(a, b, c, d)` of a round's eight mixes, in order: the four
/// columns, then the four diagonals (RFC 7693 §3.2).
pub const MIX_INDICES: [[usize; 4]; 8] = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14],
];

/// The mixing function G (RFC 7693 §3.1) on `v[a], v[b], v[c], v[d]` with message words `x`, `y`.
#[inline]
pub fn g(v: &mut [u64; 16], [a, b, c, d]: [usize; 4], x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// One round on the working vector `v`: the eight mixes of [`MIX_INDICES`], the `k`-th taking
/// the message words `SIGMA[round % 10][2k]` and `SIGMA[round % 10][2k + 1]`.
pub fn round(v: &mut [u64; 16], m: &[u64; 16], round: usize) {
    let s = &SIGMA[round % 10];
    for (k, indices) in MIX_INDICES.iter().enumerate() {
        g(v, *indices, m[s[2 * k]], m[s[2 * k + 1]]);
    }
}

/// Rounds `0..n` of the schedule on `v`: what one `BLAKE2B_ROUNDS` call computes.
pub fn rounds(v: &mut [u64; 16], m: &[u64; 16], n: u32) {
    for i in 0..n as usize {
        round(v, m, i);
    }
}

/// `m` in the order round `s` of the schedule reads it: word `j` is `m[SIGMA[s][j]]`. The
/// message the control chip sends for schedule row `s`, and the one a round row in that row
/// receives.
pub fn scheduled(m: &[u64; 16], s: usize) -> [u64; 16] {
    core::array::from_fn(|j| m[SIGMA[s][j]])
}

/// EIP-152's F: `rounds` rounds of BLAKE2b's compression of the message block `m` into the state
/// `h`, with offset counter `t` and final-block flag `f`. The reference the precompile's guest
/// side is tested against; the precompile itself proves only [`round`].
pub fn compress(rounds: u32, h: &mut [u64; 8], m: &[u64; 16], t: [u64; 2], f: bool) {
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t[0];
    v[13] ^= t[1];
    if f {
        v[14] = !v[14];
    }
    for i in 0..rounds as usize {
        round(&mut v, m, i);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod reference_tests {
    use super::*;

    fn le_words<const N: usize>(hex: &str) -> [u64; N] {
        let bytes = hex::decode(hex).unwrap();
        assert_eq!(bytes.len(), 8 * N);
        core::array::from_fn(|i| u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap()))
    }

    /// EIP-152's test vector 5: BLAKE2b-512("abc") after 12 rounds.
    #[test]
    fn compress_matches_eip_152_vector_5() {
        let mut h: [u64; 8] = le_words(
            "48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5\
             d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b",
        );
        let mut m = [0u64; 16];
        m[0] = u64::from_le_bytes(*b"abc\0\0\0\0\0");
        compress(12, &mut h, &m, [3, 0], true);
        let out: Vec<u8> = h.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(
            hex::encode(out),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
    }

    /// The schedule repeats every ten rounds, so round 10 is round 0 again.
    #[test]
    fn the_round_index_wraps_at_ten() {
        let m: [u64; 16] = core::array::from_fn(|i| 0x0123_4567_89ab_cdef ^ (i as u64) << 56);
        let v0: [u64; 16] = core::array::from_fn(|i| IV[i % 8].rotate_left(i as u32));
        let (mut a, mut b) = (v0, v0);
        round(&mut a, &m, 0);
        round(&mut b, &m, 10);
        assert_eq!(a, b);
        let mut c = v0;
        round(&mut c, &m, 1);
        assert_ne!(a, c);
    }

    /// A round is the column mixes, then the diagonal ones, each reading its two message words
    /// from SIGMA: the schedule hits every word exactly once a round.
    #[test]
    fn every_round_reads_each_message_word_once() {
        for s in SIGMA {
            let mut seen = [false; 16];
            for w in s {
                assert!(!seen[w]);
                seen[w] = true;
            }
        }
        // The eight mixes touch each working-vector word twice: once as a column, once as a
        // diagonal.
        let mut touched = [0; 16];
        for indices in MIX_INDICES {
            for i in indices {
                touched[i] += 1;
            }
        }
        assert_eq!(touched, [2; 16]);
    }
}
