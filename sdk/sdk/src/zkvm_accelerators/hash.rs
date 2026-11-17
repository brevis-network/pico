//! Keccak-256 and SHA-256 over the permutation and compression syscalls, and RIPEMD-160 in
//! software. The input may start at any address and end anywhere in a word.

use ripemd::{Digest, Ripemd160};

use super::{items, out, ZkvmStatus, ZKVM_EOK};

#[cfg(target_os = "zkvm")]
use crate::riscv_ecalls::{syscall_keccak_permute, syscall_sha256_compress, syscall_sha256_extend};

/// Keccak-256's rate, in bytes.
pub(super) const KECCAK_RATE: usize = 136;

/// `zkvm_status zkvm_keccak256(const uint8_t* data, size_t len, zkvm_keccak256_hash* output)`.
///
/// # Safety
///
/// `data` holds `len` bytes; `output` points to 32 bytes.
#[cfg_attr(target_os = "zkvm", no_mangle)]
pub unsafe extern "C" fn zkvm_keccak256(
    data: *const u8,
    len: usize,
    output: *mut [u8; 32],
) -> ZkvmStatus {
    const F: &str = "zkvm_keccak256";
    let data = items(data, len, F, "data");
    let output = out(output, F, "output");
    output.write(keccak256(data));
    ZKVM_EOK
}

/// `zkvm_status zkvm_sha256(const uint8_t* data, size_t len, zkvm_sha256_hash* output)`.
///
/// # Safety
///
/// `data` holds `len` bytes; `output` points to 32 bytes.
#[cfg_attr(target_os = "zkvm", no_mangle)]
pub unsafe extern "C" fn zkvm_sha256(
    data: *const u8,
    len: usize,
    output: *mut [u8; 32],
) -> ZkvmStatus {
    const F: &str = "zkvm_sha256";
    let data = items(data, len, F, "data");
    let output = out(output, F, "output");
    output.write(sha256(data));
    ZKVM_EOK
}

/// `zkvm_status zkvm_ripemd160(const uint8_t* data, size_t len, zkvm_ripemd160_hash* output)`:
/// the 20-byte digest after 12 zero bytes.
///
/// # Safety
///
/// `data` holds `len` bytes; `output` points to 32 bytes.
#[cfg_attr(target_os = "zkvm", no_mangle)]
pub unsafe extern "C" fn zkvm_ripemd160(
    data: *const u8,
    len: usize,
    output: *mut [u8; 32],
) -> ZkvmStatus {
    const F: &str = "zkvm_ripemd160";
    let data = items(data, len, F, "data");
    let output = out(output, F, "output");
    let mut padded = [0u8; 32];
    padded[12..].copy_from_slice(&Ripemd160::digest(data));
    output.write(padded);
    ZKVM_EOK
}

pub(super) fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut state = [0u64; 25];
    let (blocks, tail) = data.as_chunks::<KECCAK_RATE>();
    for block in blocks {
        absorb(&mut state, block);
        keccak_permute(&mut state);
    }
    // pad10*1 with Keccak's domain byte 0x01, in one final block.
    let mut last = Aligned8([0u8; KECCAK_RATE]);
    last.0[..tail.len()].copy_from_slice(tail);
    last.0[tail.len()] ^= 0x01;
    last.0[KECCAK_RATE - 1] ^= 0x80;
    absorb(&mut state, &last.0);
    keccak_permute(&mut state);

    let mut digest = Aligned8([0u8; 32]);
    // SAFETY: `Aligned8` is 8-aligned and 32 bytes are 4 lanes.
    let words = unsafe { &mut *digest.0.as_mut_ptr().cast::<[u64; 4]>() };
    for (word, lane) in words.iter_mut().zip(state) {
        *word = lane.to_le();
    }
    digest.0
}

/// Bytes on an 8-byte boundary, so they can be read and written as words.
#[repr(C, align(8))]
struct Aligned8<const N: usize>([u8; N]);

/// Lanes in one rate-sized block.
pub(super) const RATE_LANES: usize = KECCAK_RATE / 8;

/// XORs one rate-sized block into the state's first 17 lanes.
///
/// Lanes are read as words: byte-wise joins blow up the shift and bitwise tables, and a
/// misaligned load needs the unaligned-memory chip, which no shape has room for.
fn absorb(state: &mut [u64; 25], block: &[u8; KECCAK_RATE]) {
    let offset = block.as_ptr().addr() % 8;
    if offset == 0 {
        // SAFETY: the block is 8-aligned and 136 bytes are 17 lanes.
        let words = unsafe { &*block.as_ptr().cast::<[u64; RATE_LANES]>() };
        for (lane, word) in state.iter_mut().zip(words) {
            *lane ^= u64::from_le(*word);
        }
    } else {
        absorb_misaligned(state, block, offset);
    }
}

#[cfg(target_os = "zkvm")]
fn absorb_misaligned(state: &mut [u64; 25], block: &[u8; KECCAK_RATE], offset: usize) {
    let base = block.as_ptr().wrapping_sub(offset).cast::<u64>();
    // The 18 aligned words that cover the block. The first and last also hold bytes outside
    // it, so the loads are asm rather than reads through the reference.
    absorb_shifted(state, offset, |i| {
        let word: u64;
        // SAFETY: an aligned load that may read bytes outside the block's allocation. Guest
        // memory is flat and its regions are 8-aligned, so a word holding a byte of the block
        // is mapped.
        unsafe {
            core::arch::asm!(
                "ld {w}, 0({p})",
                w = out(reg) word,
                p = in(reg) base.wrapping_add(i),
                options(pure, readonly, nostack),
            );
        }
        word
    });
}

#[cfg(not(target_os = "zkvm"))]
fn absorb_misaligned(state: &mut [u64; 25], block: &[u8; KECCAK_RATE], _offset: usize) {
    for (lane, bytes) in state.iter_mut().zip(block.as_chunks::<8>().0) {
        *lane ^= u64::from_le_bytes(*bytes);
    }
}

/// XORs into each lane the 8 bytes that start `offset` (1..8) bytes into aligned word `i`,
/// joined from words `i` and `i + 1` with one shift each.
#[cfg_attr(not(any(target_os = "zkvm", test)), allow(dead_code))]
pub(super) fn absorb_shifted(state: &mut [u64; 25], offset: usize, word: impl Fn(usize) -> u64) {
    debug_assert!((1..8).contains(&offset), "offset {offset}");
    let right = 8 * offset as u32;
    let mut low = u64::from_le(word(0));
    for (i, lane) in state.iter_mut().take(RATE_LANES).enumerate() {
        let high = u64::from_le(word(i + 1));
        *lane ^= (low >> right) | (high << (64 - right));
        low = high;
    }
}

fn keccak_permute(state: &mut [u64; 25]) {
    #[cfg(target_os = "zkvm")]
    syscall_keccak_permute(state);
    #[cfg(not(target_os = "zkvm"))]
    keccak::f1600(state);
}

const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub(super) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state = SHA256_IV;
    let (blocks, tail) = data.as_chunks::<64>();
    for block in blocks {
        sha256_compress(&mut state, block);
    }
    // 0x80, zeros, then the bit length: one final block, or two when the tail leaves no room.
    let mut last = [0u8; 128];
    last[..tail.len()].copy_from_slice(tail);
    last[tail.len()] = 0x80;
    let end = if tail.len() < 56 { 64 } else { 128 };
    last[end - 8..end].copy_from_slice(&((data.len() as u64) << 3).to_be_bytes());
    for block in last[..end].as_chunks::<64>().0 {
        sha256_compress(&mut state, block);
    }

    let mut digest = [0u8; 32];
    for (bytes, word) in digest.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    #[cfg(target_os = "zkvm")]
    {
        // The syscalls take one 32-bit word in the low half of each u64.
        let mut w = [0u64; 64];
        for (word, bytes) in w.iter_mut().zip(block.as_chunks::<4>().0) {
            *word = u32::from_be_bytes(*bytes) as u64;
        }
        let mut s = state.map(u64::from);
        syscall_sha256_extend(&mut w);
        syscall_sha256_compress(&mut w, &mut s);
        *state = s.map(|v| v as u32);
    }
    #[cfg(not(target_os = "zkvm"))]
    sha2::compress256(state, &[(*block).into()]);
}
