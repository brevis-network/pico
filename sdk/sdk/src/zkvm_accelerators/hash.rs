//! Keccak-256 and SHA-256 over the permutation and compression syscalls, and RIPEMD-160 in
//! software. The input may start at any address and end anywhere in a word.

use ripemd::{Digest, Ripemd160};

use super::{items, out, ZkvmStatus, ZKVM_EOK};

#[cfg(target_os = "zkvm")]
use crate::riscv_ecalls::{syscall_keccak_permute, syscall_sha256_compress, syscall_sha256_extend};

/// Keccak-256's rate, in bytes.
const KECCAK_RATE: usize = 136;

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
    let mut last = [0u8; KECCAK_RATE];
    last[..tail.len()].copy_from_slice(tail);
    last[tail.len()] ^= 0x01;
    last[KECCAK_RATE - 1] ^= 0x80;
    absorb(&mut state, &last);
    keccak_permute(&mut state);

    let mut digest = [0u8; 32];
    for (bytes, lane) in digest.as_chunks_mut::<8>().0.iter_mut().zip(state) {
        bytes.copy_from_slice(&lane.to_le_bytes());
    }
    digest
}

/// XORs one rate-sized block into the state's first 17 lanes.
fn absorb(state: &mut [u64; 25], block: &[u8; KECCAK_RATE]) {
    for (lane, bytes) in state.iter_mut().zip(block.as_chunks::<8>().0) {
        *lane ^= u64::from_le_bytes(*bytes);
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
