//! Arbitrary-length modular exponentiation (EIP-198).
//!
//! A modulus of at most 256 bits, behind any number of zero bytes, runs square-and-multiply on the
//! `UINT256_MUL` syscall, one call a step: BN254's scalar field order, which zk verifier contracts
//! invert in with `x^(r-2)`, is the common one. A wider modulus, and a zero one, run in software,
//! revm's implementation.

use super::{items, ZkvmStatus, ZKVM_EOK};

/// A value below 2^256, in four little-endian 64-bit limbs.
type Limbs = [u64; 4];
const ZERO: Limbs = [0; 4];
const ONE: Limbs = [1, 0, 0, 0];

/// `zkvm_status zkvm_modexp(const uint8_t* base, size_t base_len, const uint8_t* exp, size_t
/// exp_len, const uint8_t* modulus, size_t mod_len, uint8_t* output)`: `base^exp mod modulus`,
/// big-endian, in exactly `mod_len` bytes. A zero modulus gives zero.
///
/// # Safety
///
/// Each input holds its length in bytes; `output` has room for `mod_len`.
#[cfg_attr(target_os = "zkvm", no_mangle)]
pub unsafe extern "C" fn zkvm_modexp(
    base: *const u8,
    base_len: usize,
    exp: *const u8,
    exp_len: usize,
    modulus: *const u8,
    mod_len: usize,
    output: *mut u8,
) -> ZkvmStatus {
    const F: &str = "zkvm_modexp";
    let base = items(base, base_len, F, "base");
    let exp = items(exp, exp_len, F, "exp");
    let modulus = items(modulus, mod_len, F, "modulus");
    if mod_len > 0 && output.is_null() {
        super::null(F, "output");
    }
    // Either result is below the modulus and big-endian; right-align it. Written last: `output`
    // may share an input's bytes.
    if let Some(m) = narrow_modulus(modulus) {
        // Below `m`, so the bytes past the modulus's own length are zero.
        let result = modexp_256(base, exp, &m, mulmod);
        let n = mod_len.min(32);
        output.write_bytes(0, mod_len - n);
        core::ptr::copy_nonoverlapping(result[32 - n..].as_ptr(), output.add(mod_len - n), n);
        return ZKVM_EOK;
    }
    // Zero may come back as one zero byte, so the copy takes the tail.
    let result = aurora_engine_modexp::modexp(base, exp, modulus);
    let n = result.len().min(mod_len);
    output.write_bytes(0, mod_len - n);
    core::ptr::copy_nonoverlapping(
        result[result.len() - n..].as_ptr(),
        output.add(mod_len - n),
        n,
    );
    ZKVM_EOK
}

/// The modulus, if it is not zero and fits in 256 bits once its leading zero bytes are dropped.
fn narrow_modulus(modulus: &[u8]) -> Option<Limbs> {
    let first = modulus.iter().position(|&b| b != 0)?;
    (modulus.len() - first <= 32).then(|| limbs_be(&modulus[first..]))
}

/// `base^exp mod m` for a non-zero `m`, big-endian in 32 bytes. `mulmod(x, y, m)` is `x * y mod
/// m`, and every call has one operand below `m`: the syscall's chip proves a quotient of at most
/// 256 bits, which needs `x * y < m * 2^256`.
fn modexp_256(
    base: &[u8],
    exp: &[u8],
    m: &Limbs,
    mulmod: impl Fn(&Limbs, &Limbs, &Limbs) -> Limbs,
) -> [u8; 32] {
    if *m == ONE {
        return [0; 32];
    }
    // Reduce the base: Horner over 32-byte big-endian chunks, the first one short, so
    // `b = b * 2^256 + chunk`. A base of one chunk needs no `2^256 mod m`.
    let mut b = ZERO;
    let mut r256 = None;
    let first = match base.len() % 32 {
        0 => 32.min(base.len()),
        n => n,
    };
    let mut at = 0;
    while at < base.len() {
        let len = if at == 0 { first } else { 32 };
        let chunk = mulmod(&limbs_be(&base[at..at + len]), &ONE, m);
        b = if at == 0 {
            chunk
        } else {
            let r = *r256.get_or_insert_with(|| {
                // `2^255 mod m`, doubled.
                let half = mulmod(&[0, 0, 0, 1 << 63], &ONE, m);
                add_mod(&half, &half, m)
            });
            add_mod(&mulmod(&b, &r, m), &chunk, m)
        };
        at += len;
    }
    // Left-to-right square-and-multiply; squares start at the exponent's first set bit. `ONE` is
    // reduced, as `m > 1`.
    let mut acc = ONE;
    let mut started = false;
    for &byte in exp {
        for i in (0..8).rev() {
            if started {
                acc = mulmod(&acc, &acc, m);
            }
            if byte >> i & 1 == 1 {
                acc = if started { mulmod(&acc, &b, m) } else { b };
                started = true;
            }
        }
    }
    let mut out = [0u8; 32];
    for (i, limb) in acc.iter().enumerate() {
        out[32 - 8 * (i + 1)..32 - 8 * i].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

/// Up to 32 big-endian bytes as limbs.
fn limbs_be(bytes: &[u8]) -> Limbs {
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(bytes);
    let mut l = ZERO;
    for (i, limb) in l.iter_mut().enumerate() {
        *limb = u64::from_be_bytes(buf[32 - 8 * (i + 1)..32 - 8 * i].try_into().unwrap());
    }
    l
}

/// `a + b mod m` for `a, b < m`. The sum can pass 2^256; it is below `2m` either way, so one
/// wrapping subtraction reduces it.
fn add_mod(a: &Limbs, b: &Limbs, m: &Limbs) -> Limbs {
    let mut s = ZERO;
    let mut carry = false;
    for i in 0..4 {
        let (x, c1) = a[i].overflowing_add(b[i]);
        let (x, c2) = x.overflowing_add(carry as u64);
        s[i] = x;
        carry = c1 | c2;
    }
    if carry || !lt(&s, m) {
        let mut borrow = false;
        for i in 0..4 {
            let (x, b1) = s[i].overflowing_sub(m[i]);
            let (x, b2) = x.overflowing_sub(borrow as u64);
            s[i] = x;
            borrow = b1 | b2;
        }
    }
    s
}

fn lt(a: &Limbs, b: &Limbs) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// `x * y mod m` on the `UINT256_MUL` syscall, which reads the modulus right after `y`.
#[cfg(target_os = "zkvm")]
fn mulmod(x: &Limbs, y: &Limbs, m: &Limbs) -> Limbs {
    let mut out = *x;
    let mut ym = [0u64; 8];
    ym[..4].copy_from_slice(y);
    ym[4..].copy_from_slice(m);
    crate::riscv_ecalls::syscall_uint256_mulmod(&mut out, ym.as_ptr() as *const [u64; 4]);
    out
}

/// `x * y mod m` in software, on the host where there is no syscall: double-and-add, first to
/// reduce `x`, then over `y`'s bits. Slow; for tests. `m > 1`.
#[cfg(not(target_os = "zkvm"))]
fn mulmod(x: &Limbs, y: &Limbs, m: &Limbs) -> Limbs {
    let bits = |v: &Limbs, add: &Limbs| {
        let mut acc = ZERO;
        for i in (0..256).rev() {
            acc = add_mod(&acc, &acc, m);
            if v[i / 64] >> (i % 64) & 1 == 1 {
                acc = add_mod(&acc, add, m);
            }
        }
        acc
    };
    let xr = bits(x, &ONE);
    bits(y, &xr)
}
