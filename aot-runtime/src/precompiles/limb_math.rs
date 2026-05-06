//! Limb-based arithmetic for field operations without BigUint allocations.
//!
//! This module provides optimized modular arithmetic operations using fixed-size
//! limb arrays instead of heap-allocated BigUint. This eliminates allocation
//! overhead in hot paths while maintaining correctness.

use num::BigUint;

/// Maximum number of u32 limbs needed (for BLS12-381: 384 bits = 12 u32s)
pub const MAX_LIMBS: usize = 12;

/// Limb representation for field elements
#[derive(Clone, Copy, Debug)]
pub struct Limbs<const N: usize> {
    pub limbs: [u32; N],
}

impl<const N: usize> Limbs<N> {
    /// Zero value
    #[inline(always)]
    pub fn zero() -> Self {
        Self { limbs: [0u32; N] }
    }

    /// Create from u32 slice
    #[inline(always)]
    pub fn from_slice(words: &[u32]) -> Self {
        let mut limbs = [0u32; N];
        let len = words.len().min(N);
        limbs[..len].copy_from_slice(&words[..len]);
        Self { limbs }
    }

    /// Convert to BigUint (for compatibility with existing code)
    #[inline(always)]
    pub fn to_biguint(&self) -> BigUint {
        BigUint::from_slice(&self.limbs)
    }

    /// Create from BigUint
    #[inline(always)]
    pub fn from_biguint(value: &BigUint) -> Self {
        let digits = value.to_u32_digits();
        let mut limbs = [0u32; N];
        let len = digits.len().min(N);
        limbs[..len].copy_from_slice(&digits[..len]);
        Self { limbs }
    }

    /// Convert to u32 slice (for writing back to memory)
    #[inline(always)]
    pub fn as_slice(&self) -> &[u32] {
        &self.limbs
    }

    /// Check if all limbs are zero
    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&x| x == 0)
    }
}

/// Cached modulus for a specific field
pub struct CachedModulus<const N: usize> {
    pub modulus: Limbs<N>,
    pub n0_inv: u32,
    pub r2: Limbs<N>,
}

impl<const N: usize> CachedModulus<N> {
    /// Create from byte slice
    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        let modulus = limbs_from_bytes_le::<N>(bytes);
        Self::from_limbs(modulus)
    }

    /// Create from limb representation
    pub fn from_limbs(modulus: Limbs<N>) -> Self {
        let n0_inv = if modulus.is_zero() {
            0
        } else {
            debug_assert!(modulus.limbs[0] & 1 == 1, "modulus must be odd");
            montgomery_n0_inv(modulus.limbs[0])
        };
        let r2 = if modulus.is_zero() {
            Limbs::zero()
        } else {
            montgomery_r2::<N>(&modulus)
        };
        Self {
            modulus,
            n0_inv,
            r2,
        }
    }
}

/// Modular addition: (a + b) % modulus
#[inline(always)]
pub fn mod_add<const N: usize>(a: &Limbs<N>, b: &Limbs<N>, modulus: &CachedModulus<N>) -> Limbs<N> {
    mod_add_limbs(a, b, &modulus.modulus)
}

/// Modular subtraction: (a - b) % modulus
#[inline(always)]
pub fn mod_sub<const N: usize>(a: &Limbs<N>, b: &Limbs<N>, modulus: &CachedModulus<N>) -> Limbs<N> {
    mod_sub_limbs(a, b, &modulus.modulus)
}

/// Modular multiplication: (a * b) % modulus
#[inline(always)]
pub fn mod_mul<const N: usize>(a: &Limbs<N>, b: &Limbs<N>, modulus: &CachedModulus<N>) -> Limbs<N> {
    debug_assert!(!modulus.modulus.is_zero(), "modulus must be non-zero");
    let a_mont = montgomery_mul(a, &modulus.r2, modulus);
    let b_mont = montgomery_mul(b, &modulus.r2, modulus);
    let ab_mont = montgomery_mul(&a_mont, &b_mont, modulus);
    montgomery_mul(&ab_mont, &Limbs::from_slice(&[1u32]), modulus)
}

// ============================================================================
// Specialized limb sizes for different field types
// ============================================================================

/// Secp256k1 / BN254 field (256-bit = 8 u32 limbs)
pub type Limbs8 = Limbs<8>;
pub type CachedModulus8 = CachedModulus<8>;

/// BLS12-381 field (384-bit = 12 u32 limbs)
pub type Limbs12 = Limbs<12>;
pub type CachedModulus12 = CachedModulus<12>;

// ============================================================================
// UINT256 operations
// ============================================================================

/// UINT256 modular multiplication using limb representation
#[inline(always)]
pub fn uint256_mod_mul(x: &Limbs8, y: &Limbs8, modulus: &Limbs8) -> Limbs8 {
    if modulus.is_zero() {
        return mul_low_limbs::<8>(x, y);
    }
    if modulus.limbs[0] & 1 == 0 {
        let product = mul_full_limbs_8(x, y);
        return mod_reduce_16_by_8(product, modulus);
    }

    let modulus_cached = CachedModulus::<8>::from_limbs(*modulus);
    let x_mont = montgomery_mul(x, &modulus_cached.r2, &modulus_cached);
    let y_mont = montgomery_mul(y, &modulus_cached.r2, &modulus_cached);
    let xy_mont = montgomery_mul(&x_mont, &y_mont, &modulus_cached);
    montgomery_mul(&xy_mont, &Limbs::from_slice(&[1u32]), &modulus_cached)
}

// ============================================================================
// Future optimizations (commented out for now):
// ============================================================================
//
// 1. Limb-level addition with carry propagation
// 2. Montgomery multiplication for faster modular multiplication
// 3. Karatsuba multiplication for large operands
// 4. Barrett reduction for faster modular reduction
// 5. Specialized reduction for known moduli (e.g., Secp256k1, BN254)
//
// These optimizations can be added incrementally while maintaining correctness.

// ============================================================================
// Internal helpers
// ============================================================================

#[inline(always)]
fn limbs_from_bytes_le<const N: usize>(bytes: &[u8]) -> Limbs<N> {
    let mut limbs = [0u32; N];
    for (i, limb) in limbs.iter_mut().enumerate().take(N) {
        let base = i * 4;
        if base >= bytes.len() {
            break;
        }
        let b0 = bytes[base];
        let b1 = bytes.get(base + 1).copied().unwrap_or(0);
        let b2 = bytes.get(base + 2).copied().unwrap_or(0);
        let b3 = bytes.get(base + 3).copied().unwrap_or(0);
        *limb = u32::from_le_bytes([b0, b1, b2, b3]);
    }
    Limbs { limbs }
}

#[inline(always)]
fn montgomery_n0_inv(modulus_0: u32) -> u32 {
    let inv = inv_mod_2_32(modulus_0);
    inv.wrapping_neg()
}

#[inline(always)]
fn inv_mod_2_32(a: u32) -> u32 {
    let mut x = a;
    x = x.wrapping_mul(2u32.wrapping_sub(a.wrapping_mul(x)));
    x = x.wrapping_mul(2u32.wrapping_sub(a.wrapping_mul(x)));
    x = x.wrapping_mul(2u32.wrapping_sub(a.wrapping_mul(x)));
    x = x.wrapping_mul(2u32.wrapping_sub(a.wrapping_mul(x)));
    x = x.wrapping_mul(2u32.wrapping_sub(a.wrapping_mul(x)));
    x
}

#[inline(always)]
fn montgomery_r2<const N: usize>(modulus: &Limbs<N>) -> Limbs<N> {
    let mut r = Limbs::zero();
    r.limbs[0] = 1;
    for _ in 0..(N * 32 * 2) {
        r = mod_add_limbs(&r, &r, modulus);
    }
    r
}

#[inline(always)]
fn mod_add_limbs<const N: usize>(a: &Limbs<N>, b: &Limbs<N>, modulus: &Limbs<N>) -> Limbs<N> {
    let (sum, carry) = add_limbs(a, b);
    if carry != 0 || ge_limbs(&sum, modulus) {
        let (reduced, _) = sub_limbs(&sum, modulus);
        reduced
    } else {
        sum
    }
}

#[inline(always)]
fn mod_sub_limbs<const N: usize>(a: &Limbs<N>, b: &Limbs<N>, modulus: &Limbs<N>) -> Limbs<N> {
    let (diff, borrow) = sub_limbs(a, b);
    if borrow != 0 {
        let (sum, _) = add_limbs(&diff, modulus);
        sum
    } else {
        diff
    }
}

#[inline(always)]
fn add_limbs<const N: usize>(a: &Limbs<N>, b: &Limbs<N>) -> (Limbs<N>, u32) {
    let mut out = [0u32; N];
    let mut carry = 0u64;
    for (i, out_limb) in out.iter_mut().enumerate().take(N) {
        let sum = a.limbs[i] as u64 + b.limbs[i] as u64 + carry;
        *out_limb = sum as u32;
        carry = sum >> 32;
    }
    (Limbs { limbs: out }, carry as u32)
}

#[inline(always)]
fn sub_limbs<const N: usize>(a: &Limbs<N>, b: &Limbs<N>) -> (Limbs<N>, u32) {
    let mut out = [0u32; N];
    let mut borrow = 0u64;
    for (i, out_limb) in out.iter_mut().enumerate().take(N) {
        let ai = a.limbs[i] as u64;
        let bi = b.limbs[i] as u64 + borrow;
        let diff = ai.wrapping_sub(bi);
        *out_limb = diff as u32;
        borrow = if ai < bi { 1 } else { 0 };
    }
    (Limbs { limbs: out }, borrow as u32)
}

#[inline(always)]
fn ge_limbs<const N: usize>(a: &Limbs<N>, b: &Limbs<N>) -> bool {
    for i in (0..N).rev() {
        let ai = a.limbs[i];
        let bi = b.limbs[i];
        if ai != bi {
            return ai > bi;
        }
    }
    true
}

#[inline(always)]
fn montgomery_mul<const N: usize>(
    a: &Limbs<N>,
    b: &Limbs<N>,
    modulus: &CachedModulus<N>,
) -> Limbs<N> {
    const MAX_DOUBLE: usize = MAX_LIMBS * 2;
    let mut t = [0u64; MAX_DOUBLE + 2];

    for i in 0..N {
        let mut carry = 0u64;
        for j in 0..N {
            let idx = i + j;
            let prod = t[idx] + (a.limbs[i] as u64) * (b.limbs[j] as u64) + carry;
            t[idx] = prod & 0xFFFF_FFFF;
            carry = prod >> 32;
        }
        let idx = i + N;
        let sum = t[idx] + carry;
        t[idx] = sum & 0xFFFF_FFFF;
        t[idx + 1] += sum >> 32;
    }

    for i in 0..N {
        let m = (t[i] as u32).wrapping_mul(modulus.n0_inv);
        let mut carry = 0u64;
        for j in 0..N {
            let idx = i + j;
            let prod = t[idx] + (m as u64) * (modulus.modulus.limbs[j] as u64) + carry;
            t[idx] = prod & 0xFFFF_FFFF;
            carry = prod >> 32;
        }
        let idx = i + N;
        let sum = t[idx] + carry;
        t[idx] = sum & 0xFFFF_FFFF;
        t[idx + 1] += sum >> 32;
    }

    let mut out = [0u32; N];
    for i in 0..N {
        out[i] = t[i + N] as u32;
    }
    let mut result = Limbs { limbs: out };
    // When t[2*N] != 0, the true result is 2^(N*32) + result, which is
    // necessarily >= modulus. The subtraction in u32 wrapping arithmetic
    // gives the correct reduced value.
    if t[2 * N] != 0 || ge_limbs(&result, &modulus.modulus) {
        let (reduced, _) = sub_limbs(&result, &modulus.modulus);
        result = reduced;
    }
    result
}

#[inline(always)]
fn mul_low_limbs<const N: usize>(a: &Limbs<N>, b: &Limbs<N>) -> Limbs<N> {
    const MAX_DOUBLE: usize = MAX_LIMBS * 2;
    let mut t = [0u64; MAX_DOUBLE + 1];

    for i in 0..N {
        let mut carry = 0u64;
        for j in 0..N {
            let idx = i + j;
            let prod = t[idx] + (a.limbs[i] as u64) * (b.limbs[j] as u64) + carry;
            t[idx] = prod & 0xFFFF_FFFF;
            carry = prod >> 32;
        }
        let idx = i + N;
        let sum = t[idx] + carry;
        t[idx] = sum & 0xFFFF_FFFF;
        t[idx + 1] += sum >> 32;
    }

    let mut out = [0u32; N];
    for i in 0..N {
        out[i] = t[i] as u32;
    }
    Limbs { limbs: out }
}

#[inline(always)]
fn mul_full_limbs_8(a: &Limbs8, b: &Limbs8) -> [u32; 16] {
    let mut t = [0u64; 17];
    for i in 0..8 {
        let mut carry = 0u64;
        for j in 0..8 {
            let idx = i + j;
            let prod = t[idx] + (a.limbs[i] as u64) * (b.limbs[j] as u64) + carry;
            t[idx] = prod & 0xFFFF_FFFF;
            carry = prod >> 32;
        }
        let idx = i + 8;
        let sum = t[idx] + carry;
        t[idx] = sum & 0xFFFF_FFFF;
        t[idx + 1] += sum >> 32;
    }
    let mut out = [0u32; 16];
    for i in 0..16 {
        out[i] = t[i] as u32;
    }
    out
}

#[inline(always)]
fn mod_reduce_16_by_8(u: [u32; 16], v: &Limbs8) -> Limbs8 {
    let mut n = 8usize;
    while n > 0 && v.limbs[n - 1] == 0 {
        n -= 1;
    }
    debug_assert!(n > 0);

    let mut v_norm = v.limbs;
    let mut u_norm = [0u32; 17];
    u_norm[..16].copy_from_slice(&u);

    let shift = v_norm[n - 1].leading_zeros();
    if shift != 0 {
        v_norm = shl_limbs_8(v_norm, shift);
        u_norm = shl_limbs_17(u_norm, shift);
    }

    if n == 1 {
        let v0 = v_norm[0] as u64;
        let mut rem = 0u64;
        for i in (0..17).rev() {
            let num = (rem << 32) + u_norm[i] as u64;
            rem = num % v0;
        }
        let mut out = [0u32; 8];
        out[0] = rem as u32;
        let mut result = Limbs { limbs: out };
        if shift != 0 {
            result.limbs = shr_limbs_8(result.limbs, shift);
        }
        if ge_limbs(&result, v) {
            let (reduced, _) = sub_limbs(&result, v);
            return reduced;
        }
        return result;
    }

    let v_n1 = v_norm[n - 1] as u64;
    let v_n2 = v_norm[n - 2] as u64;
    let base = 1u64 << 32;
    let m = 16usize - n;

    for j in (0..=m).rev() {
        let u_jn = u_norm[j + n] as u64;
        let u_jn1 = u_norm[j + n - 1] as u64;
        let u_jn2 = u_norm[j + n - 2] as u64;

        let numerator = u_jn * base + u_jn1;
        let mut qhat = numerator / v_n1;
        let mut rhat = numerator % v_n1;

        // Knuth Algorithm D step D3: refine qhat.
        // Combined loop handles both qhat >= base and the v_n2 test,
        // keeping qhat and rhat in sync (the original split lost rhat
        // when clamping qhat, causing under-estimation for large inputs).
        loop {
            if qhat < base && qhat * v_n2 <= base * rhat + u_jn2 {
                break;
            }
            qhat -= 1;
            rhat += v_n1;
            if rhat >= base {
                break;
            }
        }

        let mut borrow = 0u64;
        let mut carry = 0u64;
        for i in 0..n {
            let p = qhat * (v_norm[i] as u64) + carry;
            carry = p >> 32;
            let p_lo = p as u32;
            let (new_val, new_borrow) = sub_with_borrow(u_norm[j + i], p_lo, borrow);
            u_norm[j + i] = new_val;
            borrow = new_borrow;
        }
        let (new_val, new_borrow) = sub_with_borrow(u_norm[j + n], carry as u32, borrow);
        u_norm[j + n] = new_val;

        if new_borrow != 0 {
            let mut carry = 0u64;
            for i in 0..n {
                let sum = u_norm[j + i] as u64 + v_norm[i] as u64 + carry;
                u_norm[j + i] = sum as u32;
                carry = sum >> 32;
            }
            let sum = u_norm[j + n] as u64 + carry;
            u_norm[j + n] = sum as u32;
        }
    }

    let mut rem = [0u32; 8];
    rem[..n].copy_from_slice(&u_norm[..n]);
    if shift != 0 {
        rem = shr_limbs_8(rem, shift);
    }
    let result = Limbs { limbs: rem };
    if ge_limbs(&result, v) {
        let (reduced, _) = sub_limbs(&result, v);
        reduced
    } else {
        result
    }
}

#[inline(always)]
fn sub_with_borrow(x: u32, y: u32, borrow: u64) -> (u32, u64) {
    let rhs = y as u64 + borrow;
    let val = (x as u64).wrapping_sub(rhs);
    (val as u32, if (x as u64) < rhs { 1 } else { 0 })
}

#[inline(always)]
fn shl_limbs_8(mut limbs: [u32; 8], shift: u32) -> [u32; 8] {
    let mut carry = 0u32;
    for limb in &mut limbs {
        let new_carry = if shift == 0 { 0 } else { *limb >> (32 - shift) };
        *limb = limb.wrapping_shl(shift) | carry;
        carry = new_carry;
    }
    limbs
}

#[inline(always)]
fn shr_limbs_8(mut limbs: [u32; 8], shift: u32) -> [u32; 8] {
    let mut carry = 0u32;
    for limb in limbs.iter_mut().rev() {
        let new_carry = if shift == 0 { 0 } else { *limb << (32 - shift) };
        *limb = limb.wrapping_shr(shift) | carry;
        carry = new_carry;
    }
    limbs
}

#[inline(always)]
fn shl_limbs_17(mut limbs: [u32; 17], shift: u32) -> [u32; 17] {
    let mut carry = 0u32;
    for limb in &mut limbs {
        let new_carry = if shift == 0 { 0 } else { *limb >> (32 - shift) };
        *limb = limb.wrapping_shl(shift) | carry;
        carry = new_carry;
    }
    limbs
}

#[cfg(test)]
mod tests {
    use super::*;
    use num::BigUint;

    fn limbs8_from_biguint(v: &BigUint) -> Limbs8 {
        Limbs8::from_biguint(v)
    }

    fn biguint_from_limbs8(l: &Limbs8) -> BigUint {
        l.to_biguint()
    }

    fn biguint_from_u32_16(arr: &[u32; 16]) -> BigUint {
        BigUint::from_slice(arr)
    }

    /// Reference: compute (a * b) mod m using BigUint
    fn ref_mulmod(a: &Limbs8, b: &Limbs8, m: &Limbs8) -> Limbs8 {
        let ba = biguint_from_limbs8(a);
        let bb = biguint_from_limbs8(b);
        let bm = biguint_from_limbs8(m);
        if bm == BigUint::from(0u32) {
            let prod = ba * bb;
            let mask = (BigUint::from(1u32) << 256) - BigUint::from(1u32);
            limbs8_from_biguint(&(prod & mask))
        } else {
            limbs8_from_biguint(&((ba * bb) % bm))
        }
    }

    /// Reference: compute product mod modulus using BigUint on the 16-limb product
    fn ref_mod_reduce(product: &[u32; 16], modulus: &Limbs8) -> Limbs8 {
        let bp = biguint_from_u32_16(product);
        let bm = biguint_from_limbs8(modulus);
        limbs8_from_biguint(&(bp % bm))
    }

    // ================================================================
    // Test: mod_reduce_16_by_8 against BigUint for various inputs
    // ================================================================

    #[test]
    fn test_mod_reduce_small_even() {
        let a = Limbs8::from_slice(&[0xDEADBEEF]);
        let b = Limbs8::from_slice(&[0xCAFEBABE]);
        let m = Limbs8::from_slice(&[6]);
        let product = mul_full_limbs_8(&a, &b);
        let got = mod_reduce_16_by_8(product, &m);
        let expected = ref_mod_reduce(&product, &m);
        assert_eq!(got.limbs, expected.limbs, "small even modulus failed");
    }

    #[test]
    fn test_mod_reduce_large_even_secp256k1() {
        // secp256k1_n - 1 (a) * secp256k1_p (b) mod (secp256k1_p - 1) (even)
        let a = Limbs8::from_slice(&[
            0xD0364140, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF,
        ]);
        let b = Limbs8::from_slice(&[
            0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF,
        ]);
        let m = Limbs8::from_slice(&[
            0xFFFFFC2E, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF,
        ]);

        let product = mul_full_limbs_8(&a, &b);
        let got = mod_reduce_16_by_8(product, &m);
        let expected = ref_mod_reduce(&product, &m);

        assert_eq!(
            got.limbs, expected.limbs,
            "\nmod_reduce_16_by_8 MISMATCH for large even modulus!\ngot:      {:08X?}\nexpected: {:08X?}",
            got.limbs, expected.limbs
        );
    }

    #[test]
    fn test_mod_reduce_large_even_near_max() {
        let a = Limbs8::from_slice(&[
            0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF,
        ]);
        let b = Limbs8::from_slice(&[
            0xFFFFFFFB, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF,
        ]);
        let m = Limbs8::from_slice(&[
            0xFFFFFFFA, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF,
        ]);

        let product = mul_full_limbs_8(&a, &b);
        let got = mod_reduce_16_by_8(product, &m);
        let expected = ref_mod_reduce(&product, &m);

        assert_eq!(
            got.limbs, expected.limbs,
            "\nmod_reduce_16_by_8 MISMATCH for near-max even modulus!\ngot:      {:08X?}\nexpected: {:08X?}",
            got.limbs, expected.limbs
        );
    }

    // ================================================================
    // Test: uint256_mod_mul end-to-end
    // ================================================================

    #[test]
    fn test_uint256_mod_mul_odd_small() {
        let a = Limbs8::from_slice(&[3]);
        let b = Limbs8::from_slice(&[5]);
        let m = Limbs8::from_slice(&[7]);
        let got = uint256_mod_mul(&a, &b, &m);
        let expected = ref_mulmod(&a, &b, &m);
        assert_eq!(got.limbs, expected.limbs, "odd small modulus");
    }

    #[test]
    fn test_uint256_mod_mul_odd_large() {
        let a = Limbs8::from_slice(&[
            0xD0364140, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF,
        ]);
        let b = a;
        let m = Limbs8::from_slice(&[
            0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF,
        ]);
        let got = uint256_mod_mul(&a, &b, &m);
        let expected = ref_mulmod(&a, &b, &m);
        assert_eq!(
            got.limbs, expected.limbs,
            "\nuint256_mod_mul MISMATCH (odd, large)!\ngot:      {:08X?}\nexpected: {:08X?}",
            got.limbs, expected.limbs
        );
    }

    #[test]
    fn test_uint256_mod_mul_even_large() {
        let a = Limbs8::from_slice(&[
            0xD0364140, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF,
        ]);
        let b = Limbs8::from_slice(&[
            0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF,
        ]);
        let m = Limbs8::from_slice(&[
            0xFFFFFC2E, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF,
        ]);
        let got = uint256_mod_mul(&a, &b, &m);
        let expected = ref_mulmod(&a, &b, &m);
        assert_eq!(
            got.limbs, expected.limbs,
            "\nuint256_mod_mul MISMATCH (even, large)!\ngot:      {:08X?}\nexpected: {:08X?}",
            got.limbs, expected.limbs
        );
    }

    #[test]
    fn test_montgomery_mul_large_odd() {
        let a = Limbs8::from_slice(&[
            0xD0364140, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF,
        ]);
        let b = a;
        let m = Limbs8::from_slice(&[
            0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
            0xFFFFFFFF,
        ]);
        let got = uint256_mod_mul(&a, &b, &m);
        let expected = ref_mulmod(&a, &b, &m);
        assert_eq!(
            got.limbs, expected.limbs,
            "\nMontgomery carry bug!\ngot:      {:08X?}\nexpected: {:08X?}",
            got.limbs, expected.limbs
        );
    }

    #[test]
    fn test_mod_reduce_sweep_even_moduli() {
        let base_mod = [
            0xFFFFFFFA_u32,
            0xFFFFFFFF,
            0xFFFFFFFF,
            0xFFFFFFFF,
            0xFFFFFFFF,
            0xFFFFFFFF,
            0xFFFFFFFF,
            0xFFFFFFFF,
        ];
        for delta in [0u32, 2, 4, 6, 100, 0x10000, 0xFFFFFFFE] {
            let mut m_limbs = base_mod;
            m_limbs[0] = m_limbs[0].wrapping_sub(delta) & 0xFFFFFFFE;
            let m = Limbs8::from_slice(&m_limbs);

            let a = Limbs8::from_slice(&[
                0x12345678, 0x9ABCDEF0, 0x11111111, 0x22222222, 0xDDDDDDDD, 0xEEEEEEEE, 0xFFFFFFFF,
                0xFFFFFFF0,
            ]);
            let b = Limbs8::from_slice(&[
                0xABCDEF01, 0x23456789, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777,
                0xFFFFFFF8,
            ]);

            let product = mul_full_limbs_8(&a, &b);
            let got = mod_reduce_16_by_8(product, &m);
            let expected = ref_mod_reduce(&product, &m);
            assert_eq!(
                got.limbs, expected.limbs,
                "\nmod_reduce MISMATCH for even modulus delta={}!\nm:        {:08X?}\ngot:      {:08X?}\nexpected: {:08X?}",
                delta, m.limbs, got.limbs, expected.limbs
            );
        }
    }
}
