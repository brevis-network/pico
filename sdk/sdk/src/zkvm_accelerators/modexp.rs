//! Arbitrary-length modular exponentiation (EIP-198), in software: revm's implementation.

use super::{items, ZkvmStatus, ZKVM_EOK};

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
    // The result is minimal big-endian and below the modulus; right-align it. Zero may come back
    // as one zero byte, so the copy takes the tail. Written last: `output` may share an input's
    // bytes.
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
