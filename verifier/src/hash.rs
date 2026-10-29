//! The host mirrors of the in-circuit Poseidon2 hashes.

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_symmetric::Permutation;
use pico_mle_core::config::koala_bear_poseidon2::default_koalabear_poseidon2_16;

use crate::Kb;

/// Padding-free rate-8/width-16 overwrite-mode Poseidon2 sponge, shared by the PV digest, the
/// exe identity digest and the whitelist leaf hash. No trailing permute when the input length is
/// an exact multiple of the rate. Byte-identical to the in-circuit `hash_poseidon2_fresh`.
pub fn sponge_hash(elems: &[Kb]) -> [Kb; 8] {
    let perm = default_koalabear_poseidon2_16();
    let mut state = [Kb::ZERO; 16];
    let mut absorb_idx = 0usize;
    for &v in elems {
        state[absorb_idx] = v;
        absorb_idx += 1;
        if absorb_idx == 8 {
            perm.permute_mut(&mut state);
            absorb_idx = 0;
        }
    }
    if absorb_idx != 0 {
        perm.permute_mut(&mut state);
    }
    std::array::from_fn(|i| state[i])
}

/// Two-to-one Poseidon2 compress, `permute([l ‖ r])[..8]`: the in-circuit `compress_poseidon2`'s
/// host mirror.
pub fn compress(l: [Kb; 8], r: [Kb; 8]) -> [Kb; 8] {
    let perm = default_koalabear_poseidon2_16();
    let mut state = [Kb::ZERO; 16];
    state[..8].copy_from_slice(&l);
    state[8..].copy_from_slice(&r);
    perm.permute_mut(&mut state);
    std::array::from_fn(|i| state[i])
}

/// A digest as canonical `u32` limbs.
pub fn digest_to_u32s(digest: &[Kb; 8]) -> [u32; 8] {
    digest.map(|b| b.as_canonical_u32())
}

/// [`digest_to_u32s`] inverted (each limb reduced into the field).
pub fn digest_from_u32s(limbs: &[u32; 8]) -> [Kb; 8] {
    limbs.map(Kb::from_u32)
}
