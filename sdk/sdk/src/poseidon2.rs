//! Poseidon2 hashing over KoalaBear, with the machine's own sponge.
//!
//! [`hash`] is the sponge the machine hashes with on the host,
//! `pico_vm::primitives::Poseidon2HashField::poseidon2_hash_iter`: `PaddingFreeSponge` over a
//! 16-element state, [`RATE`] elements absorbed per permutation by overwriting the start of the
//! state, [`DIGEST_SIZE`] elements squeezed. In a guest it runs through the Poseidon2 precompile, so
//! a guest and a host that hash the same elements get the same digest.
//!
//! **Fixed-length inputs only.** The sponge adds no padding. When an input's last block is only
//! partly filled, appending elements up to the end of that block, each equal to the value its state
//! lane already holds, changes nothing: in the first block those values are zeros, so `[a]`,
//! `[a, 0]` and `[a, 0, 0, 0, 0, 0, 0, 0]` all collide; in any later block they are the previous
//! permutation's output, which anyone can compute. So inputs of different lengths can collide
//! whatever they end in. The machine hashes fixed-width data with it -- Merkle leaves, which are
//! rows of a fixed width, and the 48-element deferred-proof digest -- and where the length varies,
//! as in its verifying-key pre-hash, it puts the length ahead of the data. Do the same: to hash data
//! whose length varies, make the length part of the input, for example its first element.

#[cfg(target_os = "zkvm")]
use p3_field::PrimeCharacteristicRing;
use p3_field::PrimeField32;
use pico_patch_libs::{syscall_poseidon2_permute, Poseidon2State, POSEIDON2_WIDTH};

use crate::ZkField;

/// Elements in a digest.
pub const DIGEST_SIZE: usize = 8;
/// Elements absorbed per permutation.
pub const RATE: usize = 8;

// Checked against `pico-vm` on the host, since a guest does not compile it. DIGEST_SIZE is the width
// of pico-vm's `hash_deferred_proof` output. Nothing in pico-vm reads PERMUTATION_RATE: the rate the
// machine hashes at is pinned by `tests::the_deferred_proof_digest_is_the_machines` instead.
#[cfg(not(target_os = "zkvm"))]
const _: () = assert!(
    DIGEST_SIZE == pico_vm::primitives::consts::DIGEST_SIZE
        && RATE == pico_vm::primitives::consts::PERMUTATION_RATE
);

/// The Poseidon2 digest of `inputs`, the machine's `poseidon2_hash_iter` of the same elements.
///
/// See the [module documentation](self) for the fixed-length requirement.
pub fn hash<I: IntoIterator<Item = ZkField>>(inputs: I) -> [ZkField; DIGEST_SIZE] {
    #[cfg(target_os = "zkvm")]
    {
        // `PaddingFreeSponge::hash_iter`, step for step, with the permutation behind the syscall.
        let mut state = [ZkField::ZERO; POSEIDON2_WIDTH];
        let mut inputs = inputs.into_iter();
        'absorb: loop {
            for i in 0..RATE {
                match inputs.next() {
                    Some(x) => state[i] = x,
                    None => {
                        // A block that took nothing leaves the previous permutation's output as it
                        // is; one that took anything is permuted before squeezing.
                        if i != 0 {
                            state = permuted(&state);
                        }
                        break 'absorb;
                    }
                }
            }
            state = permuted(&state);
        }
        core::array::from_fn(|i| state[i])
    }

    #[cfg(not(target_os = "zkvm"))]
    {
        <ZkField as pico_vm::primitives::Poseidon2HashField>::poseidon2_hash_iter(
            inputs.into_iter().collect(),
        )
    }
}

/// Run one permutation over `state`.
///
/// The single place this crate reaches the syscall. It used to be three copies of the same
/// unsafe block, which is exactly where the buffers' alignment requirement rots: both
/// pointers have to be 8-byte aligned or the call has no provable trace, and a bare
/// `[u32; 16]` local is aligned to 4. Routing every caller through [`Poseidon2State`] makes
/// that unrepresentable rather than a rule to remember -- see its docs.
pub(crate) fn permuted<F: PrimeField32>(state: &[F; POSEIDON2_WIDTH]) -> [F; POSEIDON2_WIDTH] {
    let input = Poseidon2State(state.map(|f| f.as_canonical_u32()));
    let mut output = Poseidon2State::zero();

    // SAFETY: both arguments are live, correctly typed and -- by `Poseidon2State`'s
    // `repr(align(8))` -- correctly aligned for the whole call.
    unsafe {
        syscall_poseidon2_permute(&input, &mut output);
    }

    output.0.map(F::from_u32)
}

/// `pico_vm::primitives::hash_deferred_proof` for [`ZkField`], in software on the same sponge.
#[cfg(any(target_os = "zkvm", test))]
pub(crate) fn hash_deferred_proof(
    prev_digest: &[ZkField; DIGEST_SIZE],
    vk_digest: &[ZkField; DIGEST_SIZE],
    pv_digest: &[ZkField; 32],
) -> [ZkField; DIGEST_SIZE] {
    use p3_koala_bear::{default_koalabear_poseidon2_16, Poseidon2KoalaBear};
    use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};

    type Sponge =
        PaddingFreeSponge<Poseidon2KoalaBear<POSEIDON2_WIDTH>, POSEIDON2_WIDTH, RATE, DIGEST_SIZE>;
    lazy_static::lazy_static! {
        static ref HASHER: Sponge = Sponge::new(default_koalabear_poseidon2_16());
    }

    let mut inputs = Vec::with_capacity(DIGEST_SIZE * 2 + 32);
    inputs.extend_from_slice(prev_digest);
    inputs.extend_from_slice(vk_digest);
    inputs.extend_from_slice(pv_digest);
    HASHER.hash_iter(inputs)
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    #[test]
    fn the_deferred_proof_digest_is_the_machines() {
        let elems = |seed: u32| -> Vec<ZkField> {
            (0..32u32)
                .map(|i| {
                    ZkField::from_u32(seed.wrapping_mul(2_654_435_761).wrapping_add(i * 97) >> 1)
                })
                .collect()
        };
        for seed in 1..=4 {
            let prev: [ZkField; DIGEST_SIZE] = elems(seed)[..DIGEST_SIZE].try_into().unwrap();
            let vk: [ZkField; DIGEST_SIZE] = elems(seed + 10)[..DIGEST_SIZE].try_into().unwrap();
            let pv: [ZkField; 32] = elems(seed + 20).try_into().unwrap();
            assert_eq!(
                hash_deferred_proof(&prev, &vk, &pv),
                pico_vm::primitives::hash_deferred_proof(&prev, &vk, &pv)
            );
        }
    }
}
