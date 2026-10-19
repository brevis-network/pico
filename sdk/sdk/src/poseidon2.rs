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
pub use pico_vm::primitives::consts::{DIGEST_SIZE, PERMUTATION_RATE as RATE};

use crate::ZkField;

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
