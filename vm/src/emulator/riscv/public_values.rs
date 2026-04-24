use crate::{
    compiler::word::Word,
    primitives::consts::{DIGEST_SIZE, MAX_NUM_PVS, PV_DIGEST_NUM_WORDS},
};
use p3_field::FieldAlgebra;
use serde::{Deserialize, Serialize};
use std::borrow::{Borrow, BorrowMut};

#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct PublicValues<W, T> {
    /// Each `Word` slot stores 4 individual bytes (each limb < 256), not the 4×u16
    /// limbs that `Word` carries for 64-bit values. The 32 bytes feed directly into
    /// the downstream bn254 reduction (`words_to_bytes` + `felt_bytes_to_bn254_var`),
    /// so **do not** call `Word::from(u32)` / `reduce()` / `to_u64()` on these values.
    pub committed_value_digest: [W; PV_DIGEST_NUM_WORDS],

    /// The hash of all deferred proofs that have been witnessed in the VM. It will be rebuilt in
    /// recursive verification as the proofs get verified. The hash itself is a rolling poseidon2
    /// hash of each proof+vkey hash and the previous hash which is initially zero.
    pub deferred_proofs_digest: [T; DIGEST_SIZE],

    /// The chunk's start program counter as 3×u16 limbs.
    pub start_pc: [T; 3],

    /// The expected start program counter for the next chunk as 3×u16 limbs.
    pub next_pc: [T; 3],

    /// The exit code of the program.  Only valid if halt has been executed.
    pub exit_code: T,

    /// The chunk number.
    pub chunk: T,

    /// The execution chunk number.
    pub execution_chunk: T,

    /// The previous initialization address as 3×u16 limbs.
    pub previous_init_addr_limbs: [T; 3],

    /// The largest initialization address in the current chunk as 3×u16 limbs.
    pub last_init_addr_limbs: [T; 3],

    /// The previous finalization address as 3×u16 limbs.
    pub previous_finalize_addr_limbs: [T; 3],

    /// The largest finalization address in the current chunk as 3×u16 limbs.
    pub last_finalize_addr_limbs: [T; 3],

    /// This field is here to ensure that the size of the public values struct is a multiple of 8.
    pub empty: [T; 3],
}

impl PublicValues<u32, u32> {
    pub fn to_vec<F: FieldAlgebra>(&self) -> Vec<F> {
        let mut pv = vec![F::ZERO; MAX_NUM_PVS];
        let field_values = PublicValues::<Word<F>, F>::from(*self);
        let pv_ref_mut: &mut PublicValues<Word<F>, F> = pv.as_mut_slice().borrow_mut();
        *pv_ref_mut = field_values;

        pv
    }
}

impl<T: Clone> Borrow<PublicValues<Word<T>, T>> for [T] {
    fn borrow(&self) -> &PublicValues<Word<T>, T> {
        let size = std::mem::size_of::<PublicValues<Word<u8>, u8>>();
        debug_assert!(self.len() >= size);
        let slice = &self[0..size];
        let (prefix, shorts, _suffix) = unsafe { slice.align_to::<PublicValues<Word<T>, T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T: Clone> BorrowMut<PublicValues<Word<T>, T>> for [T] {
    fn borrow_mut(&mut self) -> &mut PublicValues<Word<T>, T> {
        let size = std::mem::size_of::<PublicValues<Word<u8>, u8>>();
        debug_assert!(self.len() >= size);
        let slice = &mut self[0..size];
        let (prefix, shorts, _suffix) = unsafe { slice.align_to_mut::<PublicValues<Word<T>, T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

impl<F: FieldAlgebra> From<PublicValues<u32, u32>> for PublicValues<Word<F>, F> {
    fn from(value: PublicValues<u32, u32>) -> Self {
        let PublicValues {
            committed_value_digest,
            deferred_proofs_digest,
            start_pc,
            next_pc,
            exit_code,
            chunk,
            execution_chunk,
            previous_init_addr_limbs,
            last_init_addr_limbs,
            previous_finalize_addr_limbs,
            last_finalize_addr_limbs,
            ..
        } = value;

        // Split each u32 digest word into 4 little-endian bytes so the downstream
        // bn254 reduction operates on true bytes (each limb < 256). **Do not** use
        // `Word::from(u32)` here — since the u64 rework `Word::from(u32)` produces
        // [u16, u16, 0, 0], which would make the constraint-side num2bits path and
        // the witness-side `as_canonical_u32()` path disagree.
        let committed_value_digest: [_; PV_DIGEST_NUM_WORDS] = core::array::from_fn(|i| {
            Word([
                F::from_canonical_u32(committed_value_digest[i] & 0xFF),
                F::from_canonical_u32((committed_value_digest[i] >> 8) & 0xFF),
                F::from_canonical_u32((committed_value_digest[i] >> 16) & 0xFF),
                F::from_canonical_u32((committed_value_digest[i] >> 24) & 0xFF),
            ])
        });

        let deferred_proofs_digest: [_; DIGEST_SIZE] =
            core::array::from_fn(|i| F::from_canonical_u32(deferred_proofs_digest[i]));

        let start_pc = start_pc.map(F::from_canonical_u32);
        let next_pc = next_pc.map(F::from_canonical_u32);
        let exit_code = F::from_canonical_u32(exit_code);
        let chunk = F::from_canonical_u32(chunk);
        let execution_chunk = F::from_canonical_u32(execution_chunk);
        let previous_init_addr_limbs = previous_init_addr_limbs.map(F::from_canonical_u32);
        let last_init_addr_limbs = last_init_addr_limbs.map(F::from_canonical_u32);
        let previous_finalize_addr_limbs = previous_finalize_addr_limbs.map(F::from_canonical_u32);
        let last_finalize_addr_limbs = last_finalize_addr_limbs.map(F::from_canonical_u32);

        Self {
            committed_value_digest,
            deferred_proofs_digest,
            start_pc,
            next_pc,
            exit_code,
            chunk,
            execution_chunk,
            previous_init_addr_limbs,
            last_init_addr_limbs,
            previous_finalize_addr_limbs,
            last_finalize_addr_limbs,
            empty: [F::ZERO; 3],
        }
    }
}
