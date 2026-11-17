use crate::{
    chips::utils::indices_arr,
    compiler::word::Word,
    primitives::consts::{
        DIGEST_SIZE, MAX_NUM_PVS, PV_DIGEST_NUM_WORDS, RECURSION_NUM_PVS, WORD_SIZE,
    },
};
use core::fmt::Debug;
use pico_derive::AlignedBorrow;
use rand::{
    distr::{Distribution, StandardUniform},
    Rng, RngExt,
};
use serde::{Deserialize, Serialize};
use static_assertions::const_assert_eq;
use std::{
    borrow::BorrowMut,
    mem::{size_of, transmute, MaybeUninit},
};

pub const RECURSIVE_PROOF_NUM_PV_ELTS: usize = size_of::<RecursionPublicValues<u8>>();

/// Base-field elements of [`RecursionPublicValues::global_sum`]: the numerator's coefficients, then
/// the denominator's.
pub const GLOBAL_SUM_LEN: usize = 10;

const fn make_col_map() -> RecursionPublicValues<usize> {
    let indices_arr = indices_arr::<RECURSION_NUM_PVS>();
    unsafe { transmute::<[usize; RECURSION_NUM_PVS], RecursionPublicValues<usize>>(indices_arr) }
}

pub const RECURSION_PUBLIC_VALUES_COL_MAP: RecursionPublicValues<usize> = make_col_map();

// All the fields before `digest` are hashed to produce the digest.
pub const NUM_PV_ELMS_TO_HASH: usize = RECURSION_PUBLIC_VALUES_COL_MAP.digest[0];

// `pico_verifier` hard-codes the offsets it reads; any layout drift must fail the build here.
const_assert_eq!(
    pico_verifier::public_values::RECURSION_NUM_PVS,
    RECURSION_NUM_PVS
);
const_assert_eq!(
    pico_verifier::public_values::NUM_PV_ELMS_TO_HASH,
    NUM_PV_ELMS_TO_HASH
);
const_assert_eq!(
    pico_verifier::public_values::RECURSION_PV_OFFSETS.flag_complete,
    RECURSION_PUBLIC_VALUES_COL_MAP.flag_complete
);
const _: () = {
    let v = pico_verifier::public_values::RECURSION_PV_OFFSETS;
    let col = RECURSION_PUBLIC_VALUES_COL_MAP;
    let mut i = 0;
    while i < DIGEST_SIZE {
        assert!(v.riscv_vk_digest[i] == col.riscv_vk_digest[i]);
        assert!(v.vk_root[i] == col.vk_root[i]);
        assert!(v.digest[i] == col.digest[i]);
        i += 1;
    }
    let mut i = 0;
    while i < PV_DIGEST_NUM_WORDS * WORD_SIZE {
        assert!(
            v.committed_value_digest[i]
                == col.committed_value_digest[i / WORD_SIZE].0[i % WORD_SIZE]
        );
        i += 1;
    }
};

// The global LogUp's fields are among the hashed ones. A proof's own constraints tie only the
// digest to what its circuit computed; the parent recomputes the digest over the fields the
// child published, so a child cannot publish a chain value, a sum or a count of its choosing.
const _: () = {
    let col = RECURSION_PUBLIC_VALUES_COL_MAP;
    assert!(col.global_chain_start[DIGEST_SIZE - 1] < NUM_PV_ELMS_TO_HASH);
    assert!(col.global_chain_end[DIGEST_SIZE - 1] < NUM_PV_ELMS_TO_HASH);
    assert!(col.global_sum[GLOBAL_SUM_LEN - 1] < NUM_PV_ELMS_TO_HASH);
    assert!(col.global_row_count < NUM_PV_ELMS_TO_HASH);
};

// Recursive proof has more public values than core proof, so the max number constant defined in
// pico_core should be set to `RECURSION_NUM_PVS`.
const_assert_eq!(RECURSION_NUM_PVS, MAX_NUM_PVS);

/// The PublicValues struct is used to store all of a reduce proof's public values.
#[derive(AlignedBorrow, Serialize, Deserialize, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct RecursionPublicValues<T> {
    /// The hash of all the bytes that the program has written to public values.
    /// Each `Word<T>` slot stores 4 individual bytes (each limb < 256) rather than
    /// the 4×u16 limbs of a 64-bit value. The downstream bn254 reduction consumes
    /// the 32 bytes directly via `words_to_bytes` + `felt_bytes_to_bn254_var`, so
    /// **do not** call `Word::from(u32)` / `reduce()` / `to_u64()` on these values.
    pub committed_value_digest: [Word<T>; PV_DIGEST_NUM_WORDS],

    /// The hash of all deferred proofs that have been witnessed in the VM.
    pub deferred_proofs_digest: [T; DIGEST_SIZE],

    /// Start state of reconstruct_deferred_digest.
    pub start_reconstruct_deferred_digest: [T; DIGEST_SIZE],

    /// End state of reconstruct_deferred_digest.
    pub end_reconstruct_deferred_digest: [T; DIGEST_SIZE],

    /// The start pc of chunks being proven as 3×u16 limbs.
    pub start_pc: [T; 3],

    /// The expected start pc for the next chunk as 3×u16 limbs.
    pub next_pc: [T; 3],

    /// First chunk being proven.
    pub start_chunk: T,

    /// Next chunk that should be proven.
    pub next_chunk: T,

    /// First execution chunk being proven.
    pub start_execution_chunk: T,

    /// Next execution chunk that should be proven.
    pub next_execution_chunk: T,

    /// Previous MemoryInit address as 3×u16 limbs.
    pub previous_init_addr_limbs: [T; 3],

    /// Last MemoryInit address as 3×u16 limbs.
    pub last_init_addr_limbs: [T; 3],

    /// Previous MemoryFinalize address as 3×u16 limbs.
    pub previous_finalize_addr_limbs: [T; 3],

    /// Last MemoryFinalize address as 3×u16 limbs.
    pub last_finalize_addr_limbs: [T; 3],

    /// The commitment to the Pico program being proven.
    pub riscv_vk_digest: [T; DIGEST_SIZE],

    /// The root of the vk merkle tree.
    pub vk_root: [T; DIGEST_SIZE],

    /// The global LogUp's chain over the chunks' Global table commitments, as the subtree's
    /// left neighbour must end it. A chunk's leaf carries the chain value before the chunk; a
    /// group or image node carries a wrapped value, which binds the challenges it used.
    pub global_chain_start: [T; DIGEST_SIZE],

    /// The same chain as the subtree's right neighbour must start it.
    pub global_chain_end: [T; DIGEST_SIZE],

    /// The global LogUp's fractional sum `(p, q)` over the group proofs in the subtree: two
    /// extension elements, [`GLOBAL_SUM_LEN`]` / 2` base-field coefficients each. `(0, 1)` for a
    /// subtree without a group proof.
    pub global_sum: [T; GLOBAL_SUM_LEN],

    /// An upper bound on the cross-chunk events of the chunks in the subtree, in units of
    /// `2^10` rows.
    pub global_row_count: T,

    /// Whether the proof completely proves the program execution.
    pub flag_complete: T,

    /// Whether the proof represents a collection of chunks which contain at least one execution
    /// chunk, i.e. a chunk that contains the `cpu` chip.
    pub contains_execution_chunk: T,

    /// The digest of all the previous public values elements.
    pub digest: [T; DIGEST_SIZE],

    /// The exit code of the program.  Note that this is not part of the public values digest,
    /// since it's value will be individually constrained.
    pub exit_code: T,
}

impl<T> Distribution<RecursionPublicValues<T>> for StandardUniform
where
    StandardUniform: Distribution<T>
        + Distribution<[Word<T>; PV_DIGEST_NUM_WORDS]>
        + Distribution<[T; DIGEST_SIZE]>
        + Distribution<[T; GLOBAL_SUM_LEN]>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> RecursionPublicValues<T> {
        RecursionPublicValues {
            committed_value_digest: rng.random(),
            deferred_proofs_digest: rng.random(),
            start_reconstruct_deferred_digest: rng.random(),
            end_reconstruct_deferred_digest: rng.random(),
            start_pc: rng.random(),
            next_pc: rng.random(),
            start_chunk: rng.random(),
            next_chunk: rng.random(),
            start_execution_chunk: rng.random(),
            next_execution_chunk: rng.random(),
            previous_init_addr_limbs: rng.random(),
            last_init_addr_limbs: rng.random(),
            previous_finalize_addr_limbs: rng.random(),
            last_finalize_addr_limbs: rng.random(),
            riscv_vk_digest: rng.random(),
            vk_root: rng.random(),
            global_chain_start: rng.random(),
            global_chain_end: rng.random(),
            global_sum: rng.random(),
            global_row_count: rng.random(),
            flag_complete: rng.random(),
            contains_execution_chunk: rng.random(),
            digest: rng.random(),
            exit_code: rng.random(),
        }
    }
}

/// Converts the public values to an array of elements.
impl<F: Default + Copy> RecursionPublicValues<F> {
    pub fn to_vec(&self) -> [F; RECURSION_NUM_PVS] {
        let mut ret = [F::default(); RECURSION_NUM_PVS];
        let pv: &mut RecursionPublicValues<F> = ret.as_mut_slice().borrow_mut();

        *pv = *self;
        ret
    }
}

/// Converts the public values to an array of elements.
impl<F: Copy> RecursionPublicValues<F> {
    pub fn as_array(&self) -> [F; RECURSION_NUM_PVS] {
        unsafe {
            let mut ret = [MaybeUninit::<F>::zeroed().assume_init(); RECURSION_NUM_PVS];
            let pv: &mut RecursionPublicValues<F> = ret.as_mut_slice().borrow_mut();
            *pv = *self;
            ret
        }
    }
}

impl<T: Copy> IntoIterator for RecursionPublicValues<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, RECURSION_NUM_PVS>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_array().into_iter()
    }
}
