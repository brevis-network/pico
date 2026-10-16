use crate::{
    chips::utils::indices_arr,
    compiler::word::Word,
    machine::septic::SepticDigest,
    primitives::consts::{DIGEST_SIZE, MAX_NUM_PVS, PV_DIGEST_NUM_WORDS, RECURSION_NUM_PVS},
};
use core::fmt::Debug;
use pico_derive::AlignedBorrow;
use serde::{Deserialize, Serialize};
use static_assertions::const_assert_eq;
use std::{
    borrow::BorrowMut,
    mem::{size_of, transmute, MaybeUninit},
};

pub const RECURSIVE_PROOF_NUM_PV_ELTS: usize = size_of::<RecursionPublicValues<u8>>();

const fn make_col_map() -> RecursionPublicValues<usize> {
    let indices_arr = indices_arr::<RECURSION_NUM_PVS>();
    unsafe { transmute::<[usize; RECURSION_NUM_PVS], RecursionPublicValues<usize>>(indices_arr) }
}

pub const RECURSION_PUBLIC_VALUES_COL_MAP: RecursionPublicValues<usize> = make_col_map();

// All the fields before `digest` are hashed to produce the digest.
pub const NUM_PV_ELMS_TO_HASH: usize = RECURSION_PUBLIC_VALUES_COL_MAP.digest[0];

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

    /// Current cumulative sum of lookup bus. Note that for recursive proofs for core proofs, this
    /// contains the global cumulative sum.
    pub global_cumulative_sum: SepticDigest<T>,

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
