use crate::{
    chips::utils::indices_arr,
    compiler::{
        recursion_v2::{circuit, prelude::*},
        word::Word,
    },
    configs::config::FieldGenericConfig,
    instances::configs::recur_config::StarkConfig as RecursionSC,
    primitives::consts::{
        DIGEST_SIZE, MAX_NUM_PVS_V2, PERMUTATION_RATE, PERMUTATION_WIDTH, POSEIDON_NUM_WORDS,
        PV_DIGEST_NUM_WORDS, RECURSION_NUM_PVS_V2,
    },
    recursion_v2::air::public_values::circuit::{
        config::CircuitConfig, hash::Posedion2BabyBearHasherVariable,
    },
};
use core::fmt::Debug;
use itertools::Itertools;
use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_field::{FieldAlgebra, PrimeField32};
use p3_symmetric::CryptographicPermutation;
use pico_derive::AlignedBorrow;
use serde::{Deserialize, Serialize};
use static_assertions::const_assert_eq;
use std::{
    borrow::BorrowMut,
    mem::{size_of, transmute, MaybeUninit},
};

pub const CHALLENGER_STATE_NUM_ELTS: usize = size_of::<ChallengerPublicValues<u8>>();
pub const RECURSIVE_PROOF_NUM_PV_ELTS: usize = size_of::<RecursionPublicValues<u8>>();

const fn make_col_map() -> RecursionPublicValues<usize> {
    let indices_arr = indices_arr::<RECURSION_NUM_PVS_V2>();
    unsafe { transmute::<[usize; RECURSION_NUM_PVS_V2], RecursionPublicValues<usize>>(indices_arr) }
}

pub const RECURSION_PUBLIC_VALUES_COL_MAP: RecursionPublicValues<usize> = make_col_map();

// All the fields before `digest` are hashed to produce the digest.
pub const NUM_PV_ELMS_TO_HASH: usize = RECURSION_PUBLIC_VALUES_COL_MAP.digest[0];

// Recursive proof has more public values than core proof, so the max number constant defined in
// pico_core should be set to `RECURSION_NUM_PVS`.
const_assert_eq!(RECURSION_NUM_PVS_V2, MAX_NUM_PVS_V2);

#[derive(AlignedBorrow, Serialize, Deserialize, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct ChallengerPublicValues<T> {
    pub sponge_state: [T; PERMUTATION_WIDTH],
    pub num_inputs: T,
    pub input_buffer: [T; PERMUTATION_WIDTH],
    pub num_outputs: T,
    pub output_buffer: [T; PERMUTATION_WIDTH],
}

impl<T: Clone> ChallengerPublicValues<T> {
    pub fn set_challenger<P: CryptographicPermutation<[T; PERMUTATION_WIDTH]>>(
        &self,
        challenger: &mut DuplexChallenger<T, P, PERMUTATION_WIDTH, PERMUTATION_RATE>,
    ) where
        T: PrimeField32,
    {
        challenger.sponge_state = self.sponge_state;
        let num_inputs = self.num_inputs.as_canonical_u32() as usize;
        challenger.input_buffer = self.input_buffer[..num_inputs].to_vec();
        let num_outputs = self.num_outputs.as_canonical_u32() as usize;
        challenger.output_buffer = self.output_buffer[..num_outputs].to_vec();
    }

    pub fn as_array(&self) -> [T; CHALLENGER_STATE_NUM_ELTS]
    where
        T: Copy,
    {
        unsafe {
            let mut ret = [MaybeUninit::<T>::zeroed().assume_init(); CHALLENGER_STATE_NUM_ELTS];
            let pv: &mut ChallengerPublicValues<T> = ret.as_mut_slice().borrow_mut();
            *pv = *self;
            ret
        }
    }
}
// todo: refactor
/// The PublicValues struct is used to store all of a reduce proof's public values.
#[derive(AlignedBorrow, Serialize, Deserialize, Clone, Copy, Default, Debug)]
#[repr(C)]
pub struct RecursionPublicValues<T> {
    /// The hash of all the bytes that the program has written to public values.
    pub committed_value_digest: [Word<T>; PV_DIGEST_NUM_WORDS],

    /// The start pc of chunks being proven.
    pub start_pc: T,

    /// The expected start pc for the next chunk.
    pub next_pc: T,

    /// First chunk being proven.
    pub start_chunk: T,

    /// Next chunk that should be proven.
    pub next_chunk: T,

    /// First execution chunk being proven.
    pub start_execution_chunk: T,

    /// Next execution chunk that should be proven.
    pub next_execution_chunk: T,

    /// Previous MemoryInit address bits.
    pub previous_initialize_addr_bits: [T; 32],

    /// Last MemoryInit address bits.
    pub last_initialize_addr_bits: [T; 32],

    /// Previous MemoryFinalize address bits.
    pub previous_finalize_addr_bits: [T; 32],

    /// Last MemoryFinalize address bits.
    pub last_finalize_addr_bits: [T; 32],

    /// Start state of reconstruct_challenger.
    pub start_reconstruct_challenger: ChallengerPublicValues<T>,

    /// End state of reconstruct_challenger.
    pub end_reconstruct_challenger: ChallengerPublicValues<T>,

    /// The commitment to the Pico program being proven.
    pub riscv_vk_digest: [T; DIGEST_SIZE],

    /// The root of the vk merkle tree.
    pub vk_root: [T; DIGEST_SIZE],

    /// The leaf challenger containing the entropy from the main trace commitment.
    pub base_challenger: ChallengerPublicValues<T>,

    /// Current cumulative sum of lookup bus.
    pub cumulative_sum: [T; 4],

    /// Whether the proof completely proves the program execution.
    pub flag_complete: T,

    /// Whether the proof represents a collection of chunks which contain at least one execution
    /// shard, i.e. a shard that contains the `cpu` chip.
    pub contains_execution_chunk: T,

    /// The digest of all the previous public values elements.
    pub digest: [T; DIGEST_SIZE],

    /// The exit code of the program.  Note that this is not part of the public values digest,
    /// since it's value will be individually constrained.
    pub exit_code: T,
}

/// Converts the public values to an array of elements.
impl<F: Default + Copy> RecursionPublicValues<F> {
    pub fn to_vec(&self) -> [F; RECURSION_NUM_PVS_V2] {
        let mut ret = [F::default(); RECURSION_NUM_PVS_V2];
        let pv: &mut RecursionPublicValues<F> = ret.as_mut_slice().borrow_mut();

        *pv = *self;
        ret
    }
}

/// Converts the public values to an array of elements.
impl<F: Copy> RecursionPublicValues<F> {
    pub fn as_array(&self) -> [F; RECURSION_NUM_PVS_V2] {
        unsafe {
            let mut ret = [MaybeUninit::<F>::zeroed().assume_init(); RECURSION_NUM_PVS_V2];
            let pv: &mut RecursionPublicValues<F> = ret.as_mut_slice().borrow_mut();
            *pv = *self;
            ret
        }
    }
}

impl<T: Copy> IntoIterator for RecursionPublicValues<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, RECURSION_NUM_PVS_V2>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_array().into_iter()
    }
}

impl<T: Copy> IntoIterator for ChallengerPublicValues<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, CHALLENGER_STATE_NUM_ELTS>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_array().into_iter()
    }
}

/// Compute the digest of the root public values.
pub(crate) fn embed_public_values_digest<C, H>(
    builder: &mut Builder<C>,
    public_values: &RecursionPublicValues<Felt<C::F>>,
) -> [Felt<C::F>; DIGEST_SIZE]
where
    C: CircuitConfig,
    H: Posedion2BabyBearHasherVariable<C>,
{
    let input = public_values
        .riscv_vk_digest
        .into_iter()
        .chain(
            public_values
                .committed_value_digest
                .into_iter()
                .flat_map(|word| word.0.into_iter()),
        )
        .collect::<Vec<_>>();
    H::poseidon2_hash(builder, &input)
}

/// Compute the digest of a recursive public values Struct.
pub(crate) fn recursion_public_values_digest<C, H>(
    builder: &mut Builder<C>,
    public_values: &RecursionPublicValues<Felt<C::F>>,
) -> [Felt<C::F>; DIGEST_SIZE]
where
    C: CircuitConfig,
    H: Posedion2BabyBearHasherVariable<C>,
{
    let pv_slice = public_values.as_array();
    H::poseidon2_hash(builder, &pv_slice[..NUM_PV_ELMS_TO_HASH])
}

/// Verifies the digest of a recursive public values struct.
pub(crate) fn assert_recursion_public_values_valid<C, H>(
    builder: &mut Builder<C>,
    public_values: &RecursionPublicValues<Felt<C::F>>,
) where
    C: CircuitConfig,
    H: Posedion2BabyBearHasherVariable<C>,
{
    let digest = recursion_public_values_digest::<C, H>(builder, public_values);
    for (value, expected) in public_values.digest.iter().copied().zip_eq(digest) {
        builder.assert_felt_eq(value, expected);
    }
}
