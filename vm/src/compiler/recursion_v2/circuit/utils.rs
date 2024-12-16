use crate::{
    compiler::{
        recursion_v2::ir::{Builder, Felt, Var},
        word::Word,
    },
    configs::config::FieldGenericConfig,
    primitives::consts::DIGEST_SIZE,
    recursion_v2::air::ChallengerPublicValues,
};
use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
use p3_field::{FieldAlgebra, PrimeField32};
use std::mem::MaybeUninit;

#[allow(dead_code)]
pub(crate) unsafe fn uninit_challenger_pv<FC: FieldGenericConfig>(
    _builder: &mut Builder<FC>,
) -> ChallengerPublicValues<Felt<FC::F>> {
    unsafe { MaybeUninit::zeroed().assume_init() }
}

/// Convert 8 BabyBear words into a Bn254Fr field element by shifting by 31 bits each time. The last
/// word becomes the least significant bits.
#[allow(dead_code)]
pub fn babybears_to_bn254(digest: &[BabyBear; 8]) -> Bn254Fr {
    let mut result = Bn254Fr::ZERO;
    for word in digest.iter() {
        // Since BabyBear prime is less than 2^31, we can shift by 31 bits each time and still be
        // within the Bn254Fr field, so we don't have to truncate the top 3 bits.
        result *= Bn254Fr::from_canonical_u64(1 << 31);
        result += Bn254Fr::from_canonical_u32(word.as_canonical_u32());
    }
    result
}

/// Convert 32 BabyBear bytes into a Bn254Fr field element. The first byte's most significant 3 bits
/// (which would become the 3 most significant bits) are truncated.
#[allow(dead_code)]
pub fn babybear_bytes_to_bn254(bytes: &[BabyBear; 32]) -> Bn254Fr {
    let mut result = Bn254Fr::ZERO;
    for (i, byte) in bytes.iter().enumerate() {
        debug_assert!(byte < &BabyBear::from_canonical_u32(256));
        if i == 0 {
            // 32 bytes is more than Bn254 prime, so we need to truncate the top 3 bits.
            result = Bn254Fr::from_canonical_u32(byte.as_canonical_u32() & 0x1f);
        } else {
            result *= Bn254Fr::from_canonical_u32(256);
            result += Bn254Fr::from_canonical_u32(byte.as_canonical_u32());
        }
    }
    result
}

#[allow(dead_code)]
pub fn felts_to_bn254_var<FC: FieldGenericConfig>(
    builder: &mut Builder<FC>,
    digest: &[Felt<FC::F>; DIGEST_SIZE],
) -> Var<FC::N> {
    let var_2_31: Var<_> = builder.constant(FC::N::from_canonical_u32(1 << 31));
    let result = builder.constant(FC::N::ZERO);
    for (i, word) in digest.iter().enumerate() {
        let word_var = builder.felt2var_circuit(*word);
        if i == 0 {
            builder.assign(result, word_var);
        } else {
            builder.assign(result, result * var_2_31 + word_var);
        }
    }
    result
}

#[allow(dead_code)]
pub fn felt_bytes_to_bn254_var<FC: FieldGenericConfig>(
    builder: &mut Builder<FC>,
    bytes: &[Felt<FC::F>; 32],
) -> Var<FC::N> {
    let var_256: Var<_> = builder.constant(FC::N::from_canonical_u32(256));
    let zero_var: Var<_> = builder.constant(FC::N::ZERO);
    let result = builder.constant(FC::N::ZERO);
    for (i, byte) in bytes.iter().enumerate() {
        let byte_bits = builder.num2bits_f_circuit(*byte);
        if i == 0 {
            // Since 32 bytes doesn't fit into Bn254, we need to truncate the top 3 bits.
            // For first byte, zero out 3 most significant bits.
            for i in 0..3 {
                builder.assign(byte_bits[8 - i - 1], zero_var);
            }
            let byte_var = builder.bits2num_v_circuit(&byte_bits);
            builder.assign(result, byte_var);
        } else {
            let byte_var = builder.bits2num_v_circuit(&byte_bits);
            builder.assign(result, result * var_256 + byte_var);
        }
    }
    result
}

#[allow(dead_code)]
pub fn words_to_bytes<T: Copy>(words: &[Word<T>]) -> Vec<T> {
    words.iter().flat_map(|w| w.0).collect::<Vec<_>>()
}
