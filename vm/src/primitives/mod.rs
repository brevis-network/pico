pub mod consts;
pub mod poseidon2;
#[cfg(test)]
mod poseidon2_kat;

use crate::{
    machine::field::FieldSpecificPoseidon2Config,
    primitives::consts::{DIGEST_SIZE, PERMUTATION_WIDTH},
};
use lazy_static::lazy_static;
use p3_bn254::{Bn254, Poseidon2Bn254};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use p3_poseidon2::ExternalLayerConstants;
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};
use zkhash::{
    ark_ff::{BigInteger, PrimeField as ark_PrimeField},
    fields::bn256::FpBN256 as ark_FpBN256,
    poseidon2::poseidon2_instance_bn256::RC3,
};

pub type PicoPoseidon2KoalaBear = Poseidon2KoalaBear<PERMUTATION_WIDTH>;

pub fn poseidon2_kb_hasher() -> PaddingFreeSponge<PicoPoseidon2KoalaBear, 16, 8, 8> {
    let hasher = KoalaBear::permutation();
    PaddingFreeSponge::<PicoPoseidon2KoalaBear, 16, 8, 8>::new(hasher)
}

lazy_static! {
    pub static ref POSEIDON2_KB_HASHER: PaddingFreeSponge::<PicoPoseidon2KoalaBear, 16, 8, 8> =
        poseidon2_kb_hasher();
}

pub fn hash_deferred_proof<F>(
    prev_digest: &[F; DIGEST_SIZE],
    vk_digest: &[F; DIGEST_SIZE],
    pv_digest: &[F; 32],
) -> [F; DIGEST_SIZE]
where
    F: Poseidon2HashField + Copy,
{
    let mut inputs = Vec::with_capacity(DIGEST_SIZE * 2 + 32);
    inputs.extend_from_slice(prev_digest);
    inputs.extend_from_slice(vk_digest);
    inputs.extend_from_slice(pv_digest);
    F::poseidon2_hash_iter(inputs)
}

pub trait Poseidon2HashField: p3_field::Field + Sized {
    fn poseidon2_hash_iter(inputs: Vec<Self>) -> [Self; DIGEST_SIZE];
}

impl Poseidon2HashField for KoalaBear {
    fn poseidon2_hash_iter(inputs: Vec<Self>) -> [Self; DIGEST_SIZE] {
        POSEIDON2_KB_HASHER.hash_iter(inputs)
    }
}

/// The width-3 BN254 Poseidon2 the wrap circuit's challenger and Merkle hasher run on. Not the
/// riscv-stage instance: the on-chain half hashes over BN254, with zkhash's constants.
pub type PicoPoseidon2Bn254 = Poseidon2Bn254<3>;

fn bn254_from_ark_ff(input: ark_FpBN256) -> Bn254 {
    // Plonky3 0.5 made `Bn254` its own Montgomery-form type (`[u64; 4]`, private) instead of a
    // wrapper over halo2curves' `Fr`, so go through the little-endian limb constructor, which
    // reduces mod P for us.
    let bytes = input.into_bigint().to_bytes_le();
    assert_eq!(bytes.len(), 32, "BN254 scalar must serialize to 32 bytes");

    let limbs: [u64; 4] = core::array::from_fn(|i| {
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        u64::from_le_bytes(limb)
    });

    Bn254::new(limbs)
}

pub fn pico_poseidon2bn254_init() -> PicoPoseidon2Bn254 {
    const ROUNDS_F: usize = 8;
    const ROUNDS_P: usize = 56;

    // Copy over round constants from zkhash.
    let mut round_constants: Vec<[Bn254; 3]> = RC3
        .iter()
        .map(|vec| {
            vec.iter()
                .cloned()
                .map(bn254_from_ark_ff)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        })
        .collect();

    let internal_start = ROUNDS_F / 2;
    let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
    let internal_round_constants = round_constants
        .drain(internal_start..internal_end)
        .map(|vec| vec[0])
        .collect::<Vec<_>>();
    let external_round_constants = ExternalLayerConstants::new(
        round_constants[..(ROUNDS_F / 2)].to_vec(),
        round_constants[(ROUNDS_F / 2)..].to_vec(),
    );
    // Pico Poseidon2 implementation.
    PicoPoseidon2Bn254::new(external_round_constants, internal_round_constants)
}
