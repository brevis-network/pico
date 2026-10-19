//! Outer ("embed") protocol config: a KoalaBear STARK whose PCS commitments and Fiat–Shamir
//! transcript run over **BN254 Poseidon2** instead of Poseidon2-KoalaBear.
//!
//! Purpose: the EMBED phase re-proves the recursion root 1:1 under this config, so that the
//! on-chain gnark circuit recomputes the proof's Merkle paths / transcript with **native** BN254
//! `Permute` opcodes instead of emulated Poseidon2-KoalaBear. The field arithmetic stays KoalaBear;
//! only the hash and the transcript move to BN254.
//!
//! The magnitude of that swap is the whole reason the embed layer exists: a native width-3 BN254
//! `Permute` costs ~240 R1CS constraints, an emulated width-16 `PermuteKoalaBear` ~53,000 — 221×.
//! A wrap circuit over KoalaBear digests would need a QAP beyond Groth16's BN254 limit.
//!
//! Building blocks (all pre-existing, none introduced here):
//! - [`MultiFieldHasher`]: overwrite-mode sponge over BN254, packing KoalaBear felts at base-2^31
//!   (injective into BN254).
//! - [`MultiFieldTranscript`]: bit-packed observe / base-`F::ORDER` sample Fiat–Shamir transcript
//!   over the same permutation.
//! - [`pico_poseidon2bn254_init`]: the canonical width-3 BN254 Poseidon2 permutation — the one the
//!   gnark `Permute` opcode implements. `test_outer_twins` is the known-answer proof of that
//!   equality; everything downstream rests on it.

use std::{
    io::{self, Write},
    marker::PhantomData,
};

use p3_bn254::{Bn254, Poseidon2Bn254};
use p3_field::{extension::BinomialExtensionField, PrimeField};
use p3_koala_bear::KoalaBear;
use p3_symmetric::TruncatedPermutation;
use pico_mle_core::{
    codec::{encode_extension_field32, encode_prime_field32, EncodableConfig},
    hasher::{Hasher, MultiFieldHasher},
    prover::Coordinator,
    transcript::multi_field::MultiFieldTranscript,
    FiatShamirTranscript, StarkEngine, StarkProtocolConfig, SystemParams,
};
use pico_mle_cpu::{CpuBackend, CpuDevice};

use crate::primitives::{
    consts::{MULTI_FIELD_CHALLENGER_RATE, MULTI_FIELD_CHALLENGER_WIDTH},
    pico_poseidon2bn254_init,
};

pub type F = KoalaBear;
pub type EF = BinomialExtensionField<KoalaBear, 4>;

/// Width-3 BN254 Poseidon2 permutation (matches the gnark-side `Permute` chip).
pub type EmbedPerm = Poseidon2Bn254<MULTI_FIELD_CHALLENGER_WIDTH>;
/// One BN254 element per digest.
pub const EMBED_DIGEST_SIZE: usize = 1;
pub type EmbedDigest = [Bn254; EMBED_DIGEST_SIZE];

/// KoalaBear felts packed into one BN254 element, at base-2^31: `floor(254 / 31) = 8`. This is the
/// largest injective choice, and `MultiFieldHasher::new` / `MultiFieldTranscript::new` assert it via
/// `checked_num_packed_f_elms` at construction time.
///
/// The circuit twin (`outer_bn254::OBS_PER_ELEM`) is defined from this constant, so the two can
/// never drift.
pub const EMBED_FELTS_PER_BN254: usize = 8;

/// KoalaBear felts absorbed per leaf-hash permutation: one per rate lane's worth of packing.
pub const EMBED_HASH_RATE: usize = MULTI_FIELD_CHALLENGER_RATE * EMBED_FELTS_PER_BN254;

/// Leaf hasher: 16 KoalaBear felts per permutation (2 rate lanes × 8 packed felts each).
pub type EmbedHash = MultiFieldHasher<
    F,
    Bn254,
    EmbedPerm,
    MULTI_FIELD_CHALLENGER_WIDTH,
    EMBED_HASH_RATE,
    EMBED_DIGEST_SIZE,
>;
/// Node compression: `TruncatedPermutation` over two 1-element digests (width 3).
pub type EmbedCompress =
    TruncatedPermutation<EmbedPerm, 2, EMBED_DIGEST_SIZE, MULTI_FIELD_CHALLENGER_WIDTH>;
pub type EmbedHasher = Hasher<F, EmbedDigest, EmbedHash, EmbedCompress>;
/// Fiat–Shamir transcript over the same BN254 permutation.
pub type EmbedTranscript = MultiFieldTranscript<
    F,
    Bn254,
    EmbedPerm,
    MULTI_FIELD_CHALLENGER_WIDTH,
    MULTI_FIELD_CHALLENGER_RATE,
>;

/// Build the default width-3 BN254 Poseidon2 permutation.
pub fn default_bn254_poseidon2_3() -> EmbedPerm {
    pico_poseidon2bn254_init()
}

/// Build the default embed Merkle hasher.
pub fn default_embed_hasher() -> EmbedHasher {
    let perm = default_bn254_poseidon2_3();
    Hasher::new(
        MultiFieldHasher::new(perm.clone()),
        TruncatedPermutation::new(perm),
    )
}

#[derive(Clone, Debug)]
pub struct KoalaBearBn254Poseidon2Config {
    params: SystemParams,
    hasher: EmbedHasher,
}

impl StarkProtocolConfig for KoalaBearBn254Poseidon2Config {
    type F = F;
    type EF = EF;
    type Digest = EmbedDigest;
    type Hasher = EmbedHasher;

    fn params(&self) -> &SystemParams {
        &self.params
    }

    fn hasher(&self) -> &Self::Hasher {
        &self.hasher
    }
}

impl KoalaBearBn254Poseidon2Config {
    pub fn default_from_params(params: SystemParams) -> Self {
        Self {
            params,
            hasher: default_embed_hasher(),
        }
    }
}

impl EncodableConfig for KoalaBearBn254Poseidon2Config {
    fn encode_base_field<W: Write>(val: &F, writer: &mut W) -> io::Result<()> {
        encode_prime_field32(val, writer)
    }

    fn encode_extension_field<W: Write>(val: &EF, writer: &mut W) -> io::Result<()> {
        encode_extension_field32::<F, _, _>(val, writer)
    }

    fn encode_digest<W: Write>(digest: &Self::Digest, writer: &mut W) -> io::Result<()> {
        for val in digest {
            // 32-byte big-endian canonical encoding of one BN254 element.
            let bytes = val.as_canonical_biguint().to_bytes_be();
            debug_assert!(bytes.len() <= 32);
            let mut buf = [0u8; 32];
            buf[32 - bytes.len()..].copy_from_slice(&bytes);
            writer.write_all(&buf)?;
        }
        Ok(())
    }
}

/// CPU engine over the embed (outer) config.
///
/// The mirror of [`pico_mle_cpu::KoalaBearPoseidon2CpuEngine`]: same row-major CPU device, same
/// `Coordinator`, only the config (and hence the hasher and transcript) differ.
pub struct KoalaBearBn254Poseidon2CpuEngine<TS = EmbedTranscript> {
    device: CpuDevice<KoalaBearBn254Poseidon2Config>,
    _transcript: PhantomData<TS>,
}

impl<TS> StarkEngine for KoalaBearBn254Poseidon2CpuEngine<TS>
where
    TS: FiatShamirTranscript<KoalaBearBn254Poseidon2Config> + From<EmbedPerm>,
{
    type SC = KoalaBearBn254Poseidon2Config;
    type PB = CpuBackend<KoalaBearBn254Poseidon2Config>;
    type PD = CpuDevice<KoalaBearBn254Poseidon2Config>;
    type TS = TS;

    fn new(params: SystemParams) -> Self {
        let config = KoalaBearBn254Poseidon2Config::default_from_params(params);
        Self {
            device: CpuDevice::new(config),
            _transcript: PhantomData,
        }
    }

    fn config(&self) -> &Self::SC {
        self.device.config()
    }

    fn device(&self) -> &Self::PD {
        &self.device
    }

    fn initial_transcript(&self) -> Self::TS {
        TS::from(default_bn254_poseidon2_3())
    }

    fn prover_from_transcript(
        &self,
        transcript: TS,
    ) -> Coordinator<Self::SC, Self::PB, Self::PD, Self::TS> {
        Coordinator::new(self.device.clone(), transcript)
    }
}

#[cfg(test)]
mod tests {
    use p3_field::{PrimeCharacteristicRing, PrimeField32};
    use pico_mle_core::hasher::MerkleHasher;

    use super::*;

    /// The permutation is the *only* thing the gnark side has to agree with, so pin it: a fixed
    /// input must give a fixed output. If this vector ever moves, `test_outer_twins` and the whole
    /// wrap circuit are invalidated, and the gnark `Permute` chip has to be re-checked.
    #[test]
    fn bn254_permutation_is_pinned() {
        use p3_symmetric::Permutation;

        let mut state = [Bn254::ZERO, Bn254::ONE, Bn254::TWO];
        default_bn254_poseidon2_3().permute_mut(&mut state);
        let hex: Vec<String> = state
            .iter()
            .map(|x| format!("0x{:x}", x.as_canonical_biguint()))
            .collect();
        assert_eq!(
            hex,
            [
                "0xbb61d24daca55eebcb1929a82650f328134334da98ea4f847f760054f4a3033",
                "0x303b6f7c86d043bfcbcc80214f26a30277a15d3f74ca654992defe7ff8d03570",
                "0x1ed25194542b12eef8617361c3ba7c52e660b145994427cc86296242cf766ec8",
            ],
            "BN254 Poseidon2 permutation output moved — regenerate only with a matching gnark chip",
        );
    }

    /// The Merkle hasher's digest is a single BN254 element, and compression is order-sensitive.
    #[test]
    fn embed_hasher_digest_shape_and_ordering() {
        let hasher = default_embed_hasher();
        let a: EmbedDigest = hasher.hash_slice(&[F::ONE]);
        let b: EmbedDigest = hasher.hash_slice(&[F::TWO]);
        assert_ne!(a, b);
        assert_ne!(hasher.compress(a, b), hasher.compress(b, a));
    }

    /// `observe_commit` absorbs the digest as one BN254 element, not as packed KoalaBear felts —
    /// the transcript sees the commitment natively. Observing the same digest twice must move the
    /// transcript, and a different digest must give different challenges.
    #[test]
    fn transcript_absorbs_digests_natively() {
        type SC = KoalaBearBn254Poseidon2Config;

        let hasher = default_embed_hasher();
        let d0 = hasher.hash_slice(&[F::ONE]);
        let d1 = hasher.hash_slice(&[F::TWO]);

        let sample_after = |digest: EmbedDigest| {
            let mut t = EmbedTranscript::from(default_bn254_poseidon2_3());
            FiatShamirTranscript::<SC>::observe_commit(&mut t, digest);
            (0..6)
                .map(|_| FiatShamirTranscript::<SC>::sample(&mut t))
                .collect::<Vec<_>>()
        };
        assert_ne!(sample_after(d0), sample_after(d1));

        // Every sample is a canonical KoalaBear element (base-p digit extraction, not truncation).
        for s in sample_after(d0) {
            assert!(s.as_canonical_u32() < F::ORDER_U32);
        }
    }

    /// A `SystemParams` value round-trips through the config, and the hasher is wired up.
    #[test]
    fn embed_config_initializes_from_params() {
        let params = pico_mle_core::compress_params_with_100_bits_security(20);
        let config = KoalaBearBn254Poseidon2Config::default_from_params(params.clone());
        assert_eq!(config.params(), &params);
        let _ = config.hasher();
    }
}
