use std::{
    io::{self, Read, Write},
    sync::OnceLock,
};

use crate::{
    codec::{
        decode_extension_field32, decode_prime_field32, encode_extension_field32,
        encode_prime_field32, DecodableConfig, EncodableConfig,
    },
    hasher::Hasher,
    p3_symmetric::{PaddingFreeSponge, Permutation, TruncatedPermutation},
    transcript::duplex_sponge,
    StarkProtocolConfig, SystemParams, TranscriptLog,
};
use p3_field::{extension::BinomialExtensionField, PrimeCharacteristicRing};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};

pub const RATE: usize = 8;
pub const WIDTH: usize = 16;
pub const CHUNK: usize = 8;
pub const DIGEST_SIZE: usize = CHUNK;

pub type Perm = Poseidon2KoalaBear<WIDTH>;
type Hash<P> = PaddingFreeSponge<P, WIDTH, RATE, DIGEST_SIZE>;
type Compress<P> = TruncatedPermutation<P, 2, CHUNK, WIDTH>;
type PermHasher<P> = Hasher<F, Digest, Hash<P>, Compress<P>>;

pub type F = KoalaBear;
pub type EF = BinomialExtensionField<KoalaBear, 4>;
pub const D_EF: usize = 4;
pub type Digest = [F; DIGEST_SIZE];
pub type DuplexSponge = duplex_sponge::DuplexSponge<F, Perm, WIDTH, RATE>;
pub type DuplexSpongeRecorder = duplex_sponge::DuplexSpongeRecorder<F, Perm, WIDTH, RATE>;
pub type DuplexSpongeValidator = duplex_sponge::DuplexSpongeValidator<F, Perm, WIDTH, RATE>;

/// Round constants and constructor of the 16-width KoalaBear Poseidon2, straight from Plonky3 0.5
/// (Grain LFSR: `field_type=1, alpha=3, n=31, t=16, R_F=8, R_P=20`; the values Plonky3 corrected
/// in its PR #1398). The MLE transcript, the Merkle hasher / compressor and the recursion
/// Poseidon2 chips all use exactly these; the known answers in `config::poseidon2_kat` pin them.
pub use p3_koala_bear::{
    default_koalabear_poseidon2_16, KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL, KOALABEAR_POSEIDON2_RC_16_INTERNAL,
};

/// The KoalaBear Poseidon2 Merkle hasher used by [`KoalaBearPoseidon2Config`].
pub type KoalaBearHasher = PermHasher<Perm>;

/// Build the default KoalaBear Poseidon2 Merkle hasher, matching the one held by
/// [`KoalaBearPoseidon2Config`]. Useful for driving hasher-generic PCS helpers (e.g.
/// `stacked_commit`) directly, without constructing a full config.
pub fn default_koalabear_hasher() -> KoalaBearHasher {
    let perm = default_koalabear_poseidon2_16();
    Hasher::new(
        PaddingFreeSponge::new(perm.clone()),
        TruncatedPermutation::new(perm),
    )
}

#[derive(Clone, Debug, derive_new::new)]
pub struct KoalaBearPoseidon2Config {
    params: SystemParams,
    hasher: PermHasher<Perm>,
}

impl StarkProtocolConfig for KoalaBearPoseidon2Config {
    type F = F;
    type EF = EF;
    type Digest = Digest;
    type Hasher = PermHasher<Perm>;

    fn digest_as_base(digest: &Self::Digest) -> Option<&[Self::F]> {
        Some(digest)
    }

    fn params(&self) -> &SystemParams {
        &self.params
    }

    fn hasher(&self) -> &Self::Hasher {
        &self.hasher
    }
}

impl KoalaBearPoseidon2Config {
    pub fn new_from_perm(params: SystemParams, perm: Perm) -> Self {
        let hasher = Hasher::new(
            PaddingFreeSponge::new(perm.clone()),
            TruncatedPermutation::new(perm),
        );
        Self { params, hasher }
    }

    pub fn default_from_params(params: SystemParams) -> Self {
        let perm = default_koalabear_poseidon2_16();
        Self::new_from_perm(params, perm)
    }
}

impl EncodableConfig for KoalaBearPoseidon2Config {
    fn encode_base_field<W: Write>(val: &F, writer: &mut W) -> io::Result<()> {
        encode_prime_field32(val, writer)
    }

    fn encode_extension_field<W: Write>(val: &EF, writer: &mut W) -> io::Result<()> {
        encode_extension_field32::<Self::F, _, _>(val, writer)
    }

    fn encode_digest<W: Write>(digest: &Self::Digest, writer: &mut W) -> io::Result<()> {
        for val in digest {
            encode_prime_field32(val, writer)?;
        }
        Ok(())
    }
}

impl DecodableConfig for KoalaBearPoseidon2Config {
    fn decode_base_field<R: Read>(reader: &mut R) -> io::Result<F> {
        decode_prime_field32(reader)
    }

    fn decode_extension_field<R: Read>(reader: &mut R) -> io::Result<EF> {
        decode_extension_field32::<F, _, _>(reader)
    }

    fn decode_digest<R: Read>(reader: &mut R) -> io::Result<Digest> {
        let mut result = Digest::default();
        for val in &mut result {
            *val = decode_prime_field32(reader)?;
        }
        Ok(result)
    }
}

pub fn poseidon2_perm() -> &'static Poseidon2KoalaBear<WIDTH> {
    static PERM: OnceLock<Poseidon2KoalaBear<WIDTH>> = OnceLock::new();
    PERM.get_or_init(default_koalabear_poseidon2_16)
}

pub fn poseidon2_compress_with_capacity(
    left: [F; CHUNK],
    right: [F; CHUNK],
) -> ([F; CHUNK], [F; CHUNK]) {
    let mut state = [F::ZERO; WIDTH];
    state[..CHUNK].copy_from_slice(&left);
    state[CHUNK..].copy_from_slice(&right);
    poseidon2_perm().permute_mut(&mut state);
    (
        state[..CHUNK].try_into().unwrap(),
        state[CHUNK..].try_into().unwrap(),
    )
}

pub fn default_duplex_sponge() -> DuplexSponge {
    DuplexSponge::from(poseidon2_perm().clone())
}

pub fn default_duplex_sponge_recorder() -> DuplexSpongeRecorder {
    DuplexSpongeRecorder::from(poseidon2_perm().clone())
}

pub fn default_duplex_sponge_validator(
    logs: TranscriptLog<F, [F; WIDTH]>,
) -> DuplexSpongeValidator {
    DuplexSpongeValidator::new(poseidon2_perm().clone(), logs)
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeField32;

    use super::*;
    use crate::config::riscv_params_with_100_bits_security;

    /// Every Poseidon2 round constant survives a canonical-form round-trip, the external/internal
    /// tables have the width-16 Grain schedule's shape (R_F = 8, R_P = 20, no zero rounds), and
    /// the permutation is deterministic.
    #[test]
    fn kb_poseidon2_constants_roundtrip() {
        let external = KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL
            .iter()
            .chain(KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL.iter())
            .flatten();
        for &c in external.chain(KOALABEAR_POSEIDON2_RC_16_INTERNAL.iter()) {
            let canonical = c.as_canonical_u32();
            assert!(canonical < F::ORDER_U32);
            assert_eq!(F::from_u32(canonical), c);
            assert_ne!(c, F::ZERO, "a Grain round constant is never zero");
        }

        assert_eq!(KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL.len(), 4);
        assert_eq!(KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL.len(), 4);
        assert_eq!(KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL[0].len(), WIDTH);
        assert_eq!(KOALABEAR_POSEIDON2_RC_16_INTERNAL.len(), 20);

        // The constructed permutation is deterministic and mixes its input.
        let perm = default_koalabear_poseidon2_16();
        let mut a = [F::ZERO; WIDTH];
        for (i, x) in a.iter_mut().enumerate() {
            *x = F::from_u32(i as u32);
        }
        let mut b = a;
        perm.permute_mut(&mut a);
        perm.permute_mut(&mut b);
        assert_eq!(a, b);
        assert_ne!(a, [F::ZERO; WIDTH]);
    }

    /// Cross-language pin: the wrap circuit recomputes the recursion PV digest with gnark's
    /// KoalaBear-Poseidon2 chip, so that chip's round constants must be these. The Go side asserts
    /// the same vector for the same input (`gnark/poseidon2/poseidon2_koalabear_test.go`); if the two
    /// ever diverge, the only symptom downstream is an opaque `AssertIsEqualF` at gnark solve time.
    ///
    /// Shape checks alone do not catch that — a table can have the right shape and the wrong values —
    /// so pin the permutation's actual output.
    #[test]
    fn kb_poseidon2_permutation_vector_matches_gnark() {
        let perm = default_koalabear_poseidon2_16();
        let mut state = [F::ZERO; WIDTH];
        perm.permute_mut(&mut state);
        let out: Vec<u32> = state.iter().map(|x| x.as_canonical_u32()).collect();
        assert_eq!(
            out,
            vec![
                1467453764, 68262570, 2085334433, 1711169726, 869537427, 698494029, 1998923102,
                727938840, 1236421175, 857433239, 1995651691, 1526804549, 968729910, 15322618,
                1511105384, 1900792116,
            ],
            "KoalaBear Poseidon2 permutation moved — regenerate \
             gnark/poseidon2/constants_koalabear_mle.go and TestPoseidon2KoalaBearMle in the \
             same change"
        );
    }

    /// The config's digest codec round-trips an arbitrary digest.
    #[test]
    fn kb_digest_codec_roundtrip() {
        let digest: Digest = core::array::from_fn(|i| F::from_u32((i as u32) * 7 + 1));
        let mut buf = Vec::new();
        KoalaBearPoseidon2Config::encode_digest(&digest, &mut buf).unwrap();
        let decoded = KoalaBearPoseidon2Config::decode_digest(&mut buf.as_slice()).unwrap();
        assert_eq!(digest, decoded);
    }

    /// Integration: a production KoalaBear `SystemParams` value initializes the config, and the
    /// params survive the round-trip through it.
    #[test]
    fn kb_system_params_initialize_downstream() {
        let params = riscv_params_with_100_bits_security(20);

        let config = KoalaBearPoseidon2Config::default_from_params(params.clone());
        assert_eq!(config.params(), &params);
        // Hasher is wired up and accessible.
        let _hasher = config.hasher();
    }
}
