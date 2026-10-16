//! Wrap artifact builder: turns an embed proof into the two files gnark consumes — the opcode
//! stream (`constraints.json`) and the witness (`witness.json`).
//!
//! # The mirror trick
//!
//! The wrap circuit's transcript twin reads its sampled KoalaBear felts from the witness stream as
//! base-`p` digits of a squeezed BN254 element, bound by a recomposition constraint. Those digits
//! have to come from somewhere, and they have to be in exactly the order the circuit consumes them.
//!
//! [`WrapMirrorTranscript`] is an independent duplex reimplementation of `MultiFieldTranscript` that
//! records `(digits, remainder)` at every extraction squeeze — and it implements
//! [`FiatShamirTranscript`], so the *real* Rust verifier can be run on top of it. One call does two
//! jobs: it re-verifies the proof under the mirror's semantics (any divergence from the real
//! transcript makes verification fail), and it records the digit stream in verifier order, which is
//! circuit order. Hand-replaying every observe/sample to produce the stream is unnecessary.
//!
//! # Witness order is load-bearing
//!
//! `write_wrap_witness` and the circuit's `read_wrap_proof` are a mirror pair and must be edited
//! together. The digit/remainder stream is appended *after* all proof data, so transcript sampling
//! never interleaves with proof reads and the two sides need no per-section reconciliation.

use num_bigint::BigUint;
use p3_bn254::{Bn254, Poseidon2Bn254};
use p3_field::{PrimeCharacteristicRing, PrimeField, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_symmetric::Permutation;
use pico_mle_core::{
    keygen::types::MultiStarkVerifyingKey, verifier::proof_shape::verify_proof_shape,
    FiatShamirTranscript, StarkProtocolConfig,
};

use crate::{
    compiler::recursion::{
        circuit::{
            outer_bn254::{canonical_rem_max, OBS_PER_ELEM, SAMPLES_PER_ELEM},
            wrap_mle::{wrap_public_inputs, wrap_verify_embed, write_wrap_witness},
        },
        constraints::{Constraint, ConstraintCompiler},
        ir::{Builder, Witness},
    },
    configs::field_config::KoalaBearBn254,
    instances::compiler::onchain_circuit::gnark::witness::GnarkWitness,
    mle::{
        config::koala_bear_bn254_poseidon2::{
            default_bn254_poseidon2_3, KoalaBearBn254Poseidon2Config as EmbedSc,
        },
        machine::embed::EmbedProofWithVk,
    },
    primitives::consts::{
        MULTI_FIELD_CHALLENGER_RATE as RATE, MULTI_FIELD_CHALLENGER_WIDTH as WIDTH,
    },
};

type F = KoalaBear;
type N = Bn254;
type FC = KoalaBearBn254;

/// Independent duplex reimplementation of `MultiFieldTranscript` (width 3 / rate 2 over the BN254
/// permutation) that records the digit/remainder witness stream at every extraction squeeze.
///
/// Independence is the point: `test_outer_twins` pins this duplex against the real
/// `EmbedTranscript`, and the circuit twin is written against the same semantics, so the mirror is
/// the shared reference both sides are checked against rather than a wrapper that would agree with
/// the real transcript by construction.
#[derive(Clone)]
pub struct WrapMirrorTranscript {
    perm: Poseidon2Bn254<WIDTH>,
    state: [N; WIDTH],
    absorb_idx: usize,
    sample_idx: usize,
    observe_buf: Vec<F>,
    sample_buf: Vec<F>,
    /// `(digits, remainder)` per extraction squeeze, in execution order.
    digit_stream: Vec<(Vec<F>, N)>,
}

impl Default for WrapMirrorTranscript {
    fn default() -> Self {
        Self::new()
    }
}

impl WrapMirrorTranscript {
    pub fn new() -> Self {
        Self {
            perm: default_bn254_poseidon2_3(),
            state: [N::ZERO; WIDTH],
            absorb_idx: 0,
            sample_idx: 0,
            observe_buf: vec![],
            sample_buf: vec![],
            digit_stream: vec![],
        }
    }

    /// The recorded stream, in the order the circuit consumes it.
    pub fn digit_stream(&self) -> &[(Vec<F>, N)] {
        &self.digit_stream
    }

    /// Base-2^31 little-endian packing (`f_0` lowest), mirroring `pack_f_to_sf`.
    fn pack(buf: &[F]) -> N {
        let base = N::from_u64(1 << 31);
        buf.iter().rev().fold(N::ZERO, |acc, f| {
            acc * base + N::from_u32(f.as_canonical_u32())
        })
    }

    fn absorb(&mut self, v: N) {
        self.state[self.absorb_idx] = v;
        self.absorb_idx += 1;
        if self.absorb_idx == RATE {
            self.perm.permute_mut(&mut self.state);
            self.absorb_idx = 0;
            self.sample_idx = RATE;
        }
    }

    fn squeeze(&mut self) -> N {
        if self.absorb_idx != 0 || self.sample_idx == 0 {
            self.perm.permute_mut(&mut self.state);
            self.absorb_idx = 0;
            self.sample_idx = RATE;
        }
        self.sample_idx -= 1;
        self.state[self.sample_idx]
    }

    fn flush(&mut self) {
        if !self.observe_buf.is_empty() {
            let packed = Self::pack(&self.observe_buf);
            self.absorb(packed);
            self.observe_buf.clear();
        }
    }
}

impl FiatShamirTranscript<EmbedSc> for WrapMirrorTranscript {
    fn observe(&mut self, value: F) {
        self.sample_buf.clear();
        self.observe_buf.push(value);
        if self.observe_buf.len() == OBS_PER_ELEM {
            let packed = Self::pack(&self.observe_buf);
            self.absorb(packed);
            self.observe_buf.clear();
        }
    }

    fn observe_commit(&mut self, digest: <EmbedSc as StarkProtocolConfig>::Digest) {
        self.sample_buf.clear();
        self.flush();
        for d in digest {
            self.absorb(d);
        }
    }

    fn sample(&mut self) -> F {
        if let Some(f) = self.sample_buf.pop() {
            return f;
        }
        self.flush();
        let squeezed = self.squeeze();

        // Base-`p` digit extraction, LSB-first, plus the quotient the circuit binds via the
        // recomposition constraint `squeezed == Σ digit_i·p^i + rem·p^5`.
        let p = BigUint::from(F::ORDER_U32);
        let mut x = squeezed.as_canonical_biguint();
        let mut digits: Vec<F> = Vec::with_capacity(SAMPLES_PER_ELEM);
        for _ in 0..SAMPLES_PER_ELEM {
            let r: u32 = (&x % &p).try_into().expect("base-p digit fits in u32");
            x /= &p;
            digits.push(F::from_u32(r));
        }
        // The circuit admits `rem <= canonical_rem_max()` and nothing above it. Fail here, loudly,
        // rather than emit a witness gnark would reject with an opaque bit-decomposition error.
        // Reaching this is a ~2^-98-per-squeeze event; see `outer_bn254::canonical_rem_max`.
        assert!(
            x <= canonical_rem_max().as_canonical_biguint(),
            "squeezed element falls in the canonical-decomposition completeness gap \
             (remainder {x} exceeds the circuit's bound) — reprove to resample the transcript"
        );
        let two64 = N::from_u64(1 << 32) * N::from_u64(1 << 32);
        let rem = x
            .to_u64_digits()
            .iter()
            .rev()
            .fold(N::ZERO, |acc, &limb| acc * two64 + N::from_u64(limb));
        self.digit_stream.push((digits.clone(), rem));

        // LSB-first: pop() must yield digit_0 first.
        self.sample_buf = digits;
        self.sample_buf.reverse();
        self.sample_buf.pop().expect("SAMPLES_PER_ELEM > 0")
    }
}

/// What the wrap circuit pins as the recursion whitelist root.
///
/// The root is baked into the circuit as constants, so it is part of what a Groth16 setup over
/// these constraints attests. Without it the circuit checks no `vk_root` at all: every combine
/// node's in-circuit membership check is then against a root the prover chose, so a tree of
/// arbitrary recursion programs (of the same layout) would wrap. That is why there is no `Option`
/// here: leaving the root unpinned has to be spelled out, and is only for whitelist-off dev flows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VkRootPin {
    /// Pin this whitelist root. The only mode a Groth16 setup may be generated from.
    Trusted([F; 8]),
    /// Whitelist-off dev mode: pin nothing. The constraints still solve for an honest proof, but
    /// they attest nothing about which recursion programs produced it.
    DevUnpinned,
}

impl VkRootPin {
    fn root(self) -> Option<[F; 8]> {
        match self {
            Self::Trusted(root) => Some(root),
            Self::DevUnpinned => None,
        }
    }
}

/// The two gnark inputs plus the numbers worth logging about them.
pub struct WrapArtifacts {
    pub constraints: Vec<Constraint>,
    pub witness: GnarkWitness<FC>,
    /// The circuit's two public inputs, as gnark will see them. The trusted whitelist root is NOT
    /// among them — it is baked into the circuit, so the Groth16 verifying key is its pin.
    pub vkey_hash: N,
    pub committed_values_digest: N,
    /// The whitelist root the constraints pin ([`VkRootPin::Trusted`]), `None` for
    /// [`VkRootPin::DevUnpinned`]. The constraints carry it as their one `AssertVkRoot` op, which
    /// is what `gnark -cmd setup` checks and records.
    pub vk_root: Option<[F; 8]>,
    pub num_extraction_squeezes: usize,
    pub num_vars: usize,
    pub num_felts: usize,
    pub num_exts: usize,
}

impl WrapArtifacts {
    /// Write the pair of files the gnark SDK reads.
    pub fn save(&self, constraints_path: &str, witness_path: &str) -> eyre::Result<()> {
        std::fs::write(constraints_path, serde_json::to_string(&self.constraints)?)?;
        self.witness.save(witness_path);
        Ok(())
    }
}

/// Build the wrap circuit and its witness for one embed proof.
///
/// Fails if the embed proof does not verify under the mirror transcript — which is the twin
/// equivalence check, not a formality: the digit stream is only meaningful if the mirror walked the
/// same schedule as the real transcript.
pub fn build_wrap_artifacts(
    embed_proof: &EmbedProofWithVk,
    vk_root: VkRootPin,
) -> eyre::Result<WrapArtifacts> {
    build_wrap_artifacts_with(embed_proof, vk_root, |_, _| {})
}

/// [`build_wrap_artifacts`] with a hook that may rewrite the finished witness before it is encoded.
///
/// This exists for negative testing. Corrupting the *proof* is not a test of the circuit: the mirror
/// verification below rejects it first, so gnark never runs. The adversary a circuit has to withstand
/// lies in the WITNESS while the opcode stream stays honest, which is exactly what this hook models.
/// Every witness value is supposed to be bound by some constraint, so any perturbation that still
/// solves is an under-constrained value — a real finding.
///
/// The hook also receives the number of extraction squeezes, since the transcript stream sits at the
/// tail of both arrays (one remainder var and `SAMPLES_PER_ELEM` digit felts each) and addressing a
/// specific squeeze otherwise means recomputing the mirror's bookkeeping in the caller.
pub fn build_wrap_artifacts_with(
    embed_proof: &EmbedProofWithVk,
    vk_root: VkRootPin,
    tamper: impl FnOnce(&mut Witness<FC>, usize),
) -> eyre::Result<WrapArtifacts> {
    if vk_root == VkRootPin::DevUnpinned {
        tracing::warn!(
            "wrap: building with VkRootPin::DevUnpinned — the constraints pin no whitelist root; \
             never generate a Groth16 setup from these artifacts"
        );
    }
    let (proof, vk) = embed_proof;
    let vk: &MultiStarkVerifyingKey<EmbedSc> = vk.as_ref();
    let config = EmbedSc::default_from_params(vk.inner.params.clone());
    let layouts = verify_proof_shape::<EmbedSc>(&vk.inner, proof)
        .map_err(|e| eyre::eyre!("embed proof shape rejected: {e:?}"))?;

    // One call, two jobs: twin-equivalence check + the digit/remainder stream in circuit order.
    let mut mirror = WrapMirrorTranscript::new();
    pico_mle_core::verifier::verify(&config, vk, proof, &mut mirror).map_err(|e| {
        eyre::eyre!("embed proof failed to verify under the mirror transcript: {e:?}")
    })?;

    let vk_root = vk_root.root();
    let mut builder = Builder::<FC>::default();
    let _ = wrap_verify_embed(&mut builder, vk, proof, &layouts, vk_root);
    let constraints = ConstraintCompiler::<FC>::default().emit(builder.into_operations());

    // Witness: all proof data first (read order), then the transcript stream, then the publics.
    let mut w = Witness::<FC>::default();
    write_wrap_witness(&mut w, proof);
    for (digits, rem) in mirror.digit_stream() {
        w.felts.extend_from_slice(digits);
        w.vars.push(*rem);
    }
    let (vkey_hash, committed_values_digest) = wrap_public_inputs(proof);
    w.vkey_hash = vkey_hash;
    w.committed_values_digest = committed_values_digest;
    // Tells the gnark interpreter to permute with the MLE KoalaBear-Poseidon2 table.
    w.backend = Some("mle".to_string());

    let (num_vars, num_felts, num_exts) = (w.vars.len(), w.felts.len(), w.exts.len());
    tamper(&mut w, mirror.digit_stream().len());
    Ok(WrapArtifacts {
        constraints,
        witness: GnarkWitness::new(w),
        vkey_hash,
        committed_values_digest,
        vk_root,
        num_extraction_squeezes: mirror.digit_stream().len(),
        num_vars,
        num_felts,
        num_exts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mle::config::koala_bear_bn254_poseidon2::EmbedTranscript;

    /// The mirror must be observationally identical to the real `EmbedTranscript` — that is the
    /// premise the whole witness stream rests on. Cover a schedule that crosses both boundaries
    /// that could hide a bug: the 8-felt pack boundary and the squeeze boundary where a partial
    /// observe buffer has to be flushed as-is.
    #[test]
    fn mirror_matches_the_real_embed_transcript() {
        let obs: Vec<F> = (0..23u32).map(|i| F::from_u32(i * 977 + 5)).collect();
        let digest = [N::from_u64(0x1234_5678_9abc_def0)];

        let mut real = EmbedTranscript::from(default_bn254_poseidon2_3());
        let mut mirror = WrapMirrorTranscript::new();

        let mut real_samples = Vec::new();
        let mut mirror_samples = Vec::new();
        // observe past one pack boundary, sample across a squeeze, observe a partial buffer,
        // absorb a digest, then sample again.
        for &f in &obs {
            FiatShamirTranscript::<EmbedSc>::observe(&mut real, f);
            FiatShamirTranscript::<EmbedSc>::observe(&mut mirror, f);
        }
        for _ in 0..7 {
            real_samples.push(FiatShamirTranscript::<EmbedSc>::sample(&mut real));
            mirror_samples.push(FiatShamirTranscript::<EmbedSc>::sample(&mut mirror));
        }
        FiatShamirTranscript::<EmbedSc>::observe(&mut real, F::ONE);
        FiatShamirTranscript::<EmbedSc>::observe(&mut mirror, F::ONE);
        FiatShamirTranscript::<EmbedSc>::observe_commit(&mut real, digest);
        FiatShamirTranscript::<EmbedSc>::observe_commit(&mut mirror, digest);
        for _ in 0..6 {
            real_samples.push(FiatShamirTranscript::<EmbedSc>::sample(&mut real));
            mirror_samples.push(FiatShamirTranscript::<EmbedSc>::sample(&mut mirror));
        }

        assert_eq!(real_samples, mirror_samples);
        // 4 squeezes for 13 samples, not the 3 that `ceil(13/5)` suggests: the mid-schedule observe
        // invalidates the sample buffer and discards the 3 digits still cached from the second
        // squeeze. Buffer invalidation is exactly the semantic that would silently desync the
        // circuit's witness stream, so pin the count.
        assert_eq!(mirror.digit_stream().len(), 4);
        assert!(mirror
            .digit_stream()
            .iter()
            .all(|(digits, _)| digits.len() == SAMPLES_PER_ELEM));
    }

    /// The recorded digits and remainder must recompose to the squeezed element — the exact identity
    /// the circuit's recomposition constraint asserts. If this drifts, gnark solve fails with an
    /// opaque `AssertIsEqualV` and no hint as to why.
    #[test]
    fn recorded_digits_recompose_to_the_squeeze() {
        let mut mirror = WrapMirrorTranscript::new();
        for i in 0..20u32 {
            FiatShamirTranscript::<EmbedSc>::observe(&mut mirror, F::from_u32(i + 1));
        }
        for _ in 0..12 {
            let _ = FiatShamirTranscript::<EmbedSc>::sample(&mut mirror);
        }
        assert!(!mirror.digit_stream().is_empty());

        // Replay the same schedule on a plain duplex to recover each squeezed element.
        let mut plain = WrapMirrorTranscript::new();
        for i in 0..20u32 {
            FiatShamirTranscript::<EmbedSc>::observe(&mut plain, F::from_u32(i + 1));
        }
        let p = N::from_u32(F::ORDER_U32);
        for (idx, (digits, rem)) in mirror.digit_stream().iter().enumerate() {
            // Sampling SAMPLES_PER_ELEM felts advances `plain` by exactly one squeeze.
            let _ = FiatShamirTranscript::<EmbedSc>::sample(&mut plain);
            let mut acc = N::ZERO;
            let mut p_pow = N::ONE;
            for d in digits {
                acc += N::from_u32(d.as_canonical_u32()) * p_pow;
                p_pow *= p;
            }
            acc += *rem * p_pow;
            assert_eq!(
                acc, plain.state[plain.sample_idx],
                "squeeze {idx} does not recompose from its recorded digits"
            );
            for _ in 1..SAMPLES_PER_ELEM {
                let _ = FiatShamirTranscript::<EmbedSc>::sample(&mut plain);
            }
        }
    }
}
