//! Known-answer validation of the outer (BN254) circuit twins against the Rust embed primitives.
//!
//! This is the foundation the whole wrap-circuit port rests on: if `pico_poseidon2bn254_init` is
//! not bit-identical to the gnark `Permute` chip, every downstream circuit is castles in air.
//!
//! Rust side: drive the REAL `EmbedTranscript` + `default_embed_hasher` through a fixed schedule
//! (observes crossing pack boundaries, samples crossing squeeze boundaries, a digest absorb,
//! hashing with partial lanes, a compression). An independent mirror (duplex over the same
//! permutation) reproduces every value and emits the digit/remainder witness stream.
//!
//! Circuit side: replay the same schedule with `OuterTranscript` / `outer_hash` / `outer_compress`,
//! asserting every sampled felt / digest var equals the Rust-computed value.
//!
//! `gnark solve` on the emitted files is the end-to-end referee: it also proves the Rust
//! `pico_poseidon2bn254_init` permutation equals the gnark BN254 `Permute` chip.
//!
//!
//! Run:
//! ```text
//! cargo run --release -p pico-vm --example test_outer_twins
//! go run sdk/main/main.go -cmd solve -field kb \
//!   -constraints ../outer_twins_constraints.json -witness ../outer_twins_groth16_witness.json
//! ```

use num_bigint::BigUint;
use p3_bn254::Bn254;
use p3_field::{PrimeCharacteristicRing, PrimeField, PrimeField32};
use p3_symmetric::Permutation;
use pico_mle_core::{hasher::MerkleHasher, FiatShamirTranscript};
use pico_vm::{
    compiler::recursion::{
        circuit::outer_bn254::{
            outer_compress, outer_hash, OuterTranscript, OBS_PER_ELEM, SAMPLES_PER_ELEM,
        },
        constraints::ConstraintCompiler,
        ir::{Builder, Felt, Witness},
    },
    configs::field_config::KoalaBearBn254,
    instances::compiler::onchain_circuit::gnark::witness::GnarkWitness,
    mle::config::koala_bear_bn254_poseidon2::{
        default_bn254_poseidon2_3, default_embed_hasher, EmbedTranscript,
        KoalaBearBn254Poseidon2Config,
    },
};

type F = p3_koala_bear::KoalaBear;
type N = Bn254;
type SC = KoalaBearBn254Poseidon2Config;

/// Independent mirror of `MultiFieldTranscript` (duplex width 3 / rate 2 over the same BN254
/// permutation), which also records the digit/remainder witness stream at every sample-extraction
/// squeeze.
struct Mirror {
    perm: p3_bn254::Poseidon2Bn254<3>,
    state: [N; 3],
    absorb_idx: usize,
    sample_idx: usize,
    observe_buf: Vec<F>,
    sample_buf: Vec<F>,
    /// (digits, remainder) per extraction squeeze, in execution order.
    digit_stream: Vec<(Vec<F>, N)>,
}

impl Mirror {
    fn new() -> Self {
        Self {
            perm: default_bn254_poseidon2_3(),
            state: [N::ZERO; 3],
            absorb_idx: 0,
            sample_idx: 0,
            observe_buf: vec![],
            sample_buf: vec![],
            digit_stream: vec![],
        }
    }

    fn pack(buf: &[F]) -> N {
        let base = N::from_u64(1 << 31);
        buf.iter().rev().fold(N::ZERO, |acc, f| {
            acc * base + N::from_u32(f.as_canonical_u32())
        })
    }

    fn absorb(&mut self, v: N) {
        self.state[self.absorb_idx] = v;
        self.absorb_idx += 1;
        if self.absorb_idx == 2 {
            self.perm.permute_mut(&mut self.state);
            self.absorb_idx = 0;
            self.sample_idx = 2;
        }
    }

    fn squeeze(&mut self) -> N {
        if self.absorb_idx != 0 || self.sample_idx == 0 {
            self.perm.permute_mut(&mut self.state);
            self.absorb_idx = 0;
            self.sample_idx = 2;
        }
        self.sample_idx -= 1;
        self.state[self.sample_idx]
    }

    fn observe(&mut self, f: F) {
        self.sample_buf.clear();
        self.observe_buf.push(f);
        if self.observe_buf.len() == OBS_PER_ELEM {
            let packed = Self::pack(&self.observe_buf);
            self.absorb(packed);
            self.observe_buf.clear();
        }
    }

    fn flush(&mut self) {
        if !self.observe_buf.is_empty() {
            let packed = Self::pack(&self.observe_buf);
            self.absorb(packed);
            self.observe_buf.clear();
        }
    }

    fn observe_digest(&mut self, digest: &[N]) {
        self.sample_buf.clear();
        self.flush();
        for &d in digest {
            self.absorb(d);
        }
    }

    fn sample(&mut self) -> F {
        if let Some(f) = self.sample_buf.pop() {
            return f;
        }
        self.flush();
        let squeezed = self.squeeze();

        // base-p digit extraction, LSB-first + remainder
        let p = BigUint::from(F::ORDER_U32);
        let mut x = squeezed.as_canonical_biguint();
        let mut digits: Vec<F> = Vec::with_capacity(SAMPLES_PER_ELEM);
        for _ in 0..SAMPLES_PER_ELEM {
            let r: u32 = (&x % &p).try_into().unwrap();
            x /= &p;
            digits.push(F::from_u32(r));
        }
        // remainder < 2^100: recompose into Bn254 via two u64 limbs + shift
        let limbs = x.to_u64_digits();
        let two64 = N::from_u64(1 << 32) * N::from_u64(1 << 32);
        let mut rem = N::ZERO;
        for &limb in limbs.iter().rev() {
            rem = rem * two64 + N::from_u64(limb);
        }
        self.digit_stream.push((digits.clone(), rem));

        self.sample_buf = digits;
        self.sample_buf.reverse();
        self.sample_buf.pop().unwrap()
    }
}

fn main() {
    // ── Inputs (deterministic) ───────────────────────────────────────────────────────────────
    let obs: Vec<F> = (0..23u32).map(|i| F::from_u32(i * 977 + 5)).collect();
    let obs2: Vec<F> = (0..3u32).map(|i| F::from_u32(i * 31 + 11)).collect();
    let hash_in: Vec<F> = (0..37u32).map(|i| F::from_u32(i * 131 + 7)).collect();
    let hash_in2: Vec<F> = (0..5u32).map(|i| F::from_u32(i * 17 + 3)).collect();

    // ── Rust reference: the REAL embed primitives ────────────────────────────────────────────
    let hasher = default_embed_hasher();
    let digest: [N; 1] = hasher.hash_slice(&hash_in);
    let digest2: [N; 1] = hasher.hash_slice(&hash_in2);
    let compressed: [N; 1] = hasher.compress(digest, digest2);

    let mut t = EmbedTranscript::from(default_bn254_poseidon2_3());
    let mut expected_samples: Vec<F> = Vec::new();
    for &f in &obs {
        FiatShamirTranscript::<SC>::observe(&mut t, f);
    }
    for _ in 0..7 {
        expected_samples.push(FiatShamirTranscript::<SC>::sample(&mut t));
    }
    for &f in &obs2 {
        FiatShamirTranscript::<SC>::observe(&mut t, f);
    }
    expected_samples.push(FiatShamirTranscript::<SC>::sample(&mut t));
    FiatShamirTranscript::<SC>::observe_commit(&mut t, digest);
    for _ in 0..4 {
        expected_samples.push(FiatShamirTranscript::<SC>::sample(&mut t));
    }

    // ── Mirror: same schedule, cross-checked, capturing the digit/rem stream ────────────────
    let mut m = Mirror::new();
    let mut mirror_samples: Vec<F> = Vec::new();
    for &f in &obs {
        m.observe(f);
    }
    for _ in 0..7 {
        mirror_samples.push(m.sample());
    }
    for &f in &obs2 {
        m.observe(f);
    }
    mirror_samples.push(m.sample());
    m.observe_digest(&digest);
    for _ in 0..4 {
        mirror_samples.push(m.sample());
    }
    assert_eq!(
        expected_samples, mirror_samples,
        "mirror disagrees with EmbedTranscript — twin semantics wrong"
    );
    println!(
        "Rust mirror == EmbedTranscript over {} samples ✓ ({} extraction squeezes)",
        expected_samples.len(),
        m.digit_stream.len()
    );

    // ── Circuit: replay with the twins, asserting every value ───────────────────────────────
    let mut builder = Builder::<KoalaBearBn254>::default();

    let mut ct = OuterTranscript::new(&mut builder);
    let obs_c: Vec<Felt<F>> = obs.iter().map(|&f| builder.constant(f)).collect();
    let obs2_c: Vec<Felt<F>> = obs2.iter().map(|&f| builder.constant(f)).collect();
    let hash_in_c: Vec<Felt<F>> = hash_in.iter().map(|&f| builder.constant(f)).collect();
    let hash_in2_c: Vec<Felt<F>> = hash_in2.iter().map(|&f| builder.constant(f)).collect();

    let mut asserted = 0usize;
    let mut expected_iter = expected_samples.iter();
    for &f in &obs_c {
        ct.observe(&mut builder, f);
    }
    for _ in 0..7 {
        let s = ct.sample(&mut builder);
        builder.assert_felt_eq(s, *expected_iter.next().unwrap());
        asserted += 1;
    }
    for &f in &obs2_c {
        ct.observe(&mut builder, f);
    }
    let s = ct.sample(&mut builder);
    builder.assert_felt_eq(s, *expected_iter.next().unwrap());
    asserted += 1;

    let dvar = outer_hash(&mut builder, &hash_in_c);
    builder.assert_var_eq(dvar, digest[0]);
    ct.observe_digest(&mut builder, &[dvar]);
    for _ in 0..4 {
        let s = ct.sample(&mut builder);
        builder.assert_felt_eq(s, *expected_iter.next().unwrap());
        asserted += 1;
    }

    let dvar2 = outer_hash(&mut builder, &hash_in2_c);
    builder.assert_var_eq(dvar2, digest2[0]);
    let cvar = outer_compress(&mut builder, dvar, dvar2);
    builder.assert_var_eq(cvar, compressed[0]);
    println!("circuit built: {asserted} sample asserts + 3 digest asserts");

    // ── Emit constraints + witness (digits/rems in execution order) ─────────────────────────
    let constraints =
        ConstraintCompiler::<KoalaBearBn254>::default().emit(builder.into_operations());
    println!("emitted {} gnark opcodes", constraints.len());
    std::fs::write(
        "outer_twins_constraints.json",
        serde_json::to_string(&constraints).unwrap(),
    )
    .unwrap();

    let mut witness = Witness::<KoalaBearBn254>::default();
    for (digits, rem) in &m.digit_stream {
        witness.felts.extend_from_slice(digits);
        witness.vars.push(*rem);
    }
    println!(
        "witness: vars={} felts={} exts={}",
        witness.vars.len(),
        witness.felts.len(),
        witness.exts.len()
    );
    GnarkWitness::new(witness).save("outer_twins_groth16_witness.json");
    println!("wrote outer_twins_constraints.json + outer_twins_groth16_witness.json ✓");
}
