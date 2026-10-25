//! WHIR query-index derivation, the proof → witness-stream serializer, and the convert, combine
//! and deferred setup drivers.
//!
//! [`push_proof_to_witness_stream`] serializes a RISCV proof into the block stream the verify
//! program reads via `Hint` instructions, in the exact order the program consumes them.
//! [`derive_whir_query_indices`] replays the RISCV verifier's Fiat-Shamir transcript to recover
//! the WHIR query indices that serializer needs, and [`setup_for_convert`] /
//! [`setup_for_convert_with_program`] / [`setup_for_combine_with_program`] /
//! [`setup_for_deferred_with_program`] build + execute the recursion program end to end.
//!
//! The RISCV proof and the recursion circuit share a single KoalaBear field, so the values flow
//! into the witness stream directly (no cross-field conversion).
//!
//! The WHIR query indices are recovered by the transcript-only verifier pass, rather than by a
//! full native verify whose verdict is thrown away. The two derive the same indices — the full
//! verify is kept as [`derive_whir_query_indices_with`]'s other arm so `MLE_WALKER_XCHECK=1` can
//! assert it per proof, and `mle-core`'s `verifier::tests::replay_matches_verify_*` pin the two
//! transcripts against each other.
//!
//! Three measurement knobs, all default-OFF and all `"1"`-valued; none changes a witnessed value:
//! `MLE_WITNESS_HASH` digests the finished witness stream, `MLE_TRANSCRIPT_PROF` prices the sponge
//! work inside the derive, and `MLE_WALKER_XCHECK` cross-checks the two derive paths.
//!
//! A fourth selects a shipped path rather than measuring: `MLE_REC_PARALLEL_CHILDREN` interprets
//! a combine node's two children concurrently (`Runtime::run_split`). Unlike the three above it is
//! **on** unless set to `0`. It is echoed as `split`.
//!
//! The interpreter these drivers hand off to has its own knobs, documented with it in
//! `emulator/recursion/emulator/profile.rs`: `MLE_REC_EMULATE_PROFILE` prices `Runtime::run()` by
//! instruction kind, and `MLE_REC_EMULATE_DUMP` writes the emulation's whole input for replay off
//! the box. The dump is called from here, outside the `emulate_ms` bracket, because `F` is
//! concrete at this layer and generic below it, so only the profile inflates `emulate_ms`; rule 1
//! applies to it and the timing line carries `probes`, non-zero on any arm whose `emulate_ms` is
//! not comparable with a shipped run's.
//!
//! Two rules the arms depend on:
//!
//! 1. Every knob that can move a number is echoed on the `convert_timing setup:` /
//!    `combine_timing setup:` / `deferred_timing setup:` line it moves, so a cell that set
//!    nothing, a cell that misspelled a variable, and a cell whose binary predates the knob do
//!    not all print what a live arm prints.
//! 2. Both cross-checks run OUTSIDE every timing bracket, and compare against the SAME proof.
//!    Outside, because each performs more derives than the shipped path and `derive_us` is the
//!    verdict. Same proof, because streams and derived indices are comparable only within one run:
//!    the prover's PoW witness comes from a `find_any` over a parallel iterator
//!    (`mle-core/src/transcript/traits.rs`) and is observed into the transcript, so two runs of one
//!    block sample different challenges and land on different query indices whether or not the code
//!    is correct.

use std::{borrow::Borrow, collections::VecDeque, sync::Arc};

use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField32, TwoAdicField};

use crate::{
    compiler::{
        recursion::{instruction::Instruction, ir::Block, program::RecursionProgram},
        word::Word,
    },
    emulator::{
        recursion::{
            emulator::{dump_emulation, profile as emulator_profile, RecursionRecord, Runtime},
            public_values::RECURSION_PUBLIC_VALUES_COL_MAP,
        },
        riscv::public_values::PublicValues as RiscvPublicValues,
    },
    machine::septic::{SepticCurve, SepticDigest, SepticExtension},
    mle::{
        compiler::recursion::{ConvertProgramInput, ConvertVerifierCircuit, RecursionVkLayout},
        machine::{
            air::GCS_DIGEST_LEN,
            exe::RiscvVmVk,
            vk_map::{vk_identity, MleVkMap},
        },
    },
    primitives::consts::{
        DIGEST_SIZE, KOALABEAR_S_BOX_DEGREE, MAX_NUM_PVS, RECURSION_NUM_PVS, RISCV_NUM_PVS,
    },
};
use pico_mle_core::{
    config::koala_bear_poseidon2::{
        default_koalabear_poseidon2_16, DuplexSponge, KoalaBearPoseidon2Config, EF,
    },
    keygen::types::MultiStarkVerifyingKey,
    protocol::proof::Proof,
    verifier::{replay_transcript, verify},
    FiatShamirTranscript, StarkProtocolConfig,
};

use super::{layout::extract_recursion_vk_layout, Kb, Sc};

/// The three knobs, each read once. `std::env::var` takes a process-wide lock and allocates a
/// `String`; these are consulted per child proof on the derive path.
///
/// All three are measurement knobs, default OFF, enabled with `"1"`.
mod flags {
    use std::sync::LazyLock;

    /// Off unless explicitly enabled. Only `"1"` counts, so a stray value cannot turn a
    /// measurement arm on and have it scored as the default.
    fn set(name: &str) -> bool {
        std::env::var(name).is_ok_and(|v| v == "1")
    }

    /// On unless explicitly disabled. Only `"0"` counts, so a typo or an unrecognised value leaves
    /// the shipped path in place instead of silently reverting it.
    fn set_unless_off(name: &str) -> bool {
        std::env::var(name).map_or(true, |v| v != "0")
    }

    macro_rules! flag {
        ($ident:ident, $var:literal) => {
            pub(super) static $ident: LazyLock<bool> = LazyLock::new(|| set($var));
        };
    }

    macro_rules! flag_on_by_default {
        ($ident:ident, $var:literal) => {
            pub(super) static $ident: LazyLock<bool> = LazyLock::new(|| set_unless_off($var));
        };
    }

    flag!(WITNESS_HASH, "MLE_WITNESS_HASH");
    flag!(TRANSCRIPT_PROF, "MLE_TRANSCRIPT_PROF");
    flag!(WALKER_XCHECK, "MLE_WALKER_XCHECK");

    // `MLE_REC_PARALLEL_CHILDREN` interprets a combine node's two children concurrently
    // (`Runtime::run_split`). **On by default**, `=0` puts the node back on one thread. The
    // record is the same either way — that is the gate the change is held to, and
    // `rec-emulate-replay` checks it by digest on a dumped node. A shipped path, not a
    // measurement: the module header's count of three does not include it.
    flag_on_by_default!(REC_PARALLEL_CHILDREN, "MLE_REC_PARALLEL_CHILDREN");
}

/// Every recursion knob and its resolved value — the one that selects a shipped path included, so a
/// layer above can state its whole environment contract from this one table.
///
/// Each is a `LazyLock`: the value here is the one this process uses for the rest of its life, so
/// no layer above can offer a setter for it.
#[doc(hidden)]
pub fn witness_flags() -> [(&'static str, bool); 4] {
    [
        ("MLE_WITNESS_HASH", *flags::WITNESS_HASH),
        ("MLE_TRANSCRIPT_PROF", *flags::TRANSCRIPT_PROF),
        ("MLE_WALKER_XCHECK", *flags::WALKER_XCHECK),
        ("MLE_REC_PARALLEL_CHILDREN", *flags::REC_PARALLEL_CHILDREN),
    ]
}

/// How many of the interpreter's probes are on.
///
/// Rule 1 of the module header, applied to knobs that live a layer down: this inflates
/// `emulate_ms`, so an arm that set it is not comparable with a shipped run, and the timing line
/// has to say so. A count rather than a flag because there used to be three and may be again.
/// `MLE_REC_EMULATE_DUMP` is excluded — it runs outside the bracket and so cannot move the
/// number.
fn interpreter_probes() -> u8 {
    u8::from(*emulator_profile::PROFILE)
}

// ─── Witness packing ──────────────────────────────────────────────────────────

/// Convert a digest `[Kb; 8]` to `[u32; 8]`.
pub(crate) fn digest_to_u32s(digest: &[Kb; 8]) -> [u32; 8] {
    digest.map(|b| b.as_canonical_u32())
}

/// Every `Hint` output consumes exactly one witness block — one instruction may carry several
/// (batched hints), so this counts outputs, not instructions. A mismatch means the program and the
/// stream disagree about the order or the shape of something, and it is far cheaper to catch here
/// than inside the interpreter.
fn assert_hint_count(kind: &str, program: &RecursionProgram<Kb>, stream: &VecDeque<Block<Kb>>) {
    let hint_count: usize = program
        .instructions
        .iter()
        .map(|i| match i {
            Instruction::Hint(h) => h.output_addrs_mults.len(),
            _ => 0,
        })
        .sum();
    assert_eq!(
        hint_count,
        stream.len(),
        "{kind} program expects {hint_count} hint blocks but witness_stream has {} blocks",
        stream.len()
    );
}

/// Pack one base-field element into a witness [`Block`].
fn kb_to_block(f: Kb) -> Block<Kb> {
    Block([f, Kb::ZERO, Kb::ZERO, Kb::ZERO])
}

/// Pack one extension-field element into a witness [`Block`] (`[c0, c1, c2, c3]`).
fn ef_to_block(ef: EF) -> Block<Kb> {
    let c = ef.as_basis_coefficients_slice();
    Block([c[0], c[1], c[2], c[3]])
}

/// Host replay of one in-circuit `curve_add_septic`: push its hint block —
/// `p3 = p1 + p2` (x then y, 7 limbs each) followed by `inv(p2.x − p1.x)` (7 limbs, the F7
/// inverse proving dx ≠ 0) — and return `p3`. The GCS fold in combine nodes and the initial-GCS
/// injection in convert leaves both replay their addition sequences through this.
fn push_curve_add(
    stream: &mut VecDeque<Block<Kb>>,
    p1: &SepticCurve<Kb>,
    p2: &SepticCurve<Kb>,
) -> SepticCurve<Kb> {
    let p3 = p1.add_incomplete(*p2);
    for j in 0..7 {
        stream.push_back(kb_to_block(p3.x.0[j]));
    }
    for j in 0..7 {
        stream.push_back(kb_to_block(p3.y.0[j]));
    }
    let inv_dx = (p2.x - p1.x).inv();
    for j in 0..7 {
        stream.push_back(kb_to_block(inv_dx.0[j]));
    }
    p3
}

/// FNV-1a-64 over every limb of every block, in stream order. Order-sensitive by construction:
/// two streams holding the same blocks in a different order hash differently, which is what makes
/// it usable as an `MLE_WITNESS_HASH` fingerprint of the stream a node actually built.
///
/// Comparable only WITHIN one run (module header, rule 2).
fn fnv1a_witness_stream(stream: &VecDeque<Block<Kb>>) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for block in stream {
        for limb in block.0 {
            for byte in limb.as_canonical_u32().to_le_bytes() {
                h = (h ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
    }
    h
}

// ─── WHIR query-index extraction via transcript replay ───────────────────────

/// One transcript operation as executed by the native verifier. `sample_bits` and `check_witness`
/// are trait default impls routed through `sample`/`observe`, so these four variants cover every
/// sponge operation a verify performs.
#[derive(Clone)]
enum TOp {
    Obs(<Sc as StarkProtocolConfig>::F),
    ObsCommit(<Sc as StarkProtocolConfig>::Digest),
    Sample,
    SampleBits(usize),
}

/// A [`DuplexSponge`] transcript that records every `sample_bits(bits) -> value`,
/// used to replay the RISCV verifier's Fiat-Shamir transcript and recover the WHIR
/// query indices the recursion circuit must witness.
#[derive(Clone)]
struct QueryExtractor {
    inner: DuplexSponge,
    recorded: Vec<(usize, u64)>,
    /// `MLE_TRANSCRIPT_PROF`: record the full op sequence for a timed replay. Off ⇒ `ops` stays
    /// empty and is never reserved.
    profile: bool,
    ops: Vec<TOp>,
    /// Op tally by kind, accumulated as `ops` is filled. The profile block below therefore walks
    /// `ops` once (to replay it) rather than twice.
    n_obs: usize,
    n_obs_commit: usize,
    n_sample: usize,
    n_sample_bits: usize,
}

impl QueryExtractor {
    fn new(profile: bool) -> Self {
        Self {
            inner: DuplexSponge::from(default_koalabear_poseidon2_16()),
            recorded: Vec::new(),
            profile,
            ops: Vec::new(),
            n_obs: 0,
            n_obs_commit: 0,
            n_sample: 0,
            n_sample_bits: 0,
        }
    }
}

impl FiatShamirTranscript<Sc> for QueryExtractor {
    fn observe(&mut self, value: <Sc as StarkProtocolConfig>::F) {
        FiatShamirTranscript::<Sc>::observe(&mut self.inner, value);
        if self.profile {
            self.ops.push(TOp::Obs(value));
            self.n_obs += 1;
        }
    }
    fn sample(&mut self) -> <Sc as StarkProtocolConfig>::F {
        let result = FiatShamirTranscript::<Sc>::sample(&mut self.inner);
        if self.profile {
            self.ops.push(TOp::Sample);
            self.n_sample += 1;
        }
        result
    }
    fn observe_commit(&mut self, digest: <Sc as StarkProtocolConfig>::Digest) {
        FiatShamirTranscript::<Sc>::observe_commit(&mut self.inner, digest);
        if self.profile {
            self.ops.push(TOp::ObsCommit(digest));
            self.n_obs_commit += 1;
        }
    }
    fn sample_bits(&mut self, bits: usize) -> u64 {
        let result = FiatShamirTranscript::<Sc>::sample_bits(&mut self.inner, bits);
        self.recorded.push((bits, result));
        if self.profile {
            self.ops.push(TOp::SampleBits(bits));
            self.n_sample_bits += 1;
        }
        result
    }
}

/// Replay the RISCV proof's Fiat-Shamir transcript to recover the WHIR query indices.
/// Outer index = WHIR round, inner = query index within the round.
///
/// The recorded `sample_bits` calls follow the protocol order:
///   logup_pow (×1 if > 0), mu_pow (×1 if > 0), then per WHIR round:
///   folding_pow (×k_whir if > 0), query_phase_pow (×1 if > 0), query indices (×num_queries).
fn derive_whir_query_indices(
    riscv_vk: &MultiStarkVerifyingKey<Sc>,
    proof: &Proof<Sc>,
    vk_layout: &RecursionVkLayout,
) -> Vec<Vec<usize>> {
    // The check-free pass drives the transcript. The full verify's verdict is discarded either
    // way — only the sponge's final state is read — so the two paths differ solely in the
    // algebraic work performed alongside the walk; `walker_xcheck` holds them to the same indices.
    derive_whir_query_indices_with(riscv_vk, proof, vk_layout, true)
}

/// `MLE_WALKER_XCHECK`: assert the transcript-only walk and the full verify derive the same query
/// indices for this proof. No-op with the flag unset.
///
/// **Callers must invoke this before starting their timers** (module header, rule 2): it performs
/// two derives of its own, and the shipped path's one derive is what `derive_us` is for.
///
/// On disagreement it panics. A wrong query index would otherwise be caught only by the recursion
/// circuit's `assert_f_eq` against its in-circuit transcript sample
/// (`vm/src/mle/compiler/recursion/lowering.rs`), i.e. as a rejected proof much later.
fn walker_xcheck(
    riscv_vk: &MultiStarkVerifyingKey<Sc>,
    proof: &Proof<Sc>,
    vk_layout: &RecursionVkLayout,
) {
    if !*flags::WALKER_XCHECK {
        return;
    }
    let verified = derive_whir_query_indices_with(riscv_vk, proof, vk_layout, false);
    let walked = derive_whir_query_indices_with(riscv_vk, proof, vk_layout, true);
    assert_eq!(
        verified, walked,
        "MLE_WALKER_XCHECK: the transcript-only walk derived different query indices than the \
         full verify on this proof"
    );
    let indices: usize = verified.iter().map(|round| round.len()).sum();
    // Printed only past the assert, so the line is both the arm proof and the verdict.
    tracing::info!(
        target: "bench",
        "walker_xcheck: rounds = {}, indices = {indices}, agree = 1",
        verified.len()
    );
}

/// [`derive_whir_query_indices`] with the transcript driver chosen explicitly: `walker` selects
/// `replay_transcript` (transcript only, no verdict) over `verify`. Both drive the identical
/// observe/sample sequence, pinned by `verifier::tests::replay_matches_verify_*` in `mle-core`.
///
/// The trade `walker = true` accepts: the `verify` arm's verdict is thrown away, but reaching it at
/// all means the host rejected a bad child proof HERE. The walker arm does not, so a prover-side
/// defect first surfaces at the recursion circuit's in-circuit `assert_f_eq`, which is far harder
/// to localise. `MLE_VERIFY=1` (read in `distributed-vm`) restores a host-side verify of every
/// chunk proof and is the compensating check when one is wanted.
fn derive_whir_query_indices_with(
    riscv_vk: &MultiStarkVerifyingKey<Sc>,
    proof: &Proof<Sc>,
    vk_layout: &RecursionVkLayout,
    walker: bool,
) -> Vec<Vec<usize>> {
    let params = &riscv_vk.inner.params;
    let config = KoalaBearPoseidon2Config::default_from_params(params.clone());

    let profile = *flags::TRANSCRIPT_PROF;
    let mut extractor = QueryExtractor::new(profile);
    let t_verify = std::time::Instant::now();
    if walker {
        replay_transcript(&config, riscv_vk, proof, &mut extractor)
            .expect("transcript replay: the walk must complete to derive query indices");
    } else {
        verify(&config, riscv_vk, proof, &mut extractor)
            .expect("transcript replay: proof must be valid to derive query indices");
    }
    let verify_us = t_verify.elapsed().as_micros();
    if profile {
        // Sponge-only lower bound on this derive: a transcript-walker that observes and samples
        // exactly what `verify` does, but performs none of the algebraic checks, cannot beat the
        // replay below. `verify_us` is INFLATED while this flag is on (the recording runs inside
        // it), so read the clean derive cost from a flag-off cell; `replay_us` is not inflated —
        // the recording completes before the replay timer starts and does nothing inside it.
        let mut sponge = DuplexSponge::from(default_koalabear_poseidon2_16());
        let t_replay = std::time::Instant::now();
        for op in &extractor.ops {
            match *op {
                TOp::Obs(v) => FiatShamirTranscript::<Sc>::observe(&mut sponge, v),
                TOp::ObsCommit(d) => FiatShamirTranscript::<Sc>::observe_commit(&mut sponge, d),
                TOp::Sample => {
                    // The sampled element is deliberately dropped: this loop only reproduces the
                    // sponge work. Plonky3 0.5 marks field elements `#[must_use]`.
                    let _ = FiatShamirTranscript::<Sc>::sample(&mut sponge);
                }
                TOp::SampleBits(bits) => {
                    FiatShamirTranscript::<Sc>::sample_bits(&mut sponge, bits);
                }
            }
        }
        let replay_us = t_replay.elapsed().as_micros();
        tracing::info!(
            target: "bench",
            "transcript_prof: walker = {}, verify_us = {verify_us}, replay_us = {replay_us}, \
             observe = {}, observe_commit = {}, sample = {}, sample_bits = {}",
            walker as u8,
            extractor.n_obs,
            extractor.n_obs_commit,
            extractor.n_sample,
            extractor.n_sample_bits
        );
    }
    let recorded = &extractor.recorded;

    let k_whir = params.k_whir();
    let num_whir_rounds = vk_layout.num_whir_rounds;
    let logup_pow_bits = params.logup.pow_bits;
    let mu_pow_bits = params.whir.mu_pow_bits;
    let folding_pow_bits = params.whir.folding_pow_bits;
    let query_phase_pow_bits = params.whir.query_phase_pow_bits;

    let mut pos = 0usize;
    if logup_pow_bits > 0 {
        pos += 1;
    }
    if mu_pow_bits > 0 {
        pos += 1;
    }

    let mut query_indices = Vec::with_capacity(num_whir_rounds);
    let mut expected_pos = pos;
    for r in 0..num_whir_rounds {
        if folding_pow_bits > 0 {
            pos += k_whir;
        }
        if query_phase_pow_bits > 0 {
            pos += 1;
        }
        let num_q = vk_layout.num_queries_per_whir_round[r];
        let round_indices: Vec<usize> = (0..num_q)
            .map(|_| {
                let qi = recorded[pos].1 as usize;
                pos += 1;
                qi
            })
            .collect();
        expected_pos = pos;
        query_indices.push(round_indices);
    }
    // The position walk must consume exactly the recorded sample_bits calls. A mismatch means
    // the replayed Fiat-Shamir transcript order no longer matches the verifier (e.g. a changed
    // grind or sampling order) — fail loudly rather than silently reading query indices from
    // wrong offsets.
    assert_eq!(
        recorded.len(),
        expected_pos,
        "derive_whir_query_indices: recorded {} sample_bits calls but expected {} \
         (logup_pow={} mu_pow={} folding_pow={} query_pow={} k_whir={} rounds={} n_logup={})",
        recorded.len(),
        expected_pos,
        logup_pow_bits,
        mu_pow_bits,
        folding_pow_bits,
        query_phase_pow_bits,
        k_whir,
        num_whir_rounds,
        vk_layout.n_logup,
    );
    query_indices
}

// ─── push_proof_to_witness_stream ─────────────────────────────────────────────

/// Push all proof field values to `witness_stream` in the same order that the
/// verify program reads them via `Hint` instructions.
///
/// `query_indices[r][q]` must hold the Fiat-Shamir-derived query index for WHIR round `r`,
/// query `q`.  Compute it with `derive_whir_query_indices` before calling this function.
fn push_proof_to_witness_stream(
    witness_stream: &mut VecDeque<Block<Kb>>,
    vk: &RecursionVkLayout,
    riscv_vk: &MultiStarkVerifyingKey<Sc>,
    proof: &Proof<Sc>,
    query_indices: &[Vec<usize>],
) {
    let params = &riscv_vk.inner.params;
    let per_air_vk = &riscv_vk.inner.per_air;
    let num_airs = per_air_vk.len();
    // Merged-preprocessed child vks: the merged commit itself is WITNESSED (pushed below);
    // per-air mode witnesses the app-identity commit (program table) and bakes only
    // machine-fixed ones (byte table). Presence flags and log_heights are never streamed: the
    // circuit absorbs the layout's baked values (`verify_one`).
    let merged_prep = vk.merged_preprocessed_commit.is_some();

    // ── Phase 1: VK hash + common_main_commit ───────────────────────────────
    // The vk pre-hash travels on the witness stream (the program pins the child identity via
    // its baked commitments/layout; the hinted pre-hash is Fiat-Shamir-bound to it). Push the
    // ACTUAL vk's pre_hash, not `vk.vk_pre_hash` from the layout parameter.
    {
        let vk_pre_hash = digest_to_u32s(&riscv_vk.pre_hash);
        for &h in &vk_pre_hash {
            witness_stream.push_back(kb_to_block(Kb::from_u32(h)));
        }
    }
    for f in proof.common_main_commit {
        witness_stream.push_back(kb_to_block(f));
    }
    // Merged-preprocessed commitment: witnessed by the circuit right after common_main_commit
    // (the child's program identity; see the witnessing note in `verify_one`).
    if let Some(commit) = riscv_vk.inner.merged_preprocessed_commit {
        for f in commit {
            witness_stream.push_back(kb_to_block(f));
        }
    }

    // ── Phase 2: per-AIR preamble ────────────────────────────────────────────
    // Matches the actual STARK verifier protocol, less what the circuit bakes:
    //   - is_air_present and log_height are layout constants in the circuit, never pushed.
    //   - Absent AIRs push nothing.
    //   - Present AIRs push cached_commits and PVs.
    // Machine-fixed preprocessed commits (byte) are baked as VK constants; app-identity ones
    // (program table) are pushed here (see the app_preprocessed branch below).
    for air_id in 0..num_airs {
        let avk = &per_air_vk[air_id];
        let vdata = proof.trace_vdata[air_id].as_ref();
        let is_present = vdata.is_some();

        if let Some(vd) = vdata {
            // Preprocessed handling, per the verify program's `verify_one`:
            //   - no per-air preprocessed, or merged mode → the circuit absorbs the baked
            //     log_height, push nothing;
            //   - app-identity preprocessed (RISC-V program table) → its commit is WITNESSED (the
            //     circuit `observe_digest_addrs` it); push the 8 commit elements here, matching
            //     the transcript position a baked const would occupy;
            //   - other per-air preprocessed (byte table) → commit is a baked VK constant, push
            //     nothing.
            if let Some(pdata) = avk
                .preprocessed_data
                .as_ref()
                .filter(|_| !merged_prep && vk.per_air[air_id].app_preprocessed)
            {
                for f in pdata.commit {
                    witness_stream.push_back(kb_to_block(f));
                }
            }
            // Cached commits.
            for &commit in &vd.cached_commitments {
                for f in commit {
                    witness_stream.push_back(kb_to_block(f));
                }
            }
            // Public values (actual, not padded).
            let pvs = proof
                .public_values
                .get(air_id)
                .map(|v| v.as_slice())
                .unwrap_or(&[]);
            for &pv in pvs {
                witness_stream.push_back(kb_to_block(pv));
            }
        }
        // Absent non-required AIRs: nothing pushed; no preamble.
        // Check for non-empty PVs in absent AIRs (would cause transcript mismatch).
        if !is_present {
            let absent_pvs = proof
                .public_values
                .get(air_id)
                .map(|v| v.len())
                .unwrap_or(0);
            if absent_pvs > 0 {
                tracing::warn!("ABSENT AIR {} has {} public values (non-empty!) — RISCV verifier absorbs these but circuit doesn't!",
                    air_id, absent_pvs);
            }
        }
    }

    // ── Phase 3: GKR ────────────────────────────────────────────────────────
    let gkr = &proof.gkr_proof;

    // check_witness(logup_pow_bits): observe pow_witness if bits > 0.
    if vk.logup_pow_bits > 0 {
        witness_stream.push_back(kb_to_block(gkr.logup_pow_witness));
    }

    let total_gkr_rounds = vk.l_skip + vk.n_logup;
    if vk.n_logup > 0 {
        // q0_claim (1 EF block)
        witness_stream.push_back(ef_to_block(gkr.q0_claim));

        // layer_claims[0]: p_xi_0, q_xi_0, p_xi_1, q_xi_1
        let (p0, q0, p1, q1) = gkr
            .claims_per_layer
            .first()
            .map(|c| (c.p_xi_0, c.q_xi_0, c.p_xi_1, c.q_xi_1))
            .unwrap_or((EF::ZERO, EF::ZERO, EF::ZERO, EF::ZERO));
        witness_stream.push_back(ef_to_block(p0));
        witness_stream.push_back(ef_to_block(q0));
        witness_stream.push_back(ef_to_block(p1));
        witness_stream.push_back(ef_to_block(q1));

        for round in 1..total_gkr_rounds {
            // sumcheck polys for this round (round sub-rounds, each [s1, s2, s3])
            let polys = gkr.sumcheck_polys.get(round - 1);
            for sub in 0..round {
                let evals = polys
                    .and_then(|p| p.get(sub))
                    .copied()
                    .unwrap_or([EF::ZERO; 3]);
                witness_stream.push_back(ef_to_block(evals[0]));
                witness_stream.push_back(ef_to_block(evals[1]));
                witness_stream.push_back(ef_to_block(evals[2]));
            }
            // layer_claims[round]
            let (p0, q0, p1, q1) = gkr
                .claims_per_layer
                .get(round)
                .map(|c| (c.p_xi_0, c.q_xi_0, c.p_xi_1, c.q_xi_1))
                .unwrap_or((EF::ZERO, EF::ZERO, EF::ZERO, EF::ZERO));
            witness_stream.push_back(ef_to_block(p0));
            witness_stream.push_back(ef_to_block(q0));
            witness_stream.push_back(ef_to_block(p1));
            witness_stream.push_back(ef_to_block(q1));
        }
    }

    // ── Phase 4: BatchConstraint ─────────────────────────────────────────────
    let bc = &proof.batch_constraint_proof;

    // Num + denom terms: push only for PRESENT AIRs (matches RISCV verifier transcript).
    // bc.numerator_term_per_air is indexed by the proof's trace_id ordering
    // (prover sort-for-stacking order: height-descending for different heights,
    // or equivalently air_id order for equal heights as in RISCV chips within one chunk).
    for (&num, &den) in bc
        .numerator_term_per_air
        .iter()
        .zip(bc.denominator_term_per_air.iter())
    {
        witness_stream.push_back(ef_to_block(num));
        witness_stream.push_back(ef_to_block(den));
    }

    // univariate_round_coeffs
    for &c in &bc.univariate_round_coeffs {
        witness_stream.push_back(ef_to_block(c));
    }

    // sumcheck_round_polys: n_max rounds (use actual n_max from proof heights).
    let n_max = vk.n_max;
    let s_deg = vk.max_constraint_degree + 1;
    for round in 0..n_max {
        let evals = bc.sumcheck_round_polys.get(round);
        for col in 0..s_deg {
            let v = evals.and_then(|e| e.get(col)).copied().unwrap_or(EF::ZERO);
            witness_stream.push_back(ef_to_block(v));
        }
    }

    tracing::debug!(
        "push Phase4a start: stream_len={} bc_col_openings_len={} trace_ordering_len={}",
        witness_stream.len(),
        bc.column_openings.len(),
        vk.trace_ordering.len()
    );
    // Column openings: push in trace_id order (matching bc.column_openings layout).
    // Phase 4a: common main columns for each trace (trace_id order).
    // We iterate over ALL AIRs in vk.trace_ordering.
    // Absent AIRs are SKIPPED entirely — the circuit uses addr_zero for them without reading
    // from the stream, so we must not push anything for absent AIRs here.
    //
    // bc.column_openings is indexed by present-trace position (0..num_present), while
    // trace_ordering ranges over all AIRs in identity order; for present AIRs that don't start
    // at index 0 these differ, so use present_trace_idx as the column_openings index.
    let mut present_trace_idx_4a = 0usize;
    for &air_idx in vk.trace_ordering.iter() {
        if !vk.per_air[air_idx].is_present {
            continue; // absent AIR: circuit uses addr_zero, no stream reads
        }
        let air_openings = bc.column_openings.get(present_trace_idx_4a);
        present_trace_idx_4a += 1;
        let common_main = air_openings
            .and_then(|v| v.first())
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        let n_cols = vk.per_air[air_idx].num_common_main_cols;
        let need_rot = vk.per_air[air_idx].need_rot;
        // The proof's opening slice must exactly cover the columns the layout expects. A
        // shorter slice was previously silently zero-padded, masking a VK-layout/proof width
        // mismatch that then desynced the whole witness stream far downstream — assert instead.
        let expected = if need_rot { n_cols * 2 } else { n_cols };
        assert_eq!(
            common_main.len(),
            expected,
            "Phase4a common-main opening width mismatch for air_id={air_idx}: got {} expected {} \
             (n_cols={n_cols}, need_rot={need_rot})",
            common_main.len(),
            expected,
        );
        if need_rot {
            for col in 0..n_cols {
                witness_stream.push_back(ef_to_block(common_main[col * 2]));
                witness_stream.push_back(ef_to_block(common_main[col * 2 + 1]));
            }
        } else {
            for col in 0..n_cols {
                witness_stream.push_back(ef_to_block(common_main[col]));
            }
        }
    }

    let phase4b_start_len = witness_stream.len();
    tracing::debug!("push Phase4b start: stream_len={}", phase4b_start_len);
    // Phase 4b: preprocessed + cached columns for each trace (trace_id order).
    // Same rule as Phase 4a: skip absent AIRs entirely (circuit uses addr_zero for them).
    // Same present_trace_idx indexing as Phase 4a.
    let mut present_trace_idx_4b = 0usize;
    for &air_idx in vk.trace_ordering.iter() {
        if !vk.per_air[air_idx].is_present {
            continue; // absent AIR: circuit uses addr_zero, no stream reads
        }
        let air_openings = bc.column_openings.get(present_trace_idx_4b);
        present_trace_idx_4b += 1;
        let avk = &per_air_vk[air_idx];
        let need_rot = avk.params.need_rot;
        let mut part_idx = 1usize;

        if avk.preprocessed_data.is_some() {
            let part = air_openings
                .and_then(|v| v.get(part_idx))
                .map(|v| v.as_slice())
                .unwrap_or(&[]);
            let n_cols = vk.per_air[air_idx].num_preprocessed_cols;
            let expected = if need_rot { n_cols * 2 } else { n_cols };
            assert_eq!(
                part.len(),
                expected,
                "Phase4b preprocessed opening width mismatch for air_id={air_idx}: got {} \
                 expected {} (n_cols={n_cols}, need_rot={need_rot})",
                part.len(),
                expected,
            );
            if need_rot {
                for col in 0..n_cols {
                    witness_stream.push_back(ef_to_block(part[col * 2]));
                    witness_stream.push_back(ef_to_block(part[col * 2 + 1]));
                }
            } else {
                for col in 0..n_cols {
                    witness_stream.push_back(ef_to_block(part[col]));
                }
            }
            part_idx += 1;
        }

        for (j, &w) in avk.params.width.cached_mains.iter().enumerate() {
            let part = air_openings
                .and_then(|v| v.get(part_idx + j))
                .map(|v| v.as_slice())
                .unwrap_or(&[]);
            let expected = if need_rot { w * 2 } else { w };
            assert_eq!(
                part.len(),
                expected,
                "Phase4b cached-main[{j}] opening width mismatch for air_id={air_idx}: got {} \
                 expected {} (w={w}, need_rot={need_rot})",
                part.len(),
                expected,
            );
            if need_rot {
                for col in 0..w {
                    witness_stream.push_back(ef_to_block(part[col * 2]));
                    witness_stream.push_back(ef_to_block(part[col * 2 + 1]));
                }
            } else {
                for col in 0..w {
                    witness_stream.push_back(ef_to_block(part[col]));
                }
            }
        }
    }

    // Compute expected vs actual for Phase4b (debug builds only).
    #[cfg(debug_assertions)]
    {
        let expected_4b: usize = vk
            .trace_ordering
            .iter()
            .map(|&air_id| {
                let air = &vk.per_air[air_id];
                let mult = if air.need_rot { 2 } else { 1 };
                let preproc = if air.has_preprocessed {
                    air.num_preprocessed_cols * mult
                } else {
                    0
                };
                let cached: usize = air.cached_main_widths.iter().map(|&w| w * mult).sum();
                preproc + cached
            })
            .sum();
        let actual_4b = witness_stream.len() - phase4b_start_len;
        tracing::debug!(
            "push Phase4b done: expected={} actual={} diff={}",
            expected_4b,
            actual_4b,
            expected_4b as isize - actual_4b as isize
        );
        // Log per-AIR breakdown for non-zero contributions
        for &air_id in &vk.trace_ordering {
            let air = &vk.per_air[air_id];
            let mult = if air.need_rot { 2 } else { 1 };
            let preproc = if air.has_preprocessed {
                air.num_preprocessed_cols * mult
            } else {
                0
            };
            let cached: usize = air.cached_main_widths.iter().map(|&w| w * mult).sum();
            if preproc + cached > 0 {
                let is_present = per_air_vk[air_id].preprocessed_data.is_some()
                    || !per_air_vk[air_id].params.width.cached_mains.is_empty();
                tracing::debug!(
                    "  Phase4b air_id={} preproc={} cached={} need_rot={} present_in_trace={}",
                    air_id,
                    preproc,
                    cached,
                    air.need_rot,
                    is_present
                );
            }
        }
    }
    let phase5_start_len = witness_stream.len();
    tracing::debug!("push Phase5 start: stream_len={}", phase5_start_len);
    // ── Phase 5: Stacking ────────────────────────────────────────────────────
    let stk = &proof.stacking_proof;

    // Diagnostic: compare computed stacking_widths with actual proof openings per commit
    // (debug builds only; the hard width invariant is enforced in the openings loop below).
    #[cfg(debug_assertions)]
    {
        let actual_widths: Vec<usize> = stk.stacking_openings.iter().map(|v| v.len()).collect();
        if actual_widths != vk.stacking_widths {
            tracing::warn!(
                "push_proof_to_witness_stream: stacking width MISMATCH — \
                 computed={:?} actual={:?} n_stack={} l_skip={} n_max={} n_logup={} \
                 trace_ordering={:?}",
                vk.stacking_widths,
                actual_widths,
                vk.n_stack,
                vk.l_skip,
                vk.n_max,
                vk.n_logup,
                vk.trace_ordering,
            );
        } else {
            tracing::debug!(
                "push_proof_to_witness_stream: stacking_widths match: {:?}",
                vk.stacking_widths
            );
        }
        if stk.stacking_openings.len() != vk.stacking_widths.len() {
            tracing::warn!(
                "push_proof_to_witness_stream: stacking num_commits MISMATCH — \
                 computed_commits={} actual_commits={}",
                vk.stacking_widths.len(),
                stk.stacking_openings.len(),
            );
        }
        if stk.sumcheck_round_polys.len() != vk.n_stack {
            tracing::warn!(
                "push_proof_to_witness_stream: stacking sumcheck rounds MISMATCH — \
                 computed_n_stack={} actual_rounds={}",
                vk.n_stack,
                stk.sumcheck_round_polys.len(),
            );
        }
        let gkr = &proof.gkr_proof;
        let total_gkr_rounds = vk.l_skip + vk.n_logup;
        let expected_sumcheck_polys = if total_gkr_rounds > 0 {
            total_gkr_rounds - 1
        } else {
            0
        };
        if gkr.sumcheck_polys.len() != expected_sumcheck_polys {
            tracing::warn!(
                "push_proof_to_witness_stream: GKR sumcheck polys MISMATCH — \
                 expected={} actual={} (n_logup={} l_skip={})",
                expected_sumcheck_polys,
                gkr.sumcheck_polys.len(),
                vk.n_logup,
                vk.l_skip,
            );
        }
        let bc = &proof.batch_constraint_proof;
        if bc.sumcheck_round_polys.len() != vk.n_max {
            tracing::warn!(
                "push_proof_to_witness_stream: BC sumcheck rounds MISMATCH — \
                 computed_n_max={} actual_rounds={}",
                vk.n_max,
                bc.sumcheck_round_polys.len(),
            );
        }
        tracing::info!(
            "push_proof_to_witness_stream: proof structure — n_logup={} n_max={} n_stack={} \
             l_skip={} stacking_commits={} stacking_widths={:?} \
             gkr_polys={} bc_polys={} stk_polys={}",
            vk.n_logup,
            vk.n_max,
            vk.n_stack,
            vk.l_skip,
            stk.stacking_openings.len(),
            vk.stacking_widths,
            gkr.sumcheck_polys.len(),
            bc.sumcheck_round_polys.len(),
            stk.sumcheck_round_polys.len(),
        );
    }

    // univariate_stk_coeffs
    for &c in &stk.univariate_round_coeffs {
        witness_stream.push_back(ef_to_block(c));
    }

    // sumcheck_round_polys (n_stack rounds)
    for round in 0..vk.n_stack {
        let evals = stk
            .sumcheck_round_polys
            .get(round)
            .copied()
            .unwrap_or([EF::ZERO; 2]);
        witness_stream.push_back(ef_to_block(evals[0])); // s_j_1
        witness_stream.push_back(ef_to_block(evals[1])); // s_j_2
    }

    // stacking_openings: per commit, per col. Use stacking_widths order.
    for (commit_idx, &width) in vk.stacking_widths.iter().enumerate() {
        let opening = stk
            .stacking_openings
            .get(commit_idx)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        // Same invariant as Phase 4: the computed stacking width must match the proof's
        // actual opening width (also catches a num-commits mismatch, where a missing commit
        // yields an empty slice), else the stream would be silently zero-padded.
        assert_eq!(
            opening.len(),
            width,
            "Phase5 stacking opening width mismatch at commit {commit_idx}: got {} expected {}",
            opening.len(),
            width,
        );
        for col in 0..width {
            witness_stream.push_back(ef_to_block(opening[col]));
        }
    }

    #[cfg(debug_assertions)]
    {
        let stk2 = &proof.stacking_proof;
        let expected_stk_univar = stk2.univariate_round_coeffs.len();
        let expected_stk_sumcheck = vk.n_stack * 2;
        let expected_stk_openings: usize = vk.stacking_widths.iter().sum();
        let expected_phase5 = expected_stk_univar + expected_stk_sumcheck + expected_stk_openings;
        let actual_phase5 = witness_stream.len() - phase5_start_len;
        tracing::debug!("push Phase6 start: stream_len={} Phase5: expected={} actual={} diff={} (univar={} sumcheck={} openings=sum{:?}={})",
            witness_stream.len(), expected_phase5, actual_phase5,
            expected_phase5 as isize - actual_phase5 as isize,
            expected_stk_univar, expected_stk_sumcheck, vk.stacking_widths, expected_stk_openings);
    }
    // ── Phase 6: WHIR ────────────────────────────────────────────────────────
    #[cfg(debug_assertions)]
    let phase6_start_len = witness_stream.len();
    let whir = &proof.whir_proof;
    let whir_params = &params.whir;

    tracing::debug!(
        "Phase6 params: num_rounds={} k_whir={} log_rs_domain={} log_final_poly_len={} \
         mu_pow_bits={} folding_pow_bits={} query_pow_bits={} num_queries={:?}",
        vk.num_whir_rounds,
        vk.k_whir,
        vk.log_rs_domain_size,
        vk.log_final_poly_len,
        vk.mu_pow_bits,
        whir_params.folding_pow_bits,
        whir_params.query_phase_pow_bits,
        &vk.num_queries_per_whir_round,
    );

    // check_witness(mu_pow_bits)
    if vk.mu_pow_bits > 0 {
        witness_stream.push_back(kb_to_block(whir.mu_pow_witness));
    }

    let mut sumcheck_iter = whir.whir_sumcheck_polys.iter();
    let mut fold_pow_iter = whir.folding_pow_witnesses.iter();

    for whir_round in 0..vk.num_whir_rounds {
        let is_final = whir_round == vk.num_whir_rounds - 1;
        let _round_start_len = witness_stream.len();

        for _ in 0..vk.k_whir {
            let evals = sumcheck_iter.next().copied().unwrap_or([EF::ZERO; 2]);
            witness_stream.push_back(ef_to_block(evals[0])); // ev1
            witness_stream.push_back(ef_to_block(evals[1])); // ev2
                                                             // check_witness(folding_pow_bits)
            if whir_params.folding_pow_bits > 0 {
                let pow = fold_pow_iter.next().copied().unwrap_or(Kb::ZERO);
                witness_stream.push_back(kb_to_block(pow));
            }
        }

        if is_final {
            for &ef in &whir.final_poly {
                witness_stream.push_back(ef_to_block(ef));
            }
        } else {
            // codeword_commit: 8 F
            let commit = whir
                .codeword_commits
                .get(whir_round)
                .copied()
                .unwrap_or_default();
            for f in commit {
                witness_stream.push_back(kb_to_block(f));
            }
            // ood_value
            let ood = whir.ood_values.get(whir_round).copied().unwrap_or(EF::ZERO);
            witness_stream.push_back(ef_to_block(ood));
        }

        // check_witness(query_phase_pow_bits)
        if whir_params.query_phase_pow_bits > 0 {
            let pow = whir
                .query_phase_pow_witnesses
                .get(whir_round)
                .copied()
                .unwrap_or(Kb::ZERO);
            witness_stream.push_back(kb_to_block(pow));
        }

        // WHIR query phase: push hinted data (zi_root, zi_root_inv, index_bits,
        // opened rows/EF values, and Merkle siblings) for each query.
        // Query indices come from the Fiat-Shamir transcript (pre-computed by the caller).
        let n_bits = vk.log_rs_domain_size - vk.k_whir - whir_round;
        // Verifier uses omega = two_adic_generator(log_rs_domain_size_r) where
        // log_rs_domain_size_r = log_rs_domain_size - whir_round (decrements by 1 per round).
        let log_rs_domain_size_r = vk.log_rs_domain_size - whir_round;
        let omega_full: Kb = TwoAdicField::two_adic_generator(log_rs_domain_size_r);

        let num_queries = vk
            .num_queries_per_whir_round
            .get(whir_round)
            .copied()
            .unwrap_or(0);

        for q in 0..num_queries {
            let query_index = query_indices[whir_round][q];

            // zi_root = omega_full^query_index  (matches verifier: zi_root = omega^index)
            let zi_root = omega_full.exp_u64(query_index as u64);
            // zi_root_inv: the circuit computes halving internally via addr_inv2.
            let zi_root_inv = Field::inverse(&zi_root);

            // Push zi_root (hint_f)
            witness_stream.push_back(kb_to_block(zi_root));
            // Push zi_root_inv (hint_f) — NOT pre-halved; circuit handles the ÷2 itself.
            witness_stream.push_back(kb_to_block(zi_root_inv));

            // Push index_bits[0..n_bits]: bit j = (query_index >> j) & 1 (LSB first).
            // Matches merkle_verify direction: idx >>= 1 at each level.
            for bit_idx in 0..n_bits {
                let bit = (query_index >> bit_idx) & 1;
                witness_stream.push_back(kb_to_block(Kb::from_u32(bit as u32)));
            }

            let fold_size = 1usize << vk.k_whir;

            if whir_round == 0 {
                // Initial round: for each commit, push fold_size rows × width F values,
                // then n_bits × 8 F siblings.
                for (commit_idx, &width) in vk.stacking_widths.iter().enumerate() {
                    // opened_rows: fold_size rows × width F values
                    let opened_rows = whir
                        .initial_round_opened_rows
                        .get(commit_idx)
                        .and_then(|per_commit| per_commit.get(q));
                    // Diagnostic: check row width vs. computed stacking_widths[commit_idx].
                    if q == 0 {
                        if let Some(rows) = opened_rows {
                            if let Some(row0) = rows.first() {
                                if row0.len() != width {
                                    tracing::warn!(
                                        "WHIR round0 commit[{commit_idx}] row width MISMATCH: \
                                         computed_width={width} actual_row_width={}",
                                        row0.len()
                                    );
                                }
                            }
                        }
                    }
                    // PACKED: 4 row values per block (tail zero-padded), row-major —
                    // mirrors the lowering's `hint_fs(fold_size * ceil(width/4))` read.
                    for row_idx in 0..fold_size {
                        let mut lanes = [Kb::ZERO; 4];
                        let mut lane = 0usize;
                        for col_idx in 0..width {
                            lanes[lane] = opened_rows
                                .and_then(|rows| rows.get(row_idx))
                                .and_then(|row| row.get(col_idx))
                                .copied()
                                .unwrap_or(Kb::ZERO);
                            lane += 1;
                            if lane == 4 {
                                witness_stream.push_back(Block(lanes));
                                lanes = [Kb::ZERO; 4];
                                lane = 0;
                            }
                        }
                        if lane > 0 {
                            witness_stream.push_back(Block(lanes));
                        }
                    }
                    // Merkle siblings: n_bits × 8 F values
                    let siblings = whir
                        .initial_round_merkle_proofs
                        .get(commit_idx)
                        .and_then(|per_commit| per_commit.get(q));
                    for sib_idx in 0..n_bits {
                        let sib = siblings
                            .and_then(|s| s.get(sib_idx))
                            .copied()
                            .unwrap_or([Kb::ZERO; 8]);
                        // Packed: 2 blocks of 4 lanes per sibling digest.
                        witness_stream.push_back(Block([sib[0], sib[1], sib[2], sib[3]]));
                        witness_stream.push_back(Block([sib[4], sib[5], sib[6], sib[7]]));
                    }
                }
            } else {
                // Non-initial round: push fold_size EF values (1 hint_f each as EF block),
                // then n_bits × 8 F siblings.
                let opened_ef = whir
                    .codeword_opened_values
                    .get(whir_round - 1)
                    .and_then(|per_round| per_round.get(q));
                for ef_idx in 0..fold_size {
                    let ef_val = opened_ef
                        .and_then(|vals| vals.get(ef_idx))
                        .copied()
                        .unwrap_or(EF::ZERO);
                    witness_stream.push_back(ef_to_block(ef_val));
                }
                // Merkle siblings: n_bits × 8 F values
                let siblings = whir
                    .codeword_merkle_proofs
                    .get(whir_round - 1)
                    .and_then(|per_round| per_round.get(q));
                for sib_idx in 0..n_bits {
                    let sib = siblings
                        .and_then(|s| s.get(sib_idx))
                        .copied()
                        .unwrap_or([Kb::ZERO; 8]);
                    // Packed: 2 blocks of 4 lanes per sibling digest.
                    witness_stream.push_back(Block([sib[0], sib[1], sib[2], sib[3]]));
                    witness_stream.push_back(Block([sib[4], sib[5], sib[6], sib[7]]));
                }
            }
        }
    }

    // Phase6 diagnostics: compute expected count from RecursionVkLayout and compare
    // (debug builds only).
    #[cfg(debug_assertions)]
    {
        let fold_size_diag = 1usize << vk.k_whir;
        let mut expected6 = if vk.mu_pow_bits > 0 { 1usize } else { 0 };
        for r in 0..vk.num_whir_rounds {
            let is_f = r == vk.num_whir_rounds - 1;
            let nb = vk.log_rs_domain_size - vk.k_whir - r;
            let nq = vk.num_queries_per_whir_round.get(r).copied().unwrap_or(0);
            expected6 += vk.k_whir * 2; // fold sumcheck EF
            if whir_params.folding_pow_bits > 0 {
                expected6 += vk.k_whir;
            }
            if is_f {
                expected6 += 1usize << vk.log_final_poly_len;
            } else {
                expected6 += 9; // 8 F codeword_commit + 1 EF ood_val
            }
            if whir_params.query_phase_pow_bits > 0 {
                expected6 += 1;
            }
            for _ in 0..nq {
                expected6 += 2 + nb; // zi_root + zi_root_inv + index_bits
                if r == 0 {
                    for &w in &vk.stacking_widths {
                        // PACKED opened rows: ceil(w/4) blocks per row.
                        expected6 += fold_size_diag * w.div_ceil(4) + nb * 2;
                    }
                } else {
                    expected6 += fold_size_diag + nb * 2;
                }
            }
        }
        let actual6 = witness_stream.len() - phase6_start_len;
        tracing::debug!(
            "push Phase6 end: expected_from_vk={} actual_pushed={} diff={}",
            expected6,
            actual6,
            expected6 as isize - actual6 as isize
        );
    }
}

// ─── Convert runtime: build + execute the recursion program ──────────────────

/// Build the convert verifier program for a RISCV VK + proof, then execute it to
/// produce the recursion record.
pub fn setup_for_convert(
    riscv_vk: &MultiStarkVerifyingKey<Sc>,
    riscv_vm_vk: &RiscvVmVk,
    proof: &Proof<Sc>,
) -> (Arc<RecursionProgram<Kb>>, RecursionRecord<Kb>) {
    let vk_layout = extract_recursion_vk_layout(riscv_vk, Some(proof));
    // Test helper: whitelist mode off (no vk map exists here) — natural shapes, no bucket.
    let input = ConvertProgramInput {
        vk: vk_layout,
        vk_verification: false,
    };
    let program = Arc::new(ConvertVerifierCircuit::build_verify_program(&input));
    // No deferred proofs in this helper's world, so the chain value every leaf passes through is
    // zero — which is also what the root's closure forces when no deferred node is present.
    setup_for_convert_with_program(
        riscv_vk,
        riscv_vm_vk,
        proof,
        program,
        [Kb::ZERO; DIGEST_SIZE],
        None,
    )
}

/// Execute a pre-built convert program, reusing the exact keygen program so the
/// execution trace is consistent with the preprocessed trace in the VK.
/// `deferred_digest` is the chain value this leaf passes through — the digest the tree's deferred
/// nodes end on, or zero when there are none. Every leaf in one tree must be given the same one:
/// cross-child continuity asserts it, so a mismatch makes the tree unprovable.
pub fn setup_for_convert_with_program(
    riscv_vk: &MultiStarkVerifyingKey<Sc>,
    riscv_vm_vk: &RiscvVmVk,
    proof: &Proof<Sc>,
    program: Arc<RecursionProgram<Kb>>,
    deferred_digest: [Kb; DIGEST_SIZE],
    vk_root: Option<[Kb; 8]>,
) -> (Arc<RecursionProgram<Kb>>, RecursionRecord<Kb>) {
    // The second of two identical extractions per chunk — `prepare_one` already built this exact
    // layout to key the keygen cache. Each call rebuilds every RISC-V AIR's `EvalDag`. Timed on
    // both sides before deciding whether to thread the caller's layout through.
    let t_extract = std::time::Instant::now();
    let vk_layout = extract_recursion_vk_layout(riscv_vk, Some(proof));
    let extract_us = t_extract.elapsed().as_micros();
    // Before `t_witness`/`t_derive` below: the cross-check's own derives must not land in the
    // numbers those brackets produce (module header, rule 2).
    walker_xcheck(riscv_vk, proof, &vk_layout);
    // The recursion runtime drives the same Poseidon2 the MLE engine used to produce the
    // RISCV proof (default KoalaBear constants), so the emulated Fiat-Shamir matches.
    let perm = default_koalabear_poseidon2_16();
    let mut runtime =
        Runtime::<Kb, EF, _, _, KOALABEAR_S_BOX_DEGREE>::new(Arc::clone(&program), perm);
    let t_witness = std::time::Instant::now();
    // `witness_ms` covers the derive AND every push below; `derive_ms` is the derive alone.
    let t_derive = std::time::Instant::now();
    let query_indices = derive_whir_query_indices(riscv_vk, proof, &vk_layout);
    let derive_us = t_derive.elapsed().as_micros();
    push_proof_to_witness_stream(
        &mut runtime.witness_stream,
        &vk_layout,
        riscv_vk,
        proof,
        &query_indices,
    );
    // The Global-air public values (present in EVERY chunk): [gcs (14) ‖ riscv PublicValues].
    let global_pv = proof
        .public_values
        .iter()
        .find(|p| p.len() == GCS_DIGEST_LEN + MAX_NUM_PVS)
        .expect("RISCV proof carries no Global-air public values");
    let riscv: &RiscvPublicValues<Word<Kb>, Kb> =
        global_pv[GCS_DIGEST_LEN..GCS_DIGEST_LEN + RISCV_NUM_PVS].borrow();
    // A CPU chunk's translation block hints inv(Σ start_pc limbs) (so the circuit can assert
    // the whole pc != 0). Emitted after all verify_one hints, matching the program order.
    let has_cpu = vk_layout
        .per_air
        .iter()
        .any(|a| a.is_present && a.num_public_values == RISCV_NUM_PVS);
    if has_cpu {
        let pc_sum = riscv.start_pc[0] + riscv.start_pc[1] + riscv.start_pc[2];
        runtime
            .witness_stream
            .push_back(kb_to_block(pc_sum.inverse()));
    } else {
        // Mirror of the circuit's !has_cpu branch: inv(chunk − 1) for the "non-CPU chunk
        // cannot be chunk 1" assert (honest non-CPU chunks always have chunk >= 2).
        runtime
            .witness_stream
            .push_back(kb_to_block((riscv.chunk - Kb::ONE).inverse()));
    }
    // chunk range-check bits (MAX_LOG_NUMBER_OF_CHUNKS, LSB-first), matching the circuit's
    // hinted recomposition.
    let chunk_u32 = riscv.chunk.as_canonical_u32();
    for i in 0..crate::primitives::consts::MAX_LOG_NUMBER_OF_CHUNKS {
        runtime
            .witness_stream
            .push_back(kb_to_block(Kb::from_u32((chunk_u32 >> i) & 1)));
    }

    // The chain value the leaf passes through, read right after the chunk bits. Position matters
    // and the hint-count assert cannot police it: this run and the `vk_root` run below are the
    // only two of equal length, so swapping THEM would stay green until the root.
    for l in deferred_digest {
        runtime.witness_stream.push_back(kb_to_block(l));
    }

    // VM-layer exe identity witnesses, read by the convert program right after the PV
    // translation: pc_start (3 limbs) then initial_gcs (x 7, y 7). Raw hints (never absorbed);
    // the circuit folds them into `riscv_vk_digest = H(DOMAIN ‖ program_commit ‖ pc ‖ gcs)`
    // and the apex pins that digest against the trusted `RiscvVmVk::digest()`.
    for l in riscv_vm_vk.pc_start {
        runtime.witness_stream.push_back(kb_to_block(l));
    }
    for j in 0..7 {
        runtime
            .witness_stream
            .push_back(kb_to_block(riscv_vm_vk.initial_gcs.0.x.0[j]));
    }
    for j in 0..7 {
        runtime
            .witness_stream
            .push_back(kb_to_block(riscv_vm_vk.initial_gcs.0.y.0[j]));
    }

    // Chunk-1 gating + GCS injection hints, in circuit order:
    //   1. inv(start_chunk − 1) — pushed as 0 when start_chunk == 1 (the gate then forces
    //      is_first = 1; any value works, 0 is canonical);
    //   2. four curve-add hint blocks replaying the injection fold
    //      start + sel − zero + chunk_gcs − start, sel = is_first ? initial_gcs : zero.
    {
        let diff = riscv.chunk - Kb::ONE;
        let is_first = diff == Kb::ZERO;
        let inv = if is_first { Kb::ZERO } else { diff.inverse() };
        runtime.witness_stream.push_back(kb_to_block(inv));

        let chunk_gcs = SepticCurve {
            x: SepticExtension(std::array::from_fn(|j| global_pv[j])),
            y: SepticExtension(std::array::from_fn(|j| global_pv[7 + j])),
        };
        let start = SepticDigest::<Kb>::starting_digest().0;
        let zero = SepticDigest::<Kb>::zero().0;
        let sel = if is_first {
            riscv_vm_vk.initial_gcs.0
        } else {
            zero
        };
        let mut acc = start;
        acc = push_curve_add(&mut runtime.witness_stream, &acc, &sel);
        acc = push_curve_add(&mut runtime.witness_stream, &acc, &zero.neg());
        acc = push_curve_add(&mut runtime.witness_stream, &acc, &chunk_gcs);
        push_curve_add(&mut runtime.witness_stream, &acc, &start.neg());
    }

    // Whitelist mode: the convert program witnesses vk_root into its public values.
    if let Some(root) = vk_root {
        for l in root {
            runtime.witness_stream.push_back(kb_to_block(l));
        }
    }

    let witness_ms = t_witness.elapsed().as_millis();

    assert_hint_count("convert", &program, &runtime.witness_stream);

    if *flags::WITNESS_HASH {
        let hash = fnv1a_witness_stream(&runtime.witness_stream);
        tracing::info!(
            target: "bench",
            "witness_hash: kind = convert, blocks = {}, hash = {hash:#018x}",
            runtime.witness_stream.len()
        );
    }

    runtime.dump_label = "convert";
    dump_emulation(runtime.dump_label, &program, &runtime.witness_stream);

    let t_emulate = std::time::Instant::now();
    runtime.run().expect("convert recursion runtime failed");
    tracing::info!(
        // `target: "bench"` for the same reason `combine_timing` carries it: the production
        // `RUST_LOG` filters this module's path out, and the two halves of a derive result have to
        // survive the same filter or the convert half silently reads as absent.
        target: "bench",
        "convert_timing setup: witness_ms = {witness_ms}, emulate_ms = {}, \
         derive_ms = {}, derive_us = {derive_us}, extract_us = {extract_us}, probes = {}",
        t_emulate.elapsed().as_millis(),
        derive_us / 1_000,
        interpreter_probes()
    );
    // Measurement harness (log-only, no semantic effect): deterministic per-proof cycle
    // count of the recursion program. `timestamp` increments once per executed
    // instruction, so it equals the executed instruction count.
    tracing::info!(
        "recursion_cycles = {} (instrs = {})",
        runtime.timestamp,
        program.instructions.len()
    );
    tracing::debug!("program_stats = {:?}", program.stats());
    (program, runtime.record)
}

// ─── Combine runtime: execute a pre-built aggregation program ─────────────────

/// One aggregation child: (the vk the child proof verifies under, the proof, its layout —
/// the same layout the node's program was built from).
pub type CombineChild = (
    Arc<MultiStarkVerifyingKey<Sc>>,
    Proof<Sc>,
    RecursionVkLayout,
);

/// Whitelist mode, in circuit order: vk_root (8), then per child DEPTH × (index bit, sibling
/// digest (8)). Fail-closed: a child VK absent from the map cannot even generate a witness.
fn push_vk_root_and_paths<'a>(
    stream: &mut VecDeque<Block<Kb>>,
    map: &MleVkMap,
    child_vks: impl Iterator<Item = &'a MultiStarkVerifyingKey<Sc>>,
) {
    for l in map.root() {
        stream.push_back(kb_to_block(l));
    }
    for vk in child_vks {
        let idx = map
            .find(&vk_identity(vk))
            .unwrap_or_else(|| panic!("child VK not in the whitelist (vk map)"));
        let (bits, siblings) = map.path(idx);
        for (bit, sib) in bits.iter().zip(&siblings) {
            stream.push_back(kb_to_block(Kb::from_u32(*bit as u32)));
            for l in sib {
                stream.push_back(kb_to_block(*l));
            }
        }
    }
}

/// Execute a pre-built combine program over its N child recursion proofs, producing the
/// recursion record. `is_complete` must match the flag baked into the program: root
/// programs hint one extra witness element (`inv(next_chunk - 1)`, see the completeness
/// block in the program builder), pushed LAST.
pub fn setup_for_combine_with_program(
    children: &[CombineChild],
    program: Arc<RecursionProgram<Kb>>,
    is_complete: bool,
    vk_map: Option<&MleVkMap>,
) -> (Arc<RecursionProgram<Kb>>, RecursionRecord<Kb>) {
    // The cross-check runs here, ahead of every timer below (module header, rule 2).
    for (vk, proof, layout) in children {
        walker_xcheck(vk, proof, layout);
    }

    let perm = default_koalabear_poseidon2_16();
    let mut runtime =
        Runtime::<Kb, EF, _, _, KOALABEAR_S_BOX_DEGREE>::new(Arc::clone(&program), perm);

    // Started AFTER `Runtime::new`, matching the convert path's `t_witness`, so that the two are
    // divisible against each other.
    let t_witness = std::time::Instant::now();

    // Wall clock spent deriving, summed over the children.
    // Children are pushed in program order: verify_one(vks[0]) reads first, then vks[1], …
    let mut derive_us = 0;
    for (vk, proof, layout) in children {
        let t_derive = std::time::Instant::now();
        let query_indices = derive_whir_query_indices(vk, proof, layout);
        derive_us += t_derive.elapsed().as_micros();
        push_proof_to_witness_stream(
            &mut runtime.witness_stream,
            layout,
            vk,
            proof,
            &query_indices,
        );
    }

    if children.len() > 1 {
        // The n>1 PV-merge folds the children's GCS points with `curve_add_septic`, which
        // HINTS each add as [x(7), y(7), inv(dx)(7)] (the intermediate sum plus the F7
        // inverse proving dx = p2.x - p1.x != 0) and verifies the chord-law identities
        // in-circuit. Replay the exact same addition sequence host-side and push each
        // add's hint block, in program order:
        //   acc = starting_digest; for each d_i: acc += d_i (push);
        //   if not last: acc -= zero (push);  finally acc -= starting_digest (push).
        let read_gcs = |proof: &Proof<Sc>| -> SepticCurve<Kb> {
            // The recursion PV carrier is the unique RECURSION_NUM_PVS-length slice; picking
            // the wrong one here would desync the host GCS replay from the circuit's hints.
            debug_assert_eq!(
                proof
                    .public_values
                    .iter()
                    .filter(|p| p.len() == RECURSION_NUM_PVS)
                    .count(),
                1,
                "expected exactly one recursion public-values slice"
            );
            let pvs = proof
                .public_values
                .iter()
                .find(|p| p.len() == RECURSION_NUM_PVS)
                .expect("child proof carries no recursion public values");
            let col = RECURSION_PUBLIC_VALUES_COL_MAP;
            SepticCurve {
                x: SepticExtension(std::array::from_fn(|j| {
                    pvs[col.global_cumulative_sum.0.x.0[j]]
                })),
                y: SepticExtension(std::array::from_fn(|j| {
                    pvs[col.global_cumulative_sum.0.y.0[j]]
                })),
            }
        };
        let start = SepticDigest::<Kb>::starting_digest().0;
        let zero = SepticDigest::<Kb>::zero().0;
        let neg_zero = zero.neg();
        let neg_start = start.neg();
        let n = children.len();
        let mut acc = start;
        for (i, (_, proof, _)) in children.iter().enumerate() {
            let d = read_gcs(proof);
            acc = push_curve_add(&mut runtime.witness_stream, &acc, &d);
            if i != n - 1 {
                acc = push_curve_add(&mut runtime.witness_stream, &acc, &neg_zero);
            }
        }
        push_curve_add(&mut runtime.witness_stream, &acc, &neg_start);
    }

    if let Some(map) = vk_map {
        push_vk_root_and_paths(
            &mut runtime.witness_stream,
            map,
            children.iter().map(|(vk, _, _)| &**vk),
        );
    }

    if is_complete {
        // The root program's completeness block hints inv(next_chunk - 1) as the LAST
        // witness element. The merged next_chunk is the last child's next_chunk.
        let (_, last_proof, _) = children.last().expect("combine node needs >= 1 child");
        let pvs = last_proof
            .public_values
            .iter()
            .find(|p| p.len() == RECURSION_NUM_PVS)
            .expect("child proof carries no recursion public values");
        let next_chunk = pvs[RECURSION_PUBLIC_VALUES_COL_MAP.next_chunk];
        let diff = next_chunk - Kb::ONE;
        assert!(
            diff != Kb::ZERO,
            "complete combine root with next_chunk == 1 (empty execution)"
        );
        runtime
            .witness_stream
            .push_back(kb_to_block(diff.inverse()));
    }

    let witness_ms = t_witness.elapsed().as_millis();

    assert_hint_count("combine", &program, &runtime.witness_stream);

    if *flags::WITNESS_HASH {
        let hash = fnv1a_witness_stream(&runtime.witness_stream);
        tracing::info!(
            target: "bench",
            "witness_hash: kind = combine, blocks = {}, hash = {hash:#018x}, children = {}",
            runtime.witness_stream.len(),
            children.len()
        );
    }

    runtime.dump_label = "combine";
    dump_emulation(runtime.dump_label, &program, &runtime.witness_stream);

    let t_emulate = std::time::Instant::now();
    // `run_split` runs the program whichever path it takes, and reports which — a program
    // without exactly two child ranges is interpreted serially inside it.
    let split = if *flags::REC_PARALLEL_CHILDREN {
        runtime
            .run_split()
            .expect("combine recursion runtime failed")
    } else {
        runtime.run().expect("combine recursion runtime failed");
        false
    };
    tracing::info!(
        target: "bench",
        "combine_timing setup: witness_ms = {witness_ms}, emulate_ms = {}, \
         derive_ms = {}, derive_us = {derive_us}, children = {}, split = {}, probes = {}",
        t_emulate.elapsed().as_millis(),
        derive_us / 1_000,
        children.len(),
        u8::from(split),
        interpreter_probes()
    );
    (program, runtime.record)
}

/// Execute a pre-built deferred program over its single child — a COMPLETE recursion root of a
/// *sub-program* — producing the recursion record.
///
/// Hint order after the child's own stream, matching the program's emission order:
/// `inv(child.next_chunk − 1)` (the child's completeness block), the chain's start digest (8),
/// the MAIN program's `riscv_vk_digest` (8) and `end_pc` (3), then in whitelist mode the root
/// and the child's Merkle path.
pub fn setup_for_deferred_with_program(
    child: &CombineChild,
    program: Arc<RecursionProgram<Kb>>,
    start_digest: [Kb; DIGEST_SIZE],
    riscv_vk_digest: [Kb; DIGEST_SIZE],
    end_pc: [Kb; 3],
    vk_map: Option<&MleVkMap>,
) -> (Arc<RecursionProgram<Kb>>, RecursionRecord<Kb>) {
    let (vk, proof, layout) = child;
    walker_xcheck(vk, proof, layout);

    let perm = default_koalabear_poseidon2_16();
    let mut runtime =
        Runtime::<Kb, EF, _, _, KOALABEAR_S_BOX_DEGREE>::new(Arc::clone(&program), perm);

    let t_witness = std::time::Instant::now();
    let t_derive = std::time::Instant::now();
    let query_indices = derive_whir_query_indices(vk, proof, layout);
    let derive_us = t_derive.elapsed().as_micros();
    push_proof_to_witness_stream(
        &mut runtime.witness_stream,
        layout,
        vk,
        proof,
        &query_indices,
    );

    // The completeness block the program runs over the CHILD's public values asserts
    // `next_chunk != 1` through a hinted inverse.
    let pvs = proof
        .public_values
        .iter()
        .find(|p| p.len() == RECURSION_NUM_PVS)
        .expect("deferred child carries no recursion public values");
    let diff = pvs[RECURSION_PUBLIC_VALUES_COL_MAP.next_chunk] - Kb::ONE;
    assert!(
        diff != Kb::ZERO,
        "deferred child claims to be complete with next_chunk == 1 (empty execution)"
    );
    runtime
        .witness_stream
        .push_back(kb_to_block(diff.inverse()));

    for l in start_digest
        .into_iter()
        .chain(riscv_vk_digest)
        .chain(end_pc)
    {
        runtime.witness_stream.push_back(kb_to_block(l));
    }
    if let Some(map) = vk_map {
        push_vk_root_and_paths(&mut runtime.witness_stream, map, std::iter::once(&**vk));
    }

    let witness_ms = t_witness.elapsed().as_millis();

    assert_hint_count("deferred", &program, &runtime.witness_stream);

    if *flags::WITNESS_HASH {
        let hash = fnv1a_witness_stream(&runtime.witness_stream);
        tracing::info!(
            target: "bench",
            "witness_hash: kind = deferred, blocks = {}, hash = {hash:#018x}",
            runtime.witness_stream.len()
        );
    }

    runtime.dump_label = "deferred";
    dump_emulation(runtime.dump_label, &program, &runtime.witness_stream);

    let t_emulate = std::time::Instant::now();
    runtime.run().expect("deferred recursion runtime failed");
    tracing::info!(
        target: "bench",
        "deferred_timing setup: witness_ms = {witness_ms}, emulate_ms = {}, \
         derive_ms = {}, derive_us = {derive_us}, probes = {}",
        t_emulate.elapsed().as_millis(),
        derive_us / 1_000,
        interpreter_probes()
    );
    (program, runtime.record)
}
