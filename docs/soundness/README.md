# Provable security of the MLE proof system

The MLE backend targets 128 bits of provable, round-by-round (RBR) soundness for every proof it
produces, under the model stated in section 4 (random-oracle transcript hashes, cost counted in
hash calls).
Release 3.1 brought the riscv and the recursion machines to that target, added the compress layer
(the proof that is handed out), and rebuilt the whitelist artifact on `KoalaBear^5`, with the
compress key as a leaf. `README.md`
and `docs/support-matrix.md` state the same target; the release notes of earlier releases state
theirs (100 bits for 3.0).
This document says what that number is, where its inputs come from, what the wired presets
currently score, and which assumptions the number rests on.

## 1. What is computed

A proof is an interactive protocol made non-interactive with Fiat–Shamir. RBR soundness charges
each interactive round the probability that a cheating prover gets a challenge that lets it pass
that round. Within a round the error sources add up; the proof's provable bits are `-log2` of the
largest per-round error, i.e. the minimum over rounds and components. The calculator lives in
`mle-core/src/config/soundness/` (`SoundnessCalculator::calculate_for_shape`, or
`calculate_from_vk` for a real key) and scores these components:

| Component | Round(s) charged |
|---|---|
| LogUp | The α/β challenges of the LogUp argument (Schwartz–Zippel over all messages, minus the list-size penalty), plus the grinding bits, with the sampling bias of `sample_bits` accounted for |
| LogUp-GKR sumcheck | One degree-3 sumcheck round per hypercube variable and GKR layer, plus one event for the last layer's challenges, which are coordinates of the ZeroCheck input point (`4/|F|` per round) |
| GKR batching | The λ / μ challenges that batch numerator and denominator claims across layers; a layer's closing μ and the next layer's λ are sampled with nothing observed between them, so they are charged as one round (`2/|F|`) |
| ZeroCheck sumcheck | The univariate-skip round (degree `(d+1)(2^l_skip − 1)`) and the multilinear rounds (degree `d + 1`) |
| Constraint batching (fused) | The round that samples the last LogUp-GKR μ, the ZeroCheck input-point coordinates the GKR output does not provide and the constraint-batching challenge, with nothing observed between them (degree `max(3, n_extra) + (2^l_skip − 1) + (N_C − 1)`, `N_C` = max constraints in one AIR; the last μ is the input point's univariate-skip coordinate, and the `2^l_skip − 1` term is its degree), and the across-AIR batching round (degree `3|T| − 1`, `|T|` = number of AIRs) |
| Stacked reduction | The λ challenge that batches every committed column's evaluation claims (two claims per column), and its sumcheck rounds |
| WHIR | Per round: query sampling (with grinding and sampling bias), proximity gaps, folding sumcheck, out-of-domain sample, γ batching, shift, and the μ batching of all stacked columns |

Two inputs vary per proof and are taken at their worst case over all proofs a key admits: every
trace at the stacked height, and the LogUp-GKR depth at 0 (fewer GKR layers leave more coordinates
for the constraint-batching challenge to cover, so the shallowest depth is the worst case; the unit
test `worst_case_depth_is_zero` in `mle-core/src/config/soundness/vk.rs` checks this for every
component). Where the verifier's polynomial degree is lower than what the calculator charges (WHIR
folding sumcheck: quadratic, charged as cubic; stacked-reduction batching over `c` columns: degree
`2c − 1`, charged as `2c`), the calculator is conservative.

**The WHIR terms against the verifier's transcript** (`mle-core/src/verifier/whir.rs`). Each WHIR
term charges one challenge, and each challenge is sampled only after the message it must bind is
observed. μ batching charges the μ challenge, drawn after the stacking openings and the μ grind.
Proximity gaps and folding sumcheck both charge the per-sub-round folding challenge α, drawn after
that sub-round's polynomial and the folding grind; the two are added as errors, since they share α.
Out-of-domain charges `z0`, drawn after the next round's commitment, on every round but the last.
Query charges the query indices, drawn after the query-phase grind, which follows the commitment and
`z0` or, in the last round, the final polynomial. γ batching charges γ, drawn after the query
indices in every round, the last included. Shift combines the query and γ terms, and the final
polynomial has no term of its own because the last round's shift stands in for it. The verifier
samples no other challenge, every grind the calculator credits (μ, folding, query phase) is checked
by the verifier, and out-of-domain and γ, which have no grind, are credited none. The γ term counts
one out-of-domain point in the last round too, which has none, so it is conservative there.

References: WHIR (ePrint 2024/1586) for the polynomial commitment; [BCHKS25] (ECCC TR25-169) and
Haböck (ePrint 2025/2110) for the proximity-gap and list-size terms in the list-decoding regime; the
note *Soundness of Interactions via LogUp* for the LogUp term.

## 2. Inputs and how to re-measure them

**Protocol parameters** come from the preset the machine proves with, and the verifier reads the
same values from the verifying key:

| Machine | Preset | Stacked height |
|---|---|---|
| riscv | `riscv_params_with_128_bits_security(h)` | `h` = `MLE_LOG_STACKED_HEIGHT` (default and maximum 23) |
| convert, combine, root verification | `recursion_params_with_128_bits_security()` | 21 |
| compress | `compress_params_with_128_bits_security()` | fills the two-adic domain exactly (20) |
| embed | `embed_params_with_128_bits_security()` | fills the two-adic domain exactly (20) |

These are the presets the soundness calculator scores, and all four are release presets, the ones
the production claim covers; any parameter set outside this list carries no production claim,
whatever it scores.

The last two are the tail after the combine root, in this order. Compress is the final compression
layer: the root re-proved under the inner KoalaBear-Poseidon2 config
into the one proof that is handed out. Embed starts the on-chain path that goes on from the compress
proof, embed → wrap → Groth16: the compress proof re-proved under the outer BN254-hashed config,
which the wrap step keygens with `embed_params`. Their presets carry the same values, by
choice (the compress preset's doc says why they are two presets). Both register the same recursion
chip set as convert and combine, so the recursion bounds cover them.

23 is the largest height the riscv preset can prove: with `log_blowup = 1` the RS domain is
`2^(h+1)`, and KoalaBear's two-adicity is 24, so `MAX_RISCV_LOG_STACKED_HEIGHT` is 23 and the riscv
preset refuses, at construction, a height whose domain does not exist. Every preset also
refuses, at construction, a grinding or query-index sample wider than the transcript draws from one
field element (30 bits over KoalaBear; the widest any preset asks for is 20). Every preset uses
`k_whir = 4`. Riscv and recursion use unique decoding; compress and embed use list decoding at
`m = 2`. Grinding bits: 20 per
WHIR query round, 18 for LogUp (the wired floor; the derivation needs 13 under unique decoding and
16 for compress and embed), and for WHIR folding / μ batching 5 / 15 (riscv), 4 / 13 (recursion) and
16 / 18 (compress and embed).
The WHIR query counts are derived by `WhirConfig::new` to reach the 128-bit target after the nominal
grinding bits, then re-scored by the calculator with the effective grinding bits and the sampling
bias included.

**Field constants**: KoalaBear, `p = 2^31 − 2^24 + 1`; challenge field `KoalaBear^5`
(`5 · log2 p ≈ 154.94` bits).

**Circuit shape** is read off the real verifying key as a `VkShape`: number of AIRs, maximum
constraints per AIR, maximum interactions per AIR, total trace columns (preprocessed + cached mains
+ common main), and the stacked height as the bound on every trace height. All but the interaction
count enter the score; it is recorded so the preset's documented bound on it can be checked. Every
keygen of the riscv, convert, combine, deferred, compress and embed machines logs one line (target
`mle_soundness`, level `info`, message `keygen soundness`) with `machine`, `backend`, the `VkShape`
fields, `vk_pre_hash` and `bits`, for example:

```text
INFO keygen soundness machine="riscv" backend="cpu" num_airs=54 max_constraints_per_air=4292
  max_interactions_per_air=4966 num_trace_columns=45823 log_stacked_height=23 vk_pre_hash=[...]
  bits=128.32
```

The GPU prover's keygens log the same line with `backend="gpu"`; to read them off a production run:

```bash
RUST_LOG="warn,bench=info,distributed_vm::mle=info,mle_soundness=info" \
  MLE_ELF=reth MLE_N=24006677 MLE_STEP=combine PROVER_COUNT=1 CUDA_VISIBLE_DEVICES=0 MLE_REPEAT=1 \
  bash ./single_node_mle.sh 2>&1 | grep "keygen soundness"
```

The measured shapes live in `mle-core/tests/soundness_manifest.json`, which is generated, not
edited. To re-measure after a circuit, preset or calculator change, regenerate it:

```bash
cargo run --release -p pico-vm --example mle_soundness_manifest
```

The generator keygens two sets of keys. With the whitelist off it proves fib-10 through the combine
root and on to the compress proof, so the recursion keys are the ones such a run produces, with
embed keygen'd over the compress proof; with the whitelist on it keygens, without proving, the riscv
key, one convert key per convert ladder row, every standard combine node, the deferred and compress
nodes over the combine-tier child (the one root layout of whitelist mode), and the embed node over
the compress proof's layout (`compress_proof_layout`, the compress row's heights). Per key it writes
the `VkShape`, the params, the key's identity and every component of section 1; the header records
the commit it ran at, the shipped whitelist's root, the whitelist-mode riscv key's pre-hash, and the
Groth16 test keys in `contracts/test/dev`: their wrap circuit's hash and size and the whitelist root
it was set up under. It is written by the default degree bound only.

The tests then score each preset at the bounds its doc comment assumes and at every key in the
manifest, the riscv preset at every stacked height it admits (11 to 23); pin every component at
the assumed bounds to the hundredth, and every component of a manifest key to the value the
manifest records; check that each measured shape stays within the assumed bounds; and check that
the manifest still matches the presets and the calculator, that it was generated from a clean
tree, that every whitelist-mode recursion key, the compress key included, is in the shipped
whitelist (embed's is scored but is no member: its BN254-hashed key has no KoalaBear identity to be
a leaf, and no apex verifies an embed proof), that it records
the test keys `contracts/test/dev` holds, and (in
`pico-vm`'s `the_shipped_artifact_matches_this_binary`) that its apex identities are this tree's,
that its whitelist-set embed key is the one this binary keygens, and that the compress and embed
proof shapes it records are those of this binary's keys.
A preset or calculator change that was not followed by a regeneration fails:

```bash
cargo test -p pico-mle-core --test soundness -- --nocapture --test-threads=1
```

A second test scores eight rows at a fixed shape, over the `KoalaBear^4` reference width and the
100-bit LogUp derivation the values were produced with, against pinned reference values, so a change that
moves the binding term shows up as a failing assertion rather than as a silently different verdict.
CI's soundness job runs both, with the crate's other tests, under the default degree bound
and again with `soundness-bchks25-optimized`, where the parity test is skipped:

```bash
cargo test -p pico-mle-core --test soundness_upstream_parity -- --nocapture
```

The manifest also records, per machine, the shapes a whitelist-mode proof takes at that layer
(`proof_shapes`), over each riscv shape, each convert ladder row, each combine node, the deferred
node, and compress and embed at their rows: `shapes` counts the distinct proof shapes; `max` holds
each per-proof shape input at its largest (present AIRs, constraints and interactions of a present
AIR, present columns, tallest trace, stacked width), where a key's `shape` counts every AIR of the
key; and `largest` holds the shape and wire size of the largest proof. A whitelist-mode proof's
trace heights are its shape's, so `ProofShape::from_heights` (`mle-core/src/protocol/proof_size.rs`)
gives its size without proving: 299,179 bytes for compress and 239,319 for embed. In CI,
`test_mle_e2e` (dev mode, through compress) holds every proof it makes against the size its shape
gives, as the wrap test does its embed proof, and the artifact test holds the recorded compress and
embed shapes against this binary's keys. A whitelist-mode run of `test_mle_e2e` and the ignored
whitelist-mode EVM test hold the real compress and embed proofs against the records; both are run
by hand. These records are for EF's soundcalc to score Pico's soundness and proof sizes from.

## 3. Results

Measured shapes: riscv 54 AIRs, per-AIR maxima of 4292 constraints and 4966 interactions, 45823
columns; convert, combine, deferred, compress and embed share 21 recursion AIRs, per-AIR maxima of
170 constraints and 34 interactions, 1409 columns, compress and embed at their own stacked height
(over `KoalaBear^4`
the recursion AIRs had 148 constraints and 1277 columns: the chips that store extension values grew
by the fifth coefficient). Every key of a machine reports the same shape, with the whitelist on or
off, including the root-verification key.

The shape is a property of the AIR set, not of the program, so any workload registering the full
chip set measures the same numbers; these come from the manifest, keygen'd from fib. The riscv rows
are at the default height 23; at every height the preset admits, 11 to 23, the measured riscv shape
scores 128.32. The recursion, compress and embed rows are the manifest's dev-set keys (whitelist
off, natural shapes); the whitelist-set keys, keygen'd at the tier tables' pad shapes, have the
same AIR set and preset and score the same. The shipped whitelist artifact
(`vm/src/mle/shape_vk_bins/mle_vk_map_kb.bin`) is built on `KoalaBear^5`; the manifest's
`apex.vk_root` is its root, and the Groth16 test keys are set up over the same root, which
`onchain_test_keys.vk_root` records.

| Machine / preset | LogUp | GKR sumcheck | GKR batching | ZeroCheck | Constraint batching | Stacked reduction | WHIR | **Total** |
|---|---|---|---|---|---|---|---|---|
| riscv (h = 23), measured | 133.95 | 152.94 | 153.94 | 149.04 | 142.86 | 138.46 | 128.32 | **128.32** |
| convert / combine / deferred, measured (dev set) | 133.95 | 152.94 | 153.94 | 148.71 | 147.29 | 143.48 | 128.39 | **128.39** |
| compress (m = 2), measured (dev set) | 130.63 | 152.94 | 153.94 | 145.39 | 143.98 | 140.16 | 128.05 | **128.05** |
| embed (m = 2), measured (dev set) | 130.63 | 152.94 | 153.94 | 145.39 | 143.98 | 140.16 | 128.05 | **128.05** |
| riscv preset (h = 23), assumed bounds | 133.95 | 152.94 | 153.94 | 149.04 | 142.65 | 138.33 | 128.32 | **128.32** |
| recursion preset, assumed bounds | 133.95 | 152.94 | 153.94 | 148.71 | 144.93 | 142.98 | 128.39 | **128.39** |
| compress and embed presets (m = 2), assumed bounds | 130.63 | 152.94 | 153.94 | 145.39 | 141.61 | 139.66 | 128.05 | **128.05** |

WHIR sub-terms (riscv / recursion): query 128.32 / 128.39, proximity gaps 136.94 / 136.94, folding
sumcheck 158.36 / 157.36, fold 136.94 / 136.94, out-of-domain 136.94 / 138.94, γ batching
146.91 / 147.61, shift 128.32 / 128.39, μ batching 134.94 / 133.94. Query counts: riscv
[261, 119, 110, 109], recursion [160, 114, 109], compress and embed [65, 34, 24]. The compress
proof, the one handed out, is 292.17 KiB (stacked width 20 + 5 = 25) in whitelist mode, where the
compress tier row is the program's natural heights over the combine-tier root layout (measured on
fib-10 and reth 18884864 and 24600825). In dev mode it follows the root and is at most that:
292.17 KiB on the reth blocks, 271.76 KiB (stacked width 20) on fib-10. The embed proof over it is
233.71 KiB (stacked width 11), measured on fib-10 in both modes and on reth 18884864 in whitelist
mode.

The binding term is the WHIR query phase, which depends only on the protocol parameters.
`WhirConfig::new` derives the query counts against the target minus the nominal grinding bits under
ideal sampling, while the calculator charges the effective grinding bits and the sampling bias, so
the derivation alone does not guarantee the target: the tests are the guard. The headroom is 0.32
bits for riscv, 0.39 bits for the recursion machines and 0.05 bits for compress and embed (one query
fewer in the recursion preset's first WHIR round would give 127.81). Every other component is at
least 5.9 bits above the target for riscv and recursion and 2.6 bits for compress and embed (their
LogUp terms, 133.95 and 130.63), and the circuit-shape inputs only enter those other components: for
riscv and recursion the across-AIR batching term `3|T| − 1` allows about 2^25 AIRs and the
stacked-reduction batching term `2c` just under 2^26 columns before the total drops below 128 (the
list size of compress and embed, 3.3 bits, lowers both thresholds by that much).

## 4. Assumptions

**Enforced at keygen or by the verifier** (so a proof that violates them is rejected): trace heights
≤ the stacked height, total stacked width ≤ `w_stack`, constraint degree ≤ 4, LogUp message length +
1 ≤ 128, lifted interaction count < `p`, and the query counts and grinding bits of the key. Keygen
of every production phase (riscv, convert, combine, deferred, compress, embed) and the whitelist
builder score each key as section 1 does and refuse one below 128 bits; the weak parameters of the
test utilities are keygen'd outside that check.

**Assumed, not enforced**: the circuit-shape bounds in the preset doc comments (riscv preset:
≤ 100 AIRs, ≤ 5000 constraints and ≤ 6000 interactions per AIR, ≤ 50 000 columns; recursion
preset: ≤ 50, ≤ 1000, ≤ 100, ≤ 2000). `tests/soundness.rs` checks the measured shapes against them, and the `mle_soundness`
keygen log line shows the live values and score of every key a run produces.

**Model and scope**: the transcript hash, Poseidon2 over KoalaBear (width 16, rate 8, with the
round constants Plonky3 0.5 generated for KoalaBear — `default_koalabear_poseidon2_16`, re-exported
by `mle-core/src/config/koala_bear_poseidon2.rs`; the riscv stage -- its Poseidon2 chip, the Global
chip's hash-to-curve and the Poseidon2 syscall -- runs that same instance through
`FieldSpecificPoseidon2Config`), is treated as a random oracle, its 8-element
digest as collision resistant, and grinding cost is counted in Poseidon2 permutations; every number
here is conditional on that instance being sound. The embed proof's commitments and transcript run
over a second instance, Poseidon2 over BN254 (width 3, a one-element digest;
`vm/src/mle/config/koala_bear_bn254_poseidon2.rs`), held to the same assumptions: a random oracle,
its digest collision resistant, its grinding counted in BN254 permutations. The
`sample_bits` bias term is exact for any `p` and sampled width `n`; because `2^24` divides `p − 1`,
every width up to 24 has a single heavy residue and the term is about `2^-31` per query (the widest
sample here is 20 bits). Of the presets a proof actually runs on, riscv and recursion rely only on
unique-decoding results; compress, the proof that is handed out, and embed, which the wrap step
keygens, rest on list decoding at `m = 2`.

**Composing proofs**: the bits are per proof and per round. Under two obligations they compose by
counting hash calls, the measure the grinding bits already assume. The first is that every
challenge binds the full statement of its round: everything the round's checks depend on is hashed
in before the challenge is drawn, so one call cannot serve two statements. The second is that the
Poseidon2 instance the recursion circuits evaluate in-circuit is a random oracle, as the host's is.
Where both hold, each challenge costs a cheating prover one call to a transcript hash, and one
call can rescue at most one round of one proof, so over `Q` calls the chance that any false proof
is accepted is at most `Q · 2^-b`, where `b` is the smallest per-round figure among the proofs; the
number of proofs drops out, since a longer chain costs calls already counted in `Q`. Neither
obligation is checked by the tests here: the first is argued from the circuits' code, the second
is an assumption.

At the release presets of section 2 every key scores at least 128 bits per proof: riscv 128.32
(measured), the recursion machines (convert, combine, deferred) 128.39, and compress and embed
128.05 (measured at the dev-set shapes; the whitelist-set keys score the same), per section 3 and the
manifest.

The convert, combine and deferred circuits absorb, at the transcript positions the host verifier
uses, the presence flag of each child AIR that may be absent and the trace height of each present
child AIR, as constants of their own key, so a child's transcript fixes the shape it is checked
under. A present AIR with its own preprocessed commitment, which only a riscv child has, absorbs
that commitment in place of its height: a constant for a fixed table, and for the program table a
witness, hashed into the `riscv_vk_digest` that the root's verifier compares with the program's own.
With the whitelist on, the mode a deployment verifies, the whitelist fixes which convert, combine,
deferred and compress keys are accepted, and with them those constants.
The compress circuit absorbs the root it re-proves, and the embed circuit the compress proof,
the way the combine circuits absorb their children, on the same argument from the circuit
code. Granting both obligations, a prover making `Q` calls to the transcript hashes gets a false
proof accepted anywhere in the chain — riscv, convert, combine or deferred up to the combine root,
then compress, then embed — with probability at most `Q · 2^-128.05`: at the release presets every
proof in the chain scores at least 128 bits, the weakest being compress and embed (riscv scores
128.32, the recursion machines 128.39, at their measured dev-set shapes). This bounds the soundness
of the proofs, not whether each circuit states what it is meant to, and it does not cover the
on-chain tail below.

**The on-chain tail** (wrap → Groth16 over the embed proof) is held to BN254's own
level, not to the figure above: the curve is estimated at about 100 bits after the exTNFS attacks
(Barbulescu–Duquesne, *Updating key size estimations for pairings*, Journal of Cryptology, 2019),
and Groth16's knowledge soundness is an idealized-model assumption at that level. Groth16 also
assumes a trusted setup in which at least one participant was honest. The Groth16 keys in this
repository are test keys, generated in a single process, so a production deployment needs a setup
ceremony first.
