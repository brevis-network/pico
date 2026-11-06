//! Provable security of the wired production presets over KoalaBear / KoalaBear^5.
//!
//! The riscv machine proves with `riscv_params_with_128_bits_security(h)`, `h` = 23 by default and
//! any height the preset admits on request; the convert, combine and deferred machines, and the
//! CPU-side root verification, prove with `recursion_params_with_128_bits_security()`; compress
//! with `compress_params_with_128_bits_security()` and embed with
//! `embed_params_with_128_bits_security()` (the same values, two presets; see the compress preset's
//! doc). Each preset is scored at two circuit shapes: the bounds
//! its doc comment assumes, and the shape of every key in `soundness_manifest.json`, which
//! `vm/examples/mle_soundness_manifest.rs` writes from a real keygen of the production machines.
//! Run with `--nocapture` to see the per-component breakdown.

use std::collections::BTreeMap;

use pico_mle_core::{
    config::{
        compress_params_with_128_bits_security, embed_params_with_128_bits_security,
        koala_bear_poseidon2::KoalaBearPoseidon2Config,
        recursion_params_with_128_bits_security, riscv_params_with_128_bits_security,
        soundness::{SoundnessCalculator, VkShape, DEGREE_BOUND, PRODUCTION_SECURITY_BITS},
        try_riscv_params_with_128_bits_security, MAX_RISCV_LOG_STACKED_HEIGHT,
    },
    SystemParams,
};
use serde::Deserialize;

/// Every stacked height the riscv preset admits: production keygen refuses a key below the budget
/// at any of them, and `MLE_LOG_STACKED_HEIGHT` or the SDK can pick any of them. 23, the top, is
/// the default operating point.
fn riscv_log_stacked_heights() -> Vec<usize> {
    (0..=MAX_RISCV_LOG_STACKED_HEIGHT)
        .filter(|&h| try_riscv_params_with_128_bits_security(h).is_ok())
        .collect()
}

// The bounds the preset doc comments assume (`config/mod.rs`). `log_stacked_height` is filled in
// per preset by `score`.
const RISCV_ASSUMED: VkShape = VkShape {
    num_airs: 100,
    max_constraints_per_air: 5000,
    max_interactions_per_air: 2000,
    num_trace_columns: 40_000,
    log_stacked_height: 0,
};
const RECURSION_ASSUMED: VkShape = VkShape {
    num_airs: 50,
    max_constraints_per_air: 1000,
    max_interactions_per_air: 100,
    num_trace_columns: 2000,
    log_stacked_height: 0,
};

// Measured shapes: `soundness_manifest.json`, generated, never edited by hand. Per key it holds the
// `VkShape::from_vk` of a real keygen, the params the key was generated under, its pre-hash and
// every calculator component, plus the commit it was generated at. Two key sets: the whitelist-off
// keys of a fib-10 run through the combine root, compress and embed (over the compress proof), the
// ones `test_mle_e2e` keygens, and the whitelisted keys (the riscv key, one convert key per ladder
// row, every standard combine node, the deferred and compress nodes over the combine-tier child,
// and the embed node over the compress proof's layout).
//
// The shape is a property of the AIR set, not of the program being proved, so any workload that
// registers the full chip set measures the same numbers; the riscv shape does not move with the
// whitelist mode either, and every recursion key shares one shape.
//
// Regenerate the manifest whenever the AIR set, a column count, a preset or the calculator moves.
// A moved preset or calculator fails `check_key` below; a moved AIR does not -- only a keygen sees
// it -- so until the manifest is regenerated it scores the old shape.
const REGENERATE: &str =
    "regenerate it: cargo run --release -p pico-vm --example mle_soundness_manifest";

/// The calculator the manifest is written by; components are compared only in a build that runs
/// the same one.
const MANIFEST_DEGREE_BOUND: &str = "closed-form";

/// The machines the recursion preset proves, as the manifest names them.
const RECURSION_MACHINES: [&str; 3] = ["convert", "combine", "deferred"];

#[derive(Deserialize)]
struct Manifest {
    commit: String,
    dirty: bool,
    dirty_paths: Vec<String>,
    calculator: String,
    shipped_whitelist: String,
    apex: Apex,
    onchain_test_keys: OnchainTestKeys,
    /// Machines the generator did not keygen (a riscv-only manifest names them); empty for a
    /// manifest CI accepts.
    not_generated: Vec<serde_json::Value>,
    keys: Vec<ManifestKey>,
}

/// The identities an apex verifier is built from in whitelist mode, `vk_root` among them; `vm`'s
/// `the_shipped_artifact_matches_this_binary` holds both to the tree.
#[derive(Deserialize)]
struct Apex {
    riscv_vk_pre_hash: [u32; 8],
}

/// The Groth16 test key set `contracts/` ships, and the whitelist root its wrap circuit was set up
/// under.
#[derive(Deserialize)]
struct OnchainTestKeys {
    vk_root: [u32; 8],
    circuit_sha256: String,
    nb_constraints: u64,
    gnark: String,
}

/// The fields of gnark's setup record the manifest copies. `vk_root` is the root the setup pinned
/// into the wrap circuit; a setup over unpinned constraints records none.
#[derive(Deserialize)]
struct GnarkSetupManifest {
    circuit_sha256: String,
    nb_constraints: u64,
    gnark: String,
    vk_root: Option<[u32; 8]>,
}

#[derive(Deserialize)]
struct ManifestKey {
    machine: String,
    mode: String,
    role: String,
    /// Decimal strings on embed's BN254-hashed key, limbs elsewhere.
    vk_pre_hash: Vec<serde_json::Value>,
    #[serde(with = "VkShapeDef")]
    shape: VkShape,
    params: SystemParams,
    soundness: BTreeMap<String, f64>,
    whir_details: BTreeMap<String, f64>,
    /// Recorded on the whitelist set's convert, combine, deferred and compress keys only.
    in_shipped_whitelist: Option<bool>,
}

#[derive(Deserialize)]
#[serde(remote = "VkShape")]
struct VkShapeDef {
    num_airs: usize,
    max_constraints_per_air: usize,
    max_interactions_per_air: usize,
    num_trace_columns: usize,
    log_stacked_height: usize,
}

fn manifest() -> Manifest {
    let manifest: Manifest = serde_json::from_str(include_str!("soundness_manifest.json"))
        .unwrap_or_else(|e| panic!("soundness_manifest.json does not parse ({e}); {REGENERATE}"));
    assert_eq!(
        manifest.calculator, MANIFEST_DEGREE_BOUND,
        "the manifest was written by another calculator; {REGENERATE}"
    );
    manifest
}

impl Manifest {
    fn keys_of(&self, machine: &str) -> Vec<&ManifestKey> {
        let keys: Vec<_> = self.keys.iter().filter(|k| k.machine == machine).collect();
        assert!(
            !keys.is_empty(),
            "the manifest has no {machine} key; {REGENERATE}"
        );
        keys
    }

    /// Holds a key to the preset it is scored at: the key must have been generated under that
    /// preset's params, and its recorded components must be the ones `s` computed (when this build
    /// runs the calculator the manifest was written with). Either failing means the manifest is
    /// stale.
    fn check_key(key: &ManifestKey, params: &SystemParams, s: &SoundnessCalculator) {
        let label = key.label();
        assert_eq!(
            key.params, *params,
            "{label}: generated under params other than the preset's; {REGENERATE}"
        );
        if DEGREE_BOUND != MANIFEST_DEGREE_BOUND {
            return;
        }
        for (recorded, computed) in [
            (&key.soundness, s.components()),
            (&key.whir_details, s.whir_details.components()),
        ] {
            assert_eq!(
                recorded.len(),
                computed.len(),
                "{label}: the manifest records other components than the calculator has; \
                 {REGENERATE}"
            );
            for (name, bits) in computed {
                let r = recorded
                    .get(name)
                    .unwrap_or_else(|| panic!("{label}: no {name} in the manifest; {REGENERATE}"));
                // Loose enough for the libm differences between the machine that generated the
                // manifest and the one testing it.
                assert!(
                    (r - bits).abs() < 1e-6,
                    "{label}: {name} is {bits} but the manifest records {r}; {REGENERATE}"
                );
            }
        }
    }
}

impl ManifestKey {
    fn label(&self) -> String {
        format!(
            "{} ({}, {}) at measured shape",
            self.machine, self.mode, self.role
        )
    }
}

/// Scores `params` at `shape`, with the trace-height bound the preset itself enforces.
fn score(label: &str, params: &SystemParams, shape: &VkShape) -> SoundnessCalculator {
    let shape = VkShape {
        log_stacked_height: params.log_stacked_height(),
        ..*shape
    };
    let s = SoundnessCalculator::calculate_for_shape::<KoalaBearPoseidon2Config>(params, &shape);
    let queries: Vec<usize> = params.whir.rounds.iter().map(|r| r.num_queries).collect();
    println!("\n=== {label} ===");
    println!(
        "params: l_skip={} n_stack={} w_stack={} log_blowup={} k_whir={} queries={queries:?} \
         mu_pow={} fold_pow={} query_pow={} logup_pow={}",
        params.l_skip,
        params.n_stack,
        params.w_stack,
        params.log_blowup,
        params.whir.k,
        params.whir.mu_pow_bits,
        params.whir.folding_pow_bits,
        params.whir.query_phase_pow_bits,
        params.logup.pow_bits
    );
    println!("shape: {shape:?}");
    println!("LogUp (α/β + PoW):       {:.2} bits", s.logup_bits);
    println!("GKR sumcheck:            {:.2} bits", s.gkr_sumcheck_bits);
    println!("GKR batching (μ/λ):      {:.2} bits", s.gkr_batching_bits);
    println!(
        "ZeroCheck sumcheck:      {:.2} bits",
        s.zerocheck_sumcheck_bits
    );
    println!(
        "Constraint batching:     {:.2} bits",
        s.constraint_batching_bits
    );
    println!(
        "Stacked reduction:       {:.2} bits",
        s.stacked_reduction_bits
    );
    println!("WHIR:                    {:.2} bits", s.whir_bits);
    let w = &s.whir_details;
    println!(
        "  WHIR: query={:.2} prox={:.2} sumcheck={:.2} fold={:.2} ood={:.2} gamma={:.2} \
         shift={:.2} mu={:.2}",
        w.query_bits,
        w.proximity_gaps_bits,
        w.sumcheck_bits,
        w.fold_rbr_bits,
        w.ood_rbr_bits,
        w.gamma_batching_bits,
        w.shift_rbr_bits,
        w.mu_batching_bits
    );
    println!("TOTAL:                   {:.2} bits", s.total_bits);
    s
}

fn assert_target(label: &str, s: &SoundnessCalculator) {
    assert!(
        s.total_bits >= PRODUCTION_SECURITY_BITS,
        "{label}: {:.2} bits < {PRODUCTION_SECURITY_BITS}",
        s.total_bits
    );
}

#[test]
fn riscv_preset_meets_128_bits_at_assumed_bounds() {
    let heights = riscv_log_stacked_heights();
    assert_eq!(
        (heights.first(), heights.last()),
        (Some(&11), Some(&MAX_RISCV_LOG_STACKED_HEIGHT)),
        "the admitted riscv heights moved: {heights:?}"
    );
    for h in heights {
        let params = riscv_params_with_128_bits_security(h);
        let label = format!("riscv({h}) at assumed bounds");
        assert_target(&label, &score(&label, &params, &RISCV_ASSUMED));
    }
}

#[test]
fn recursion_preset_meets_128_bits_at_assumed_bounds() {
    let params = recursion_params_with_128_bits_security();
    let label = "recursion at assumed bounds";
    assert_target(label, &score(label, &params, &RECURSION_ASSUMED));
}

/// Each riscv key is held to the manifest at the height it was keygen'd at, then its shape, which
/// does not move with the height, is scored at every other admitted height.
#[test]
fn riscv_machine_meets_128_bits_at_measured_shape() {
    let manifest = manifest();
    for key in manifest.keys_of("riscv") {
        let keyed_at = key.shape.log_stacked_height;
        let params = riscv_params_with_128_bits_security(keyed_at);
        Manifest::check_key(key, &params, &score(&key.label(), &params, &key.shape));
        for h in riscv_log_stacked_heights() {
            let label = format!("{} at h = {h}", key.label());
            let s = score(&label, &riscv_params_with_128_bits_security(h), &key.shape);
            assert_target(&label, &s);
        }
    }
}

#[test]
fn recursion_machines_meet_128_bits_at_measured_shape() {
    let manifest = manifest();
    let params = recursion_params_with_128_bits_security();
    for machine in RECURSION_MACHINES {
        for key in manifest.keys_of(machine) {
            let s = score(&key.label(), &params, &key.shape);
            Manifest::check_key(key, &params, &s);
            assert_target(&key.label(), &s);
        }
    }
}

#[test]
fn embed_machine_meets_128_bits_at_measured_shape() {
    let manifest = manifest();
    let params = embed_params_with_128_bits_security();
    for key in manifest.keys_of("embed") {
        let s = score(&key.label(), &params, &key.shape);
        Manifest::check_key(key, &params, &s);
        assert_target(&key.label(), &s);
    }
}

/// The compress key (the final compression layer) at its measured shape: the recursion
/// chip set over the combine root, at the compress preset.
#[test]
fn compress_machine_meets_128_bits_at_measured_shape() {
    let manifest = manifest();
    let params = compress_params_with_128_bits_security();
    for key in manifest.keys_of("compress") {
        let s = score(&key.label(), &params, &key.shape);
        Manifest::check_key(key, &params, &s);
        assert_target(&key.label(), &s);
    }
}

/// The measured shapes must stay within the bounds the preset doc comments assume; when a machine
/// grows past a bound, raise the bound (and re-run the assumed-bounds tests) rather than letting
/// the doc comment go stale.
#[test]
fn measured_shapes_are_within_assumed_bounds() {
    for key in manifest().keys {
        let measured = &key.shape;
        let assumed = match key.machine.as_str() {
            "riscv" => &RISCV_ASSUMED,
            m if RECURSION_MACHINES.contains(&m) || m == "embed" || m == "compress" => {
                &RECURSION_ASSUMED
            }
            m => panic!("{m}: a manifest machine no test scores; give it a preset and a bound"),
        };
        assert!(
            measured.num_airs <= assumed.num_airs
                && measured.max_constraints_per_air <= assumed.max_constraints_per_air
                && measured.max_interactions_per_air <= assumed.max_interactions_per_air
                && measured.num_trace_columns <= assumed.num_trace_columns,
            "{}: measured {measured:?} exceeds assumed {assumed:?}",
            key.label()
        );
    }
}

/// The manifest records which tree it measured and which whitelist its membership is against; the
/// fields no other test reads are held here, so none can go stale unseen.
#[test]
fn manifest_identities_are_recorded() {
    let manifest = manifest();
    assert!(
        !manifest.dirty && manifest.dirty_paths.is_empty(),
        "the manifest was generated from a tree with uncommitted changes {:?}; {REGENERATE}",
        manifest.dirty_paths
    );
    assert!(
        manifest.commit.len() == 40 && manifest.commit.bytes().all(|b| b.is_ascii_hexdigit()),
        "the manifest's commit `{}` is not a full SHA; {REGENERATE}",
        manifest.commit
    );
    assert!(!manifest.shipped_whitelist.is_empty());
    // The whitelist set is complete: every key kind a whitelist-mode prover
    // keygens is scored, and the recursion ones among them are held to membership below.
    for machine in ["convert", "combine", "deferred", "embed", "compress"] {
        assert!(
            manifest
                .keys
                .iter()
                .any(|k| k.mode == "whitelist" && k.machine == machine),
            "the manifest has no whitelist-mode {machine} key; {REGENERATE}"
        );
    }
    assert!(
        manifest.not_generated.is_empty(),
        "the manifest lists machines it did not generate {:?}; {REGENERATE}",
        manifest.not_generated
    );
    for key in &manifest.keys {
        // The keys the whitelist can hold: every KoalaBear-digest recursion key and the compress
        // key; the riscv key is pinned by its pre-hash, the embed key is BN254-hashed.
        let member_checked = key.machine != "riscv" && key.machine != "embed";
        let expected = (key.mode == "whitelist" && member_checked).then_some(true);
        assert_eq!(
            key.in_shipped_whitelist,
            expected,
            "{}: whitelist membership (every whitelist-mode convert, combine, deferred and compress \
             key is a member of the shipped whitelist, and no other key records it); {REGENERATE}",
            key.label()
        );
    }
    let riscv: Vec<u32> = manifest
        .keys_of("riscv")
        .into_iter()
        .find(|k| k.mode == "whitelist")
        .unwrap_or_else(|| panic!("the manifest has no whitelist-mode riscv key; {REGENERATE}"))
        .vk_pre_hash
        .iter()
        .map(|limb| limb.as_u64().expect("a riscv pre-hash limb") as u32)
        .collect();
    assert_eq!(
        riscv, manifest.apex.riscv_vk_pre_hash,
        "the apex's riscv pre-hash is not the whitelist-mode riscv key's; {REGENERATE}"
    );
    let setup: GnarkSetupManifest =
        serde_json::from_str(include_str!("../../contracts/test/dev/manifest.json"))
            .expect("contracts/test/dev/manifest.json parses");
    let onchain = &manifest.onchain_test_keys;
    assert_eq!(
        (
            &onchain.circuit_sha256,
            onchain.nb_constraints,
            &onchain.gnark
        ),
        (&setup.circuit_sha256, setup.nb_constraints, &setup.gnark),
        "the manifest records other on-chain test keys than contracts/test/dev; {REGENERATE}"
    );
    let setup_root = setup.vk_root.unwrap_or_else(|| {
        panic!(
            "contracts/test/dev/manifest.json has no vk_root: its keys were set up over unpinned \
             constraints, or predate the field; rerun the setup per contracts/README.md, then \
             for the soundness manifest {REGENERATE}"
        )
    });
    assert_eq!(
        onchain.vk_root, setup_root,
        "the manifest records another whitelist root than contracts/test/dev was set up under; \
         {REGENERATE}"
    );
}

/// The challenge field is `KoalaBear^5`: `5 · log2(2^31 - 2^24 + 1)` bits.
#[test]
fn koalabear_field_constants() {
    use pico_mle_core::config::{base_field_order, challenge_field_bits};
    assert_eq!(base_field_order(), 2130706433.0);
    assert!((challenge_field_bits() - 154.9434).abs() < 1e-3);
}

// ---------------------------------------------------------------------------------------------
// The tail after the combine root: combine -> compress (the final proof, under the inner config)
// -> embed -> wrap -> Groth16, the EVM path. Compress re-proves the combine root and embed
// the compress proof, both with the recursion chip set, so `RECURSION_ASSUMED` bounds them too —
// for them that is the looser bound (their doc comments assume 21 AIRs, not 50), and scoring
// against the looser one can only understate the margin.
// ---------------------------------------------------------------------------------------------

#[test]
fn compress_preset_meets_128_bits_at_assumed_bounds() {
    let params = compress_params_with_128_bits_security();
    let label = "compress at assumed bounds";
    assert_target(label, &score(label, &params, &RECURSION_ASSUMED));
}

/// The compress and embed presets carry the same values. They are separate presets because they
/// are tuned for different costs (proof size; the Groth16 circuit's cost per query); embed verifies
/// the compress proof, and keeping its values equal is a choice (the wrap circuit over them is
/// 7,243,820 R1CS, 13.6% under 2^23). A retune for the wrap circuit moves
/// the embed key, and with it the wrap circuit, its Groth16 setup and the soundness manifest, but
/// not the whitelist; then this test goes.
#[test]
fn compress_and_embed_params_agree_today() {
    assert_eq!(
        compress_params_with_128_bits_security(),
        embed_params_with_128_bits_security()
    );
}

#[test]
fn embed_preset_meets_128_bits_at_assumed_bounds() {
    let params = embed_params_with_128_bits_security();
    let label = "embed at assumed bounds";
    assert_target(label, &score(label, &params, &RECURSION_ASSUMED));
}

/// Embed proves over the whole two-adic subgroup, so `l_skip + n_stack + log_blowup` must land
/// exactly on KoalaBear's two-adicity — one too many and the RS domain does not exist.
#[test]
fn embed_preset_uses_the_full_two_adic_domain() {
    use p3_field::TwoAdicField;
    use p3_koala_bear::KoalaBear;

    let params = embed_params_with_128_bits_security();
    assert_eq!(
        params.l_skip + params.n_stack + params.log_blowup,
        KoalaBear::TWO_ADICITY,
    );
}

// ---------------------------------------------------------------------------------------------
// Every component pinned at the assumed bounds, not only the minimum: a calculator change that
// moves a term the total does not bind on fails here instead of passing silently. Values to the
// hundredth, as `score` prints them; the compress and embed presets are the ones that differ under
// `soundness-bchks25-optimized`. The measured shapes are pinned by the manifest, `check_key`.
// ---------------------------------------------------------------------------------------------

/// The two LogUp-GKR terms depend on the challenge field alone: `|F| - log2(4)` and `|F| - log2(2)`.
const GKR_SUMCHECK: f64 = 152.94;
const GKR_BATCHING: f64 = 153.94;

struct Pinned {
    logup: f64,
    zerocheck: f64,
    constraint_batching: f64,
    stacked_reduction: f64,
    total: f64,
    /// WHIR sub-terms: query, proximity gaps, folding sumcheck, fold, OOD, γ batching, shift, μ.
    whir: [f64; 8],
}

fn assert_pinned(label: &str, s: &SoundnessCalculator, pinned: &Pinned) {
    let w = &s.whir_details;
    let whir_min = pinned.whir.iter().copied().fold(f64::INFINITY, f64::min);
    let actual_and_pinned = [
        ("LogUp", s.logup_bits, pinned.logup),
        ("GKR sumcheck", s.gkr_sumcheck_bits, GKR_SUMCHECK),
        ("GKR batching", s.gkr_batching_bits, GKR_BATCHING),
        ("ZeroCheck", s.zerocheck_sumcheck_bits, pinned.zerocheck),
        (
            "constraint batching",
            s.constraint_batching_bits,
            pinned.constraint_batching,
        ),
        (
            "stacked reduction",
            s.stacked_reduction_bits,
            pinned.stacked_reduction,
        ),
        ("WHIR", s.whir_bits, whir_min),
        ("WHIR query", w.query_bits, pinned.whir[0]),
        ("WHIR proximity gaps", w.proximity_gaps_bits, pinned.whir[1]),
        ("WHIR folding sumcheck", w.sumcheck_bits, pinned.whir[2]),
        ("WHIR fold", w.fold_rbr_bits, pinned.whir[3]),
        ("WHIR OOD", w.ood_rbr_bits, pinned.whir[4]),
        ("WHIR γ batching", w.gamma_batching_bits, pinned.whir[5]),
        ("WHIR shift", w.shift_rbr_bits, pinned.whir[6]),
        ("WHIR μ batching", w.mu_batching_bits, pinned.whir[7]),
        ("total", s.total_bits, pinned.total),
    ];
    for (component, actual, expected) in actual_and_pinned {
        assert!(
            (actual - expected).abs() <= 0.01,
            "{label}: {component} is {actual:.4} bits, pinned at {expected:.2}"
        );
    }
}

const RISCV_WHIR: [f64; 8] = [
    128.32, 136.94, 158.36, 136.94, 136.94, 146.91, 128.32, 134.94,
];
const RECURSION_WHIR: [f64; 8] = [
    128.39, 136.94, 157.36, 136.94, 138.94, 147.61, 128.39, 133.94,
];

#[test]
fn riscv_components_are_pinned() {
    let params = riscv_params_with_128_bits_security(23);
    let label = "riscv(23) at assumed bounds";
    let pinned = Pinned {
        logup: 133.95,
        zerocheck: 149.04,
        constraint_batching: 142.65,
        stacked_reduction: 138.66,
        total: 128.32,
        whir: RISCV_WHIR,
    };
    assert_pinned(label, &score(label, &params, &RISCV_ASSUMED), &pinned);
}

#[test]
fn recursion_components_are_pinned() {
    let params = recursion_params_with_128_bits_security();
    let label = "recursion at assumed bounds";
    let pinned = Pinned {
        logup: 133.95,
        zerocheck: 148.71,
        constraint_batching: 144.93,
        stacked_reduction: 142.98,
        total: 128.39,
        whir: RECURSION_WHIR,
    };
    assert_pinned(label, &score(label, &params, &RECURSION_ASSUMED), &pinned);
}

/// The pins of the list-decoding (`m = 2`) presets, compress and embed. The optimized degree bound
/// shrinks the list size, which every term charging `log2(L_PCS)` gains; at 128 bits over
/// KoalaBear^5 WHIR's query term binds under both bounds.
fn list_decoding_pins() -> Pinned {
    if cfg!(feature = "soundness-bchks25-optimized") {
        Pinned {
            logup: 131.15,
            zerocheck: 145.91,
            constraint_batching: 142.13,
            stacked_reduction: 140.17,
            total: 128.05,
            whir: [
                128.05, 129.56, 163.36, 129.56, 131.02, 142.80, 128.05, 131.98,
            ],
        }
    } else {
        Pinned {
            logup: 130.63,
            zerocheck: 145.39,
            constraint_batching: 141.61,
            stacked_reduction: 139.66,
            total: 128.05,
            whir: [
                128.05, 128.92, 163.04, 128.92, 130.30, 142.48, 128.05, 130.94,
            ],
        }
    }
}

#[test]
fn compress_components_are_pinned() {
    let params = compress_params_with_128_bits_security();
    let label = "compress at assumed bounds";
    assert_pinned(
        label,
        &score(label, &params, &RECURSION_ASSUMED),
        &list_decoding_pins(),
    );
}

#[test]
fn embed_components_are_pinned() {
    let params = embed_params_with_128_bits_security();
    let label = "embed at assumed bounds";
    assert_pinned(
        label,
        &score(label, &params, &RECURSION_ASSUMED),
        &list_decoding_pins(),
    );
}

// ---------------------------------------------------------------------------------------------
// Negative fixtures: each must fail, and for the reason its name gives.
// ---------------------------------------------------------------------------------------------

/// One query fewer in the recursion preset's first WHIR round drops the query term below the target.
#[test]
#[should_panic(expected = "recursion, one query fewer in round 0: 127.81 bits < 128")]
fn a_budget_weakened_below_128_bits_fails_the_target() {
    let mut params = recursion_params_with_128_bits_security();
    params.whir.rounds[0].num_queries -= 1;
    let label = "recursion, one query fewer in round 0";
    assert_target(label, &score(label, &params, &RECURSION_ASSUMED));
}

/// riscv at height 24 encodes onto `2^25` points, past KoalaBear's two-adicity; the preset refuses it
/// before anything is scored or built.
#[test]
#[should_panic(
    expected = "RS domain 2^25 (log_stacked_height 24 + log_blowup 1) has no subgroup in a field of \
                two-adicity 24"
)]
fn an_rs_domain_past_the_two_adicity_is_refused() {
    riscv_params_with_128_bits_security(24);
}
