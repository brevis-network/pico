//! Provable security of the wired production presets over KoalaBear / KoalaBear^4.
//!
//! The riscv machine proves with `riscv_params_with_100_bits_security(h)`, `h` = 23 by default and
//! any height the preset admits on request; the convert, combine and deferred machines, and the
//! CPU-side root verification, prove with `recursion_params_with_100_bits_security()`; embed with
//! `embed_params_with_100_bits_security()`. Each preset is scored at two circuit shapes: the bounds
//! its doc comment assumes, and the shape of every key in `soundness_manifest.json`, which
//! `vm/examples/mle_soundness_manifest.rs` writes from a real keygen of the production machines.
//! Run with `--nocapture` to see the per-component breakdown.

use std::collections::BTreeMap;

use pico_mle_core::{
    config::{
        compress_params_with_100_bits_security, embed_params_with_100_bits_security,
        koala_bear_poseidon2::KoalaBearPoseidon2Config,
        recursion_params_with_100_bits_security, riscv_params_with_100_bits_security,
        soundness::{SoundnessCalculator, VkShape, DEGREE_BOUND, PRODUCTION_SECURITY_BITS},
        try_riscv_params_with_100_bits_security, MAX_RISCV_LOG_STACKED_HEIGHT,
    },
    SystemParams,
};
use serde::Deserialize;

/// Every stacked height the riscv preset admits: production keygen refuses a key below the budget
/// at any of them, and `MLE_LOG_STACKED_HEIGHT` or the SDK can pick any of them. 23, the top, is
/// the default operating point.
fn riscv_log_stacked_heights() -> Vec<usize> {
    (0..=MAX_RISCV_LOG_STACKED_HEIGHT)
        .filter(|&h| try_riscv_params_with_100_bits_security(h).is_ok())
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
// keys of a fib-10 run through the combine root and embed, the ones `test_mle_e2e` keygens, and
// the whitelisted keys (the riscv key, one convert key per ladder row, every standard combine
// node, the deferred node).
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
    /// Recorded on the whitelist set's recursion keys only.
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
fn riscv_preset_meets_100_bits_at_assumed_bounds() {
    let heights = riscv_log_stacked_heights();
    assert_eq!(
        (heights.first(), heights.last()),
        (Some(&11), Some(&MAX_RISCV_LOG_STACKED_HEIGHT)),
        "the admitted riscv heights moved: {heights:?}"
    );
    for h in heights {
        let params = riscv_params_with_100_bits_security(h);
        let label = format!("riscv({h}) at assumed bounds");
        assert_target(&label, &score(&label, &params, &RISCV_ASSUMED));
    }
}

#[test]
fn recursion_preset_meets_100_bits_at_assumed_bounds() {
    let params = recursion_params_with_100_bits_security();
    let label = "recursion at assumed bounds";
    assert_target(label, &score(label, &params, &RECURSION_ASSUMED));
}

/// Each riscv key is held to the manifest at the height it was keygen'd at, then its shape, which
/// does not move with the height, is scored at every other admitted height.
#[test]
fn riscv_machine_meets_100_bits_at_measured_shape() {
    let manifest = manifest();
    for key in manifest.keys_of("riscv") {
        let keyed_at = key.shape.log_stacked_height;
        let params = riscv_params_with_100_bits_security(keyed_at);
        Manifest::check_key(key, &params, &score(&key.label(), &params, &key.shape));
        for h in riscv_log_stacked_heights() {
            let label = format!("{} at h = {h}", key.label());
            let s = score(&label, &riscv_params_with_100_bits_security(h), &key.shape);
            assert_target(&label, &s);
        }
    }
}

#[test]
fn recursion_machines_meet_100_bits_at_measured_shape() {
    let manifest = manifest();
    let params = recursion_params_with_100_bits_security();
    for machine in RECURSION_MACHINES {
        for key in manifest.keys_of(machine) {
            let s = score(&key.label(), &params, &key.shape);
            Manifest::check_key(key, &params, &s);
            assert_target(&key.label(), &s);
        }
    }
}

#[test]
fn embed_machine_meets_100_bits_at_measured_shape() {
    let manifest = manifest();
    let params = embed_params_with_100_bits_security();
    for key in manifest.keys_of("embed") {
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
            m if RECURSION_MACHINES.contains(&m) || m == "embed" => &RECURSION_ASSUMED,
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
    for key in &manifest.keys {
        let recursion = key.machine != "riscv" && key.machine != "embed";
        let expected = (key.mode == "whitelist" && recursion).then_some(true);
        assert_eq!(
            key.in_shipped_whitelist,
            expected,
            "{}: whitelist membership (every whitelist-mode recursion key is a member of the \
             shipped whitelist, and no other key records it); {REGENERATE}",
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

/// The challenge field is `KoalaBear^4`: `4 · log2(2^31 - 2^24 + 1)` bits.
#[test]
fn koalabear_field_constants() {
    use pico_mle_core::config::{base_field_order, challenge_field_bits};
    assert_eq!(base_field_order(), 2130706433.0);
    assert!((challenge_field_bits() - 123.9547).abs() < 1e-3);
}

// ---------------------------------------------------------------------------------------------
// The EVM path's stages: combine -> embed -> wrap -> Groth16. They register the same recursion
// chip set as convert and combine, so `RECURSION_ASSUMED` bounds them too — for embed that is the
// looser bound (its doc comment assumes 21 AIRs, not 50), and scoring against the looser one can
// only understate the margin.
// ---------------------------------------------------------------------------------------------

/// Heights compress is scored at: the one it is wired at, and the largest one it could be given.
/// With `log_blowup = 2` the RS domain is `2^(h+2)` against KoalaBear's two-adicity of 24, so 22 is
/// the last height whose domain exists; the constructor refuses 23.
const COMPRESS_LOG_STACKED_HEIGHTS: [usize; 2] = [20, 22];

#[test]
fn compress_preset_meets_100_bits_at_assumed_bounds() {
    for h in COMPRESS_LOG_STACKED_HEIGHTS {
        let params = compress_params_with_100_bits_security(h);
        let label = format!("compress({h}) at assumed bounds");
        assert_target(&label, &score(&label, &params, &RECURSION_ASSUMED));
    }
}

#[test]
fn embed_preset_meets_100_bits_at_assumed_bounds() {
    let params = embed_params_with_100_bits_security();
    let label = "embed at assumed bounds";
    assert_target(label, &score(label, &params, &RECURSION_ASSUMED));
}

/// Embed proves over the whole two-adic subgroup, so `l_skip + n_stack + log_blowup` must land
/// exactly on KoalaBear's two-adicity — one too many and the RS domain does not exist.
#[test]
fn embed_preset_uses_the_full_two_adic_domain() {
    use p3_field::TwoAdicField;
    use p3_koala_bear::KoalaBear;

    let params = embed_params_with_100_bits_security();
    assert_eq!(
        params.l_skip + params.n_stack + params.log_blowup,
        KoalaBear::TWO_ADICITY,
    );
}

// ---------------------------------------------------------------------------------------------
// Every component pinned at the assumed bounds, not only the minimum: a calculator change that
// moves a term the total does not bind on fails here instead of passing silently. Values to the
// hundredth, as `score` prints them; the embed preset is the one that differs under
// `soundness-bchks25-optimized`. The measured shapes are pinned by the manifest, `check_key`.
// ---------------------------------------------------------------------------------------------

/// The two LogUp-GKR terms depend on the challenge field alone: `|F| - log2(4)` and `|F| - log2(2)`.
const GKR_SUMCHECK: f64 = 121.95;
const GKR_BATCHING: f64 = 122.95;

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
    100.09, 105.95, 127.37, 105.95, 105.95, 116.35, 100.09, 103.96,
];
const RECURSION_WHIR: [f64; 8] = [
    100.01, 105.95, 126.37, 105.95, 107.95, 117.06, 100.01, 102.96,
];

#[test]
fn riscv_components_are_pinned() {
    let params = riscv_params_with_100_bits_security(23);
    let label = "riscv(23) at assumed bounds";
    let pinned = Pinned {
        logup: 102.97,
        zerocheck: 118.05,
        constraint_batching: 111.66,
        stacked_reduction: 107.67,
        total: 100.09,
        whir: RISCV_WHIR,
    };
    assert_pinned(label, &score(label, &params, &RISCV_ASSUMED), &pinned);
}

#[test]
fn recursion_components_are_pinned() {
    let params = recursion_params_with_100_bits_security();
    let label = "recursion at assumed bounds";
    let pinned = Pinned {
        logup: 102.97,
        zerocheck: 117.73,
        constraint_batching: 113.94,
        stacked_reduction: 111.99,
        total: 100.01,
        whir: RECURSION_WHIR,
    };
    assert_pinned(label, &score(label, &params, &RECURSION_ASSUMED), &pinned);
}

#[test]
fn compress_components_are_pinned() {
    for (h, constraint_batching, whir) in [
        (
            20,
            113.95,
            [
                100.01, 107.95, 127.37, 107.95, 108.95, 117.06, 100.01, 105.96,
            ],
        ),
        (
            22,
            113.94,
            [
                100.01, 105.95, 127.37, 105.95, 106.95, 117.06, 100.01, 103.96,
            ],
        ),
    ] {
        let params = compress_params_with_100_bits_security(h);
        let label = format!("compress({h}) at assumed bounds");
        let pinned = Pinned {
            logup: 102.97,
            zerocheck: 117.73,
            constraint_batching,
            stacked_reduction: 111.99,
            total: 100.01,
            whir,
        };
        assert_pinned(&label, &score(&label, &params, &RECURSION_ASSUMED), &pinned);
    }
}

/// The optimized degree bound shrinks the list size, which every term charging `log2(L_PCS)` gains;
/// LogUp then clears WHIR's query term, which binds instead.
#[test]
fn embed_components_are_pinned() {
    let params = embed_params_with_100_bits_security();
    let label = "embed at assumed bounds";
    let pinned = if cfg!(feature = "soundness-bchks25-optimized") {
        Pinned {
            logup: 101.38,
            zerocheck: 116.14,
            constraint_batching: 112.36,
            stacked_reduction: 110.40,
            total: 100.66,
            whir: [
                100.66, 102.79, 133.37, 102.79, 102.04, 113.14, 100.66, 105.73,
            ],
        }
    } else {
        Pinned {
            logup: 100.38,
            zerocheck: 115.14,
            constraint_batching: 111.36,
            stacked_reduction: 109.40,
            total: 100.38,
            whir: [
                100.66, 101.61, 132.78, 101.61, 100.78, 112.55, 100.66, 103.62,
            ],
        }
    };
    assert_pinned(label, &score(label, &params, &RECURSION_ASSUMED), &pinned);
}

// ---------------------------------------------------------------------------------------------
// Negative fixtures: each must fail, and for the reason its name gives.
// ---------------------------------------------------------------------------------------------

/// One query fewer in the recursion preset's first WHIR round drops the query term below the target.
#[test]
#[should_panic(expected = "recursion, one query fewer in round 0: 99.33 bits < 100")]
fn a_budget_weakened_below_100_bits_fails_the_target() {
    let mut params = recursion_params_with_100_bits_security();
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
    riscv_params_with_100_bits_security(24);
}
