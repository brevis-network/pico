//! Soundness manifest: keygen the production machines and write, per verifying key, what the
//! soundness calculator reads off it -- the `VkShape` and the params -- with the key's identity and
//! every calculator component, to `mle-core/tests/soundness_manifest.json`, the file
//! `mle-core/tests/soundness.rs` scores. The identity is the pre-hash, plus the merged preprocessed
//! commitment on a recursion key (every combine-tier node shares one pre-hash). The manifest also
//! records the commit it was generated at and the command that generated it.
//!
//! Two key sets, one per whitelist mode:
//!
//!   dev        whitelist off: natural heights, the way `test_mle_e2e` runs by default. The riscv
//!              key, the convert key of each riscv record, the combine root, a deferred node over
//!              that root and the embed key over it. Outside the whitelist a recursion key is keyed
//!              to the heights of the proof it verifies, so fib-10 is proved through the combine
//!              root -- its two records make a one-node tree -- and the deferred node and embed are
//!              keygen'd over the root, from its proof's layout, not proved.
//!   whitelist  bucketed shapes, the keys a whitelisted deployment proves with. The riscv key, one
//!              convert key per convert ladder row (the first whitelist shape that pads to it; the
//!              whitelist holds one per riscv shape, too many to keygen here), every standard
//!              combine node over the child kinds C0..C2 and B, and the deferred node. Nothing is
//!              proved: under the whitelist a key is a function of its shape. Each of its
//!              recursion keys records whether the shipped whitelist holds it.
//!
//! Embed is generated in the dev set only: its key follows the layout of the root proof it wraps,
//! and the whitelist set proves no root. Its key is BN254-hashed, so its pre-hash is written as
//! decimal strings.
//!
//! The header records the identities an apex verifier is built from in whitelist mode: the
//! shipped whitelist's root (`MLE_VK_ROOT`) and the whitelist-mode riscv key's pre-hash. The
//! shipped whitelist must load, since membership is recorded against it.
//!
//! It also records the on-chain test keys (`contracts/test/dev/manifest.json`): the wrap circuit's
//! hash, its constraint count, gnark's version and the whitelist root the setup pinned into the
//! circuit, all copied from that file. A wrap circuit can only be built from a proof, so the root
//! is not re-derived here, and a setup record without one -- keys set up over unpinned constraints,
//! or older than the field -- is refused. Replace the keys with `contracts/README.md`'s commands,
//! then regenerate this manifest.
//!
//! The manifest is written by the default calculator, the one CI compares every component
//! against; a build with `soundness-bchks25-optimized` refuses to write it.
//!
//! A riscv key is a function of the program and the stacked height, and a dev-mode recursion key of
//! the records, so the environment that moves either is refused rather than recorded.
//!
//! Usage (from the workspace root, a few minutes on a laptop):
//!   cargo run --release -p pico-vm --example mle_soundness_manifest
//!
//! Environment:
//!   MLE_SOUNDNESS_MANIFEST_OUT  output path, default mle-core/tests/soundness_manifest.json

use std::{process::Command, sync::Arc, time::Instant};

use p3_field::PrimeField32;
use pico_mle_core::{
    config::{
        embed_params_with_100_bits_security, recursion_params_with_100_bits_security,
        soundness::{SoundnessCalculator, VkShape, DEGREE_BOUND},
        StarkProtocolConfig,
    },
    keygen::types::MultiStarkVerifyingKey,
    StarkEngine, SystemParams,
};
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{opts::EmulatorOpts, stdin::EmulatorStdin},
    machine::logger::setup_logger,
    mle::{
        compiler::recursion::{ConvertProgramInput, ConvertVerifierCircuit},
        machine::{
            combine::CombineMachine,
            convert::ConvertMachine,
            deferred::DeferredMachine,
            embed::EmbedMachine,
            exe::RiscvVmVk,
            recursion::{
                extract_recursion_vk_layout, recursion_natural_rows, select_convert_row, Engine,
            },
            riscv::{self, Sc},
            shape::{mle_riscv_shapes, MLE_RECURSION_CONVERT_LADDER},
            vk_map::{
                synthesized_convert_layout, vk_identity, whitelist_convert_vk, whitelist_riscv_vk,
                MleVkMap,
            },
        },
    },
};
use tracing::info;

const COMMAND: &str = "cargo run --release -p pico-vm --example mle_soundness_manifest";
const DEFAULT_OUT: &str = "mle-core/tests/soundness_manifest.json";
const FIB_ELF: &str = "perf/bench_data/rv64/fib-elf";
const FIB_N: u32 = 10;
const SHIPPED_WHITELIST: &str = "vm/src/mle/shape_vk_bins/mle_vk_map_kb.bin";
const EMBED_REASON: &str = "the embed key follows the layout of the root proof it wraps, and \
                            the whitelist set proves no root; the dev set's embed key has the \
                            same params and shape";
const ONCHAIN_TEST_KEYS: &str = "contracts/test/dev/manifest.json";
const ONCHAIN_NOTE: &str = "test keys from a single-process Groth16 setup (contracts/README.md); \
                            a deployment needs a setup ceremony";

/// JSON text, written field by field rather than through `serde_json::Value`: without serde_json's
/// `preserve_order` its map sorts the keys, which would scatter a row's components.
fn j(v: impl serde::Serialize) -> String {
    serde_json::to_string(&v).expect("serializable")
}

/// A JSON array spaced as the `keygen soundness` log line prints one, so the two compare by eye.
fn list<T: serde::Serialize>(xs: &[T]) -> String {
    format!("[{}]", xs.iter().map(j).collect::<Vec<_>>().join(", "))
}

/// A JSON object with its fields in the given order; the values are JSON text already.
fn object(fields: &[(&str, String)]) -> String {
    let body: Vec<String> = fields
        .iter()
        .map(|(k, v)| format!("{}: {v}", j(k)))
        .collect();
    format!("{{{}}}", body.join(", "))
}

/// One manifest row: `(field, JSON text)` in the order they are written.
type Row = Vec<(&'static str, String)>;

fn row(
    machine: &str,
    mode: &str,
    role: String,
    vk: &MultiStarkVerifyingKey<Sc>,
    whitelist: Option<&MleVkMap>,
) -> Row {
    let pre_hash = vk.pre_hash.map(|f| f.as_canonical_u32());
    // A recursion key's whitelist identity is the pair: every combine-tier node shares a pre-hash.
    let merged_commit = vk
        .inner
        .merged_preprocessed_commit
        .map(|c| c.map(|f| f.as_canonical_u32()));
    let mut identity = vec![("vk_pre_hash", list(&pre_hash))];
    if let Some(commit) = merged_commit {
        identity.push(("merged_preprocessed_commit", list(&commit)));
    }
    let mut out = scored_row(machine, mode, role, vk, identity);
    if let Some(map) = whitelist {
        out.push((
            "in_shipped_whitelist",
            j(map.find(&vk_identity(vk)).is_some()),
        ));
    }
    out
}

/// A row's naming fields, then `identity`, then what the calculator reads off `vk` and its score.
fn scored_row<SC: StarkProtocolConfig>(
    machine: &str,
    mode: &str,
    role: String,
    vk: &MultiStarkVerifyingKey<SC>,
    identity: Vec<(&'static str, String)>,
) -> Row {
    let shape = VkShape::from_vk(vk);
    let s = SoundnessCalculator::calculate_from_vk(vk);
    let p: &SystemParams = &vk.inner.params;
    let bits = s.components();
    let whir = s.whir_details.components();
    // JSON has no infinity: serde_json would write `null`, which the test cannot read back as bits.
    for (name, v) in bits.iter().chain(whir.iter()) {
        assert!(v.is_finite(), "{machine} ({role}): {name} = {v}");
    }
    info!(
        "manifest: {machine:<8} {mode:<9} {role}: {shape:?} vk_pre_hash={:?} bits={:.2}",
        vk.pre_hash, s.total_bits
    );
    let mut out: Row = vec![
        ("machine", j(machine)),
        ("mode", j(mode)),
        ("role", j(&role)),
    ];
    out.extend(identity);
    out.extend([
        (
            "shape",
            object(&[
                ("num_airs", j(shape.num_airs)),
                ("max_constraints_per_air", j(shape.max_constraints_per_air)),
                (
                    "max_interactions_per_air",
                    j(shape.max_interactions_per_air),
                ),
                ("num_trace_columns", j(shape.num_trace_columns)),
                ("log_stacked_height", j(shape.log_stacked_height)),
            ]),
        ),
        ("params", j(p)),
        ("soundness", object(&bits.map(|(name, v)| (name, j(v))))),
        ("whir_details", object(&whir.map(|(name, v)| (name, j(v))))),
    ]);
    out
}

/// The header fields, then each row with one field per line, so a moved key is a small diff.
fn render(header: &[(&str, String)], rows: &[Row]) -> String {
    let mut out = String::from("{\n");
    for (k, v) in header {
        out += &format!("  {}: {v},\n", j(k));
    }
    out += "  \"keys\": [\n";
    for (i, r) in rows.iter().enumerate() {
        let fields: Vec<String> = r
            .iter()
            .map(|(k, v)| format!("      {}: {v}", j(k)))
            .collect();
        let sep = if i + 1 == rows.len() { "" } else { "," };
        out += &format!("    {{\n{}\n    }}{sep}\n", fields.join(",\n"));
    }
    out += "  ]\n}\n";
    out
}

fn git(args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("git {args:?}: {e}"));
    assert!(out.status.success(), "git {args:?} failed");
    String::from_utf8(out.stdout).expect("git output is UTF-8")
}

fn main() {
    setup_logger();
    let t0 = Instant::now();
    assert_eq!(
        DEGREE_BOUND, "closed-form",
        "built with soundness-bchks25-optimized: the manifest is written by the default \
         calculator, the one CI compares every component against"
    );
    for var in ["MLE_LOG_STACKED_HEIGHT", "CHUNK_SIZE", "SPLIT_THRESHOLD"] {
        assert!(
            std::env::var(var).is_err(),
            "{var} is set: it moves the keys, and the manifest is keyed to the defaults the prover \
             ships with"
        );
    }
    let out_path =
        std::env::var("MLE_SOUNDNESS_MANIFEST_OUT").unwrap_or_else(|_| DEFAULT_OUT.to_string());
    let commit = git(&["rev-parse", "HEAD"]).trim().to_string();
    // Tracked changes only, the manifest itself excluded: those are what could move a key.
    let dirty_paths: Vec<String> = git(&["status", "--porcelain", "--untracked-files=no"])
        .lines()
        .map(|l| l[3..].to_string())
        .filter(|p| *p != out_path)
        .collect();

    // Read before keygen, so a bad record costs seconds, not the whole run.
    let onchain: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(ONCHAIN_TEST_KEYS)
            .unwrap_or_else(|e| panic!("cannot read `{ONCHAIN_TEST_KEYS}`: {e}")),
    )
    .unwrap_or_else(|e| panic!("`{ONCHAIN_TEST_KEYS}` does not parse: {e}"));
    let field = |k: &str| {
        onchain
            .get(k)
            .filter(|v| v.is_string() || v.is_u64())
            .unwrap_or_else(|| panic!("`{ONCHAIN_TEST_KEYS}` has no `{k}`"))
            .clone()
    };
    let (circuit, nb_constraints, gnark) = (
        field("circuit_sha256"),
        field("nb_constraints"),
        field("gnark"),
    );
    let setup_root: [u32; 8] = serde_json::from_value(
        onchain
            .get("vk_root")
            .unwrap_or_else(|| {
                panic!(
                    "`{ONCHAIN_TEST_KEYS}` has no `vk_root`: its keys were set up over unpinned \
                     constraints, or predate the field; rerun the setup per contracts/README.md"
                )
            })
            .clone(),
    )
    .unwrap_or_else(|e| panic!("`{ONCHAIN_TEST_KEYS}`: `vk_root` is not 8 limbs: {e}"));

    let elf = std::fs::read(FIB_ELF).unwrap_or_else(|e| panic!("cannot read `{FIB_ELF}`: {e}"));
    let program = Compiler::new(SourceType::RISCV, &elf)
        .expect("parse fib")
        .compile();
    let h = riscv::DEFAULT_LOG_STACKED_HEIGHT;
    let mut rows: Vec<Row> = Vec::new();

    // Dev set: fib-10 proved through the combine root.
    let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    stdin.write(&FIB_N);
    let stdin = stdin.finalize();
    // `test_mle_e2e`'s emulator options, so its records -- and with them the convert keys -- match.
    let records = riscv::emulate_with_opts(
        program.clone(),
        &stdin,
        EmulatorOpts::from_env_chunk_size(1 << 23),
    )
    .expect("emulation failed")
    .records;
    let (riscv_vk, riscv_proofs) = riscv::prove_riscv(program.clone(), &records, h, false)
        .expect("riscv prove")
        .into_parts();
    rows.push(row("riscv", "dev", format!("fib-{FIB_N}"), &riscv_vk, None));

    let vm_vk = RiscvVmVk::from_program_and_vk(&program, &riscv_vk);
    let convert = ConvertMachine::new(
        riscv_vk.clone(),
        vm_vk.clone(),
        &riscv_proofs,
        recursion_params_with_100_bits_security(),
        false,
    )
    .expect("convert machine");
    let children = convert
        .prove_with_vks(&riscv_proofs)
        .expect("convert prove");
    // One row per distinct key, in the order of the first record it verifies.
    let mut convert_keys: Vec<(Arc<MultiStarkVerifyingKey<Sc>>, Vec<usize>)> = Vec::new();
    for (i, (_, vk)) in children.iter().enumerate() {
        match convert_keys
            .iter_mut()
            .find(|(k, _)| vk_identity(k) == vk_identity(vk))
        {
            Some((_, records)) => records.push(i),
            None => convert_keys.push((vk.clone(), vec![i])),
        }
    }
    for (vk, records) in &convert_keys {
        rows.push(row(
            "convert",
            "dev",
            format!("riscv records {records:?}"),
            vk,
            None,
        ));
    }

    let n_children = children.len();
    let mut combine = CombineMachine::new(
        recursion_params_with_100_bits_security(),
        vm_vk.clone(),
        false,
    );
    let root = combine.prove_tree(children).expect("combine prove");
    assert_eq!(
        combine.num_distinct_shapes(),
        1,
        "the dev tree keyed more than its root; give the other nodes rows"
    );
    rows.push(row(
        "combine",
        "dev",
        format!("root over {n_children} convert children"),
        &root.1,
        None,
    ));

    let root_layout = extract_recursion_vk_layout(&root.1, Some(&root.0));
    let mut embed = EmbedMachine::new(embed_params_with_100_bits_security(), vm_vk.clone(), false);
    let embed_vk = embed
        .preregister(&root_layout)
        .unwrap_or_else(|e| panic!("{e}"));
    let embed_pre_hash: Vec<String> = embed_vk.pre_hash.iter().map(|x| x.to_string()).collect();
    let embed_commit: Option<Vec<String>> = embed_vk
        .inner
        .merged_preprocessed_commit
        .map(|c| c.iter().map(|x| x.to_string()).collect());
    let mut embed_identity = vec![("vk_pre_hash", list(&embed_pre_hash))];
    if let Some(commit) = embed_commit {
        embed_identity.push(("merged_preprocessed_commit", list(&commit)));
    }
    rows.push(scored_row(
        "embed",
        "dev",
        "over the combine root".to_string(),
        &embed_vk,
        embed_identity,
    ));

    let mut deferred =
        DeferredMachine::new(recursion_params_with_100_bits_security(), vm_vk, false);
    let deferred_vk = deferred
        .preregister(&root_layout)
        .unwrap_or_else(|e| panic!("{e}"));
    rows.push(row(
        "deferred",
        "dev",
        "node over the combine root".to_string(),
        &deferred_vk,
        None,
    ));
    info!("dev keys: {:.0} s", t0.elapsed().as_secs_f64());

    // Whitelist set: keygen only.
    let t1 = Instant::now();
    let shipped = MleVkMap::try_load_bin(SHIPPED_WHITELIST)
        .unwrap_or_else(|e| panic!("cannot load the shipped whitelist `{SHIPPED_WHITELIST}`: {e}"));
    let wl_riscv_vk = whitelist_riscv_vk(program.clone()).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(wl_riscv_vk.inner.params.log_stacked_height(), h);
    rows.push(row(
        "riscv",
        "whitelist",
        "bucketed program table".to_string(),
        &wl_riscv_vk,
        None,
    ));

    // A convert program's row follows from its natural heights, so the first shape of each row is
    // found by building programs, not keys. The core family leads the enumeration and reaches the
    // last row with its catch-all.
    let rows_n = MLE_RECURSION_CONVERT_LADDER.len();
    let mut first_on_row: Vec<Option<usize>> = vec![None; rows_n];
    let shapes = mle_riscv_shapes();
    for (i, (_, shape)) in shapes.iter().enumerate() {
        let program = ConvertVerifierCircuit::build_verify_program(&ConvertProgramInput {
            vk: synthesized_convert_layout(&wl_riscv_vk, shape),
            vk_verification: true,
        });
        first_on_row[select_convert_row(&recursion_natural_rows(&program))].get_or_insert(i);
        if first_on_row.iter().all(Option::is_some) {
            break;
        }
    }
    let engine: Engine = StarkEngine::new(recursion_params_with_100_bits_security());
    let mut convert_vk_row0 = None;
    for (r, first) in first_on_row.iter().enumerate() {
        let i = first.unwrap_or_else(|| panic!("no whitelist shape pads to convert row {r}"));
        let (label, shape) = &shapes[i];
        let vk = whitelist_convert_vk(&engine, &wl_riscv_vk, label, shape)
            .unwrap_or_else(|e| panic!("{e}"));
        rows.push(row(
            "convert",
            "whitelist",
            format!("ladder row {r} (C{r}), shape `{label}`"),
            &vk,
            Some(&shipped),
        ));
        convert_vk_row0.get_or_insert(vk);
    }
    let convert_vk_row0 = convert_vk_row0.expect("the convert ladder is empty");

    let wl_vm_vk = RiscvVmVk::from_program_and_vk(&program, &wl_riscv_vk);
    let mut combine = CombineMachine::new(
        recursion_params_with_100_bits_security(),
        wl_vm_vk.clone(),
        true,
    );
    let combine_vks = combine
        .preregister_standard_shapes(&convert_vk_row0)
        .unwrap_or_else(|e| panic!("{e}"));
    // `preregister_standard_shapes`' order, which the whitelist's leaf order also rests on: the
    // ordered pairs over the child kinds (ladder rows, then the combine tier) non-root and then
    // root, then the single-child roots.
    let kinds: Vec<String> = (0..rows_n)
        .map(|r| format!("C{r}"))
        .chain(["B".to_string()])
        .collect();
    let mut roles = Vec::new();
    for complete in [false, true] {
        let node = if complete { "root" } else { "non-root node" };
        for left in &kinds {
            for right in &kinds {
                roles.push(format!("{node} over [{left}, {right}]"));
            }
        }
    }
    roles.extend(kinds.iter().map(|k| format!("root over [{k}]")));
    assert_eq!(roles.len(), combine_vks.len());
    for (role, vk) in roles.into_iter().zip(&combine_vks) {
        rows.push(row("combine", "whitelist", role, vk, Some(&shipped)));
    }

    let mut deferred =
        DeferredMachine::new(recursion_params_with_100_bits_security(), wl_vm_vk, true);
    let combine_tier = combine
        .combine_tier_child_layout(&convert_vk_row0)
        .unwrap_or_else(|e| panic!("{e}"));
    let deferred_vk = deferred
        .preregister(&combine_tier)
        .unwrap_or_else(|e| panic!("{e}"));
    rows.push(row(
        "deferred",
        "whitelist",
        "node over a combine-tier (B) child".to_string(),
        &deferred_vk,
        Some(&shipped),
    ));
    info!("whitelist keys: {:.0} s", t1.elapsed().as_secs_f64());

    let header: Vec<(&str, String)> = vec![
        ("generated_by", j(COMMAND)),
        ("commit", j(&commit)),
        ("dirty", j(!dirty_paths.is_empty())),
        ("dirty_paths", list(&dirty_paths)),
        ("calculator", j(DEGREE_BOUND)),
        ("program", j(format!("{FIB_ELF}, n = {FIB_N}"))),
        ("shipped_whitelist", j(SHIPPED_WHITELIST)),
        (
            "apex",
            object(&[
                (
                    "vk_root",
                    list(&shipped.root().map(|f| f.as_canonical_u32())),
                ),
                (
                    "riscv_vk_pre_hash",
                    list(&wl_riscv_vk.pre_hash.map(|f| f.as_canonical_u32())),
                ),
            ]),
        ),
        (
            "onchain_test_keys",
            object(&[
                ("source", j(ONCHAIN_TEST_KEYS)),
                ("vk_root", list(&setup_root)),
                ("circuit_sha256", j(&circuit)),
                ("nb_constraints", j(&nb_constraints)),
                ("gnark", j(&gnark)),
                ("note", j(ONCHAIN_NOTE)),
            ]),
        ),
        (
            "not_generated",
            format!(
                "[{}]",
                object(&[
                    ("machine", j("embed")),
                    ("mode", j("whitelist")),
                    ("reason", j(EMBED_REASON))
                ])
            ),
        ),
    ];
    std::fs::write(&out_path, render(&header, &rows))
        .unwrap_or_else(|e| panic!("cannot write `{out_path}`: {e}"));
    info!(
        "manifest written: `{out_path}`, {} keys, {:.0} s",
        rows.len(),
        t0.elapsed().as_secs_f64()
    );
}
