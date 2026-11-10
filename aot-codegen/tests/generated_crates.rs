//! What `AotCompiler::compile_with` writes for a real guest: its ELF's SHA-256 and the codegen
//! stamp in the dispatch crate's `AOT`, the runtime dependency it was handed in every generated
//! manifest, and blocks that read the sink once and hand it to every helper. And that
//! `generate_crates`, through `compile`, takes that dependency from `PICO_AOT_RUNTIME_SPEC`. And
//! the generated code for fib and poseidon2 against a committed digest, and every block's
//! recording body with `AOT`'s recording entry point, which keeps no chunk-split tally.

use std::{fs, path::PathBuf, process::Command};

use pico_aot_codegen::{parse_elf, AotCompiler, AotConfig, RuntimeSpec, CODEGEN_STAMP};
use pico_vm::compiler::riscv::instruction::Instruction as VmInstruction;
use sha2::{Digest, Sha256};
use syn::visit::{self, Visit};

fn guest_elf_path(guest: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../perf/bench_data/rv64/{guest}-elf"))
}

fn fib_elf_path() -> PathBuf {
    guest_elf_path("fib")
}

fn guest_elf(guest: &str) -> Vec<u8> {
    let path = guest_elf_path(guest);
    fs::read(&path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

fn fib_elf() -> Vec<u8> {
    guest_elf("fib")
}

fn generate(elf: &[u8], runtime: &RuntimeSpec, name: &str) -> PathBuf {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    AotCompiler::new(parse_elf(elf), AotConfig::new(out.clone()))
        .compile_with(runtime)
        .expect("AOT crate generation failed");
    out
}

/// Each generated crate's source, by its path under `out`: the dispatch crate's, then the chunks'.
fn sources(out: &std::path::Path) -> Vec<(String, syn::File)> {
    let mut paths = vec![PathBuf::from("src/lib.rs")];
    let mut chunks: Vec<PathBuf> = fs::read_dir(out.join("chunks"))
        .expect("the chunks directory")
        .map(|chunk| {
            PathBuf::from("chunks")
                .join(chunk.expect("a chunk crate").file_name())
                .join("src/lib.rs")
        })
        .collect();
    chunks.sort();
    paths.extend(chunks);
    paths
        .into_iter()
        .map(|path| {
            let source = fs::read_to_string(out.join(&path))
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
            let file = syn::parse_file(&source)
                .unwrap_or_else(|e| panic!("{} does not parse: {e}", path.display()));
            (path.display().to_string(), file)
        })
        .collect()
}

fn item_name(item: &syn::Item) -> Option<String> {
    match item {
        syn::Item::Fn(item) => Some(item.sig.ident.to_string()),
        syn::Item::Const(item) => Some(item.ident.to_string()),
        syn::Item::Static(item) => Some(item.ident.to_string()),
        _ => None,
    }
}

/// The `AotProgram::stamped` call `pub static AOT` is built by, read back out of the generated
/// source, under the `with_recorder` that adds its recording entry point.
fn aot_call(lib_rs: &str) -> syn::ExprCall {
    let file = syn::parse_file(lib_rs).expect("the dispatch crate's source parses");
    let aot = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Static(item) if item.ident == "AOT" => Some(item),
            _ => None,
        })
        .expect("the dispatch crate exports `static AOT`");
    assert!(
        matches!(aot.vis, syn::Visibility::Public(_)),
        "`AOT` is pub"
    );

    let syn::Expr::MethodCall(recorder) = &*aot.expr else {
        panic!(
            "`AOT` does not add a recording entry point: {}",
            quote::quote!(#aot)
        );
    };
    assert_eq!(recorder.method, "with_recorder", "{}", quote::quote!(#aot));
    let syn::Expr::Call(call) = &*recorder.receiver else {
        panic!("`AOT` is not built by a call: {}", quote::quote!(#aot));
    };
    call.clone()
}

fn int_literal(expr: &syn::Expr) -> u32 {
    match expr {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Int(int),
            ..
        }) => int.base10_parse().expect("an integer"),
        other => panic!("not an integer literal: {}", quote::quote!(#other)),
    }
}

/// The byte array `pub static AOT` is built from, read back out of the generated source.
fn exported_digest(lib_rs: &str) -> [u8; 32] {
    let call = aot_call(lib_rs);
    let Some(syn::Expr::Array(digest)) = call.args.first() else {
        panic!(
            "`AOT`'s first argument is not an array: {}",
            quote::quote!(#call)
        );
    };
    let digest: Vec<u8> = digest
        .elems
        .iter()
        .map(|byte| match byte {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Int(byte),
                ..
            }) => byte.base10_parse().expect("a byte"),
            other => panic!("not a byte literal: {}", quote::quote!(#other)),
        })
        .collect();
    digest.try_into().expect("a 32-byte digest")
}

fn manifests(out: &std::path::Path) -> Vec<PathBuf> {
    let mut manifests = vec![out.join("Cargo.toml")];
    for chunk in fs::read_dir(out.join("chunks")).expect("the chunks directory") {
        manifests.push(chunk.expect("a chunk crate").path().join("Cargo.toml"));
    }
    manifests
}

#[test]
fn the_dispatch_crate_exports_the_elf_sha256() {
    let elf = fib_elf();
    let out = generate(&elf, &RuntimeSpec::InTree, "aot-codegen-elf-sha256");

    let lib_rs = fs::read_to_string(out.join("src/lib.rs")).expect("the dispatch crate's lib.rs");
    let expected: [u8; 32] = Sha256::digest(&elf).into();
    assert_eq!(exported_digest(&lib_rs), expected);
}

#[test]
fn the_dispatch_crate_exports_the_codegen_stamp() {
    let out = generate(&fib_elf(), &RuntimeSpec::InTree, "aot-codegen-stamp");

    let lib_rs = fs::read_to_string(out.join("src/lib.rs")).expect("the dispatch crate's lib.rs");
    let call = aot_call(&lib_rs);
    let stamp = call.args.iter().nth(1).expect("`AOT`'s second argument");
    assert_eq!(int_literal(stamp), CODEGEN_STAMP);
}

/// How one generated block uses the sink: its reads into `emitting`, its helper calls, and every
/// call that does not take that flag but writes events.
#[derive(Default)]
struct SinkUse {
    reads: usize,
    helpers: usize,
    untold: Vec<String>,
}

impl<'ast> Visit<'ast> for SinkUse {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if matches!(&local.pat, syn::Pat::Ident(pat) if pat.ident == "emitting") {
            self.reads += 1;
        }
        visit::visit_local(self, local);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let name = call.method.to_string();
        let told = || {
            call.args
                .first()
                .is_some_and(|arg| quote::quote!(#arg).to_string() == "emitting")
        };
        if name.ends_with("_no_count") {
            self.helpers += 1;
            if !told() {
                self.untold.push(quote::quote!(#call).to_string());
            }
        } else if ["write_reg_no_count", "emit_cpu", "emit_alu"].contains(&name.as_str()) {
            self.untold.push(quote::quote!(#call).to_string());
        }
        visit::visit_expr_method_call(self, call);
    }
}

/// Every block reads the sink once, on entry, and hands that flag to every helper
/// it calls: a call that tested the sink itself would test it again after every emitting call
/// before it, and the compiler could no longer run the block's plain bodies back to back.
#[test]
fn every_block_hands_its_one_read_of_the_sink_to_every_helper() {
    let out = generate(&fib_elf(), &RuntimeSpec::InTree, "aot-codegen-sink-flag");
    let (mut blocks, mut helpers) = (0, 0);
    for chunk in fs::read_dir(out.join("chunks")).expect("the chunks directory") {
        let path = chunk.expect("a chunk crate").path().join("src/lib.rs");
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        let file = syn::parse_file(&source).expect("a chunk crate's source parses");
        for item in &file.items {
            let syn::Item::Fn(block) = item else {
                continue;
            };
            let name = block.sig.ident.to_string();
            if !name.starts_with("block_0x") {
                continue;
            }
            let mut uses = SinkUse::default();
            uses.visit_item_fn(block);
            assert_eq!(uses.reads, 1, "{name} reads the sink {} times", uses.reads);
            assert!(
                uses.untold.is_empty(),
                "{name} writes events without its flag: {:?}",
                uses.untold
            );
            blocks += 1;
            helpers += uses.helpers;
        }
    }
    assert!(
        blocks > 0 && helpers > blocks,
        "{blocks} blocks, {helpers} helper calls"
    );
}

#[test]
fn the_runtime_spec_lands_in_every_generated_manifest() {
    let entry = r#"git = "https://github.com/brevis-network/pico", tag = "v0.0.0-spec-test""#;
    let out = generate(
        &fib_elf(),
        &RuntimeSpec::Entry(entry.to_string()),
        "aot-codegen-runtime-spec",
    );

    let expected = format!("pico-aot-runtime = {{ {entry} }}");
    let manifests = manifests(&out);
    assert!(
        manifests.len() > 1,
        "the dispatch crate and at least one chunk"
    );
    for manifest in manifests {
        let toml = fs::read_to_string(&manifest).expect("a generated manifest");
        assert!(
            toml.lines().any(|line| line == expected),
            "{} does not depend on the runtime it was handed:\n{toml}",
            manifest.display()
        );
    }
}

/// `compile_with` takes the runtime only as a parameter, so a host generating in-process never sets
/// a variable its other threads may be reading; `compile`, behind the binary the scripts run,
/// reads `PICO_AOT_RUNTIME_SPEC`. A process of its own, so that this one never sets it.
#[test]
fn generate_crates_takes_the_runtime_spec_from_the_variable() {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("aot-codegen-spec-variable");
    let output = Command::new(env!("CARGO_BIN_EXE_generate_crates"))
        .arg(fib_elf_path())
        .arg(&out)
        .env("PICO_AOT_RUNTIME_SPEC", r#"path = "/from/the/variable""#)
        .output()
        .expect("run generate_crates");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for manifest in manifests(&out) {
        let toml = fs::read_to_string(&manifest).expect("a generated manifest");
        assert!(
            toml.lines()
                .any(|line| line == r#"pico-aot-runtime = { path = "/from/the/variable" }"#),
            "{} does not take the runtime from the variable:\n{toml}",
            manifest.display()
        );
    }
}

/// Every chunk crate also gets its `rec_lookup`; the recording entry point is what the AOT replay
/// workers run.
#[test]
fn every_block_has_its_recording_body_and_aot_its_recording_entry_point() {
    let generated = sources(&generate(
        &fib_elf(),
        &RuntimeSpec::InTree,
        "aot-codegen-recording-bodies",
    ));
    let (mut blocks, mut recording) = (0, 0);
    for (path, file) in &generated {
        let names: Vec<String> = file.items.iter().filter_map(item_name).collect();
        let has = |name: &str| names.iter().any(|item| item == name);
        if path == "src/lib.rs" {
            assert!(
                ["run_aot", "run_aot_record", "lookup_record_block"]
                    .iter()
                    .all(|name| has(name)),
                "{path}: {names:?}"
            );
            let aot = file
                .items
                .iter()
                .find_map(|item| match item {
                    syn::Item::Static(item) if item.ident == "AOT" => {
                        Some(quote::quote!(#item).to_string())
                    }
                    _ => None,
                })
                .expect("the dispatch crate exports `static AOT`");
            assert!(
                aot.contains("AotProgram :: stamped")
                    && aot.contains(" . with_recorder (run_aot_record) ;"),
                "{path}: {aot}"
            );
            continue;
        }
        assert!(has("rec_lookup"), "{path}: no rec_lookup");
        for name in &names {
            if let Some(pc) = name.strip_prefix("block_0x") {
                assert!(
                    has(&format!("rec_block_0x{pc}")),
                    "{path}: {name} has no recording body"
                );
                blocks += 1;
            }
            recording += usize::from(name.starts_with("rec_block_0x"));
        }
    }
    assert!(
        blocks > 0 && recording == blocks,
        "{blocks} blocks, {recording} recording bodies"
    );
}

/// The SHA-256 of every generated crate's files under `out`, by path: each path, a zero byte,
/// the file's length as eight little-endian bytes, then the file. Only manifests and sources:
/// the `metrics.json` that `PICO_AOT_SAVE_METRICS` adds is not code.
fn crates_digest(out: &std::path::Path) -> String {
    fn walk(dir: &std::path::Path, files: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).expect("a generated directory") {
            let path = entry.expect("a generated entry").path();
            if path.is_dir() {
                walk(&path, files);
            } else if path.file_name().is_some_and(|name| name == "Cargo.toml")
                || path.extension().is_some_and(|extension| extension == "rs")
            {
                files.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(out, &mut files);
    let mut files: Vec<(String, PathBuf)> = files
        .into_iter()
        .map(|path| {
            let relative = path.strip_prefix(out).expect("under the output directory");
            let name = relative
                .components()
                .map(|part| part.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            (name, path)
        })
        .collect();
    files.sort();
    let mut hasher = Sha256::new();
    for (name, path) in files {
        let bytes = fs::read(&path).unwrap_or_else(|e| panic!("failed to read {name}: {e}"));
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The generated code is the committed one byte for byte, so a change to it, the codegen stamp
/// included, moves the digest on purpose in the same commit. `perf/aot/codegen_diff.sh` shows what
/// moved against another revision.
#[test]
fn the_generated_code_is_the_committed_one() {
    const COMMITTED: [(&str, &str); 2] = [
        (
            "fib",
            "c405dc88f21108839a177ca31f7c5e2d262466c2425c45d6df5346c4c0fe5989",
        ),
        (
            "poseidon2",
            "be04caac9fd96c43cc6733d0f4d63c4c961d4d988ccb7fecc253e0f2327d8db0",
        ),
    ];
    for (guest, committed) in COMMITTED {
        let out = generate(
            &guest_elf(guest),
            &RuntimeSpec::InTree,
            &format!("aot-codegen-committed-{guest}"),
        );
        assert_eq!(
            crates_digest(&out),
            committed,
            "{guest}: generated code changed; update the digest only if intended"
        );
    }
}

/// What one recording body calls on the core. Anything but its recorder's writers, its entry test
/// and counts, the clock, the yield test and the hand-back would write through the core's sink,
/// empty while the recorder holds it, or keep a chunk-split tally a replay worker, whose split is
/// off, never reads.
#[derive(Default)]
struct RecorderUse {
    untold: Vec<String>,
    helpers: usize,
    /// Every call on the core, by name, in source order.
    calls: Vec<String>,
}

impl<'ast> Visit<'ast> for RecorderUse {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let on_core = matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident("emu"));
        let name = call.method.to_string();
        if on_core {
            self.calls.push(name.clone());
        }
        if on_core && name == "with_sink_on_core" {
            // The hand-back: what runs inside writes through the core's sink, put back for it.
            return;
        }
        if on_core {
            let rec_first = call
                .args
                .first()
                .is_some_and(|arg| quote::quote!(#arg).to_string() == "rec");
            if name.ends_with("_rec") && rec_first {
                self.helpers += 1;
            } else if ![
                "can_run_record_block",
                "count_recorder_block",
                "update_insn_clock",
                "should_yield",
                // A jump's target check, which ends the run as the interpreter's does.
                "check_jump_target",
                // `EBREAK`'s and `UNIMP`'s error, which ends the run as the interpreter's does and
                // writes no row: a trap emits no CPU event.
                "breakpoint",
                "illegal_instruction",
            ]
            .contains(&name.as_str())
            {
                self.untold.push(quote::quote!(#call).to_string());
            }
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_ident(&mut self, ident: &'ast proc_macro2::Ident) {
        if ident == "emitting" {
            self.untold.push("emitting".to_string());
        }
    }
}

/// The blocks a body steps to by name (`Direct(name)`), as the generated code names them.
#[derive(Default)]
struct DirectSteps(Vec<String>);

impl<'ast> Visit<'ast> for DirectSteps {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let direct = matches!(&*call.func, syn::Expr::Path(path)
            if path.path.segments.last().is_some_and(|segment| segment.ident == "Direct"));
        if let (true, Some(syn::Expr::Path(target))) = (direct, call.args.first()) {
            if let Some(name) = target.path.get_ident() {
                self.0.push(name.to_string());
            }
        }
        visit::visit_expr_call(self, call);
    }
}

/// Every recording body calls its entry test first and once, writes only through its recorder or
/// the hand-back, and steps only to recording bodies, by name only within its chunk crate: a step
/// to another chunk goes by pc, through the dispatch run's lookup.
#[test]
fn every_recording_body_writes_only_through_its_recorder() {
    let out = generate(
        &fib_elf(),
        &RuntimeSpec::InTree,
        "aot-codegen-recorder-writes",
    );
    let (mut bodies, mut helpers, mut direct_steps) = (0, 0, 0);
    for (path, file) in sources(&out) {
        let defined: std::collections::HashSet<String> =
            file.items.iter().filter_map(item_name).collect();
        for item in &file.items {
            let syn::Item::Fn(body) = item else {
                continue;
            };
            let name = body.sig.ident.to_string();
            if !name.starts_with("rec_block_0x") {
                continue;
            }
            let mut uses = RecorderUse::default();
            uses.visit_block(&body.block);
            assert!(
                uses.untold.is_empty(),
                "{path}: {name} calls past its recorder: {:?}",
                uses.untold
            );
            let entries = uses
                .calls
                .iter()
                .filter(|call| *call == "can_run_record_block")
                .count();
            assert_eq!(
                (uses.calls.first().map(String::as_str), entries),
                (Some("can_run_record_block"), 1),
                "{path}: {name} does not enter through one entry test first: {:?}",
                uses.calls
            );
            let source = quote::quote!(#body).to_string();
            assert!(
                !source.contains("NextStep :: Direct"),
                "{path}: {name} steps to an ordinary block: {source}"
            );
            let mut steps = DirectSteps::default();
            steps.visit_block(&body.block);
            for target in &steps.0 {
                assert!(
                    target.starts_with("rec_block_0x") && defined.contains(target),
                    "{path}: {name} steps by name to {target}, not a recording body of its chunk"
                );
            }
            bodies += 1;
            helpers += uses.helpers;
            direct_steps += steps.0.len();
        }
    }
    assert!(
        bodies > 0 && helpers > bodies && direct_steps > 0,
        "{bodies} recording bodies, {helpers} recorder writes, {direct_steps} steps by name"
    );
}

/// The chunk-split bookkeeping one body does, by call name, in source order: its rows on the
/// per-instruction chips, its memory events and its chunk-boundary tests. Not what runs inside the
/// hand-back, which is `ECALL`'s plain sequence.
#[derive(Default)]
struct SplitTally(Vec<String>);

impl<'ast> Visit<'ast> for SplitTally {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let name = call.method.to_string();
        if name == "with_sink_on_core" {
            return;
        }
        if ["add_leaf_rows", "add_memory_rw_events"].contains(&name.as_str())
            || name.starts_with("check_chunk_boundary")
        {
            self.0.push(name);
        }
        visit::visit_expr_method_call(self, call);
    }
}

/// Every plain body adds its rows on the per-instruction chips (each instruction adds a CPU row);
/// no recording body keeps any chunk-split tally or tests a chunk boundary: it runs only on a
/// replay worker, whose split is off, so nothing reads the tally and no test could cut.
#[test]
fn only_the_plain_body_keeps_the_chunk_split_tally() {
    for guest in ["fib", "poseidon2"] {
        let out = generate(
            &guest_elf(guest),
            &RuntimeSpec::InTree,
            &format!("aot-codegen-split-tally-{guest}"),
        );
        let (mut plain, mut recording) = (0, 0);
        let mut by_call = std::collections::BTreeMap::<String, usize>::new();
        for (path, file) in sources(&out) {
            for item in &file.items {
                let syn::Item::Fn(body) = item else {
                    continue;
                };
                let name = body.sig.ident.to_string();
                let mut tally = SplitTally::default();
                tally.visit_block(&body.block);
                if name.starts_with("rec_block_0x") {
                    assert_eq!(
                        tally.0,
                        Vec::<String>::new(),
                        "{guest}: {path}: {name} keeps a chunk-split tally"
                    );
                    recording += 1;
                } else if name.starts_with("block_0x") {
                    assert!(
                        tally.0.iter().any(|call| call == "add_leaf_rows"),
                        "{guest}: {path}: {name} adds no leaf rows: {:?}",
                        tally.0
                    );
                    for call in tally.0 {
                        *by_call.entry(call).or_default() += 1;
                    }
                    plain += 1;
                }
            }
        }
        assert!(
            plain > 0 && recording == plain,
            "{guest}: {plain} plain bodies, {recording} recording bodies"
        );
        for call in ["add_memory_rw_events", "check_chunk_boundary_fast"] {
            assert!(
                by_call.get(call).is_some_and(|&count| count > 0),
                "{guest}: no plain body calls {call}: {by_call:?}"
            );
        }
    }
}

/// One recording body's writes, as the generated code calls them.
#[derive(Default)]
struct RecordingWrites {
    /// Each direct write: its entry, its pc, `Instruction::new`'s arguments and the ALU list it
    /// names, as token strings.
    direct: Vec<(String, u64, Vec<String>, Option<String>)>,
    /// The room the body reserves, by field, but for the ALU lists.
    room: Option<std::collections::BTreeMap<String, u64>>,
    /// The `_rec` entries that run an ordinary helper's emitting body.
    emitting: usize,
}

impl<'ast> Visit<'ast> for RecordingWrites {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let name = call.method.to_string();
        let args: Vec<&syn::Expr> = call.args.iter().collect();
        let tokens = |expr: &syn::Expr| quote::quote!(#expr).to_string();
        if name.ends_with("_direct_rec") {
            let syn::Expr::Call(insn) = args[2] else {
                panic!("{name} is not handed an instruction: {}", tokens(args[2]));
            };
            let fields = insn.args.iter().map(tokens).collect();
            let pc = u64::from(int_literal(args[1]));
            self.direct
                .push((name, pc, fields, args.get(3).map(|stream| tokens(stream))));
        } else if name == "reserve_rows_rec" {
            let syn::Expr::Struct(room) = args[1] else {
                panic!("the room is not a BlockRows: {}", tokens(args[1]));
            };
            let fields = room.fields.iter().filter_map(|field| {
                let syn::Member::Named(name) = &field.member else {
                    return None;
                };
                (name != "alu").then(|| (name.to_string(), u64::from(int_literal(&field.expr))))
            });
            self.room = Some(fields.collect());
        } else if name.ends_with("_rec") {
            self.emitting += 1;
        }
        visit::visit_expr_method_call(self, call);
    }
}

/// The integer a `const NAME` in `body` is set to.
fn block_const(body: &syn::ItemFn, name: &str) -> u32 {
    body.block
        .stmts
        .iter()
        .find_map(|stmt| match stmt {
            syn::Stmt::Item(syn::Item::Const(item)) if item.ident == name => {
                Some(int_literal(&item.expr))
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("{} declares no {name}", body.sig.ident))
}

/// The entry a recording body calls to write `insn`'s rows directly.
fn expected_entry(insn: &VmInstruction) -> &'static str {
    use pico_vm::compiler::riscv::opcode::Opcode;
    let load = insn.is_memory_instruction()
        && !matches!(
            insn.opcode,
            Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD
        );
    let x0 = insn.op_a == 0;
    match insn.opcode {
        Opcode::AUIPC if x0 => "auipc_x0_direct_rec",
        Opcode::AUIPC => "auipc_direct_rec",
        Opcode::JAL => "jal_direct_rec",
        Opcode::JALR => "jalr_direct_rec",
        _ if insn.is_alu_instruction() && x0 => "alu_x0_direct_rec",
        _ if insn.is_alu_instruction() => "alu_direct_rec",
        _ if load && x0 => "load_x0_direct_rec",
        _ if load => "load_direct_rec",
        _ if insn.is_memory_instruction() => "store_direct_rec",
        _ if insn.is_branch_instruction() => "branch_direct_rec",
        other => panic!("{other:?} is not written directly"),
    }
}

/// In every recording body, each instruction that writes a row but `ECALL` is one direct write of
/// the program's own instruction through the entry its class and `x0` destination pick, naming its
/// ALU list when it has one; a branch or `JAL` whose target no row holds runs an emitting body
/// instead. The block's direct count and reserved room match those writes exactly.
#[test]
fn recording_bodies_write_every_instruction_but_ecall_directly_from_the_programs_instructions() {
    use pico_vm::{
        compiler::riscv::opcode::Opcode,
        emulator::riscv::{history::Slots, record::AluStream},
    };

    let elf = fib_elf();
    let program = parse_elf(&elf);
    let out = generate(&elf, &RuntimeSpec::InTree, "aot-codegen-recorder-direct");
    let mut by_entry = std::collections::BTreeMap::<&str, usize>::new();
    let (mut direct, mut x0, mut instructions) = (0, 0, 0);
    for (path, file) in sources(&out) {
        for item in &file.items {
            let syn::Item::Fn(body) = item else {
                continue;
            };
            let name = body.sig.ident.to_string();
            let Some(pc) = name.strip_prefix("rec_block_0x") else {
                continue;
            };
            let block_pc = u64::from_str_radix(pc, 16).expect("a block's pc");
            let mut writes = RecordingWrites::default();
            writes.visit_block(&body.block);

            let insns: Vec<_> = (0..u64::from(block_const(body, "BLOCK_INSNS")))
                .map(|i| {
                    let pc = block_pc + 4 * i;
                    (
                        pc,
                        program.instructions[((pc - program.pc_base) / 4) as usize],
                    )
                })
                .collect();
            let to_a_row = |pc: u64, offset: u64| u32::try_from(pc.wrapping_add(offset)).is_ok();
            let (converted, unconverted): (Vec<_>, Vec<_>) = insns
                .iter()
                .copied()
                // `EBREAK` and `UNIMP` end the run and write no row.
                .filter(|(_, insn)| {
                    !matches!(insn.opcode, Opcode::ECALL | Opcode::EBREAK | Opcode::UNIMP)
                })
                .partition(|&(pc, insn)| match insn.opcode {
                    Opcode::JAL => to_a_row(pc, insn.op_b),
                    _ if insn.is_branch_instruction() => to_a_row(pc, insn.op_c),
                    _ => true,
                });
            assert_eq!(
                writes
                    .direct
                    .iter()
                    .map(|(_, pc, ..)| *pc)
                    .collect::<Vec<_>>(),
                converted.iter().map(|(pc, _)| *pc).collect::<Vec<_>>(),
                "{path}: {name}'s direct writes"
            );
            assert_eq!(
                writes.emitting,
                unconverted.len(),
                "{path}: {name}'s emitting bodies"
            );
            assert_eq!(
                block_const(body, "BLOCK_DIRECT_INSNS") as usize,
                converted.len(),
                "{path}: {name}"
            );
            let expected_room = (!converted.is_empty()).then(|| {
                let count = |rows: fn(&VmInstruction) -> usize| {
                    converted.iter().map(|(_, insn)| rows(insn) as u64).sum()
                };
                std::collections::BTreeMap::from([
                    (
                        "branch".to_string(),
                        count(|insn| usize::from(insn.is_branch_instruction())),
                    ),
                    (
                        "memory".to_string(),
                        count(|insn| usize::from(insn.is_memory_instruction())),
                    ),
                    (
                        "operand_exceptions".to_string(),
                        count(|insn| usize::from(expected_entry(insn).contains("x0"))),
                    ),
                    (
                        "reads".to_string(),
                        count(|insn| Slots::of(insn).len() - Slots::of(insn).write_count()),
                    ),
                    ("steps".to_string(), converted.len() as u64),
                    (
                        "writes".to_string(),
                        count(|insn| Slots::of(insn).write_count()),
                    ),
                ])
            });
            assert_eq!(writes.room, expected_room, "{path}: {name}'s room");
            for ((entry, pc, fields, stream), (_, insn)) in writes.direct.iter().zip(&converted) {
                let token = |value: proc_macro2::TokenStream| value.to_string();
                let (op_a, op_b, op_c) = (insn.op_a, insn.op_b, insn.op_c);
                let (imm_b, imm_c) = (insn.imm_b, insn.imm_c);
                assert_eq!(
                    fields,
                    &[
                        format!("Opcode :: {:?}", insn.opcode),
                        token(quote::quote!(#op_a)),
                        token(quote::quote!(#op_b)),
                        token(quote::quote!(#op_c)),
                        token(quote::quote!(#imm_b)),
                        token(quote::quote!(#imm_c)),
                    ],
                    "{path}: {name} at {pc:#x}"
                );
                let expected = expected_entry(insn);
                assert_eq!(entry, expected, "{path}: {name} at {pc:#x}");
                let expected_stream = (insn.is_alu_instruction() && insn.op_a != 0)
                    .then(|| format!("AluStream :: {:?}", AluStream::of(insn.opcode)));
                assert_eq!(stream, &expected_stream, "{path}: {name} at {pc:#x}");
                *by_entry.entry(expected).or_default() += 1;
                x0 += usize::from(expected.contains("x0"));
            }
            direct += converted.len();
            instructions += insns.len();
        }
    }
    assert!(direct > 0, "no direct write in any recording body");
    eprintln!(
        "{direct} of {instructions} instructions written directly, {x0} through an x0 entry: \
         {by_entry:?}"
    );
}
