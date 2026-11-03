//! What `AotCompiler::compile_with` writes for a real guest: its ELF's SHA-256 and the codegen
//! stamp in the dispatch crate's `AOT`, the runtime dependency it was handed in every generated
//! manifest, and blocks that read the sink once and hand it to every helper. And that
//! `generate_crates`, through `compile`, takes that dependency from `PICO_AOT_RUNTIME_SPEC`.

use std::{fs, path::PathBuf, process::Command};

use pico_aot_codegen::{parse_elf, AotCompiler, AotConfig, RuntimeSpec, CODEGEN_STAMP};
use sha2::{Digest, Sha256};
use syn::visit::{self, Visit};

fn fib_elf_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../perf/bench_data/rv64/fib-elf")
}

fn fib_elf() -> Vec<u8> {
    let path = fib_elf_path();
    fs::read(&path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

fn generate(elf: &[u8], runtime: &RuntimeSpec, name: &str) -> PathBuf {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    AotCompiler::new(parse_elf(elf), AotConfig::new(out.clone()))
        .compile_with(runtime)
        .expect("AOT crate generation failed");
    out
}

/// The call `pub static AOT` is built by, read back out of the generated source.
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

    let syn::Expr::Call(call) = &*aot.expr else {
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
