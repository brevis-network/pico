//! What `AotCompiler::compile_with` writes for a real guest: its ELF's SHA-256 in the dispatch
//! crate's `AOT`, and the runtime dependency it was handed in every generated manifest. And that
//! `generate_crates`, through `compile`, takes that dependency from `PICO_AOT_RUNTIME_SPEC`.

use std::{fs, path::PathBuf, process::Command};

use pico_aot_codegen::{parse_elf, AotCompiler, AotConfig, RuntimeSpec};
use sha2::{Digest, Sha256};

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

/// The byte array `pub static AOT` is built from, read back out of the generated source.
fn exported_digest(lib_rs: &str) -> [u8; 32] {
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
    let Some(syn::Expr::Array(digest)) = call.args.first() else {
        panic!(
            "`AOT`'s first argument is not an array: {}",
            quote::quote!(#aot)
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
