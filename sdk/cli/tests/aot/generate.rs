//! `cargo pico aot`.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use pico_cli::source::release_has_aot;

use crate::{
    assert_error, cargo_pico, fib_sha256, from_release, output, scratch::scratch_dir,
    stand_in_pico, FIB_ELF, VERSION,
};

/// This checkout, the Pico source of every case not about the release.
fn checkout() -> PathBuf {
    fs::canonicalize(concat!(env!("CARGO_MANIFEST_DIR"), "/../..")).expect("the checkout")
}

/// `cargo pico aot`, taking Pico from this checkout unless `configure` says otherwise.
fn cargo_pico_aot(
    elf: &Path,
    out: &Path,
    configure: impl FnOnce(&mut Command),
) -> (Output, String, String) {
    let mut command = cargo_pico(&checkout());
    command
        .arg("aot")
        .arg("--elf")
        .arg(elf)
        .arg("--out")
        .arg(out);
    configure(&mut command);
    output(&mut command)
}

fn assert_generated(output: &Output, stdout: &str, stderr: &str, out: &Path) {
    assert!(output.status.success(), "{stdout}\n{stderr}");
    let chunks = fs::read_dir(out.join("chunks")).expect("chunks/").count();
    assert!(chunks > 0, "no chunk crate");
    assert!(
        stdout.contains(&format!("pico-aot-dispatch and {chunks} chunk crate(s)")),
        "{stdout}"
    );
}

/// The byte array `pub static AOT` is built from, read back out of the dispatch crate's source.
fn exported_digest(out: &Path) -> [u8; 32] {
    let lib_rs = fs::read_to_string(out.join("src/lib.rs")).expect("the dispatch crate's lib.rs");
    let file = syn::parse_file(&lib_rs).expect("the dispatch crate's source parses");
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
        panic!("`AOT` is not built by a call");
    };
    let Some(syn::Expr::Array(digest)) = call.args.first() else {
        panic!("`AOT`'s first argument is not an array");
    };
    let digest: Vec<u8> = digest
        .elems
        .iter()
        .map(|byte| match byte {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Int(byte),
                ..
            }) => byte.base10_parse().expect("a byte"),
            _ => panic!("not a byte literal"),
        })
        .collect();
    digest.try_into().expect("a 32-byte digest")
}

/// Every generated manifest depends on the runtime through exactly `entry`.
fn assert_runtime(out: &Path, entry: &str) {
    let expected = format!("pico-aot-runtime = {{ {entry} }}");
    let mut manifests = vec![out.join("Cargo.toml")];
    for chunk in fs::read_dir(out.join("chunks")).expect("chunks/") {
        manifests.push(chunk.expect("a chunk crate").path().join("Cargo.toml"));
    }
    for manifest in manifests {
        let toml = fs::read_to_string(&manifest).expect("a generated manifest");
        assert!(
            toml.lines().any(|line| line == expected),
            "{} does not carry `{expected}`:\n{toml}",
            manifest.display()
        );
    }
}

#[test]
fn the_dispatch_crate_exports_the_elf_digest_and_takes_the_runtime_from_pico_source() {
    let dir = scratch_dir("aot_pico_source");
    let out = dir.join("aot");
    let (output, stdout, stderr) = cargo_pico_aot(Path::new(FIB_ELF), &out, |_| {});
    assert_generated(&output, &stdout, &stderr, &out);

    assert_eq!(exported_digest(&out), fib_sha256());
    assert_runtime(
        &out,
        &format!(r#"path = "{}/aot-runtime""#, checkout().display()),
    );
}

#[test]
fn the_release_runtime_needs_a_release_with_aot_and_its_tag() {
    let dir = scratch_dir("aot_release");
    let tagged = stand_in_pico(&dir.join("tagged.git"), Some(&format!("v{VERSION}")));
    let untagged = stand_in_pico(&dir.join("untagged.git"), None);

    let out = dir.join("aot");
    let (output, stdout, stderr) = cargo_pico_aot(Path::new(FIB_ELF), &out, |command| {
        from_release(command, &tagged);
    });
    if !release_has_aot() {
        assert_error(&output, &stderr, "the first Pico release with AOT");
        assert!(!out.exists(), "crates generated for a release without AOT");
        return;
    }
    assert_generated(&output, &stdout, &stderr, &out);
    assert_runtime(
        &out,
        &format!(r#"git = "https://github.com/brevis-network/pico", tag = "v{VERSION}""#),
    );

    let out = dir.join("aot-untagged");
    let (output, _, stderr) = cargo_pico_aot(Path::new(FIB_ELF), &out, |command| {
        from_release(command, &untagged);
    });
    assert_error(&output, &stderr, &format!("has no tag `v{VERSION}`"));
    assert!(!out.exists(), "crates generated for a missing tag");
}

#[test]
fn a_previous_generation_is_replaced() {
    let dir = scratch_dir("aot_replace");
    let out = dir.join("aot");
    let (output, stdout, stderr) = cargo_pico_aot(Path::new(FIB_ELF), &out, |_| {});
    assert_generated(&output, &stdout, &stderr, &out);
    fs::write(out.join("stale"), "").expect("a stale file");

    let (output, stdout, stderr) = cargo_pico_aot(Path::new(FIB_ELF), &out, |_| {});
    assert_generated(&output, &stdout, &stderr, &out);
    assert!(
        !out.join("stale").exists(),
        "the previous generation was kept"
    );
}

#[test]
fn a_directory_of_other_files_is_left_alone() {
    let dir = scratch_dir("aot_foreign");
    let kept = dir.join("kept");
    fs::write(&kept, "").expect("a file of the user's");

    let (output, _, stderr) = cargo_pico_aot(Path::new(FIB_ELF), &dir, |_| {});
    assert_error(
        &output,
        &stderr,
        "holds no generated AOT crates; not replacing it",
    );
    assert!(kept.exists(), "the user's file was deleted");
}

#[test]
fn a_missing_or_non_elf_input_is_an_error() {
    let dir = scratch_dir("aot_bad_elf");
    let out = dir.join("aot");

    let (output, _, stderr) = cargo_pico_aot(&dir.join("missing"), &out, |_| {});
    assert_error(&output, &stderr, "cannot read");

    let text = dir.join("text");
    fs::write(&text, "not an ELF").expect("a text file");
    let (output, _, stderr) = cargo_pico_aot(&text, &out, |_| {});
    assert_error(&output, &stderr, "is not a guest ELF");
    assert!(!out.exists(), "an output directory for a rejected input");
}

#[test]
fn an_unwritable_out_is_an_error() {
    let dir = scratch_dir("aot_unwritable");
    let file = dir.join("file");
    fs::write(&file, "").expect("a regular file");

    let (output, _, stderr) = cargo_pico_aot(Path::new(FIB_ELF), &file.join("aot"), |_| {});
    assert_error(&output, &stderr, "cannot write AOT crates to");

    let (output, _, stderr) = cargo_pico_aot(Path::new(FIB_ELF), &file, |_| {});
    assert_error(&output, &stderr, "cannot write AOT crates to");
}
