//! `--aot` on `prove` and `execute`, by building and running a helper binary.
//!
//! This CLI cannot link code generated for one ELF, so `--aot` builds a binary that does: this
//! CLI's entry point, [`run_with_aot`], on the ELF's generated crates. It lives in the AOT cache at
//! `<root>/<elf sha256>-<cli version>-<generator id>-<source id>/`, a crate whose files are written
//! once:
//!
//! - `aot/`, the generated dispatch crate and its chunk crates;
//! - `Cargo.toml` and `src/main.rs`, a package named for the entry, taking `pico-cli` from the
//!   source the generated crates take `pico-aot-runtime` from, so that Cargo resolves one copy of
//!   each;
//! - `Cargo.lock`, this CLI's own lock, so Cargo keeps its crates.io versions and resolves only the
//!   Pico packages afresh, and `rust-toolchain`, this CLI's own toolchain.
//!
//! Every run then builds it into `<root>/target`, which all entries share so that Pico's crates
//! compile once per source rather than once per ELF, and where each entry's package name keeps its
//! executable apart. Cargo makes the build a no-op when nothing changed, and reports where the
//! executable is, wherever the user's Cargo configuration puts it. The helper runs with the same
//! arguments and [`HELPER_ENV`] set, passing its stdio and exit code through. In the helper,
//! `--aot` means the program [`run_with_aot`] registered; one without a program refuses rather than
//! build another.
//!
//! The generator id is a digest of this CLI's executable, whose linked code generator wrote the
//! entry's crates, so that a reinstall that changes the generator does not reuse them. The source id
//! is the release tag, or for a [`PICO_SOURCE_ENV`] checkout a digest of its path and
//! `git describe --always --dirty`, so that a helper is never shared by two states of a checkout.
//! Edits that leave `describe` unchanged are Cargo's to notice, in the build every run makes.
//! [`check_release`] vets a release source only when its entry is created, so a cached entry never
//! reaches the network.
//!
//! The whole cache can be deleted whenever no run is using it; the next run writes and builds what
//! it needs again.

use std::{
    env,
    ffi::OsString,
    fs,
    io::{self, BufReader},
    path::{Path, PathBuf},
    process::{self, Command, ExitStatus, Stdio},
};

use anyhow::{bail, Context, Result};
use cargo_metadata::Message;
use sha2::{Digest, Sha256};

use crate::{
    clean_command_env,
    source::{check_release, pico_dependency, pico_source, release_tag, PICO_SOURCE_ENV},
    subcommand::aot::{generate, validate_elf},
};

/// Set in the helper's environment: `--aot` there must use the registered program.
pub const HELPER_ENV: &str = "PICO_AOT_HELPER";

/// The AOT cache's root [default: `~/.pico/aot`].
pub const CACHE_ENV: &str = "PICO_AOT_CACHE";

const HELPER_PACKAGE: &str = "pico-aot-helper";

const LOCK: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"));

const TOOLCHAIN: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../rust-toolchain"));

#[cfg(feature = "aot")]
static PROGRAM: std::sync::OnceLock<&'static pico_aot_runtime::AotProgram> =
    std::sync::OnceLock::new();

/// A helper's entry point: [`run`](crate::run) on this process's arguments, with `--aot` meaning
/// `program`.
#[cfg(feature = "aot")]
pub fn run_with_aot(program: &'static pico_aot_runtime::AotProgram) -> Result<()> {
    // Only a helper's `main` calls this, once.
    let _ = PROGRAM.set(program);
    crate::run(env::args_os())
}

/// The program [`run_with_aot`] registered.
#[cfg(feature = "aot")]
pub(crate) fn program() -> Option<&'static pico_aot_runtime::AotProgram> {
    PROGRAM.get().copied()
}

pub(crate) fn has_program() -> bool {
    #[cfg(feature = "aot")]
    return program().is_some();
    #[cfg(not(feature = "aot"))]
    false
}

/// Builds the helper for `elf` and runs it with `args`, this process's arguments without the
/// program name. A helper that fails exits this process with its code.
pub(crate) fn build_and_run(elf_path: &Path, args: &[OsString]) -> Result<()> {
    if env::var_os(HELPER_ENV).is_some() {
        bail!(
            "{HELPER_ENV} is set, so this is an AOT helper, but it carries no AOT program; it does \
             not build another"
        );
    }
    let elf =
        fs::read(elf_path).with_context(|| format!("cannot read `{}`", elf_path.display()))?;
    validate_elf(elf_path, &elf)?;
    let pico_source = pico_source()?;
    let source_id = match &pico_source {
        Some(checkout) => source_id(Some((checkout, &describe(checkout)?))),
        None => source_id(None),
    };
    let key = cache_key(
        &Sha256::digest(&elf).into(),
        env!("CARGO_PKG_VERSION"),
        &generator_id()?,
        &source_id,
    );
    let root = cache_root()?;
    let dir = root.join(&key);
    let package = helper_package(&key);
    if !dir.exists() {
        if pico_source.is_none() {
            check_release()?;
        }
        create(&dir, &package, &elf, pico_source.as_deref())?;
    }

    let helper = build(&dir, &package, &root.join("target"))?;
    let status = Command::new(&helper)
        .args(args)
        .env(HELPER_ENV, "1")
        .status()
        .with_context(|| format!("cannot run `{}`", helper.display()))?;
    if !status.success() {
        process::exit(exit_code(status));
    }
    Ok(())
}

/// One entry per ELF, CLI version, code generator and Pico source.
fn cache_key(
    elf_sha256: &[u8; 32],
    cli_version: &str,
    generator_id: &str,
    source_id: &str,
) -> String {
    format!(
        "{}-{cli_version}-{generator_id}-{source_id}",
        hex::encode(elf_sha256)
    )
}

/// The entry's package, whose executable in the shared target dir is then the entry's alone.
fn helper_package(key: &str) -> String {
    format!(
        "{HELPER_PACKAGE}-{}",
        hex::encode(&Sha256::digest(key)[..8])
    )
}

/// A digest of this executable, whose linked code generator writes an entry's crates.
fn generator_id() -> Result<String> {
    let exe = env::current_exe().context("cannot find this executable")?;
    let mut sha256 = Sha256::new();
    fs::File::open(&exe)
        .and_then(|mut file| io::copy(&mut file, &mut sha256))
        .with_context(|| format!("cannot read `{}`", exe.display()))?;
    Ok(format!("gen-{}", hex::encode(&sha256.finalize()[..8])))
}

/// The release tag, or for a checkout at a path and `git describe`, a digest of the two.
fn source_id(checkout: Option<(&str, &str)>) -> String {
    match checkout {
        None => release_tag(),
        Some((path, describe)) => {
            let digest = Sha256::digest(format!("{path}\n{describe}"));
            format!("src-{}", hex::encode(&digest[..8]))
        }
    }
}

fn describe(checkout: &str) -> Result<String> {
    let output = Command::new("git")
        .args(["-C", checkout, "describe", "--always", "--dirty"])
        .output()
        .context("cannot run git")?;
    if !output.status.success() {
        bail!(
            "{PICO_SOURCE_ENV}=`{checkout}`: `git describe` failed, so the AOT cache cannot tell \
             its states apart: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Absolute, because Cargo reads the shared target dir from inside an entry.
fn cache_root() -> Result<PathBuf> {
    let root = match env::var_os(CACHE_ENV).filter(|root| !root.is_empty()) {
        Some(root) => PathBuf::from(root),
        None => dirs::home_dir()
            .context("cannot find the home directory, where `.pico` lives")?
            .join(".pico/aot"),
    };
    std::path::absolute(&root).with_context(|| format!("{CACHE_ENV}=`{}`", root.display()))
}

/// Writes the entry beside `dir`, then renames it into place, so an entry that exists is whole.
fn create(dir: &Path, package: &str, elf: &[u8], pico_source: Option<&str>) -> Result<()> {
    let mut partial = dir.as_os_str().to_owned();
    partial.push(format!(".partial-{}", process::id()));
    let partial = PathBuf::from(partial);
    eprintln!("aot: generating the crates in {}", dir.display());
    let written = generate(
        elf,
        &partial.join("aot"),
        &pico_dependency(pico_source, "aot-runtime"),
    )
    .and_then(|_| write_helper_crate(&partial, package, pico_source));
    if written.is_err() {
        let _ = fs::remove_dir_all(&partial);
        return written;
    }
    match fs::rename(&partial, dir) {
        Ok(()) => Ok(()),
        // Another run got there first, with the same files.
        Err(_) if dir.exists() => {
            let _ = fs::remove_dir_all(&partial);
            Ok(())
        }
        Err(e) => Err(e).with_context(|| format!("cannot create `{}`", dir.display())),
    }
}

fn write_helper_crate(dir: &Path, package: &str, pico_source: Option<&str>) -> Result<()> {
    let manifest = format!(
        "[package]\nname = \"{package}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
         publish = false\n\n[dependencies]\nanyhow = \"1\"\npico-aot-dispatch = {{ path = \"aot\" }}\n\
         pico-cli = {{ {}, features = [\"aot\"] }}\n\n\
         # Its own workspace, so a cache inside another project is not taken for part of it.\n\
         [workspace]\n",
        pico_dependency(pico_source, "sdk/cli")
    );
    let main = "fn main() -> anyhow::Result<()> {\n    \
                pico_cli::run_with_aot(&pico_aot_dispatch::AOT)\n}\n";
    let files = [
        ("Cargo.toml", manifest),
        ("Cargo.lock", LOCK.to_owned()),
        ("rust-toolchain", toolchain()),
        ("src/main.rs", main.to_owned()),
    ];
    for (name, contents) in files {
        let path = dir.join(name);
        fs::create_dir_all(path.parent().expect("a file in the crate"))
            .and_then(|()| fs::write(&path, contents))
            .with_context(|| format!("cannot write `{}`", path.display()))?;
    }
    Ok(())
}

/// This CLI's toolchain channel, without the components its own development wants.
fn toolchain() -> String {
    let channel = TOOLCHAIN
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == "channel").then(|| value.trim().trim_matches('"'))
        })
        .expect("the workspace's rust-toolchain names a channel");
    format!("[toolchain]\nchannel = \"{channel}\"\n")
}

/// Builds the entry at `dir` into `target_dir` and returns `package`'s executable, where Cargo put
/// it.
fn build(dir: &Path, package: &str, target_dir: &Path) -> Result<PathBuf> {
    eprintln!("aot: building the helper in {}", dir.display());
    // In `dir`, for rustup to read its `rust-toolchain`. Cargo renders diagnostics on stderr and
    // writes only its messages to stdout, which are read here, so that the user's stdout is the
    // helper's alone.
    let mut cargo = clean_command_env("cargo")
        .args([
            "build",
            "--release",
            "--message-format=json-render-diagnostics",
            "--target-dir",
        ])
        .arg(target_dir)
        .current_dir(dir)
        .stdout(Stdio::piped())
        .spawn()
        .context("cannot run cargo")?;
    let mut executable = None;
    let messages = BufReader::new(cargo.stdout.take().expect("cargo's stdout is piped"));
    for message in Message::parse_stream(messages) {
        match message.context("cannot read cargo's output")? {
            Message::CompilerArtifact(artifact) if artifact.target.name == package => {
                executable = artifact.executable;
            }
            Message::TextLine(line) => eprintln!("{line}"),
            _ => {}
        }
    }
    let status = cargo.wait().context("cannot run cargo")?;
    if !status.success() {
        bail!(
            "building the AOT helper in `{}` failed ({status})",
            dir.display()
        );
    }
    executable.map(PathBuf::from).with_context(|| {
        format!(
            "building the AOT helper in `{}` reported no executable for `{package}`",
            dir.display()
        )
    })
}

fn exit_code(status: ExitStatus) -> i32 {
    #[cfg(unix)]
    if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(&status) {
        return 128 + signal;
    }
    status.code().unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERSION: &str = env!("CARGO_PKG_VERSION");

    const GENERATOR: &str = "gen-0011223344556677";

    #[test]
    fn the_cache_key_moves_with_the_elf_the_version_the_generator_and_the_source() {
        let key = cache_key(&[1; 32], "3.0.0", GENERATOR, "v3.0.0");
        assert_eq!(key, format!("{}-3.0.0-{GENERATOR}-v3.0.0", "01".repeat(32)));
        assert_ne!(cache_key(&[2; 32], "3.0.0", GENERATOR, "v3.0.0"), key);
        assert_ne!(cache_key(&[1; 32], "3.0.1", GENERATOR, "v3.0.0"), key);
        assert_ne!(
            cache_key(&[1; 32], "3.0.0", "gen-8899aabbccddeeff", "v3.0.0"),
            key
        );
        assert_ne!(
            cache_key(&[1; 32], "3.0.0", GENERATOR, "src-0123456789abcdef"),
            key
        );
    }

    #[test]
    fn the_generator_id_is_this_executables_digest() {
        let exe = fs::read(env::current_exe().expect("this executable")).expect("its bytes");
        let id = generator_id().expect("a generator id");
        assert_eq!(
            id,
            format!("gen-{}", hex::encode(&Sha256::digest(exe)[..8]))
        );
    }

    #[test]
    fn each_entry_has_its_own_package() {
        let key = cache_key(&[1; 32], "3.0.0", GENERATOR, "v3.0.0");
        let package = helper_package(&key);
        assert!(
            package.starts_with("pico-aot-helper-") && package.len() == 32,
            "{package}"
        );
        assert_ne!(
            helper_package(&cache_key(&[2; 32], "3.0.0", GENERATOR, "v3.0.0")),
            package
        );
    }

    #[test]
    fn a_checkout_source_id_moves_with_its_path_and_its_state() {
        assert_eq!(source_id(None), format!("v{VERSION}"));
        let id = source_id(Some(("/src/pico", "v3.0.0-4-gabcdef0")));
        assert!(id.starts_with("src-") && id.len() == 20, "{id}");
        assert_ne!(source_id(Some(("/src/other", "v3.0.0-4-gabcdef0"))), id);
        assert_ne!(
            source_id(Some(("/src/pico", "v3.0.0-4-gabcdef0-dirty"))),
            id
        );
        assert_ne!(source_id(Some(("/src/pico", "v3.0.0-5-g1234567"))), id);
    }

    fn workspace_file(name: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(name);
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    fn written(dir: &Path, name: &str) -> String {
        fs::read_to_string(dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
    }

    #[test]
    fn the_helper_crate_takes_the_cli_from_the_source_with_this_toolchain_and_lock() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        write_helper_crate(dir.path(), "pico-aot-helper-0123", Some("/src/pico"))
            .expect("the helper crate");

        let manifest = written(dir.path(), "Cargo.toml");
        for line in [
            r#"name = "pico-aot-helper-0123""#,
            r#"pico-cli = { path = "/src/pico/sdk/cli", features = ["aot"] }"#,
            r#"pico-aot-dispatch = { path = "aot" }"#,
            "[workspace]",
        ] {
            assert!(
                manifest.lines().any(|l| l == line),
                "no `{line}` in:\n{manifest}"
            );
        }
        assert!(
            written(dir.path(), "src/main.rs")
                .contains("pico_cli::run_with_aot(&pico_aot_dispatch::AOT)"),
            "main does not run the generated program"
        );
        assert_eq!(
            written(dir.path(), "Cargo.lock"),
            workspace_file("Cargo.lock")
        );

        let channel = workspace_file("rust-toolchain")
            .lines()
            .find(|line| line.starts_with("channel"))
            .expect("the workspace's channel")
            .to_owned();
        assert_eq!(
            written(dir.path(), "rust-toolchain"),
            format!("[toolchain]\n{channel}\n")
        );

        write_helper_crate(dir.path(), "pico-aot-helper-0123", None).expect("the helper crate");
        let manifest = written(dir.path(), "Cargo.toml");
        let line = format!(
            r#"pico-cli = {{ git = "https://github.com/brevis-network/pico", tag = "v{VERSION}", features = ["aot"] }}"#
        );
        assert!(
            manifest.lines().any(|l| l == line),
            "no `{line}` in:\n{manifest}"
        );
    }
}
