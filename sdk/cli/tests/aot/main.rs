//! `cargo pico aot`, and `--aot` on `prove` and `execute`, driven through the binary on the fib
//! guest. Nothing is built, which takes minutes: the generated crates are read, and the helper is
//! "built" by a stand-in cargo. No case reaches the network: one that takes Pico from the release
//! has git find the public repository in a local stand-in.

mod generate;
#[cfg(unix)]
mod helper;

#[path = "../../../prover/src/tests/scratch.rs"]
mod scratch;

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use pico_cli::source::PICO_SOURCE_ENV;
use sha2::{Digest, Sha256};

const FIB_ELF: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vm/src/compiler/test_elf/fib-elf"
);

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn fib_sha256() -> [u8; 32] {
    Sha256::digest(fs::read(FIB_ELF).expect("the fib ELF")).into()
}

/// `cargo pico`, taking Pico from `pico_source`.
fn cargo_pico(pico_source: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cargo-pico"));
    command
        .arg("pico")
        .env(PICO_SOURCE_ENV, pico_source)
        .env_remove("PICO_AOT_SAVE_METRICS")
        .env_remove("RUST_LOG")
        .env_remove("RUST_LOGGER");
    command
}

fn output(command: &mut Command) -> (Output, String, String) {
    let output = command.output().expect("run cargo-pico");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (output, stdout, stderr)
}

/// A clean error, which `main` reports with exit code 1, where a panic exits with 101.
fn assert_error(output: &Output, stderr: &str, message: &str) {
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert!(stderr.contains(message), "no `{message}` in:\n{stderr}");
}

/// Git with an identity, which CI does not configure, and with the caller's global and system
/// configuration cut off, so that neither can decide a case.
fn isolated_git_env(command: &mut Command) -> &mut Command {
    command
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Pico")
        .env("GIT_AUTHOR_EMAIL", "pico@example.com")
        .env("GIT_COMMITTER_NAME", "Pico")
        .env("GIT_COMMITTER_EMAIL", "pico@example.com")
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = isolated_git_env(Command::new("git").args(args).current_dir(dir))
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {args:?} in {}:\n{}",
        dir.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// A bare stand-in for the public repository at `path`, with one commit, tagged `tag`.
fn stand_in_pico(path: &Path, tag: Option<&str>) -> PathBuf {
    fs::create_dir_all(path).expect("the stand-in's directory");
    git(path, &["init", "-q", "--bare"]);
    let tree = git(path, &["mktree"]);
    let commit = git(path, &["commit-tree", &tree, "-m", "release"]);
    if let Some(tag) = tag {
        git(path, &["tag", tag, &commit]);
    }
    path.to_path_buf()
}

/// Takes Pico from the release, which git finds in `stand_in`.
fn from_release<'a>(command: &'a mut Command, stand_in: &Path) -> &'a mut Command {
    isolated_git_env(command)
        .env_remove(PICO_SOURCE_ENV)
        .env("GIT_CONFIG_COUNT", "1")
        .env(
            "GIT_CONFIG_KEY_0",
            format!("url.{}.insteadOf", stand_in.display()),
        )
        .env(
            "GIT_CONFIG_VALUE_0",
            "https://github.com/brevis-network/pico",
        )
}
