//! `prove --aot` and `execute --aot` outside a helper, with a stand-in `cargo` first on `PATH`. The
//! stand-in records how it was run and "builds" a helper that records its own arguments and
//! environment and exits with [`HELPER_EXIT`]. It puts the helper where a configured target triple
//! would, which only Cargo's report of the artifact says, and reports a second package's executable
//! after it.

use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use pico_cli::{
    aot_helper::{CACHE_ENV, HELPER_ENV},
    source::release_has_aot,
};
use sha2::{Digest, Sha256};

use crate::{
    assert_error, cargo_pico, fib_sha256, from_release, git, output,
    scratch::{scratch_dir, ScratchDir},
    stand_in_pico, FIB_ELF, VERSION,
};

const OTHER_ELF: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vm/src/compiler/test_elf/riscv64im-pico-fibnacci-elf"
);

const HELPER_EXIT: i32 = 7;

const FAKE_CARGO: &str = r#"#!/bin/sh
set -e
{ pwd -P; echo "$*"; } >> "$PICO_TEST_LOG/cargo"
env > "$PICO_TEST_LOG/cargo-env"
echo "stand-in cargo: a rendered diagnostic" >&2
while [ "$#" -gt 0 ] && [ "$1" != --target-dir ]; do shift; done
package=$(sed -n 's/^name = "\(.*\)"$/\1/p' Cargo.toml)
helper="$2/a-target-triple/release/$package"
mkdir -p "${helper%/*}"
cat > "$helper" <<'EOF'
#!/bin/sh
{ echo "$PICO_AOT_HELPER"; echo "$*"; } > "$PICO_TEST_LOG/helper"
echo "the helper's stdout"
exit 7
EOF
chmod +x "$helper"
artifact='{"reason":"compiler-artifact","package_id":"%s","target":{"name":"%s","kind":["bin"],"src_path":"src/main.rs"},"profile":{"opt_level":"3","debug_assertions":false,"overflow_checks":false,"test":false},"features":[],"filenames":["%s"],"executable":"%s","fresh":false}\n'
printf "$artifact" "$package" "$package" "$helper" "$helper"
printf "$artifact" other other /not/the/helper /not/the/helper
echo '{"reason":"build-finished","success":true}'
exit "${PICO_TEST_CARGO_EXIT:-0}"
"#;

struct Fixture {
    dir: ScratchDir,
}

impl Fixture {
    /// A stand-in cargo, and a stand-in Pico checkout for `git describe` to name.
    fn new(tag: &str) -> Self {
        let dir = scratch_dir(tag);
        let bin = dir.join("bin");
        fs::create_dir_all(&bin).expect("bin/");
        fs::create_dir_all(dir.join("log")).expect("log/");
        let cargo = bin.join("cargo");
        fs::write(&cargo, FAKE_CARGO).expect("the stand-in cargo");
        fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755)).expect("chmod");
        let checkout = dir.join("checkout");
        fs::create_dir_all(&checkout).expect("checkout/");
        git(&checkout, &["init", "-q"]);
        git(
            &checkout,
            &["commit", "-q", "--allow-empty", "-m", "checkout"],
        );
        Self { dir }
    }

    fn cache(&self) -> PathBuf {
        self.dir.join("cache")
    }

    fn log(&self, name: &str) -> Option<String> {
        fs::read_to_string(self.dir.join("log").join(name)).ok()
    }

    /// The cache's entries, without the target dir they share.
    fn entries(&self) -> Vec<String> {
        let mut entries: Vec<String> = fs::read_dir(self.cache())
            .expect("the cache")
            .map(|entry| {
                entry
                    .expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| name != "target")
            .collect();
        entries.sort();
        entries
    }

    fn run(&self, command: &str, configure: impl FnOnce(&mut Command)) -> (Output, String, String) {
        self.run_on(command, FIB_ELF, configure)
    }

    /// `cargo pico <command> --aot --elf <elf>`, taking Pico from the stand-in checkout, with
    /// every variable this path reads set here.
    fn run_on(
        &self,
        command: &str,
        elf: &str,
        configure: impl FnOnce(&mut Command),
    ) -> (Output, String, String) {
        let path = format!(
            "{}:{}",
            self.dir.join("bin").display(),
            env::var("PATH").expect("PATH")
        );
        let mut cargo_pico = cargo_pico(&self.dir.join("checkout"));
        cargo_pico
            .args([command, "--aot", "--elf", elf])
            .env("PATH", path)
            .env(CACHE_ENV, self.cache())
            .env("PICO_TEST_LOG", self.dir.join("log"))
            .env_remove(HELPER_ENV);
        configure(&mut cargo_pico);
        output(&mut cargo_pico)
    }
}

/// An entry's name up to its source id.
fn entry_prefix(elf_sha256: &[u8; 32]) -> String {
    let cli = fs::read(env!("CARGO_BIN_EXE_cargo-pico")).expect("the cargo-pico executable");
    let generator = hex::encode(&Sha256::digest(cli)[..8]);
    format!("{}-{VERSION}-gen-{generator}-", hex::encode(elf_sha256))
}

fn release_entry() -> String {
    format!("{}v{VERSION}", entry_prefix(&fib_sha256()))
}

fn package(entry: &str) -> String {
    format!(
        "pico-aot-helper-{}",
        hex::encode(&Sha256::digest(entry)[..8])
    )
}

fn canonical(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn aot_builds_the_helper_in_the_cache_and_runs_it_with_the_same_arguments() {
    let fixture = Fixture::new("aot_helper_run");
    let (output, stdout, stderr) = fixture.run("execute", |_| {});
    assert_eq!(output.status.code(), Some(HELPER_EXIT), "{stderr}");
    assert!(stderr.contains("aot: generating"), "{stderr}");
    assert!(
        stderr.contains("stand-in cargo: a rendered diagnostic"),
        "cargo's stderr did not reach the user's:\n{stderr}"
    );
    assert_eq!(
        stdout, "the helper's stdout\n",
        "stdout is not the helper's alone"
    );

    let entries = fixture.entries();
    let [entry] = entries.as_slice() else {
        panic!("not one entry: {entries:?}");
    };
    let prefix = entry_prefix(&fib_sha256());
    assert!(
        entry.starts_with(&format!("{prefix}src-")) && entry.len() == prefix.len() + 20,
        "`{entry}` is not named for the ELF, version, generator and checkout"
    );
    let dir = fixture.cache().join(entry);
    for file in [
        "aot/Cargo.toml",
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain",
        "src/main.rs",
    ] {
        assert!(dir.join(file).is_file(), "no {file} in the entry");
    }
    let name = format!("name = \"{}\"", package(entry));
    assert!(
        fs::read_to_string(dir.join("Cargo.toml"))
            .expect("the entry's manifest")
            .lines()
            .any(|line| line == name),
        "the entry's package is not named for it"
    );

    assert_eq!(
        fixture.log("cargo").as_deref(),
        Some(
            format!(
                "{}\nbuild --release --message-format=json-render-diagnostics --target-dir {}\n",
                canonical(&dir).display(),
                fixture.cache().join("target").display()
            )
            .as_str()
        ),
        "cargo was not run once, in the entry, into the shared target dir"
    );
    assert_eq!(
        fixture.log("helper").as_deref(),
        Some(format!("1\npico execute --aot --elf {FIB_ELF}\n").as_str()),
    );

    let (output, _, stderr) = fixture.run("prove", |_| {});
    assert_eq!(output.status.code(), Some(HELPER_EXIT), "{stderr}");
    assert!(
        !stderr.contains("aot: generating"),
        "the entry was not reused:\n{stderr}"
    );
    assert_eq!(
        fixture.log("helper").as_deref(),
        Some(format!("1\npico prove --aot --elf {FIB_ELF}\n").as_str()),
    );
    assert_eq!(
        fixture.log("cargo").map(|log| log.lines().count()),
        Some(4),
        "every run builds the helper, for Cargo to say whether it is current"
    );
}

#[test]
fn entries_share_the_target_dir_and_keep_their_own_helpers() {
    let fixture = Fixture::new("aot_helper_shared_target");
    for elf in [FIB_ELF, OTHER_ELF] {
        let (output, _, stderr) = fixture.run_on("execute", elf, |_| {});
        assert_eq!(output.status.code(), Some(HELPER_EXIT), "{stderr}");
        assert_eq!(
            fixture.log("helper").as_deref(),
            Some(format!("1\npico execute --aot --elf {elf}\n").as_str()),
        );
    }

    let entries = fixture.entries();
    assert_eq!(entries.len(), 2, "{entries:?}");
    let target = fixture.cache().join("target");
    let build = format!(
        "build --release --message-format=json-render-diagnostics --target-dir {}",
        target.display()
    );
    let log = fixture.log("cargo").expect("the stand-in cargo's log");
    let builds: Vec<&str> = log.lines().skip(1).step_by(2).collect();
    assert_eq!(builds, [build.as_str(), build.as_str()], "{log}");

    let mut helpers: Vec<String> = fs::read_dir(target.join("a-target-triple/release"))
        .expect("the helpers")
        .map(|entry| {
            entry
                .expect("a helper")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    helpers.sort();
    let mut packages: Vec<String> = entries.iter().map(|entry| package(entry)).collect();
    packages.sort();
    assert_eq!(helpers, packages, "the entries' helpers are not their own");
}

#[test]
fn a_release_entry_is_created_only_for_a_release_with_aot_and_its_tag() {
    let fixture = Fixture::new("aot_helper_release");
    let tagged = stand_in_pico(
        &fixture.dir.join("tagged.git"),
        Some(&format!("v{VERSION}")),
    );
    let untagged = stand_in_pico(&fixture.dir.join("untagged.git"), None);

    if !release_has_aot() {
        let (output, _, stderr) = fixture.run("execute", |command| {
            from_release(command, &tagged);
        });
        assert_error(&output, &stderr, "the first Pico release with AOT");
        assert_eq!(
            fixture.log("cargo"),
            None,
            "cargo ran for a release without AOT"
        );
        assert!(
            !fixture.cache().exists(),
            "an entry for a release without AOT"
        );
        return;
    }

    let (output, _, stderr) = fixture.run("execute", |command| {
        from_release(command, &untagged);
    });
    assert_error(&output, &stderr, &format!("has no tag `v{VERSION}`"));
    assert_eq!(fixture.log("cargo"), None, "cargo ran for a missing tag");
    assert!(!fixture.cache().exists(), "an entry for a missing tag");

    let (output, _, stderr) = fixture.run("execute", |command| {
        from_release(command, &tagged);
    });
    assert_eq!(output.status.code(), Some(HELPER_EXIT), "{stderr}");
    assert_eq!(fixture.entries(), [release_entry()]);
}

#[test]
fn a_cached_release_entry_is_not_checked_again() {
    let fixture = Fixture::new("aot_helper_release_cached");
    let entry = fixture.cache().join(release_entry());
    fs::create_dir_all(&entry).expect("the entry");
    fs::write(
        entry.join("Cargo.toml"),
        format!("[package]\nname = \"{}\"\n", package(&release_entry())),
    )
    .expect("the entry's manifest");
    // A check would fail whichever way the version falls: before AOT, or for the missing tag.
    let untagged = stand_in_pico(&fixture.dir.join("untagged.git"), None);

    let (output, _, stderr) = fixture.run("prove", |command| {
        from_release(command, &untagged);
    });
    assert_eq!(output.status.code(), Some(HELPER_EXIT), "{stderr}");
    assert!(!stderr.contains("aot: generating"), "{stderr}");
    let log = fixture.log("cargo").expect("the stand-in cargo's log");
    assert!(
        log.starts_with(&format!("{}\n", canonical(&entry).display())),
        "cargo did not build the cached entry:\n{log}"
    );
}

#[test]
fn the_helper_build_keeps_the_users_jobs_and_cargo_home_and_nothing_else_stripped() {
    let fixture = Fixture::new("aot_helper_build_env");
    let cargo_home = fixture.dir.join("cargo-home");
    let (output, _, stderr) = fixture.run("execute", |command| {
        command
            .env("CARGO_BUILD_JOBS", "2")
            .env("CARGO_HOME", &cargo_home)
            .env("CARGO_TARGET_DIR", fixture.dir.join("elsewhere"))
            .env("CARGO", "/the/outer/cargo")
            .env("RUSTUP_TOOLCHAIN", "the-outer-toolchain");
    });
    assert_eq!(output.status.code(), Some(HELPER_EXIT), "{stderr}");

    let env = fixture
        .log("cargo-env")
        .expect("the stand-in cargo's environment");
    let vars: Vec<&str> = env.lines().collect();
    for set in [
        "CARGO_BUILD_JOBS=2".to_owned(),
        format!("CARGO_HOME={}", cargo_home.display()),
    ] {
        assert!(vars.contains(&set.as_str()), "no `{set}` in:\n{env}");
    }
    for stripped in ["CARGO_TARGET_DIR=", "CARGO=", "RUSTUP_TOOLCHAIN="] {
        assert!(
            !vars.iter().any(|var| var.starts_with(stripped)),
            "`{stripped}` reached the helper build:\n{env}"
        );
    }
}

#[test]
fn a_helper_never_builds_another() {
    let fixture = Fixture::new("aot_helper_guard");
    let (output, _, stderr) = fixture.run("execute", |command| {
        command.env(HELPER_ENV, "1");
    });
    assert_error(&output, &stderr, "carries no AOT program");
    assert_eq!(fixture.log("cargo"), None, "a helper ran cargo");
    assert!(!fixture.cache().exists(), "a helper wrote to the cache");
}

#[test]
fn a_failed_build_is_an_error() {
    let fixture = Fixture::new("aot_helper_build_fails");
    let (output, _, stderr) = fixture.run("execute", |command| {
        command.env("PICO_TEST_CARGO_EXIT", "3");
    });
    assert_error(&output, &stderr, "building the AOT helper");
    assert_eq!(
        fixture.log("helper"),
        None,
        "a helper whose build failed was run"
    );
}
