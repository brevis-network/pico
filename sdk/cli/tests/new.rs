//! `cargo pico new`, driven through the binary against a local template repository, so that no case
//! reaches the network.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

#[path = "../../prover/src/tests/scratch.rs"]
mod scratch;
use scratch::scratch_dir;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const PROJECT: &str = "app";

/// Git with an identity, which CI does not configure and `new`'s initial commit needs, and with the
/// caller's global and system configuration cut off, so that neither can decide a case.
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
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn write_source(work: &Path, source: &str) {
    fs::write(work.join("SOURCE"), source).expect("write SOURCE");
}

/// A bare repository with a `main` and an `evm` branch whose `SOURCE` file names the branch. When
/// `released`, each branch's tip sits one commit past the release tag `new` looks for, whose
/// `SOURCE` names the tag. A `no-manifest` branch has no `Cargo.toml`, and a `forge` branch has a
/// contract test that imports forge-std.
fn template(dir: &Path, released: bool) -> PathBuf {
    let work = dir.join("work");
    fs::create_dir(&work).expect("create work tree");
    git(&work, &["init", "-q"]);
    git(&work, &["symbolic-ref", "HEAD", "refs/heads/main"]);
    fs::write(work.join("README"), "a template\n").expect("write README");
    git(&work, &["add", "."]);
    git(&work, &["commit", "-qm", "start"]);

    let branches = [
        ("main", format!("v{VERSION}")),
        ("evm", format!("evm-v{VERSION}")),
    ];
    for (branch, tag) in &branches {
        git(&work, &["checkout", "-qB", branch, "main"]);
        fs::write(
            work.join("Cargo.toml"),
            "[package]\nname = \"$PROJECT_NAME$\"\n",
        )
        .expect("write Cargo.toml");
        write_source(&work, &format!("{tag} tag"));
        git(&work, &["add", "."]);
        git(&work, &["commit", "-qm", "release"]);
        if released {
            git(&work, &["tag", "-a", "-m", "release", tag]);
        }
        write_source(&work, &format!("{branch} branch"));
        git(&work, &["commit", "-qam", "tip"]);
    }

    git(&work, &["checkout", "-q", "--orphan", "no-manifest"]);
    git(&work, &["rm", "-rfq", "."]);
    write_source(&work, "no-manifest branch");
    git(&work, &["add", "."]);
    git(&work, &["commit", "-qm", "no manifest"]);

    git(&work, &["checkout", "-qB", "forge", "main"]);
    fs::create_dir_all(work.join("contracts/test")).expect("create contracts/test");
    fs::write(
        work.join("contracts/test/Fibonacci.t.sol"),
        "import \"forge-std/Test.sol\";\n",
    )
    .expect("write the contract test");
    write_source(&work, "forge branch");
    git(&work, &["add", "."]);
    git(&work, &["commit", "-qm", "forge"]);

    let bare = dir.join("template.git");
    git(
        dir,
        &["clone", "-q", "--bare", "work", bare.to_str().unwrap()],
    );
    bare
}

/// `cargo pico new` in `dir`. Its output goes to pipes, so it must carry no escape code.
fn cargo_pico_new(dir: &Path, template_url: &Path, args: &[&str]) -> (Output, String, String) {
    cargo_pico_new_with(dir, template_url, args, |_| {})
}

fn cargo_pico_new_with(
    dir: &Path,
    template_url: &Path,
    args: &[&str],
    configure: impl FnOnce(&mut Command),
) -> (Output, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cargo-pico"));
    command
        .args(["pico", "new", PROJECT, "--template-url"])
        .arg(template_url)
        .args(args)
        .current_dir(dir)
        .env_remove("RUST_LOG")
        .env_remove("RUST_LOGGER");
    isolated_git_env(&mut command);
    configure(&mut command);
    let out = command.output().expect("run cargo-pico");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stdout.contains('\x1b') && !stderr.contains('\x1b'),
        "an escape code written to a pipe:\n{stdout}\n{stderr}"
    );
    (out, stdout, stderr)
}

fn read(project: &Path, file: &str) -> String {
    fs::read_to_string(project.join(file)).unwrap_or_else(|e| panic!("read {file}: {e}"))
}

fn assert_named(project: &Path) {
    assert_eq!(
        read(project, "Cargo.toml"),
        format!("[package]\nname = \"{PROJECT}\"\n")
    );
}

fn fallback_note(release: &str, branch: &str) -> String {
    format!("the template has no release `{release}`; using its `{branch}` branch")
}

#[test]
fn the_release_tag_is_cloned_into_a_fresh_repository() {
    let dir = scratch_dir("new_release_tag");
    let url = template(&dir, true);

    let (out, stdout, stderr) = cargo_pico_new(&dir, &url, &[]);
    assert!(out.status.success(), "{stdout}\n{stderr}");

    let project = dir.join(PROJECT);
    assert_eq!(read(&project, "SOURCE"), format!("v{VERSION} tag"));
    assert!(!stderr.contains("has no release"), "{stderr}");
    assert_named(&project);
    // The template's own history would carry a remote and its commits.
    assert_eq!(git(&project, &["remote"]), "");
    assert_eq!(
        git(&project, &["log", "--format=%s", "main"]),
        "Initial commit\n"
    );
    assert_eq!(git(&project, &["status", "--porcelain"]), "");
}

#[test]
fn the_branch_is_cloned_with_a_note_when_the_template_has_no_release() {
    let dir = scratch_dir("new_no_release");
    let url = template(&dir, false);

    let (out, stdout, stderr) = cargo_pico_new(&dir, &url, &[]);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(
        stderr.contains(&fallback_note(&format!("v{VERSION}"), "main")),
        "{stderr}"
    );

    let project = dir.join(PROJECT);
    assert_eq!(read(&project, "SOURCE"), "main branch");
    assert_named(&project);
}

#[test]
fn the_evm_template_takes_its_own_release_tag_without_vcs() {
    let dir = scratch_dir("new_evm_release_tag");
    let url = template(&dir, true);

    let (out, stdout, stderr) = cargo_pico_new(&dir, &url, &["--template", "evm", "--vcs", "none"]);
    assert!(out.status.success(), "{stdout}\n{stderr}");

    let project = dir.join(PROJECT);
    assert_eq!(read(&project, "SOURCE"), format!("evm-v{VERSION} tag"));
    assert!(!stderr.contains("has no release"), "{stderr}");
    assert_named(&project);
    assert!(!project.join(".git").exists());
}

#[test]
fn the_evm_template_falls_back_to_the_evm_branch() {
    let dir = scratch_dir("new_evm_no_release");
    let url = template(&dir, false);

    let (out, stdout, stderr) = cargo_pico_new(&dir, &url, &["--template", "evm", "--vcs", "none"]);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(
        stderr.contains(&fallback_note(&format!("evm-v{VERSION}"), "evm")),
        "{stderr}"
    );
    assert_eq!(read(&dir.join(PROJECT), "SOURCE"), "evm branch");
}

#[test]
fn an_evm_project_made_with_git_fetches_nothing_but_the_template() {
    let dir = scratch_dir("new_evm_git");
    let url = template(&dir, true);

    // Only local transports: anything `new` fetches from elsewhere fails it.
    let (out, stdout, stderr) =
        cargo_pico_new_with(&dir, &url, &["--template", "evm"], |command| {
            command.env("GIT_ALLOW_PROTOCOL", "file");
        });
    assert!(out.status.success(), "{stdout}\n{stderr}");

    let project = dir.join(PROJECT);
    assert_eq!(read(&project, "SOURCE"), format!("evm-v{VERSION} tag"));
    assert!(!project.join(".gitmodules").exists());
    assert_eq!(
        git(&project, &["log", "--format=%s", "main"]),
        "Initial commit\n"
    );
    assert_eq!(git(&project, &["status", "--porcelain"]), "");
}

#[test]
fn a_template_that_imports_forge_std_asks_for_the_submodule_and_only_warns_when_that_fails() {
    let dir = scratch_dir("new_forge_std");
    let url = template(&dir, true);

    // Only local transports: the submodule's clone from GitHub fails without reaching it.
    let (out, stdout, stderr) =
        cargo_pico_new_with(&dir, &url, &["--template-ref", "forge"], |command| {
            command.env("GIT_ALLOW_PROTOCOL", "file");
        });
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(stderr.contains("forge-std was not added"), "{stderr}");
    assert!(
        stderr.contains("git submodule add https://github.com/foundry-rs/forge-std"),
        "{stderr}"
    );

    let project = dir.join(PROJECT);
    assert!(!project.join(".gitmodules").exists());
    assert_eq!(
        git(&project, &["log", "--format=%s", "main"]),
        "Initial commit\n"
    );
    assert_eq!(git(&project, &["status", "--porcelain"]), "");
}

#[test]
fn a_template_ref_is_cloned_as_given_with_no_note() {
    let dir = scratch_dir("new_template_ref");
    let url = template(&dir, true);

    let (out, stdout, stderr) = cargo_pico_new(&dir, &url, &["--template-ref", "main"]);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(!stderr.contains("has no release"), "{stderr}");
    assert_eq!(read(&dir.join(PROJECT), "SOURCE"), "main branch");
}

#[test]
fn a_template_ref_that_does_not_exist_is_an_error_and_leaves_no_directory() {
    let dir = scratch_dir("new_missing_ref");
    let url = template(&dir, true);

    let (out, _, stderr) = cargo_pico_new(&dir, &url, &["--template-ref", "v0.0.0-missing"]);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("`v0.0.0-missing`") && stderr.contains("--template-ref"),
        "{stderr}"
    );
    assert!(!dir.join(PROJECT).exists());
}

#[test]
fn an_unreachable_template_is_an_error_carrying_git_s_message_and_leaves_no_directory() {
    let dir = scratch_dir("new_unreachable");

    let (out, _, stderr) = cargo_pico_new(&dir, &dir.join("missing.git"), &[]);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("fatal:"), "{stderr}");
    assert!(!dir.join(PROJECT).exists());
}

#[test]
fn a_failure_after_the_clone_removes_the_directory() {
    let dir = scratch_dir("new_no_manifest");
    let url = template(&dir, true);

    let (out, _, stderr) = cargo_pico_new(&dir, &url, &["--template-ref", "no-manifest"]);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("Cargo.toml"), "{stderr}");
    assert!(!dir.join(PROJECT).exists());
}

#[test]
fn an_empty_directory_that_existed_before_is_emptied_again_on_failure() {
    let dir = scratch_dir("new_existing_empty_dir");
    let url = template(&dir, true);
    let project = dir.join(PROJECT);
    fs::create_dir(&project).expect("create project dir");

    let (out, _, stderr) = cargo_pico_new(&dir, &url, &["--template-ref", "no-manifest"]);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("Cargo.toml"), "{stderr}");
    assert!(project.is_dir(), "the user's directory was removed");
    assert_eq!(fs::read_dir(&project).unwrap().count(), 0);
}

#[test]
fn a_directory_that_existed_before_is_left_as_it_was() {
    let dir = scratch_dir("new_existing_dir");
    let url = template(&dir, true);
    let project = dir.join(PROJECT);
    fs::create_dir(&project).expect("create project dir");
    fs::write(project.join("mine"), "kept\n").expect("write mine");

    let (out, _, stderr) = cargo_pico_new(&dir, &url, &[]);
    assert!(!out.status.success(), "{stderr}");
    // The clone's own message, which only a piped stderr can carry.
    assert!(stderr.contains("already exists"), "{stderr}");
    assert_eq!(read(&project, "mine"), "kept\n");
}

#[test]
fn a_failed_initial_commit_keeps_the_project_and_says_why() {
    let dir = scratch_dir("new_no_identity");
    let url = template(&dir, true);

    // No identity, and none guessed from the host: a machine git was never configured on.
    let (out, stdout, stderr) = cargo_pico_new_with(&dir, &url, &[], |command| {
        command
            .env_remove("GIT_AUTHOR_NAME")
            .env_remove("GIT_AUTHOR_EMAIL")
            .env_remove("GIT_COMMITTER_NAME")
            .env_remove("GIT_COMMITTER_EMAIL")
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "user.useConfigOnly")
            .env("GIT_CONFIG_VALUE_0", "true");
    });
    assert!(out.status.success(), "{stdout}\n{stderr}");
    assert!(stderr.contains("no initial commit was made"), "{stderr}");
    assert!(stderr.contains("git commit"), "{stderr}");

    let project = dir.join(PROJECT);
    assert_named(&project);
    assert_eq!(
        git(&project, &["symbolic-ref", "HEAD"]),
        "refs/heads/main\n"
    );
    assert!(git(&project, &["status", "--porcelain"]).contains("A  SOURCE"));
}

#[test]
fn a_dangling_link_where_the_project_would_go_is_left_alone() {
    let dir = scratch_dir("new_dangling_link");
    let url = template(&dir, true);
    let project = dir.join(PROJECT);
    std::os::unix::fs::symlink(dir.join("nowhere"), &project).expect("link");

    let (out, _, stderr) = cargo_pico_new(&dir, &url, &[]);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        fs::symlink_metadata(&project).is_ok(),
        "the link was removed"
    );
}
