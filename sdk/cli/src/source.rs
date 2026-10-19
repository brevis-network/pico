//! Where crates this CLI generates take Pico's packages from.
//!
//! By default from this CLI's release tag, the source a project template pins: Cargo then resolves
//! one copy of each Pico package for a project and its generated crates, and so one `pico-vm`,
//! whose types the two sides share. A `rev` of the same commit would be a second source and a
//! second copy, and the generated `AOT` would not typecheck against the project's prover. With
//! [`PICO_SOURCE_ENV`] set, from that checkout instead, for a CLI built ahead of its tag.
//!
//! Only releases from 3.0.0 on have AOT, and a CLI can be built before its release is tagged, so
//! [`check_release`] confirms both before AOT takes Pico from the release.

use std::{env, fs, path::Path, process::Command};

use anyhow::{anyhow, bail, Context, Result};
use cargo_metadata::semver::Version;

use crate::run_captured;

/// A Pico checkout to take Pico's packages from instead of the release.
pub const PICO_SOURCE_ENV: &str = "PICO_SOURCE";

const PICO_REPOSITORY_URL: &str = "https://github.com/brevis-network/pico";

/// The first Pico release with `aot-runtime`, and `pico-cli`'s `aot` feature.
const FIRST_AOT_RELEASE: Version = Version::new(3, 0, 0);

/// [`PICO_SOURCE_ENV`] made absolute, or `None` when it is unset or empty.
pub fn pico_source() -> Result<Option<String>> {
    let Some(source) = env::var_os(PICO_SOURCE_ENV).filter(|source| !source.is_empty()) else {
        return Ok(None);
    };
    // Absolute, because the manifests that name it sit at different depths.
    let source = fs::canonicalize(&source)
        .with_context(|| format!("{PICO_SOURCE_ENV}=`{}`", Path::new(&source).display()))?;
    source
        .into_os_string()
        .into_string()
        .map(Some)
        .map_err(|source| {
            anyhow!(
                "{PICO_SOURCE_ENV}=`{}` is not UTF-8",
                Path::new(&source).display()
            )
        })
}

/// The fields of a dependency on the Pico package at `package_dir` in a Pico checkout, e.g.
/// `aot-runtime`: from the checkout at `pico_source`, or else from this CLI's release tag.
pub fn pico_dependency(pico_source: Option<&str>, package_dir: &str) -> String {
    match pico_source {
        Some(root) => format!("path = {}", toml_string(&format!("{root}/{package_dir}"))),
        None => format!(
            "git = \"{PICO_REPOSITORY_URL}\", tag = \"{}\"",
            release_tag()
        ),
    }
}

/// This CLI's release tag in the public repository.
pub fn release_tag() -> String {
    format!("v{}", env!("CARGO_PKG_VERSION"))
}

/// Whether this CLI's release has AOT.
pub fn release_has_aot() -> bool {
    has_aot(&release_version())
}

/// Checks that this CLI's release has AOT and that the public repository carries its tag. When
/// git cannot reach the repository it only warns, for Cargo may have fetched the tag before.
pub fn check_release() -> Result<()> {
    check_release_at(PICO_REPOSITORY_URL, &release_version())
}

fn release_version() -> Version {
    Version::parse(env!("CARGO_PKG_VERSION")).expect("Cargo's package version is semver")
}

/// Unlike in semver's order, a pre-release of the first release with AOT has it.
fn has_aot(version: &Version) -> bool {
    (version.major, version.minor, version.patch)
        >= (
            FIRST_AOT_RELEASE.major,
            FIRST_AOT_RELEASE.minor,
            FIRST_AOT_RELEASE.patch,
        )
}

fn check_release_at(url: &str, version: &Version) -> Result<()> {
    if !has_aot(version) {
        bail!(
            "this CLI's version, {version}, predates {FIRST_AOT_RELEASE}, the first Pico release \
             with AOT, so its release has no AOT crates to build against; set {PICO_SOURCE_ENV} \
             to a Pico checkout"
        );
    }
    let tag = format!("v{version}");
    match has_tag(url, &tag) {
        Ok(true) => Ok(()),
        Ok(false) => bail!(
            "{url} has no tag `{tag}`, this CLI's release, for the AOT crates to take Pico from; \
             set {PICO_SOURCE_ENV} to a Pico checkout"
        ),
        Err(error) => {
            eprintln!(
                "warning: cannot check that {url} has the tag `{tag}`, which Cargo may have \
                 fetched before: {error:#}"
            );
            Ok(())
        }
    }
}

fn has_tag(url: &str, tag: &str) -> Result<bool> {
    let pattern = format!("refs/tags/{tag}");
    let refs = run_captured(Command::new("git").args(["ls-remote", "--tags", url, &pattern]))?;
    Ok(!refs.is_empty())
}

fn toml_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_release_is_its_tag_in_the_public_repository() {
        assert_eq!(
            pico_dependency(None, "aot-runtime"),
            format!(
                r#"git = "https://github.com/brevis-network/pico", tag = "v{}""#,
                env!("CARGO_PKG_VERSION")
            )
        );
    }

    #[test]
    fn a_checkout_is_the_package_directory_inside_it() {
        assert_eq!(
            pico_dependency(Some("/src/pico"), "aot-runtime"),
            r#"path = "/src/pico/aot-runtime""#
        );
        assert_eq!(
            pico_dependency(Some(r#"/src/"a"\b"#), "sdk/prover"),
            r#"path = "/src/\"a\"\\b/sdk/prover""#
        );
    }

    fn version(version: &str) -> Version {
        Version::parse(version).expect("a version")
    }

    #[test]
    fn a_release_has_aot_from_the_first_release_with_it_and_its_pre_releases() {
        for without in ["2.1.2", "2.99.99", "0.3.0"] {
            assert!(!has_aot(&version(without)), "{without}");
        }
        for with in ["3.0.0-rc.1", "3.0.0", "3.0.1", "3.1.0", "10.0.0"] {
            assert!(has_aot(&version(with)), "{with}");
        }
    }

    /// A bare repository with one commit, tagged with each of `tags`.
    fn repository(tags: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let git = |args: &[&str]| {
            run_captured(
                Command::new("git")
                    .args(args)
                    .current_dir(dir.path())
                    .env("GIT_CONFIG_GLOBAL", "/dev/null")
                    .env("GIT_CONFIG_NOSYSTEM", "1")
                    .env("GIT_AUTHOR_NAME", "Pico")
                    .env("GIT_AUTHOR_EMAIL", "pico@example.com")
                    .env("GIT_COMMITTER_NAME", "Pico")
                    .env("GIT_COMMITTER_EMAIL", "pico@example.com"),
            )
            .expect("git")
        };
        git(&["init", "-q", "--bare"]);
        let tree = git(&["mktree"]);
        let commit = git(&["commit-tree", &tree, "-m", "release"]);
        for tag in tags {
            git(&["tag", tag, &commit]);
        }
        dir
    }

    fn url(repository: &tempfile::TempDir) -> &str {
        repository.path().to_str().expect("a UTF-8 path")
    }

    #[test]
    fn a_release_with_aot_and_its_tag_passes() {
        let repository = repository(&["v3.0.0", "v3.0.1-rc.1"]);
        check_release_at(url(&repository), &version("3.0.0")).expect("the tag is there");
        check_release_at(url(&repository), &version("3.0.1-rc.1")).expect("the tag is there");
    }

    #[test]
    fn a_release_whose_tag_is_missing_is_refused() {
        let repository = repository(&["v3.0.0", "v3.0.10"]);
        let error = check_release_at(url(&repository), &version("3.0.1"))
            .expect_err("no tag v3.0.1")
            .to_string();
        assert!(error.contains("has no tag `v3.0.1`"), "{error}");
        assert!(error.contains(PICO_SOURCE_ENV), "{error}");
    }

    #[test]
    fn a_release_before_aot_is_refused_even_when_tagged() {
        let repository = repository(&["v2.1.2"]);
        let error = check_release_at(url(&repository), &version("2.1.2"))
            .expect_err("2.1.2 predates AOT")
            .to_string();
        assert!(
            error.contains("predates 3.0.0, the first Pico release with AOT"),
            "{error}"
        );
        assert!(error.contains(PICO_SOURCE_ENV), "{error}");
    }

    #[test]
    fn an_unreachable_repository_only_warns() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let missing = dir.path().join("missing");
        let missing = missing.to_str().expect("a UTF-8 path");
        assert!(has_tag(missing, "v3.0.0").is_err(), "git reached nothing");
        check_release_at(missing, &version("3.0.0")).expect("a warning, not an error");
    }
}
