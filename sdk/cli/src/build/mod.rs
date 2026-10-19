use anyhow::{bail, Context};
use cargo_metadata::Package;
use std::{
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
};

#[allow(clippy::module_inception)]
pub mod build;

/// Runs `command` to completion with each line of its output shown as it comes, prefixed.
pub(crate) fn execute_command(mut command: Command) -> anyhow::Result<()> {
    println!("Start to execute command...");
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("cannot run `{}`", crate::spell(&command)))?;
    let stdout = BufReader::new(child.stdout.take().unwrap());
    let stderr = BufReader::new(child.stderr.take().unwrap());

    let msg = "[pico]";
    let stdout_handle = thread::spawn(move || {
        stdout.lines().for_each(|line| {
            println!("{} {}", msg, line.unwrap());
        });
    });
    stderr.lines().for_each(|line| {
        eprintln!("{} {}", msg, line.unwrap());
    });
    stdout_handle.join().unwrap();

    let result = child.wait().context("execution of the command failed")?;
    if result.success() {
        return Ok(());
    }
    match result.code() {
        Some(code) => bail!("Cargo build failed with code: {code}"),
        None => bail!("Cargo build failed"),
    }
}

/// The path in `target_dir` of the ELF that `bin` names, or of the package's only bin target.
pub fn find_target_file(
    program_pkg: &Package,
    target_dir: impl AsRef<Path>,
    bin: Option<&str>,
) -> anyhow::Result<PathBuf> {
    let bins: Vec<&str> = program_pkg
        .targets
        .iter()
        .filter(|target| {
            target.kind.contains(&"bin".to_owned())
                && target.crate_types.contains(&"bin".to_owned())
        })
        .map(|target| target.name.as_str())
        .collect();
    let listed = if bins.is_empty() {
        "none".to_string()
    } else {
        bins.join(", ")
    };
    let name = match (bin, bins.as_slice()) {
        (Some(name), _) if bins.contains(&name) => name,
        (Some(name), _) => bail!(
            "no bin target `{name}` in package `{}`; its bins: {listed}",
            program_pkg.name
        ),
        (None, [only]) => only,
        (None, []) => bail!("package `{}` has no bin target", program_pkg.name),
        (None, _) => bail!(
            "package `{}` has {} bin targets: {listed}; pass `--bin <name>` to build one",
            program_pkg.name,
            bins.len()
        ),
    };
    Ok(target_dir.as_ref().join(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A package with a lib target, which is never an ELF, beside `bins`.
    pub(super) fn package(bins: &[&str]) -> Package {
        let targets: Vec<_> = std::iter::once(json!({
            "name": "guest",
            "kind": ["lib"],
            "crate_types": ["lib"],
            "src_path": "/guest/src/lib.rs",
        }))
        .chain(bins.iter().map(|name| {
            json!({
                "name": name,
                "kind": ["bin"],
                "crate_types": ["bin"],
                "src_path": format!("/guest/src/bin/{name}.rs"),
            })
        }))
        .collect();
        serde_json::from_value(json!({
            "name": "guest",
            "version": "0.1.0",
            "id": "path+file:///guest#0.1.0",
            "dependencies": [],
            "features": {},
            "manifest_path": "/guest/Cargo.toml",
            "targets": targets,
        }))
        .unwrap()
    }

    fn error(result: anyhow::Result<PathBuf>) -> String {
        result.unwrap_err().to_string()
    }

    #[test]
    fn the_only_bin_needs_no_name() {
        let found = find_target_file(&package(&["first"]), "/release", None).unwrap();
        assert_eq!(found, Path::new("/release/first"));
    }

    #[test]
    fn two_bins_without_a_name_are_refused_and_listed() {
        let message = error(find_target_file(
            &package(&["first", "second"]),
            "/release",
            None,
        ));
        assert_eq!(
            message,
            "package `guest` has 2 bin targets: first, second; pass `--bin <name>` to build one"
        );
    }

    #[test]
    fn two_bins_with_a_name_pick_that_bin() {
        let found =
            find_target_file(&package(&["first", "second"]), "/release", Some("second")).unwrap();
        assert_eq!(found, Path::new("/release/second"));
    }

    #[test]
    fn an_unknown_bin_name_is_refused_and_the_bins_listed() {
        let message = error(find_target_file(
            &package(&["first", "second"]),
            "/release",
            Some("nope"),
        ));
        assert_eq!(
            message,
            "no bin target `nope` in package `guest`; its bins: first, second"
        );
    }

    #[test]
    fn a_package_without_bins_is_refused() {
        let pkg = package(&[]);
        assert_eq!(
            error(find_target_file(&pkg, "/release", None)),
            "package `guest` has no bin target"
        );
        assert_eq!(
            error(find_target_file(&pkg, "/release", Some("guest"))),
            "no bin target `guest` in package `guest`; its bins: none"
        );
    }
}
