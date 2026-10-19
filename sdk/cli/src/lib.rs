use anyhow::{bail, Context, Result};
use std::{env, fs, io, path::Path, process::Command};

pub mod aot_helper;
pub mod build;
mod cli;
pub mod groth16;
pub mod guest;
pub mod options;
pub mod source;
pub mod subcommand;

#[cfg(feature = "aot")]
pub use aot_helper::run_with_aot;
pub use cli::run;

pub const DEFAULT_ELF_DIR: &str = "elf";
/// The guest toolchain's name in rustup: `cargo pico install` links it, `cargo pico build` builds
/// with it.
pub const RUSTUP_TOOLCHAIN_NAME: &str = "pico";

pub fn log_command(command: &Command) {
    println!("Command: {:?}", spell(command));
}

/// `command` as it would be typed: its program and arguments, space-separated.
pub fn spell(command: &Command) -> String {
    std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|part| part.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Runs `command` with its output captured, so that a failure carries the command's own message:
/// its spelling and its stderr unless it exits 0. Returns its stdout, trimmed.
pub fn run_captured(command: &mut Command) -> Result<String> {
    let spelled = spell(command);
    let output = command
        .output()
        .with_context(|| format!("cannot run `{spelled}`"))?;
    if !output.status.success() {
        bail!(
            "`{spelled}` failed ({}):\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim_end()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Removes `path` whatever it is, without following a link. A path that is not there is fine.
pub fn remove_path(path: &Path) -> Result<()> {
    let removed = match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => Err(e),
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
    };
    removed.with_context(|| format!("removing {}", path.display()))
}

/// `name` without the variables that describe the invocation `cargo pico` runs in (the outer
/// cargo's `CARGO`, its package and build-script variables, rustup's toolchain override), any of
/// which would steer a nested cargo.
pub fn clean_command_env(name: &str) -> Command {
    clean_command_env_from(
        name,
        env::vars_os().filter_map(|(key, _)| key.into_string().ok()),
    )
}

fn clean_command_env_from(name: &str, keys: impl IntoIterator<Item = String>) -> Command {
    let mut cmd = Command::new(name);
    for key in keys {
        if key.starts_with("CARGO") && !reaches_nested_cargo(&key) {
            cmd.env_remove(key);
        }
    }
    cmd.env_remove("RUSTUP_TOOLCHAIN");
    cmd
}

/// The user's settings for where crates come from and how many jobs build them. Without them a
/// guest build behind a proxy cannot fetch, and one with a moved cargo home fetches into
/// `~/.cargo`.
fn reaches_nested_cargo(key: &str) -> bool {
    matches!(key, "CARGO_HOME" | "CARGO_BUILD_JOBS")
        || [
            "CARGO_NET_",
            "CARGO_HTTP_",
            "CARGO_REGISTRY_",
            "CARGO_REGISTRIES_",
        ]
        .iter()
        .any(|prefix| key.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn a_nested_cargo_keeps_the_users_fetch_settings_and_loses_the_outer_invocation() {
        let keys = [
            "CARGO",
            "CARGO_PKG_NAME",
            "CARGO_MANIFEST_DIR",
            "CARGO_TARGET_DIR",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_HOME",
            "CARGO_BUILD_JOBS",
            "CARGO_NET_GIT_FETCH_WITH_CLI",
            "CARGO_HTTP_PROXY",
            "CARGO_REGISTRY_TOKEN",
            "CARGO_REGISTRIES_MINE_INDEX",
            "PATH",
        ];
        let command = clean_command_env_from("cargo", keys.map(String::from));
        let removed: BTreeSet<&str> = command
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(key, _)| key.to_str().unwrap())
            .collect();
        assert_eq!(
            removed,
            BTreeSet::from([
                "CARGO",
                "CARGO_ENCODED_RUSTFLAGS",
                "CARGO_MANIFEST_DIR",
                "CARGO_PKG_NAME",
                "CARGO_TARGET_DIR",
                "RUSTUP_TOOLCHAIN",
            ])
        );
    }
}
