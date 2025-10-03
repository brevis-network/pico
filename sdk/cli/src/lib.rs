use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::Error;
use cargo_metadata::MetadataCommand;

pub mod build;
pub mod subcommand;

pub const DEFAULT_ELF_DIR: &str = "elf";

pub fn log_command(command: &Command) {
    let command_string = format!(
        "{} {}",
        command.get_program().to_string_lossy(),
        command
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!("Command: {:?}", command_string);
}

/// get the target directory by the manifest file
pub fn get_target_directory(manifest_path: &Path) -> Result<PathBuf, Error> {
    Ok(MetadataCommand::new()
        .manifest_path(manifest_path)
        .no_deps()
        .exec()?
        .target_directory
        .into())
}

pub fn get_rustc_path(toolchain: &str) -> String {
    let rustc_output = clean_command_env("rustup")
        .args([toolchain, "which", "rustc"])
        .output()
        .expect("Failed to find nightly toolchain")
        .stdout;

    String::from_utf8(rustc_output).unwrap().trim().to_string()
}

pub fn clean_command_env(name: &str) -> Command {
    let mut cmd = Command::new(name);
    for (key, _val) in env::vars().filter(|x| x.0.starts_with("CARGO")) {
        cmd.env_remove(key);
    }
    cmd.env_remove("RUSTUP_TOOLCHAIN");
    cmd
}
