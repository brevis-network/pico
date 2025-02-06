use anyhow::{Context, Error};
use cargo_metadata::Package;
use std::{
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
};

#[allow(clippy::module_inception)]
pub mod build;
pub mod utils;

// Execute the command and handle the output depending on the context.
pub(crate) fn execute_command(
    mut command: Command,
    target_dir: impl AsRef<Path>,
) -> Result<PathBuf, Option<i32>> {
    println!("Start to execute command...");
    // Add necessary tags for stdout and stderr from the command.
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn command")
        .expect("cargo build failed");
    let stdout = BufReader::new(child.stdout.take().unwrap());
    let stderr = BufReader::new(child.stderr.take().unwrap());

    // Add prefix to the output of the process depending on the context.
    let msg = "[pico]";

    // Pipe stdout and stderr to the parent process with [docker] prefix
    let stdout_handle = thread::spawn(move || {
        stdout.lines().for_each(|line| {
            println!("{} {}", msg, line.unwrap());
        });
    });
    stderr.lines().for_each(|line| {
        eprintln!("{} {}", msg, line.unwrap());
    });
    stdout_handle.join().unwrap();

    // Wait for the child process to finish and check the result.
    let result = child.wait().expect("execution of the command failed");
    if !result.success() {
        println!("error: {:?}", result.code());
        Err(result.code())
    } else {
        Ok(target_dir
            .as_ref()
            .join("riscv32im-risc0-zkvm-elf")
            .join("release"))
    }
}

/// Find the target file in the target directory.
pub fn find_target_file(
    program_pkg: Package,
    target_dir: impl AsRef<Path>,
) -> anyhow::Result<PathBuf> {
    let target_dir: &Path = target_dir.as_ref();
    let elf_paths = program_pkg
        .targets
        .into_iter()
        .filter(move |target| {
            target.kind.contains(&"bin".to_owned())
                && target.crate_types.contains(&"bin".to_owned())
        })
        .collect::<Vec<_>>();
    if elf_paths.len() != 1 {
        Err(Error::msg(format!(
            "Expected 1 target, got {}: {:#?}",
            elf_paths.len(),
            elf_paths
        )))
    } else {
        Ok(target_dir.join(&elf_paths[0].name))
    }
}
