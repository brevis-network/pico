use anyhow::{Error, Result};
use cargo_metadata::{MetadataCommand, Package};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use crate::{
    clean_command_env, get_rustc_path, get_target_directory, log_command,
    subcommand::build::BuildArgs,
};

use super::{execute_command, find_target_file};

const RUSTUP_TOOLCHAIN_NAME: &str = "nightly-2024-11-27";
const TARGET_ELF: &str = "riscv32im-pico-zkvm-elf";

pub fn build_program(args: &BuildArgs, program_dir: Option<PathBuf>) -> Result<PathBuf, Error> {
    let program_dir = program_dir.unwrap_or_else(|| std::env::current_dir().unwrap());

    let pkg = get_package(&program_dir);

    // get build directory by the manifest path
    let target_dir: PathBuf = get_target_directory(pkg.manifest_path.as_ref())?;
    fs::create_dir_all(&target_dir).unwrap();

    let rust_flags = vec![];

    let mut build_command: Command = create_cargo_build_command("build", &rust_flags);

    if !args.features.is_empty() {
        build_command.args(["--features", &args.features.join(",")]);
    }

    build_command.args([
        "--manifest-path",
        pkg.manifest_path.as_str(),
        "--target-dir",
        target_dir.to_str().unwrap(),
    ]);

    log_command(&build_command);

    env::vars()
        .map(|v| v.0)
        .filter(|v| v.starts_with("CARGO_FEATURE_") || v.starts_with("CARGO_CFG_"))
        .fold(&mut build_command, Command::env_remove);

    match execute_command(build_command, target_dir.clone()) {
        Ok(build_dir) => {
            println!("Build directory: {:?}", build_dir.display());

            let binary_file = find_target_file(pkg, build_dir)?;
            println!("Found binary file: {:?}", binary_file.display());

            let output_dir = target_dir.parent().unwrap().join(&args.output_directory);
            println!("Copying binary file to {:?}", output_dir);

            copy_elf_file(args, binary_file, output_dir)
        }
        Err(Some(code)) => Err(Error::msg(format!(
            "Cargo build failed with code: {}",
            code
        ))),
        Err(None) => Err(Error::msg("Cargo build failed")),
    }
}

pub fn create_cargo_build_command(subcmd: &str, rust_flags: &[&str]) -> Command {
    let toolchain = format!("+{RUSTUP_TOOLCHAIN_NAME}");

    let rustc = get_rustc_path(&toolchain);
    println!("rustc version: {rustc}");

    let mut cmd = clean_command_env("cargo");
    let mut args = vec![
        &toolchain,
        subcmd,
        "--release",
        "--target",
        "riscv32im-risc0-zkvm-elf",
    ];

    args.extend_from_slice(&[
        "-Z",
        "build-std=alloc,core,proc_macro,panic_abort,std",
        "-Z",
        "build-std-features=compiler-builtins-mem",
    ]);
    // cmd.env("__CARGO_TESTS_ONLY_SRC_ROOT", rust_src);
    // }

    println!("Building guest package: cargo {}", args.join(" "));

    let encoded_rust_flags = encode_rust_flags(rust_flags);

    cmd.env("RUSTC", rustc)
        .env("CARGO_ENCODED_RUSTFLAGS", encoded_rust_flags)
        .args(args);
    cmd
}
/// Returns a string that can be set as the value of CARGO_ENCODED_RUSTFLAGS when compiling guests
pub(crate) fn encode_rust_flags(rustc_flags: &[&str]) -> String {
    [
        // Append other rust flags
        rustc_flags,
        &[
            // Replace atomic ops with nonatomic versions since the guest is single threaded.
            "-C",
            "passes=lower-atomic",
            // Specify where to start loading the program in
            // memory.  The clang linker understands the same
            // command line arguments as the GNU linker does; see
            // https://ftp.gnu.org/old-gnu/Manuals/ld-2.9.1/html_mono/ld.html#SEC3
            // for details.
            "-C",
            &format!("link-arg=-Ttext=0x{:08X}", 0x0020_0800),
            // Apparently not having an entry point is only a linker warning(!), so
            // error out in this case.
            "-C",
            "link-arg=--fatal-warnings",
            "-C",
            "panic=abort",
        ],
    ]
    .concat()
    .join("\x1f")
}

/// Returns the given cargo Package from the metadata in the Cargo.toml manifest
/// within the provided `manifest_dir`.
pub fn get_package(manifest_dir: impl AsRef<Path>) -> Package {
    let manifest_path: PathBuf =
        fs::canonicalize(manifest_dir.as_ref().join("Cargo.toml")).unwrap();
    let manifest_meta = MetadataCommand::new()
        .manifest_path(&manifest_path)
        .no_deps()
        .exec()
        .expect("cargo metadata command failed");
    let mut matching: Vec<Package> = manifest_meta
        .packages
        .into_iter()
        .filter(|pkg| {
            let std_path: &Path = pkg.manifest_path.as_ref();
            std_path == manifest_path
        })
        .collect();
    if matching.is_empty() {
        eprintln!(
            "ERROR: No package found in {}",
            manifest_dir.as_ref().display()
        );
        std::process::exit(-1);
    }
    if matching.len() > 1 {
        eprintln!(
            "ERROR: Multiple packages found in {}",
            manifest_dir.as_ref().display()
        );
        std::process::exit(-1);
    }
    matching.pop().unwrap()
}

fn copy_elf_file(args: &BuildArgs, from: PathBuf, to_dir: PathBuf) -> Result<PathBuf> {
    let elf_name = if !args.elf_name.is_empty() {
        args.elf_name.clone()
    } else if !args.binary.is_empty() {
        args.binary.clone()
    } else {
        TARGET_ELF.to_string()
    };

    fs::create_dir_all(&to_dir)?;

    let to_file = to_dir.join(&elf_name);
    fs::copy(from, to_file.clone())?;

    Ok(to_file)
}

/// check if the docker is installed in the host machine
pub fn is_docker_installed() -> bool {
    // Run the `docker ps` command to check if the daemon is running
    let output = Command::new("docker").arg("ps").output();

    // Check if the command executed successfully
    match output {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}
