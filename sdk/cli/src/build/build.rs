use super::{execute_command, find_target_file};
use crate::{
    clean_command_env, log_command,
    subcommand::{build::BuildArgs, install::Rustup},
    RUSTUP_TOOLCHAIN_NAME,
};
use anyhow::{bail, Context, Error, Result};
use cargo_metadata::{MetadataCommand, Package};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const TARGET_TRIPLE: &str = "riscv64im-pico-zkvm-elf";
/// The copied ELF's name when neither `--elf-name` nor `--bin` gives one.
const TARGET_ELF: &str = TARGET_TRIPLE;

pub fn build_program(args: &BuildArgs, program_dir: Option<PathBuf>) -> Result<PathBuf, Error> {
    // Checked here rather than left to cargo, whose message for a missing toolchain is rustup's
    // and names no fix.
    if !Rustup::default().installed(RUSTUP_TOOLCHAIN_NAME) {
        bail!("the `{RUSTUP_TOOLCHAIN_NAME}` toolchain is not installed; run `cargo pico install`");
    }
    let program_dir = match program_dir {
        Some(dir) => dir,
        None => env::current_dir().context("reading the current directory")?,
    };

    let (pkg, target_dir) = get_package(&program_dir)?;
    let build_dir = target_dir.join(TARGET_TRIPLE).join("release");
    let binary_file = find_target_file(&pkg, &build_dir, args.binary())?;
    fs::create_dir_all(&target_dir)
        .with_context(|| format!("creating {}", target_dir.display()))?;

    // The flags are set whole, so neither variable reaches the build: `CARGO_ENCODED_RUSTFLAGS` is
    // replaced, and it outranks `RUSTFLAGS`.
    for name in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"] {
        if env::var_os(name).is_some_and(|value| !value.is_empty()) {
            eprintln!("warning: {name} is ignored for the guest build; pass `--rustflags` instead");
        }
    }
    // Trimming remaps sources, not the target dir that build scripts generate sources into. A path
    // dependency outside the workspace still moves the ELF: cargo hashes its absolute path into
    // `-C metadata`, which reaches symbol hashes and type ids, and no rustc flag undoes that.
    let target_remap = format!("--remap-path-prefix={}=/pico/target", target_dir.display());
    let rust_flags: Vec<&str> = std::iter::once(target_remap.as_str())
        .chain(
            args.rustflags
                .iter()
                .flat_map(|flags| flags.split_whitespace()),
        )
        .collect();

    let mut build_command: Command = create_cargo_build_command("build", &rust_flags);
    build_command.args(cargo_build_args(args, &pkg, &target_dir));

    log_command(&build_command);

    env::vars()
        .map(|v| v.0)
        .filter(|v| v.starts_with("CARGO_FEATURE_") || v.starts_with("CARGO_CFG_"))
        .fold(&mut build_command, Command::env_remove);

    execute_command(build_command)?;
    println!("Build directory: {:?}", build_dir.display());
    println!("Found binary file: {:?}", binary_file.display());

    let output_dir = program_dir.join(&args.output_directory);
    println!("Copying binary file to {:?}", output_dir);

    copy_elf_file(args, binary_file, output_dir)
}

fn cargo_build_args(args: &BuildArgs, pkg: &Package, target_dir: &Path) -> Vec<String> {
    let mut cargo_args = Vec::new();
    if !args.features.is_empty() {
        cargo_args.extend(["--features".to_string(), args.features.join(",")]);
    }
    if args.no_default_features {
        cargo_args.push("--no-default-features".to_string());
    }
    if args.ignore_rust_version {
        cargo_args.push("--ignore-rust-version".to_string());
    }
    if let Some(bin) = args.binary() {
        cargo_args.extend(["--bin".to_string(), bin.to_string()]);
    }
    cargo_args.extend([
        "--manifest-path".to_string(),
        pkg.manifest_path.to_string(),
        "--target-dir".to_string(),
        target_dir.display().to_string(),
    ]);
    cargo_args
}

pub fn create_cargo_build_command(subcmd: &str, rust_flags: &[&str]) -> Command {
    let toolchain = format!("+{RUSTUP_TOOLCHAIN_NAME}");

    let mut cmd = clean_command_env("cargo");
    let args = vec![
        &toolchain,
        subcmd,
        "--release",
        "--target",
        TARGET_TRIPLE,
        "-Z",
        "build-std=alloc,core,proc_macro,panic_abort,std",
        "-Z",
        "build-std-features=compiler-builtins-mem",
        // Panic locations and `file!()` are string data in the ELF, and its memory image is the
        // program id. Trimmed, the toolchain, the cargo home and every dependency outside the
        // workspace appear by name and version, not by where this machine keeps them.
        "-Z",
        "trim-paths",
        "--config",
        "profile.release.trim-paths=\"all\"",
    ];

    println!("Building guest package: cargo {}", args.join(" "));

    let encoded_rust_flags = encode_rust_flags(rust_flags);

    cmd.env("CARGO_ENCODED_RUSTFLAGS", encoded_rust_flags)
        .args(args);
    cmd
}
/// Returns a string that can be set as the value of CARGO_ENCODED_RUSTFLAGS when compiling guests
pub(crate) fn encode_rust_flags(rustc_flags: &[&str]) -> String {
    [
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
            // getrandom 0.4 (reached through p3's `rand`) has no backend for this target and
            // refuses to compile without one; `pico_sdk` supplies it.
            "--cfg",
            "getrandom_backend=\"custom\"",
        ],
    ]
    .concat()
    .join("\x1f")
}

/// Returns the given cargo Package from the metadata in the Cargo.toml manifest
/// within the provided `manifest_dir`, and the target directory it builds into.
pub fn get_package(manifest_dir: impl AsRef<Path>) -> Result<(Package, PathBuf)> {
    let manifest_dir = manifest_dir.as_ref();
    let manifest_path = manifest_dir.join("Cargo.toml");
    if !manifest_path.is_file() {
        bail!("no Cargo.toml in {}; pass --path", manifest_dir.display());
    }
    let manifest_path = fs::canonicalize(&manifest_path)
        .with_context(|| format!("cannot resolve {}", manifest_path.display()))?;
    let manifest_meta = MetadataCommand::new()
        .manifest_path(&manifest_path)
        .no_deps()
        .exec()
        .context("cargo metadata command failed")?;
    let target_dir = manifest_meta.target_directory.into();
    let mut matching: Vec<Package> = manifest_meta
        .packages
        .into_iter()
        .filter(|pkg| {
            let std_path: &Path = pkg.manifest_path.as_ref();
            std_path == manifest_path
        })
        .collect();
    match matching.len() {
        0 => bail!(
            "no package found in {}; pass --path",
            manifest_dir.display()
        ),
        1 => Ok((matching.remove(0), target_dir)),
        _ => bail!("multiple packages found in {}", manifest_dir.display()),
    }
}

fn copy_elf_file(args: &BuildArgs, from: PathBuf, to_dir: PathBuf) -> Result<PathBuf> {
    let elf_name = args.elf_name().or(args.binary()).unwrap_or(TARGET_ELF);
    fs::create_dir_all(&to_dir).with_context(|| format!("creating {}", to_dir.display()))?;
    let to_file = to_dir.join(elf_name);
    fs::copy(&from, &to_file)
        .with_context(|| format!("copying {} to {}", from.display(), to_file.display()))?;
    Ok(to_file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::tests::package;
    use clap::Parser;

    fn cargo_args(cli: &[&str]) -> Vec<String> {
        let args =
            BuildArgs::try_parse_from(std::iter::once("build").chain(cli.iter().copied())).unwrap();
        cargo_build_args(&args, &package(&["first", "second"]), Path::new("/target"))
    }

    fn has(args: &[String], flag: &str) -> bool {
        args.iter().any(|arg| arg == flag)
    }

    #[test]
    fn no_default_features_reaches_cargo_only_when_set() {
        assert!(!has(&cargo_args(&[]), "--no-default-features"));
        assert!(has(
            &cargo_args(&["--no-default-features"]),
            "--no-default-features"
        ));
    }

    #[test]
    fn ignore_rust_version_reaches_cargo_only_when_set() {
        assert!(!has(&cargo_args(&[]), "--ignore-rust-version"));
        assert!(has(
            &cargo_args(&["--ignore-rust-version"]),
            "--ignore-rust-version"
        ));
    }

    #[test]
    fn bin_reaches_cargo_with_its_name_only_when_set() {
        assert!(!has(&cargo_args(&[]), "--bin"));
        assert!(!has(&cargo_args(&["--bin", ""]), "--bin"));
        for spelling in ["--bin", "--binary"] {
            let args = cargo_args(&[spelling, "second"]);
            assert!(
                args.windows(2).any(|pair| pair == ["--bin", "second"]),
                "{args:?}"
            );
        }
    }

    #[test]
    fn features_reach_cargo_joined_only_when_set() {
        assert!(!has(&cargo_args(&[]), "--features"));
        let args = cargo_args(&["--features", "a,b", "--features", "c"]);
        assert!(
            args.windows(2).any(|pair| pair == ["--features", "a,b,c"]),
            "{args:?}"
        );
    }

    #[test]
    fn a_directory_without_a_manifest_is_refused() {
        let message = get_package("/no/such/guest").unwrap_err().to_string();
        assert_eq!(message, "no Cargo.toml in /no/such/guest; pass --path");
    }

    #[test]
    fn manifest_and_target_dir_are_always_passed() {
        let args = cargo_args(&[]);
        assert_eq!(
            args,
            [
                "--manifest-path",
                "/guest/Cargo.toml",
                "--target-dir",
                "/target"
            ]
        );
    }
}
