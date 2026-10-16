//! Build each patch guest under `vm/examples/patch-testing/patches` and run its prover. Run from
//! the repository root, with this tree's `cargo pico` on `PATH` (`cargo build --release -p pico-cli`
//! puts it in `target/release`). An older install fails every guest: `pico-sdk` pulls getrandom 0.4,
//! whose backend cfg only the current CLI passes.
//!
//! `secp256k1-sys` cross-compiles C, so a full run needs a RISC-V C compiler named for the guest
//! target, which the driver passes through rather than guesses, since its name depends on how it
//! was installed. Ubuntu's `gcc-riscv64-unknown-elf`:
//!
//! ```text
//! CC_riscv64im_pico_zkvm_elf=riscv64-unknown-elf-gcc
//! AR_riscv64im_pico_zkvm_elf=riscv64-unknown-elf-ar
//! CFLAGS_riscv64im_pico_zkvm_elf=-ffreestanding
//! ```
//!
//! Homebrew's is `riscv64-elf-gcc` / `riscv64-elf-ar`. `-ffreestanding` keeps gcc off the hosted
//! headers it does not ship, and `AR` matters on macOS, where the system `ar` writes an archive
//! index `rust-lld` cannot read.
//!
//! `PATCH_ELF_DIR`, when set, skips every guest build and runs each prover on
//! `$PATCH_ELF_DIR/<patch>/riscv64im-pico-zkvm-elf`, for a host that cannot build guests. Nothing
//! checks that those ELFs were built from the current sources, so build them from the revision
//! under test.

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Output},
};

enum Status {
    Success,
    Failed,
}

impl Status {
    fn as_symbol(&self) -> &str {
        match self {
            Status::Success => "\x1b[32m✓\x1b[0m", // Green checkmark
            Status::Failed => "\x1b[31m✗\x1b[0m",  // Red cross
        }
    }
}

struct Colors {
    blue: &'static str,
    green: &'static str,
    red: &'static str,
    yellow: &'static str,
    cyan: &'static str,
    reset: &'static str,
}

static COLORS: Colors = Colors {
    blue: "\x1b[1;34m",
    green: "\x1b[32m",
    red: "\x1b[31m",
    yellow: "\x1b[33m",
    cyan: "\x1b[1;36m",
    reset: "\x1b[0m",
};

/// Run a command and return its output or an error message.
fn run_command(
    command: &str,
    args: &[&str],
    current_dir: &Path,
    env_vars: Option<(&str, &Path)>,
) -> Result<Output, String> {
    let mut cmd = Command::new(command);
    cmd.args(args)
        .current_dir(current_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    if let Some((env_name, env_path)) = env_vars {
        let canonical_path = env_path
            .canonicalize()
            .map_err(|_| format!("Failed to canonicalize path: {}", env_path.display()))?;
        cmd.env(env_name, canonical_path);
    }

    cmd.output()
        .map_err(|e| format!("Failed to execute command: {}", e))
}

const ELF_NAME: &str = "riscv64im-pico-zkvm-elf";
const GUEST_CC: &str = "CC_riscv64im_pico_zkvm_elf";

fn build_app(app_dir: &Path) -> Result<Output, String> {
    run_command("cargo", &["pico", "build"], app_dir, None)
}

fn run_prover(prover_dir: &Path, elf_path: &Path) -> Result<Output, String> {
    run_command(
        "cargo",
        &["run", "--release", "--quiet"],
        prover_dir,
        Some(("ELF_PATH", elf_path)),
    )
}

fn validate_elf_exists(elf_path: &Path) -> bool {
    elf_path.exists()
}

fn print_tree_node(step: &str, status: &Status, is_last: bool) {
    let prefix = if is_last { "└── " } else { "├── " };
    println!("{}{} [{}]", prefix, step, status.as_symbol());
}

/// Print command output; propagate I/O errors.
fn print_command_output(output: &Output) -> io::Result<()> {
    if !output.stdout.is_empty() {
        println!("  {}Stdout:{}", COLORS.yellow, COLORS.reset);
        io::stdout().write_all(&output.stdout)?;
        println!();
    }
    if !output.stderr.is_empty() {
        println!("  {}Stderr:{}", COLORS.red, COLORS.reset);
        io::stderr().write_all(&output.stderr)?;
        println!();
    }
    Ok(())
}

/// Helper function to run a step and print its final status.
/// Returns an error string if the step fails.
fn execute_step<F>(name: &str, is_last: bool, action: F) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String>,
{
    match action() {
        Ok(()) => {
            print_tree_node(name, &Status::Success, is_last);
            Ok(())
        }
        Err(err) => {
            print_tree_node(name, &Status::Failed, is_last);
            Err(err)
        }
    }
}

fn test_patch(
    patch_path: &Path,
    total_patches: usize,
    current_index: usize,
    prebuilt: Option<&Path>,
) -> Result<(), String> {
    let patch_name = patch_path.file_name().unwrap().to_string_lossy();
    println!(
        "\n{}[{}/{}] Testing patch: {}{}",
        COLORS.blue,
        current_index + 1,
        total_patches,
        patch_name,
        COLORS.reset
    );
    println!("│");

    let app_dir = patch_path.join("app");
    let prover_dir = patch_path.join("prover");

    let elf_path = match prebuilt {
        Some(dir) => {
            let elf_path = dir.join(&*patch_name).join(ELF_NAME);
            println!(
                "├── Building ELF [skipped: PATCH_ELF_DIR gives {}]",
                elf_path.display()
            );
            elf_path
        }
        None => {
            let elf_path = app_dir.join("elf").join(ELF_NAME);
            // A stale ELF would pass validation even when this build produced nothing.
            match fs::remove_file(&elf_path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => {
                    return Err(format!("Failed to remove {}: {}", elf_path.display(), e));
                }
                _ => {}
            }

            execute_step("Building ELF", false, || {
                let output = build_app(&app_dir)?;
                if !output.status.success() {
                    println!(
                        "│  {}Build failed for patch: {}{}",
                        COLORS.red,
                        patch_path.display(),
                        COLORS.reset
                    );
                    if std::env::var_os(GUEST_CC).is_none() {
                        println!(
                            "│  {} is unset; the guest C toolchain is in vm/examples/test_patches.rs",
                            GUEST_CC
                        );
                    }
                    print_command_output(&output)
                        .map_err(|e| format!("Failed printing output: {}", e))?;
                    Err("Build step failed".to_string())
                } else {
                    Ok(())
                }
            })?;
            elf_path
        }
    };

    // Validating ELF
    execute_step("Validating ELF", false, || {
        if !validate_elf_exists(&elf_path) {
            println!(
                "│  {}ELF file not found at {}!{}",
                COLORS.red,
                elf_path.display(),
                COLORS.reset
            );
            Err("ELF file not found".to_string())
        } else {
            Ok(())
        }
    })?;

    // Running Prover
    execute_step("Running Prover", true, || {
        let output = run_prover(&prover_dir, &elf_path)?;
        if !output.status.success() {
            println!(
                "  {}Prover failed for patch: {}{}",
                COLORS.red,
                patch_path.display(),
                COLORS.reset
            );
            print_command_output(&output).map_err(|e| format!("Failed printing output: {}", e))?;
            Err("Prover step failed".to_string())
        } else {
            for line in String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|line| line.starts_with("patch result:"))
            {
                println!("    {}", line);
            }
            Ok(())
        }
    })?;

    Ok(())
}

fn find_patch_directories(base_dir: &Path) -> Vec<PathBuf> {
    match fs::read_dir(base_dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
            .map(|entry| entry.path())
            .collect(),
        Err(e) => {
            eprintln!(
                "{}Error reading directory {}: {}{}",
                COLORS.red,
                base_dir.display(),
                e,
                COLORS.reset
            );
            Vec::new()
        }
    }
}

/// Arguments, if any, name the patches to run; with none, every patch runs.
fn main() {
    let patches_dir = PathBuf::from("vm/examples/patch-testing/patches");
    let mut patch_dirs = find_patch_directories(&patches_dir);
    patch_dirs.sort();

    let wanted: Vec<String> = std::env::args().skip(1).collect();
    if let Some(unknown) = wanted
        .iter()
        .find(|name| !patch_dirs.iter().any(|dir| dir.ends_with(name.as_str())))
    {
        eprintln!(
            "{}No patch named {} in {}{}",
            COLORS.red,
            unknown,
            patches_dir.display(),
            COLORS.reset
        );
        std::process::exit(1);
    }
    if !wanted.is_empty() {
        patch_dirs.retain(|dir| wanted.iter().any(|name| dir.ends_with(name.as_str())));
    }

    if patch_dirs.is_empty() {
        eprintln!(
            "{}No patch directories found in {}{}",
            COLORS.red,
            patches_dir.display(),
            COLORS.reset
        );
        std::process::exit(1);
    }

    println!("{}== Patch Testing Summary =={}", COLORS.cyan, COLORS.reset);
    println!("Found {} patches to test", patch_dirs.len());

    let prebuilt = std::env::var_os("PATCH_ELF_DIR").map(PathBuf::from);
    let mut failed = Vec::new();
    for (i, patch_path) in patch_dirs.iter().enumerate() {
        match test_patch(patch_path, patch_dirs.len(), i, prebuilt.as_deref()) {
            Ok(()) => println!(
                "{}✓ Patch {} tested successfully.{}",
                COLORS.green,
                patch_path.display(),
                COLORS.reset
            ),
            Err(err) => {
                eprintln!(
                    "{}Error testing patch {}: {}{}",
                    COLORS.red,
                    patch_path.display(),
                    err,
                    COLORS.reset
                );
                failed.push(
                    patch_path
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }

    println!("\n{}== Testing Complete =={}", COLORS.cyan, COLORS.reset);
    if failed.is_empty() {
        println!(
            "Results: {}all {} patches tested successfully.{}",
            COLORS.green,
            patch_dirs.len(),
            COLORS.reset
        );
    } else {
        println!(
            "Results: {}{} of {} patches failed: {}{}",
            COLORS.red,
            failed.len(),
            patch_dirs.len(),
            failed.join(", "),
            COLORS.reset
        );
        std::process::exit(1);
    }
}
