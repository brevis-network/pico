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

fn test_patch(patch_path: &Path, total_patches: usize, current_index: usize) -> Result<(), String> {
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
    let elf_path = app_dir.join("elf").join("riscv32im-pico-zkvm-elf");

    // Building ELF
    execute_step("Building ELF", false, || {
        let output = build_app(&app_dir)?;
        if !output.status.success() {
            println!(
                "│  {}Build failed for patch: {}{}",
                COLORS.red,
                patch_path.display(),
                COLORS.reset
            );
            print_command_output(&output).map_err(|e| format!("Failed printing output: {}", e))?;
            Err("Build step failed".to_string())
        } else {
            Ok(())
        }
    })?;

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

fn main() {
    let patches_dir = PathBuf::from("vm/examples/patch-testing/patches");
    let patch_dirs = find_patch_directories(&patches_dir);

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

    // Process each patch and exit if any step fails.
    for (i, patch_path) in patch_dirs.iter().enumerate() {
        if let Err(err) = test_patch(patch_path, patch_dirs.len(), i) {
            eprintln!(
                "{}Error testing patch {}: {}{}",
                COLORS.red,
                patch_path.display(),
                err,
                COLORS.reset
            );
            std::process::exit(1);
        }
        println!(
            "{}✓ Patch {} tested successfully.{}",
            COLORS.green,
            patch_path.display(),
            COLORS.reset
        );
    }

    println!("\n{}== Testing Complete =={}", COLORS.cyan, COLORS.reset);
    println!("Results: {} all patches tested successfully.", COLORS.green);
}
