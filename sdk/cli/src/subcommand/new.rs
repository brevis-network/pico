use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use yansi::Paint;

use crate::{remove_path, run_captured};

/// Supported version control systems.
#[derive(ValueEnum, Clone)]
enum Vcs {
    Git,
    None,
}

#[derive(ValueEnum, Clone, Debug)]
enum TemplateVariant {
    Basic,
    Evm,
}

#[derive(Parser)]
#[command(
    name = "new",
    about = "Setup a new project that runs inside the Pico zkVM."
)]
pub struct NewCmd {
    /// The name of the project.
    name: String,

    /// The template to use for the project.
    #[arg(long, value_enum, default_value = "basic")]
    template: TemplateVariant,

    /// Version control system to use (e.g., git, none).
    #[arg(long, value_enum, default_value = "git")]
    vcs: Vcs,

    /// The template tag or branch to clone. Without it, the template's release for this CLI's
    /// version (`v<version>`, or `evm-v<version>` for the EVM template), or its `main` or `evm`
    /// branch when it has no such release.
    #[arg(long, value_name = "REF")]
    template_ref: Option<String>,

    /// The template repository, for tests and mirrors.
    #[arg(long, hide = true, default_value = TEMPLATE_REPOSITORY_URL)]
    template_url: String,
}

const TEMPLATE_REPOSITORY_URL: &str = "https://github.com/brevis-network/pico-zkapp-template";
/// What a template whose contracts import `forge-std/` expects at `FORGE_STD_PATH`.
const FORGE_STD_URL: &str = "https://github.com/foundry-rs/forge-std";
const FORGE_STD_VERSION: &str = "v1.9.6";
const FORGE_STD_PATH: &str = "contracts/lib/forge-std";

/// What was at the project path before `new` ran, and so what a failure leaves there.
enum Before {
    Nothing,
    /// A clone fills it, so a failure empties it again.
    EmptyDir,
    /// The user's, left as it was: a file, a link, or a directory with content.
    Theirs,
}

impl Before {
    fn at(root: &Path) -> Self {
        // `exists` follows a link, and a dangling one is still the user's.
        match fs::symlink_metadata(root) {
            Err(_) => Self::Nothing,
            Ok(metadata) if metadata.is_dir() && is_empty(root) => Self::EmptyDir,
            Ok(_) => Self::Theirs,
        }
    }
}

fn is_empty(dir: &Path) -> bool {
    fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_none())
}

/// Removes everything in `dir`, keeping the directory.
fn clear(dir: &Path) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))? {
        remove_path(&entry?.path())?;
    }
    Ok(())
}

impl NewCmd {
    pub fn run(&self) -> Result<()> {
        let root = Path::new(&self.name);
        let before = Before::at(root);
        let result = self.create(root);
        if result.is_err() {
            let cleared = match before {
                Before::Nothing => remove_path(root),
                Before::EmptyDir => clear(root),
                Before::Theirs => Ok(()),
            };
            if let Err(error) = cleared {
                eprintln!("    {} {error:#}", "Warning:".yellow().bold());
            }
        }
        result
    }

    fn create(&self, root: &Path) -> Result<()> {
        let template_name = match self.template {
            TemplateVariant::Basic => "BASIC",
            TemplateVariant::Evm => "EVM",
        };
        println!("Using the {} template!", template_name.blue().bold());

        let reference = self.template_reference()?;
        println!(
            "     {} {} at {reference}",
            "Cloning".green().bold(),
            self.template_url
        );
        git(
            Path::new("."),
            &[
                "clone",
                "--depth=1",
                "--branch",
                &reference,
                &self.template_url,
                &self.name,
            ],
        )
        .with_context(|| format!("failed to clone the template from {}", self.template_url))?;
        fs::remove_dir_all(root.join(".git"))?;

        Self::replace_placeholder(&root.join("Cargo.toml"), "$PROJECT_NAME$", &self.name)?;

        match self.vcs {
            Vcs::Git => self.initialize_git(root)?,
            Vcs::None => println!(
                "     {} No version control system initialized",
                "Info:".blue().bold()
            ),
        }

        println!(
            " {} {} ({})",
            "Initialized".green().bold(),
            self.name,
            fs::canonicalize(root)?.display()
        );

        Ok(())
    }

    /// The ref to clone: `--template-ref` exactly, else this CLI's release tag, else the
    /// template's branch with a note that it may not match.
    fn template_reference(&self) -> Result<String> {
        let url = &self.template_url;
        if let Some(reference) = &self.template_ref {
            let heads = format!("refs/heads/{reference}");
            let tags = format!("refs/tags/{reference}");
            let found = git(Path::new("."), &["ls-remote", url, &heads, &tags])
                .with_context(|| format!("failed to read the refs of {url}"))?;
            if found.is_empty() {
                bail!("--template-ref `{reference}` is neither a branch nor a tag of {url}");
            }
            return Ok(reference.clone());
        }

        let version = env!("CARGO_PKG_VERSION");
        let (release, branch) = match self.template {
            TemplateVariant::Basic => (format!("v{version}"), "main"),
            TemplateVariant::Evm => (format!("evm-v{version}"), "evm"),
        };
        let tag = format!("refs/tags/{release}");
        let found = git(Path::new("."), &["ls-remote", "--tags", url, &tag])
            .with_context(|| format!("failed to read the tags of {url}"))?;
        if !found.is_empty() {
            return Ok(release);
        }
        eprintln!(
            "       {} the template has no release `{release}`; using its `{branch}` branch, \
             which may not match this CLI",
            "Note:".yellow().bold()
        );
        Ok(branch.to_string())
    }

    /// A repository with the template as its initial commit, and forge-std as a submodule when
    /// the template's contracts import it. Two steps only warn, so that a machine without GitHub
    /// or a git identity still gets a project that builds and proves.
    fn initialize_git(&self, root: &Path) -> Result<()> {
        println!("     {} Initializing Git repository", "Git".blue().bold());
        git(root, &["init"])?;
        // `branch -m` cannot rename an unborn branch before git 2.30.
        git(root, &["symbolic-ref", "HEAD", "refs/heads/main"])?;

        if imports_forge_std(root) {
            if let Err(error) = add_forge_std(root) {
                eprintln!(
                    "    {} forge-std was not added; `forge test` needs it, so add it by hand: \
                     `git submodule add {FORGE_STD_URL} {FORGE_STD_PATH}`: {error:#}",
                    "Warning:".yellow().bold()
                );
            }
        }

        git(root, &["add", "."])?;
        if let Err(error) = git(root, &["commit", "-m", "Initial commit"]) {
            eprintln!(
                "    {} no initial commit was made; commit by hand: {error:#}",
                "Warning:".yellow().bold()
            );
        }

        Ok(())
    }

    fn replace_placeholder(file_path: &Path, placeholder: &str, replacement: &str) -> Result<()> {
        let content = fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read file: {}", file_path.display()))?;
        fs::write(file_path, content.replace(placeholder, replacement))
            .with_context(|| format!("Failed to write to file: {}", file_path.display()))?;
        Ok(())
    }
}

/// Whether a Solidity file under `contracts`, outside its `lib`, imports from `forge-std/`, which
/// the template then expects at `FORGE_STD_PATH` and does not ship.
fn imports_forge_std(root: &Path) -> bool {
    !root.join(FORGE_STD_PATH).exists()
        && sol_files(&root.join("contracts")).iter().any(|file| {
            fs::read_to_string(file).is_ok_and(|source| source.contains("\"forge-std/"))
        })
}

fn sol_files(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name != "lib") {
                found.extend(sol_files(&path));
            }
        } else if path.extension().is_some_and(|extension| extension == "sol") {
            found.push(path);
        }
    }
    found
}

fn add_forge_std(root: &Path) -> Result<()> {
    println!(
        "     {} Adding forge-std {FORGE_STD_VERSION} as a submodule",
        "Git".blue().bold()
    );
    git(root, &["submodule", "add", FORGE_STD_URL, FORGE_STD_PATH])?;
    git(
        &root.join(FORGE_STD_PATH),
        &["checkout", "--quiet", FORGE_STD_VERSION],
    )?;
    Ok(())
}

/// `git args` in `dir`, with git's own message on failure.
fn git(dir: &Path, args: &[&str]) -> Result<String> {
    run_captured(Command::new("git").args(args).current_dir(dir))
}
