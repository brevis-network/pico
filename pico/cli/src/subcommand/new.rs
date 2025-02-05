use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
};
use yansi::Paint;

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
}

// TODO: update the url
const TEMPLATE_REPOSITORY_URL: &str = "https://github.com/brevis-network/pico-zkapp-template";

impl NewCmd {
    pub fn run(&self) -> Result<()> {
        let root = Path::new(&self.name);

        // Create the root directory if it doesn't exist.
        if !root.exists() {
            fs::create_dir(&self.name)?;
        }

        println!(
            "     \x1b[1m{}\x1b[0m {}",
            Paint::green("Cloning"),
            TEMPLATE_REPOSITORY_URL
        );

        let (branch, template_name) = match self.template {
            TemplateVariant::Basic => ("main", "BASIC"),
            TemplateVariant::Evm => ("evm", "EVM"),
        };

        println!(
            "Using the {} template!",
            format_args!("\x1b[1;34m{}\x1b[0m", template_name)
        );

        // Clone the repository with the specified version.
        let mut command = Command::new("git");

        command
            .arg("clone")
            .arg("--branch")
            .arg(branch)
            .arg(TEMPLATE_REPOSITORY_URL)
            .arg(root.as_os_str())
            .arg("--depth=1");

        // Stream output to stdout.
        command.stdout(Stdio::inherit()).stderr(Stdio::inherit());

        let output = command.output().expect("failed to execute command");
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("failed to clone repository: {}", stderr));
        }

        // Remove the .git directory.
        fs::remove_dir_all(root.join(".git"))?;

        Self::replace_placeholder(&root.join("Cargo.toml"), "$PROJECT_NAME$", &self.name)?;

        // Handle VCS operations based on the user's selection.
        match self.vcs {
            Vcs::Git => self.initialize_git(root)?,
            Vcs::None => println!(
                "     \x1b[1m{}\x1b[0m No version control system initialized",
                Paint::blue("Info:")
            ),
        }

        println!(
            " \x1b[1m{}\x1b[0m {} ({})",
            Paint::green("Initialized"),
            self.name,
            fs::canonicalize(root)
                .expect("failed to canonicalize")
                .to_str()
                .unwrap()
        );

        Ok(())
    }

    /// Initializes a Git repository and performs related setup.
    fn initialize_git(&self, root: &Path) -> Result<()> {
        println!(
            "     \x1b[1m{}\x1b[0m Initializing Git repository",
            Paint::blue("Git")
        );

        // Initialize a new Git repository.
        Command::new("git")
            .arg("init")
            .current_dir(root)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .context("Failed to initialize git repository")?;

        // Rename the default branch to `main`.
        Command::new("git")
            .arg("branch")
            .arg("-m")
            .arg("main")
            .current_dir(root)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .context("Failed to rename branch to main")?;

        // Add submodule only if the template is EVM.
        if matches!(self.template, TemplateVariant::Evm) {
            self.add_submodule(root)?;
        }

        // Add all files to the new repository.
        Command::new("git")
            .arg("add")
            .arg(".")
            .current_dir(root)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .context("Failed to add files to git repository")?;

        // Create an initial commit.
        let commit_output = Command::new("git")
            .arg("commit")
            .arg("-m")
            .arg("Initial commit")
            .current_dir(root)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output();

        if let Err(error) = commit_output {
            println!(
                "    \x1b[1m{}\x1b[0m Could not create an initial commit. Please commit manually.",
                Paint::yellow("Warning:")
            );
            println!("    Error: {}", error);
        } else if !commit_output.unwrap().status.success() {
            println!(
                "    \x1b[1m{}\x1b[0m Initial commit failed. Please commit manually.",
                Paint::yellow("Warning:")
            );
        }

        Ok(())
    }

    /// Replaces a placeholder in a file with the specified value.
    fn replace_placeholder(file_path: &Path, placeholder: &str, replacement: &str) -> Result<()> {
        // Read the file content.
        let content = fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read file: {}", file_path.display()))?;

        // Replace the placeholder.
        let new_content = content.replace(placeholder, replacement);

        // Write the modified content back to the file.
        fs::write(file_path, new_content)
            .with_context(|| format!("Failed to write to file: {}", file_path.display()))?;

        Ok(())
    }

    /// Adds the Git submodule for `forge-std` at the specified path if the template is EVM.
    fn add_submodule(&self, root: &Path) -> Result<()> {
        println!(
            "     \x1b[1m{}\x1b[0m Adding Git submodule",
            Paint::blue("Git Submodule")
        );

        // Add the submodule for `forge-std`.
        Command::new("git")
            .arg("submodule")
            .arg("add")
            .arg("https://github.com/foundry-rs/forge-std")
            .arg("contracts/lib/forge-std")
            .current_dir(root)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .context("Failed to add submodule")?;

        println!(
            "     \x1b[1m{}\x1b[0m Checking out v1.9.6 for submodule",
            Paint::blue("Git Submodule")
        );

        // Checkout the specific version (v1.9.6) for the submodule.
        Command::new("git")
            .arg("checkout")
            .arg("v1.9.6")
            .current_dir(root.join("contracts/lib/forge-std"))
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .context("Failed to checkout v1.9.6 for submodule")?;

        // // Initialize and update the submodule.
        // Command::new("git")
        //     .arg("submodule")
        //     .arg("update")
        //     .arg("--init")
        //     .arg("--recursive")
        //     .current_dir(root)
        //     .stdout(Stdio::inherit())
        //     .stderr(Stdio::inherit())
        //     .output()
        //     .context("Failed to update submodule")?;

        Ok(())
    }
}
