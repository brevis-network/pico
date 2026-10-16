use anyhow::Result;
use clap::Parser;

use crate::{build::build::build_program, DEFAULT_ELF_DIR};

#[derive(Parser)]
#[command(name = "build", about = "Build the ELF binary")]
pub struct BuildCmd {
    #[clap(flatten)]
    build_args: BuildArgs,
}

impl BuildCmd {
    pub fn run(&self) -> Result<()> {
        println!("Building ELF binary...");
        let program_dir = self.build_args.path.as_ref().map(std::path::PathBuf::from);
        let elf_path = build_program(&self.build_args, program_dir)?;
        println!("ELF binary built at: {:?}", elf_path.display());
        Ok(())
    }
}

#[derive(Clone, Parser)]
pub struct BuildArgs {
    #[clap(long, action, help = "Path to the program directory")]
    pub path: Option<String>,

    #[clap(
        long,
        action,
        value_delimiter = ',',
        help = "Space or comma separated list of features to activate"
    )]
    pub features: Vec<String>,

    // No comma delimiter: a rustc flag can contain one, as `-C target-feature=+m,+a` does.
    #[clap(
        long,
        action,
        help = "Space separated extra flags to invoke `rustc` with; may be repeated"
    )]
    pub rustflags: Vec<String>,

    #[clap(long, action, help = "Do not activate the `default` feature")]
    pub no_default_features: bool,

    #[clap(long, action, help = "Ignore `rust-version` specification in packages")]
    pub ignore_rust_version: bool,

    #[clap(alias = "bin", long, action, help = "Build only the specified binary")]
    pub binary: Option<String>,

    #[clap(
        long,
        action,
        help = "Name of the copied ELF; defaults to the `--bin` name, else `riscv64im-pico-zkvm-elf`"
    )]
    pub elf_name: Option<String>,

    #[clap(
        alias = "out-dir",
        long,
        action,
        help = "Copy the compiled ELF to this directory",
        default_value = DEFAULT_ELF_DIR
    )]
    pub output_directory: String,
}

impl BuildArgs {
    /// `--bin`; an empty value means the default, as a script that always passes the flag relies
    /// on.
    pub fn binary(&self) -> Option<&str> {
        given(&self.binary)
    }

    /// `--elf-name`; an empty value means the default.
    pub fn elf_name(&self) -> Option<&str> {
        given(&self.elf_name)
    }
}

fn given(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(cli: &[&str]) -> BuildArgs {
        BuildArgs::try_parse_from(std::iter::once("build").chain(cli.iter().copied())).unwrap()
    }

    #[test]
    fn an_empty_bin_or_elf_name_means_the_default() {
        let args = parse(&["--bin", "", "--elf-name", ""]);
        assert_eq!(args.binary(), None);
        assert_eq!(args.elf_name(), None);

        let args = parse(&["--bin", "first", "--elf-name", "out.elf"]);
        assert_eq!(args.binary(), Some("first"));
        assert_eq!(args.elf_name(), Some("out.elf"));
    }
}
