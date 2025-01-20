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
        let elf_path = build_program(&self.build_args, None)?;
        println!("ELF binary built at: {:?}", elf_path.display());
        Ok(())
    }
}

#[derive(Clone, Parser)]
pub struct BuildArgs {
    #[clap(
        long,
        action,
        value_delimiter = ',',
        help = "Space or comma separated list of features to activate"
    )]
    pub features: Vec<String>,

    #[clap(
        long,
        action,
        value_delimiter = ',',
        help = "Space or comma separated list of extra flags to invokes `rustc` with"
    )]
    pub rustflags: Vec<String>,

    #[clap(long, action, help = "Do not activate the `default` feature")]
    pub no_default_features: bool,

    #[clap(long, action, help = "Ignore `rust-version` specification in packages")]
    pub ignore_rust_version: bool,

    #[clap(
        alias = "bin",
        long,
        action,
        help = "Build only the specified binary",
        default_value = ""
    )]
    pub binary: String,

    #[clap(long, action, help = "ELF binary name", default_value = "")]
    pub elf_name: String,

    #[clap(
        alias = "out-dir",
        long,
        action,
        help = "Copy the compiled ELF to this directory",
        default_value = DEFAULT_ELF_DIR
    )]
    pub output_directory: String,
}
