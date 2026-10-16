use anyhow::Result;
use clap::{crate_version, Parser, Subcommand};
use pico_sdk::init_logger;
use std::{ffi::OsString, path::Path};

use crate::{
    aot_helper,
    subcommand::{
        aot::AotCmd, build::BuildCmd, execute::ExecuteCmd, install::InstallCmd, new::NewCmd,
        prove::ProveCmd,
    },
};

#[derive(Parser)]
#[command(name = "cargo", bin_name = "cargo")]
pub enum Cargo {
    Pico(PicoCli),
}

#[derive(clap::Args)]
#[command(
    author,
    about,
    long_about = None,
    args_conflicts_with_subcommands = true,
    arg_required_else_help = true,
    version = crate_version!()
)]
pub struct PicoCli {
    #[clap(subcommand)]
    pub command: SubCommands,
}

#[derive(Subcommand)]
pub enum SubCommands {
    Install(InstallCmd),
    Build(BuildCmd),
    Prove(ProveCmd),
    Execute(ExecuteCmd),
    Aot(AotCmd),
    New(NewCmd),
}

impl SubCommands {
    /// The ELF of a `prove` or `execute` given `--aot`.
    fn aot_elf(&self) -> Option<&Path> {
        match self {
            Self::Prove(cmd) => cmd.aot_elf(),
            Self::Execute(cmd) => cmd.aot_elf(),
            _ => None,
        }
    }
}

/// Runs `cargo pico` on `args`, which start with the program name, as `std::env::args_os()` does.
///
/// It builds its own tokio runtime, so it panics if called from inside one; and on a usage error,
/// `--help` or `--version` clap prints and exits the process rather than returning. So does an
/// `--aot` run outside a helper when the helper fails, with the helper's exit code.
#[tokio::main]
pub async fn run<I, T>(args: I) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    yansi::whenever(yansi::Condition::TTY_AND_COLOR);
    init_logger();
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let Cargo::Pico(cli) = Cargo::parse_from(&args);

    if let Some(elf) = cli.command.aot_elf() {
        if !aot_helper::has_program() {
            return aot_helper::build_and_run(elf, &args[1..]);
        }
    }

    match cli.command {
        SubCommands::Install(cmd) => cmd.run().await,
        SubCommands::Build(cmd) => cmd.run(),
        SubCommands::Prove(cmd) => cmd.run(),
        SubCommands::Execute(cmd) => cmd.run(),
        SubCommands::Aot(cmd) => cmd.run(),
        SubCommands::New(cmd) => cmd.run(),
    }
}
