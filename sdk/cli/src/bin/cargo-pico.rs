use anyhow::Result;
use clap::{Parser, Subcommand};
use pico_cli::subcommand::{build::BuildCmd, new::NewCmd, prove::ProveCmd};
use pico_sdk::init_logger;

#[derive(Parser)]
#[command(name = "cargo", bin_name = "cargo")]
pub enum Cargo {
    Pico(PicoCli),
}

#[derive(clap::Args)]
#[command(author, about, long_about = None, args_conflicts_with_subcommands = true, version = "0.1.0")]
pub struct PicoCli {
    #[clap(subcommand)]
    pub command: Option<SubCommands>,
}

#[derive(Subcommand)]
pub enum SubCommands {
    Build(BuildCmd),
    Prove(ProveCmd),
    New(NewCmd),
}

fn main() -> Result<()> {
    init_logger();
    let Cargo::Pico(args) = Cargo::parse();
    let command: SubCommands = args.command.unwrap();

    match command {
        SubCommands::Build(cmd) => cmd.run(),
        SubCommands::Prove(cmd) => cmd.run(),
        SubCommands::New(cmd) => cmd.run(),
    }
}
