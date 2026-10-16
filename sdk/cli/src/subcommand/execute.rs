use std::path::Path;

use anyhow::Result;
use clap::Parser;

use crate::{
    guest::{encode_hex, GuestArgs},
    options::ProverArgs,
};

#[derive(Parser)]
#[command(
    name = "execute",
    about = "Run an ELF in the emulator without proving it"
)]
pub struct ExecuteCmd {
    #[clap(flatten)]
    guest: GuestArgs,

    #[clap(flatten)]
    prover: ProverArgs,
}

impl ExecuteCmd {
    pub(crate) fn aot_elf(&self) -> Option<&Path> {
        self.prover.aot.then_some(self.guest.elf.as_path())
    }

    pub fn run(&self) -> Result<()> {
        let options = self.prover.resolve_for_execute()?;
        let elf = self.guest.read_elf()?;
        let execution = options.builder(&elf).execute(self.guest.stdin())?;
        println!(
            "executed: {} cycle(s), {} chunk(s)",
            execution.cycles, execution.chunks
        );
        println!(
            "committed ({} byte(s), not proved): {}",
            execution.committed_bytes.len(),
            encode_hex(&execution.committed_bytes)
        );
        if !execution.precompile_calls.is_empty() {
            let mut calls: Vec<_> = execution
                .precompile_calls
                .iter()
                .map(|(code, n)| (code.to_string(), n))
                .collect();
            calls.sort_unstable();
            let calls: Vec<_> = calls
                .iter()
                .map(|(code, n)| format!("{code}={n}"))
                .collect();
            println!("precompiles: {}", calls.join(" "));
        }
        Ok(())
    }
}
