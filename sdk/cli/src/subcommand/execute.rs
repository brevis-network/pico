use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use pico_prover::{Execution, PureExecution};

use crate::{
    guest::{encode_hex, GuestArgs},
    options::ProverArgs,
};

#[derive(Parser)]
#[command(
    name = "execute",
    about = "Run an ELF in the emulator without proving it",
    long_about = "Run an ELF in the emulator without proving it.\n\n\
        Exit status: 0 when the guest halts successfully, 1 when the guest fails (a non-zero exit \
        code, a panic, a fault, or a syscall it may not make; an exit code, when there is one, is \
        written to --exit-code-file), 2 when the run cannot be executed at all."
)]
pub struct ExecuteCmd {
    #[clap(flatten)]
    guest: GuestArgs,

    #[clap(flatten)]
    prover: ProverArgs,

    /// Pure execution: run the guest to its halt without chunking it, in constant memory. Reports
    /// no chunk or precompile counts, and does not catch a hint read into memory the guest wrote
    #[clap(long, conflicts_with_all = ["aot", "serial_emulation"])]
    pure: bool,

    /// Write the bytes the guest committed to this file when it halts successfully
    #[clap(long, value_name = "FILE")]
    public_output: Option<PathBuf>,

    /// Write the guest's exit code to this file, in decimal: 0 when it halts successfully,
    /// otherwise its 32-bit exit code
    #[clap(long, value_name = "FILE")]
    exit_code_file: Option<PathBuf>,
}

/// How a guest's run ended, as the exit status reports it.
enum Halt {
    Success,
    Abnormal,
}

impl ExecuteCmd {
    pub(crate) fn aot_elf(&self) -> Option<&Path> {
        self.prover.aot.then_some(self.guest.elf.as_path())
    }

    /// Runs the guest and exits the process with the status the command documents.
    pub fn run(&self) -> Result<()> {
        match self.execute() {
            Ok(Halt::Success) => Ok(()),
            Ok(Halt::Abnormal) => std::process::exit(1),
            Err(e) => {
                eprintln!("Error: {e:?}");
                std::process::exit(2)
            }
        }
    }

    fn execute(&self) -> Result<Halt> {
        // A file left from an earlier run must not pass for this one's.
        for path in [&self.public_output, &self.exit_code_file]
            .into_iter()
            .flatten()
        {
            match std::fs::remove_file(path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(e).with_context(|| format!("cannot remove `{}`", path.display()))
                }
                _ => {}
            }
        }
        let options = self.prover.resolve_for_execute()?;
        let elf = self.guest.read_elf()?;
        let builder = options.builder(&elf);
        let run = if self.pure {
            builder.execute(self.guest.stdin()).map(|pure| {
                print_pure_execution(&pure);
                pure.committed_bytes
            })
        } else {
            builder.execute_chunked(self.guest.stdin()).map(|chunked| {
                print_execution(&chunked);
                chunked.committed_bytes
            })
        };
        let committed = match run {
            Ok(committed) => committed,
            Err(e) if e.is_guest_fault() => {
                eprintln!("Error: {e}");
                if let Some(code) = e.exit_code() {
                    self.write_exit_code(code)?;
                }
                return Ok(Halt::Abnormal);
            }
            Err(e) => return Err(e.into()),
        };
        if let Some(path) = &self.public_output {
            std::fs::write(path, &committed)
                .with_context(|| format!("cannot write `{}`", path.display()))?;
        }
        self.write_exit_code(0)?;
        Ok(Halt::Success)
    }

    fn write_exit_code(&self, code: u32) -> Result<()> {
        match &self.exit_code_file {
            Some(path) => std::fs::write(path, code.to_string())
                .with_context(|| format!("cannot write `{}`", path.display())),
            None => Ok(()),
        }
    }
}

fn print_pure_execution(execution: &PureExecution) {
    println!("executed: {} cycle(s)", execution.cycles);
    println!("misaligned accesses: {}", execution.misaligned_accesses);
    println!(
        "committed ({} byte(s), not proved): {}",
        execution.committed_bytes.len(),
        encode_hex(&execution.committed_bytes)
    );
}

fn print_execution(execution: &Execution) {
    println!(
        "executed: {} cycle(s), {} chunk(s)",
        execution.cycles, execution.chunks
    );
    println!("misaligned accesses: {}", execution.misaligned_accesses);
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
}
