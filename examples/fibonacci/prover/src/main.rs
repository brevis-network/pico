//! Run the fibonacci guest through the host prover: emulate it, prove it, and verify the proof in
//! another process.
//!
//! ```text
//! (cd ../app && cargo pico build)
//! cargo run --release -- execute 100
//! cargo run --release -- prove fibonacci.pico 100
//! cargo run --release -- verify fibonacci.pico
//! ```
//!
//! `verify` also accepts the file `cargo pico prove --phase riscv` writes for this ELF at the CLI's
//! defaults, whatever `n` it was given: the check below recomputes the sequence from the `n` the
//! guest committed. A file proved at another `--log-stacked-height`, or in whitelist mode, is
//! refused: the verifier's operating point decides, never the file's.
//!
//! This runs in dev mode: no whitelist, natural trace heights. The same ELF has a different program
//! id under `verify_keys(true)`, and that is the id a contract pins.
//!
//! The file holds the RISC-V proof because that is the phase a process that proved nothing can
//! verify from the ELF alone. The combine root that `Prover::prove` returns verifies outside the
//! process that produced it only against the whitelist. The price is the weaker statement: a
//! RISC-V proof binds the output to a set of separately proved chunks, not to one complete
//! execution (`Proof::binds_complete_execution`).

use std::{error::Error, process::ExitCode};

use alloy_sol_types::SolType;
use fibonacci_lib::{fibonacci, PublicValuesStruct};
use pico_prover::{Phase, Proof, ProofArtifact, Prover, Stdin};

/// Where `cargo pico build` writes the guest.
const ELF_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../app/elf/riscv64im-pico-zkvm-elf"
);

const DEFAULT_N: u32 = 100;

const USAGE: &str =
    "usage: fibonacci-prover execute [n] | prove <proof-file> [n] | verify <proof-file>";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let elf = std::fs::read(ELF_PATH).map_err(|e| {
        format!("{ELF_PATH}: {e}; build the guest with `cargo pico build` in ../app")
    })?;

    // Each arm reads its arguments before keygen, which takes seconds.
    match args.as_slice() {
        ["execute", n @ ..] => {
            // Emulation only, without keygen: seconds, and nothing is proved.
            let n = parse_n(n)?;
            let execution = Prover::builder(&elf).execute(Stdin::from(&n))?;
            let values = check(&execution.committed_bytes, Some(n))?;
            println!(
                "executed {} cycle(s) in {} chunk(s); the guest committed F({}) = ({}, {}), not proved",
                execution.cycles, execution.chunks, values.n, values.a, values.b
            );
        }
        ["prove", path, n @ ..] => {
            let n = parse_n(n)?;
            let mut prover = Prover::new(&elf)?;
            let proof = prover.prove_to(Stdin::from(&n), Phase::Riscv)?;
            let values = check(proof.committed().as_bytes(), Some(n))?;
            proof.write(path)?;
            println!(
                "proved F({}) = ({}, {}) and wrote {path}",
                values.n, values.a, values.b
            );
            report(&proof);
        }
        ["verify", path] => {
            let artifact = ProofArtifact::read(path)?;
            let prover = Prover::new(&elf)?;
            let proof = prover.verify_artifact(artifact)?;
            let values = check(proof.committed().as_bytes(), None)?;
            println!(
                "verified {path}: the proof commits F({}) = ({}, {})",
                values.n, values.a, values.b
            );
            report(&proof);
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

fn parse_n(args: &[&str]) -> Result<u32, Box<dyn Error>> {
    match args {
        [] => Ok(DEFAULT_N),
        [n] => Ok(n.parse().map_err(|e| format!("n = `{n}`: {e}"))?),
        _ => Err(USAGE.into()),
    }
}

/// Decode what the guest committed, the way a Solidity verifier would, and hold it to the sequence
/// recomputed here. Validated decoding re-encodes and compares, so bytes that are not exactly one
/// struct's encoding are refused. `asked` is the `n` this process gave the guest, if it gave one.
fn check(committed: &[u8], asked: Option<u32>) -> Result<PublicValuesStruct, Box<dyn Error>> {
    let values = PublicValuesStruct::abi_decode(committed, true)
        .map_err(|e| format!("the committed bytes are not a PublicValuesStruct: {e}"))?;
    if let Some(asked) = asked.filter(|&asked| asked != values.n) {
        return Err(format!(
            "the guest commits F({}), not the F({asked}) it was given",
            values.n
        )
        .into());
    }
    let (a, b) = fibonacci(0, 1, values.n);
    if (values.a, values.b) != (a, b) {
        return Err(format!(
            "the guest commits F({}) = ({}, {}), not ({a}, {b})",
            values.n, values.a, values.b
        )
        .into());
    }
    Ok(values)
}

/// Both commands that print this run in dev mode, and `verify_artifact` refuses a file from the
/// other mode.
fn report(proof: &Proof) {
    if !proof.binds_complete_execution() {
        eprintln!(
            "note: a {} proof binds each chunk, not one complete execution",
            proof.phase()
        );
    }
    println!(
        "program id (dev mode, not the id an on-chain verifier pins): {}",
        proof.program_id()
    );
}
