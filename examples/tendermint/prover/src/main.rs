//! Prove a Tendermint light-client update, and hold what the guest committed to the host's own
//! verification of the same two blocks.
//!
//! ```text
//! (cd ../app && cargo pico build)
//! cargo run --release
//! ```
//!
//! It emulates first, which costs seconds and no keygen, and checks the emulated output against the
//! host before spending minutes proving. Then `Prover::prove` proves the whole chain to one combine
//! root and verifies it in process.
//!
//! It needs a large machine: at the prover's defaults it peaks near 200 GB. `examples/README.md`
//! has the measurements, and the options that trade proving time for memory.
//!
//! This runs in dev mode, as the fibonacci example does, so this prover's program id is not the one
//! a contract pins.

use std::{error::Error, process::ExitCode};

use pico_prover::{Prover, Stdin};
use tendermint_lib::verify_update;
use tendermint_light_client_verifier::types::LightBlock;

/// Where `cargo pico build` writes the guest.
const ELF_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../app/elf/riscv64im-pico-zkvm-elf"
);

/// The guest's three commits, in the order it makes them.
const SEGMENTS: [&str; 3] = ["trusted header hash", "untrusted header hash", "verdict"];

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
    let elf = std::fs::read(ELF_PATH).map_err(|e| {
        format!("{ELF_PATH}: {e}; build the guest with `cargo pico build` in ../app")
    })?;
    let trusted = load_light_block(2279100)?;
    let untrusted = load_light_block(2279130)?;
    let expected = expected_commits(&trusted, &untrusted)?;
    let stdin = guest_input(&trusted, &untrusted)?;

    let execution = Prover::builder(&elf).execute(stdin.clone())?;
    check(&execution.committed_bytes, &expected, "the emulation")?;
    println!(
        "executed {} cycle(s) in {} chunk(s); the emulated commits match the host",
        execution.cycles, execution.chunks
    );

    let mut prover = Prover::new(&elf)?;
    let proof = prover.prove(stdin)?;
    check(proof.committed().as_bytes(), &expected, "the proof")?;
    println!(
        "proved and verified the update from block {} to block {}; all three commits match the host",
        trusted.height(),
        untrusted.height()
    );
    println!(
        "program id (dev mode, not the id an on-chain verifier pins): {}",
        proof.program_id()
    );
    Ok(())
}

fn load_light_block(height: u64) -> Result<LightBlock, Box<dyn Error>> {
    let path = format!("{}/files/block_{height}.json", env!("CARGO_MANIFEST_DIR"));
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

/// The two blocks as the guest reads them: CBOR, trusted first.
fn guest_input(trusted: &LightBlock, untrusted: &LightBlock) -> Result<Stdin, Box<dyn Error>> {
    let mut stdin = Stdin::new();
    stdin
        .write_bytes(&serde_cbor::to_vec(trusted)?)
        .write_bytes(&serde_cbor::to_vec(untrusted)?);
    Ok(stdin)
}

/// What the guest commits for these two blocks, recomputed here: both header hashes, then the
/// verdict of the same `verify_update` the guest calls, CBOR-encoded.
fn expected_commits(
    trusted: &LightBlock,
    untrusted: &LightBlock,
) -> Result<[Vec<u8>; 3], Box<dyn Error>> {
    let verdict = verify_update(trusted, untrusted)?;
    Ok([
        trusted.signed_header.header.hash().as_bytes().to_vec(),
        untrusted.signed_header.header.hash().as_bytes().to_vec(),
        serde_cbor::to_vec(&verdict)?,
    ])
}

/// Compare the committed stream segment by segment, so a mismatch names the one that differs.
/// `source` says what produced the bytes, an emulation or a proof.
fn check(committed: &[u8], expected: &[Vec<u8>; 3], source: &str) -> Result<(), String> {
    let total: usize = expected.iter().map(Vec::len).sum();
    if committed.len() != total {
        return Err(format!(
            "{source} commits {} byte(s); the host expects {total}",
            committed.len()
        ));
    }
    let mut rest = committed;
    for (name, want) in SEGMENTS.iter().zip(expected) {
        let (got, tail) = rest.split_at(want.len());
        if got != want.as_slice() {
            return Err(format!(
                "{name}: {source} commits {got:02x?}, the host computes {want:02x?}"
            ));
        }
        rest = tail;
    }
    Ok(())
}
