//! Prove the aggregator guest together with the two fibonacci proofs it claims, and verify the
//! result in this process.
//!
//! ```text
//! cargo run --release -- prove
//! ```
//!
//! The guest reads a list of program ids and committed outputs, and calls `verify_pico_proof` for
//! each pair. That call proves nothing inside the guest: it folds the claim into the run's
//! `deferred_proofs_digest`, and the recursion tree has to close that digest with one deferred
//! node per claim, each verifying a real complete proof of the claimed program. So the flow is:
//!
//! 1. prove fibonacci for two `n` to a combine root each — the sub-proofs;
//! 2. emulate and prove the aggregator over those two claims;
//! 3. prove one deferred node per sub-proof, chained in the order the guest claimed them;
//! 4. convert and combine the aggregator's chunks behind those nodes into one root, and verify it.
//!
//! The SDK (`pico-prover`) has no entry point for deferred proofs, so this drives the machines in
//! `pico-vm` directly. It runs in dev mode (no whitelist) and verifies only in this process: a
//! combine root verifies in another process only against the whitelist.

mod tree;

use std::sync::Arc;

use alloy_sol_types::SolType;
use eyre::{ensure, eyre, WrapErr};
use fibonacci_lib::{fibonacci, PublicValuesStruct};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use pico_mle_core::{
    config::recursion_params_with_100_bits_security, keygen::types::MultiStarkVerifyingKey,
    protocol::proof::Proof,
};
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        opts::EmulatorOpts,
        recursion::public_values::RECURSION_PUBLIC_VALUES_COL_MAP,
        stdin::{EmulatorStdin, EmulatorStdinBuilder},
    },
    machine::logger::setup_logger,
    mle::machine::{
        convert::ProofWithVk,
        deferred::DeferredMachine,
        exe::RiscvVmVk,
        recursion::{recursion_public_values, Kb},
        riscv::{self, EmulationOutput},
    },
    primitives::{consts::DIGEST_SIZE, hash_deferred_proof},
};
use sha2::{Digest, Sha256};
use tracing::info;
use tree::build_tree;

const FIBONACCI_ELF: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fibonacci/app/elf/riscv64im-pico-zkvm-elf"
);
const AGGREGATOR_ELF: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../app/elf/riscv64im-pico-zkvm-elf"
);

/// The fibonacci inputs whose proofs the aggregator claims.
const FIBONACCI_NS: [u32; 2] = [10, 20];

const LOG_STACKED_HEIGHT: usize = 23;

const USAGE: &str = "usage: aggregator-prover prove";

fn main() -> eyre::Result<()> {
    setup_logger();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["prove"] => prove(),
        _ => Err(eyre!(USAGE)),
    }
}

/// One proved program: its chunk proofs and keys, and what its guest committed.
struct Proved {
    riscv_vk: Arc<MultiStarkVerifyingKey<riscv::Sc>>,
    vm_vk: RiscvVmVk,
    proofs: Vec<Proof<riscv::Sc>>,
    emulated: EmulationOutput,
}

fn prove() -> eyre::Result<()> {
    let col = RECURSION_PUBLIC_VALUES_COL_MAP;

    // ── The sub-proofs: fibonacci, proved to a complete root for each n ──────────────────────
    let fibonacci_elf = read_elf(FIBONACCI_ELF)?;
    let mut sub_roots = Vec::new();
    let mut vk_digests: Vec<[u32; DIGEST_SIZE]> = Vec::new();
    let mut public_values: Vec<Vec<u8>> = Vec::new();
    let mut outputs = Vec::new();
    for n in FIBONACCI_NS {
        let fib = prove_riscv(&fibonacci_elf, |stdin| stdin.write(&n))?;
        let values = check_fibonacci(&fib.emulated.committed_bytes, n)?;
        let root = build_tree(
            &fib.riscv_vk,
            &fib.vm_vk,
            &fib.proofs,
            [Kb::ZERO; DIGEST_SIZE],
            &[],
        )
        .wrap_err_with(|| format!("fibonacci({n}) root"))?;
        check_committed(&root, &fib.emulated.committed_bytes)?;

        // The id a deferred node publishes for its sub-proof, and the one the guest has to claim.
        let pvs = root_public_values(&root)?;
        let vk_digest = std::array::from_fn(|j| pvs[col.riscv_vk_digest[j]].as_canonical_u32());
        info!(
            "fibonacci({n}) = ({}, {}): root proved and verified, program id {vk_digest:?}",
            values.a, values.b
        );
        vk_digests.push(vk_digest);
        public_values.push(fib.emulated.committed_bytes);
        outputs.push(values);
        sub_roots.push(root);
    }

    // ── The aggregator, claiming both sub-proofs ─────────────────────────────────────────────
    let agg = prove_riscv(&read_elf(AGGREGATOR_ELF)?, |stdin| {
        stdin.write(&vk_digests);
        stdin.write(&public_values);
    })?;
    // The guest commits both lists back, each through its own `commit`.
    let expected = [
        bincode::serialize(&vk_digests)?,
        bincode::serialize(&public_values)?,
    ]
    .concat();
    ensure!(
        agg.emulated.committed_bytes == expected,
        "the aggregator did not commit the program ids and outputs it was given"
    );
    info!("aggregator: {} chunk proof(s)", agg.proofs.len());

    // One node per claim, in the order the guest claimed them. A node publishes the identity of
    // the MAIN program, so the machine is keyed to the aggregator, not to fibonacci.
    let mut deferred = DeferredMachine::new(
        recursion_params_with_100_bits_security(),
        agg.vm_vk.clone(),
        false,
    );
    let (nodes, chain_end) = deferred
        .prove_chain(&sub_roots)
        .wrap_err("deferred nodes")?;
    info!("{} deferred node(s) proved", nodes.len());

    // The nodes lead the tree, ahead of the aggregator's leaves, which carry the chain's end.
    let root = build_tree(&agg.riscv_vk, &agg.vm_vk, &agg.proofs, chain_end, &nodes)
        .wrap_err("aggregator root")?;
    // The guest's claims, folded here the way its `verify_pico_proof` folds them, must be what
    // the root closed over.
    let claimed = vk_digests.iter().zip(&public_values).fold(
        [Kb::ZERO; DIGEST_SIZE],
        |prev, (vk_digest, values)| {
            let pv_digest: [u8; 32] = Sha256::digest(values).into();
            hash_deferred_proof(
                &prev,
                &vk_digest.map(Kb::from_u32),
                &pv_digest.map(|b| Kb::from_u32(b.into())),
            )
        },
    );
    let pvs = root_public_values(&root)?;
    ensure!(
        (0..DIGEST_SIZE).all(|j| pvs[col.deferred_proofs_digest[j]] == claimed[j]),
        "the root's deferred_proofs_digest is not the fold of the guest's claims"
    );
    check_committed(&root, &agg.emulated.committed_bytes)?;

    println!(
        "aggregator root proved and verified, closing over {} proof(s):",
        nodes.len()
    );
    for (values, vk_digest) in outputs.iter().zip(&vk_digests) {
        println!(
            "  fibonacci({}) = ({}, {}), program id {vk_digest:?}",
            values.n, values.a, values.b
        );
    }
    println!("program ids are dev-mode ids, not the ones an on-chain verifier pins");
    Ok(())
}

fn read_elf(path: &str) -> eyre::Result<Vec<u8>> {
    std::fs::read(path).wrap_err_with(|| format!("{path}: build the guest with `cargo pico build`"))
}

/// Emulate a guest over the stdin `write_input` fills, and prove its RISC-V chunks.
fn prove_riscv(
    elf: &[u8],
    write_input: impl FnOnce(&mut EmulatorStdinBuilder<Vec<u8>, KoalaBearPoseidon2>),
) -> eyre::Result<Proved> {
    let program = Arc::new(Compiler::new(SourceType::RISCV, elf)?.compile());
    let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    write_input(&mut stdin);
    let opts = EmulatorOpts::from_env_chunk_size(1 << LOG_STACKED_HEIGHT);
    // `CHUNK_SIZE` can widen a chunk past the stacked height, which proves the wrong shape.
    ensure!(
        (opts.chunk_size as u64) <= (1u64 << LOG_STACKED_HEIGHT),
        "chunk_size {} exceeds 2^{LOG_STACKED_HEIGHT}",
        opts.chunk_size
    );
    let emulated = riscv::emulate_with_opts(Arc::clone(&program), &stdin.finalize(), opts)?;
    let (riscv_vk, proofs) = riscv::prove_riscv(
        Arc::clone(&program),
        &emulated.records,
        LOG_STACKED_HEIGHT,
        false,
    )?
    .into_parts();
    let vm_vk = RiscvVmVk::from_program_and_vk(&program, &riscv_vk);
    Ok(Proved {
        riscv_vk,
        vm_vk,
        proofs,
        emulated,
    })
}

fn root_public_values(root: &ProofWithVk) -> eyre::Result<Vec<Kb>> {
    Ok(recursion_public_values(&root.0.public_values)?.to_vec())
}

/// Hold the committed bytes to the digest the root attests to, which is what binds them to it.
fn check_committed(root: &ProofWithVk, committed: &[u8]) -> eyre::Result<()> {
    let pvs = root_public_values(root)?;
    let col = RECURSION_PUBLIC_VALUES_COL_MAP;
    let digest: Vec<u32> = col
        .committed_value_digest
        .iter()
        .flat_map(|word| word.0)
        .map(|i| pvs[i].as_canonical_u32())
        .collect();
    let expected = Sha256::digest(committed);
    ensure!(
        digest
            .iter()
            .copied()
            .eq(expected.iter().map(|&b| u32::from(b))),
        "the committed bytes do not hash to the root's committed_value_digest"
    );
    Ok(())
}

/// Decode fibonacci's ABI-encoded output and hold it to the sequence recomputed here.
fn check_fibonacci(committed: &[u8], n: u32) -> eyre::Result<PublicValuesStruct> {
    let values = PublicValuesStruct::abi_decode(committed, true)
        .map_err(|e| eyre!("fibonacci committed bytes: {e}"))?;
    ensure!(
        (values.n, values.a, values.b) == {
            let (a, b) = fibonacci(0, 1, n);
            (n, a, b)
        },
        "fibonacci committed F({}) = ({}, {}), not F({n})",
        values.n,
        values.a,
        values.b
    );
    Ok(values)
}
