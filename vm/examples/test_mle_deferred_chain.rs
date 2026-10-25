//! The reconstruct chain is no longer vacuous: what a convert leaf carries through it is now a
//! witnessed value the root closes around, not a hardwired zero.
//!
//! Ten cases, two guests, all in this process. Over fib, which defers nothing:
//!
//!   * `baseline` — an honest tree (the guest committed no deferred proof, so the chain's value is
//!     zero). MUST prove and verify. This is the harness's detection-power check: if the baseline
//!     fails, nothing else here means anything.
//!   * `nonzero-chain` — the same leaves, handed a non-zero chain value. MUST FAIL: it trips BOTH
//!     of the root's closures at once (the chain's left end is pinned to zero, and its right end
//!     to the guest's zero digest).
//!   * `unclosed-chain` — two real deferred nodes at the head of the tree, with the leaves carrying
//!     the value the chain ends on. MUST FAIL, and this one ISOLATES the right-hand closure: the
//!     first node starts at zero so the left end holds, continuity holds, and what cannot hold is
//!     `end_reconstruct == deferred_proofs_digest` — this guest committed zero. It is also the one
//!     tree node whose BOTH children are deferred, the only place the GCS fold adds and subtracts
//!     the neutral point around itself.
//!
//! Over the aggregator guest (`perf/bench_data/rv64/aggregator-elf`, built from
//! `examples/aggregator/app`), handed fib's exe identity and committed bytes, so its own
//! `deferred_proofs_digest` is one chain step over fib's root:
//!
//!   * `happy` — two deferred nodes over fib's root (the guest claims it twice) ahead of the
//!     aggregator's leaves. MUST prove and verify, with the root's `deferred_proofs_digest` equal
//!     to the chain the nodes built. The tree node joining the two is the one place the GCS fold
//!     pairs the neutral point with itself, here in a tree that has to verify.
//!   * `missing-node` — the same leaves carrying a zero chain value, no node: a caller that forgot
//!     the chain. MUST FAIL at the root, and isolates `end_reconstruct == deferred_proofs_digest`
//!     — the left end holds, the guest committed a digest nothing backs.
//!   * `seam-host` — `happy`'s first node alone, ahead of leaves carrying the guest's committed
//!     digest. MUST FAIL before proving, on combine's host-side check that the leaves start the
//!     chain where the nodes end it.
//!   * `seam` — the same children with that check switched off. MUST FAIL at the root, and
//!     isolates the continuity between children: the node starts at zero and the last leaf ends on
//!     the digest the guest committed, so both closures hold, and what cannot hold is the node's
//!     end (one chain step) equalling the first leaf's start (two).
//!   * `one-node` — `seam`'s control: the aggregator claiming fib's root once, its one node ahead
//!     of as many leaves as `seam` has, starting where it ends. MUST prove and verify, so the tree
//!     `seam` builds, whose first node pairs a deferred node with a convert leaf as no other case
//!     does, is not what `seam` fails on.
//!   * `nested` — `happy`'s root handed to a deferred node as its sub-proof: a complete, honest
//!     root whose own `deferred_proofs_digest` is not zero. MUST FAIL the node's verify.
//!   * `nested-control` — the same node over the same sub-proof, keygen'd without the requirement
//!     that the sub-proof's digest is zero. MUST prove and verify, so that requirement is the one
//!     `nested` fails on.
//!
//! Every failure but `seam-host`'s surfaces as a proof failing to VERIFY, not as proving
//! panicking: the recursion interpreter runs an unsatisfiable assertion out into the trace, and the
//! constraint system is what rejects it. The verify error names no constraint, so `seam` and
//! `nested`, the cases built over tree shapes no other case proves, each carry a control that
//! proves the same shape honestly.
//!
//! Not covered: a sub-proof that is not complete. Where the chunk cut lands in the commit run is
//! `test_mle_deferred_split`'s.
//!
//! Run by hand, as `test_cvd_forgery` is: a harness whose cases are mostly expected to fail is
//! read for its per-case verdicts, not for a green tick. The regression CI needs — that an honest
//! tree still proves with the chain in place — is the existing `test_mle_e2e` run.
//!
//! Usage:
//!   cargo run --release -p pico-vm --example test_mle_deferred_chain
//!
//! The process exits 0 only when every case matched its expectation.

use std::{panic, sync::Arc};

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use pico_mle_core::config::recursion_params_with_100_bits_security;
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{recursion::public_values::RECURSION_PUBLIC_VALUES_COL_MAP, stdin::EmulatorStdin},
    machine::logger::setup_logger,
    mle::machine::{
        combine::CombineMachine,
        convert::{ConvertMachine, ProofWithVk},
        deferred::DeferredMachine,
        exe::RiscvVmVk,
        recursion::{recursion_public_values, Kb},
        riscv,
    },
    primitives::consts::DIGEST_SIZE,
};
use tracing::info;

#[path = "common/emulate.rs"]
mod emulate;
/// How a tree whose root rejects its own constraints fails.
const ROOT_REJECTED: &str = "root combine proof failed STARK verify";
/// How a deferred node whose constraints reject its sub-proof fails.
const NODE_REJECTED: &str = "deferred node failed STARK verify";
/// How combine's host-side check refuses leaves that do not start where the nodes end.
const SEAM_REFUSED: &str = "the leaves do not start the deferred chain where the nodes end it";

#[path = "common/tree.rs"]
mod tree;
use tree::build_tree;

const ELF: &str = "./perf/bench_data/rv64/fib-elf";
const AGGREGATOR_ELF: &str = "./perf/bench_data/rv64/aggregator-elf";
const LOG_STACKED_HEIGHT: usize = 23;

fn main() {
    setup_logger();
    // The GPU riscv prover allocates from the shared pool; a CPU build has none to set up.
    #[cfg(feature = "cuda-mle")]
    riscv::init_mle_gpu_pool(riscv::MLE_GPU_DEVICE);

    let program = Arc::new(
        Compiler::new(SourceType::RISCV, &std::fs::read(ELF).expect("elf"))
            .expect("parse elf")
            .compile(),
    );
    let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    stdin.write(&10u32);
    let opts = emulate::opts_from_env_chunk_size(1 << 23);
    // A chunk wider than the stacked height proves the wrong shape, and both are env-settable.
    assert!(
        (opts.chunk_size as u64) <= (1u64 << LOG_STACKED_HEIGHT),
        "chunk_size {} exceeds 2^{LOG_STACKED_HEIGHT}: raise the height with CHUNK_SIZE",
        opts.chunk_size
    );
    let emulated = emulate::emulate_with_opts(Arc::clone(&program), &stdin.finalize(), opts);

    let bundle = riscv::prove_riscv(
        Arc::clone(&program),
        &emulated.records,
        LOG_STACKED_HEIGHT,
        false,
    )
    .expect("riscv prove failed");
    let (riscv_vk, riscv_proofs) = bundle.into_parts();
    let vm_vk = RiscvVmVk::from_program_and_vk(&program, &riscv_vk);
    info!("RISCV: {} chunk proof(s) ✓", riscv_proofs.len());

    // The baseline doubles as the sub-proof the deferred node verifies, so the honest tree is
    // built once rather than twice.
    let (baseline_ok, baseline) = run_case("baseline", true, ROOT_REJECTED, || {
        build_tree(
            &riscv_vk,
            &vm_vk,
            &riscv_proofs,
            [Kb::ZERO; DIGEST_SIZE],
            &[],
        )
    });
    assert!(
        baseline_ok,
        "the baseline must prove — nothing else here means anything"
    );
    let sub_root = baseline.expect("a matched baseline has a root");

    let mut deferred = DeferredMachine::new(
        recursion_params_with_100_bits_security(),
        vm_vk.clone(),
        false,
    );
    // Two nodes over the same sub-proof: the chain takes two steps, and the tree gets a node whose
    // BOTH children are deferred — the one pairing where the GCS fold adds and subtracts the
    // neutral point around itself, so a degenerate chord would surface here as a host-side
    // inverse-of-zero rather than as the root verify failure the case expects.
    let (nodes, chain_end) = deferred
        .prove_chain(&[sub_root.clone(), sub_root.clone()])
        .expect("deferred prove_chain failed");
    assert_eq!(nodes.len(), 2, "two sub-proofs should give two nodes");
    info!("two deferred nodes over that root ✓");

    let forged: [Kb; DIGEST_SIZE] = std::array::from_fn(|j| Kb::from_u32(j as u32 + 1));
    let mut failures = 0;
    for (name, deferred_digest, prefix) in [
        ("nonzero-chain", forged, &[][..]),
        ("unclosed-chain", chain_end, &nodes[..]),
    ] {
        let (matched, _) = run_case(name, false, ROOT_REJECTED, || {
            build_tree(&riscv_vk, &vm_vk, &riscv_proofs, deferred_digest, prefix)
        });
        if !matched {
            failures += 1;
        }
    }

    // ── A guest that defers: the aggregator, claiming fib's root ─────────────────────────────
    let col = RECURSION_PUBLIC_VALUES_COL_MAP;
    let sub_pvs = recursion_public_values(&sub_root.0.public_values).expect("sub-root pvs");
    let fib_identity: [u32; DIGEST_SIZE] =
        std::array::from_fn(|j| sub_pvs[col.riscv_vk_digest[j]].as_canonical_u32());
    let agg_program = Arc::new(
        Compiler::new(
            SourceType::RISCV,
            &std::fs::read(AGGREGATOR_ELF).expect("aggregator elf"),
        )
        .expect("parse aggregator elf")
        .compile(),
    );
    let mut agg_stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    agg_stdin.write(&vec![fib_identity; 2]);
    agg_stdin.write(&vec![emulated.committed_bytes.clone(); 2]);
    let agg_emulated = emulate::emulate_with_opts(
        Arc::clone(&agg_program),
        &agg_stdin.finalize(),
        emulate::opts_from_env_chunk_size(1 << 23),
    );
    let (agg_riscv_vk, agg_proofs) = riscv::prove_riscv(
        Arc::clone(&agg_program),
        &agg_emulated.records,
        LOG_STACKED_HEIGHT,
        false,
    )
    .expect("aggregator riscv prove failed")
    .into_parts();
    let agg_vm_vk = RiscvVmVk::from_program_and_vk(&agg_program, &agg_riscv_vk);
    info!("aggregator: {} chunk proof(s) ✓", agg_proofs.len());

    // The node publishes the MAIN program's identity, so it is keyed to the aggregator.
    let mut agg_deferred = DeferredMachine::new(
        recursion_params_with_100_bits_security(),
        agg_vm_vk.clone(),
        false,
    );
    let (agg_nodes, agg_chain_end) = agg_deferred
        .prove_chain(&[sub_root.clone(), sub_root.clone()])
        .expect("aggregator deferred prove_chain failed");

    let mut happy_root = None;
    for (name, must_prove, chain, prefix) in [
        ("happy", true, agg_chain_end, &agg_nodes[..]),
        ("missing-node", false, [Kb::ZERO; DIGEST_SIZE], &[][..]),
    ] {
        let (matched, root) = run_case(name, must_prove, ROOT_REJECTED, || {
            build_tree(&agg_riscv_vk, &agg_vm_vk, &agg_proofs, chain, prefix)
        });
        // A tree that closes carries the guest's digest, and it is the chain the nodes built.
        let closes_on_chain = root.as_ref().is_none_or(|root| {
            let pvs = recursion_public_values(&root.0.public_values).expect("root pvs");
            (0..DIGEST_SIZE).all(|j| pvs[col.deferred_proofs_digest[j]] == agg_chain_end[j])
        });
        if !(matched && closes_on_chain) {
            failures += 1;
        }
        if name == "happy" {
            happy_root = root;
        }
    }

    // Seam: one node where the chain takes two. The first node of `happy`'s chain starts at zero
    // and ends one step in. The leaves carry the digest the aggregator committed, two steps in,
    // which is also what the root compares the chain's end against. So the left closure (the
    // first child starts at zero) and the right one (the last child ends on the committed digest)
    // both hold, and only the link from the node to the first leaf breaks.
    let node_pvs = recursion_public_values(&agg_nodes[0].0.public_values).expect("node pvs");
    assert!(
        (0..DIGEST_SIZE).all(|j| node_pvs[col.start_reconstruct_deferred_digest[j]] == Kb::ZERO),
        "seam: the node must start the chain at zero, or the left closure fails too"
    );
    assert!(
        (0..DIGEST_SIZE)
            .any(|j| node_pvs[col.end_reconstruct_deferred_digest[j]] != agg_chain_end[j]),
        "seam: the node must end short of the committed digest, or no link breaks"
    );
    // `build_tree`, with combine's host-side seam check optionally switched off.
    let seam_tree = |check_seam: bool| -> eyre::Result<ProofWithVk> {
        let mut convert = ConvertMachine::new(
            agg_riscv_vk.clone(),
            agg_vm_vk.clone(),
            &agg_proofs,
            recursion_params_with_100_bits_security(),
            false,
        )?;
        convert.set_final_deferred_digest(agg_chain_end);
        let mut children = agg_nodes[..1].to_vec();
        children.extend(convert.prove_with_vks(&agg_proofs)?);
        let mut combine = CombineMachine::new(
            recursion_params_with_100_bits_security(),
            agg_vm_vk.clone(),
            false,
        );
        if !check_seam {
            combine.skip_seam_check_for_testing();
        }
        let root = combine.prove_tree(children)?;
        combine.verify(&root)?;
        Ok(root)
    };
    for (name, check_seam, failure) in [
        ("seam-host", true, SEAM_REFUSED),
        ("seam", false, ROOT_REJECTED),
    ] {
        let (matched, _) = run_case(name, false, failure, || seam_tree(check_seam));
        if !matched {
            failures += 1;
        }
    }

    // The control for `seam`: the aggregator claiming fib's root once, so one node is the whole
    // chain and the leaves start where it ends. With as many leaves as `seam`, the tree reduces
    // the same way, pairing the deferred node with the first convert leaf, and must prove.
    let mut one_stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    one_stdin.write(&vec![fib_identity; 1]);
    one_stdin.write(&vec![emulated.committed_bytes.clone(); 1]);
    let one_emulated = emulate::emulate_with_opts(
        Arc::clone(&agg_program),
        &one_stdin.finalize(),
        emulate::opts_from_env_chunk_size(1 << 23),
    );
    let (one_riscv_vk, one_proofs) = riscv::prove_riscv(
        Arc::clone(&agg_program),
        &one_emulated.records,
        LOG_STACKED_HEIGHT,
        false,
    )
    .expect("one-claim aggregator riscv prove failed")
    .into_parts();
    assert_eq!(
        one_proofs.len(),
        agg_proofs.len(),
        "one-node: as many leaves as `seam`, or its tree is shaped differently"
    );
    let one_vm_vk = RiscvVmVk::from_program_and_vk(&agg_program, &one_riscv_vk);
    let mut one_deferred = DeferredMachine::new(
        recursion_params_with_100_bits_security(),
        one_vm_vk.clone(),
        false,
    );
    let (one_nodes, one_chain_end) = one_deferred
        .prove_chain(std::slice::from_ref(&sub_root))
        .expect("one-claim deferred prove_chain failed");
    let (matched, _) = run_case("one-node", true, ROOT_REJECTED, || {
        build_tree(
            &one_riscv_vk,
            &one_vm_vk,
            &one_proofs,
            one_chain_end,
            &one_nodes,
        )
    });
    if !matched {
        failures += 1;
    }

    // Nested: a sub-proof that defers. `happy`'s root verified as a complete root, so every
    // completeness relation the node re-runs on it holds; its own digest is the aggregator's
    // chain, not zero. `nested-control` proves the same node over the same sub-proof without the
    // zero-digest requirement, the one thing the two keys differ in.
    match happy_root {
        Some(happy_root) => {
            let pvs = recursion_public_values(&happy_root.0.public_values).expect("root pvs");
            assert_eq!(
                pvs[col.flag_complete],
                Kb::ONE,
                "nested: the sub-proof is complete"
            );
            assert!(
                (0..DIGEST_SIZE).any(|j| pvs[col.deferred_proofs_digest[j]] != Kb::ZERO),
                "nested: the sub-proof's own deferred digest must be non-zero"
            );
            for (name, must_prove, admit_nested) in
                [("nested", false, false), ("nested-control", true, true)]
            {
                let mut nested = DeferredMachine::new(
                    recursion_params_with_100_bits_security(),
                    agg_vm_vk.clone(),
                    false,
                );
                if admit_nested {
                    nested.admit_nested_for_testing();
                }
                let (matched, _) = run_case(name, must_prove, NODE_REJECTED, || {
                    let (nodes, _) = nested.prove_chain(std::slice::from_ref(&happy_root))?;
                    nested.verify(&nodes[0])?;
                    Ok(nodes[0].clone())
                });
                if !matched {
                    failures += 1;
                }
            }
        }
        None => {
            tracing::error!("cases nested, nested-control: not run, `happy` gave no root to nest");
            failures += 2;
        }
    }

    assert_eq!(failures, 0, "{failures} case(s) did not match expectation");
    info!("Deferred chain: every case matched ✓");
}

/// Run one case and report it: whether it matched its expectation, and the proof when it proved
/// (which the caller consumes as a sub-proof).
///
/// A case that fails for the wrong reason would be worthless, so the reason is printed rather than
/// swallowed: a must-fail case matches only when it fails with `failure`, the verify of the proof
/// whose constraints carry the check, not earlier.
fn run_case(
    name: &str,
    must_prove: bool,
    failure: &str,
    run: impl FnOnce() -> eyre::Result<ProofWithVk>,
) -> (bool, Option<ProofWithVk>) {
    let outcome = panic::catch_unwind(panic::AssertUnwindSafe(run));
    let (root, reason) = match outcome {
        Ok(Ok(root)) => (Some(root), String::from("proved and verified")),
        Ok(Err(e)) => (None, format!("{e}")),
        Err(payload) => {
            let msg = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
                .unwrap_or_else(|| String::from("panic with no message"));
            (None, msg)
        }
    };
    let proved = root.is_some();
    // A case that died in keygen or witness generation would also be "not proved", and would leave
    // this harness green while testing nothing.
    let right_place = must_prove || reason.contains(failure);
    let matched = proved == must_prove && right_place;
    if matched {
        info!("case {name}: proved = {proved} (as expected) — {reason}");
    } else if proved != must_prove {
        tracing::error!("case {name}: proved = {proved} (WRONG) — {reason}");
    } else {
        tracing::error!("case {name}: failed in the WRONG PLACE — {reason}");
    }
    (matched, root)
}
